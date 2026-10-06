from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
import sys

import pytest

from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.models import RunStatus
from svarog.audit_history.repository import HistoryRepository
from svarog.audit_history.service import HistoryServiceError, audit_with_history
from svarog.audit_history.service import _fingerprint
from svarog.dependency_audit.models import (
    AdvisoryRecord, AdvisorySeverity, AuditIssue, DatabaseMetadata, DependencyFinding, InstalledPackage,
    InventoryResult, VulnerabilitySnapshot,
)
from svarog.webui.adapters import _AuditExecution
from svarog.project_audit.models import LockSnapshot, LockedDependency, LockedPackage


PROJECT = "proj_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
NOW = datetime(2026, 9, 30, 8, 0, 0, tzinfo=UTC)


@pytest.fixture
def repository(tmp_path: Path):
    manager = DatabaseManager.open(tmp_path / "history.sqlite3")
    try:
        yield HistoryRepository(manager.connection)
    finally:
        manager.close()


@pytest.fixture
def environment(tmp_path: Path) -> Path:
    path = tmp_path / "venv"
    path.mkdir()
    (path / "pyvenv.cfg").write_text("implementation = CPython\nversion = 3.11.7\n", encoding="utf-8")
    return path


@pytest.fixture
def prepared(environment: Path) -> _AuditExecution:
    inventory = InventoryResult(
        environment_path=str(environment), site_packages=(),
        packages=(InstalledPackage("Demo", "demo", "1.0", True, str(environment / "secret")),),
        ambiguous_names=frozenset(), issues=(), total_metadata_dirs=1,
        truncated_metadata_dirs=0,
    )
    vulnerability = VulnerabilitySnapshot(
        DatabaseMetadata(path="source.db", size_bytes=1, sources=("osv",),
                         last_sync_at="2026-09-30T07:00:00Z", last_sync_status="ok"),
        advisories=(),
    )
    return _AuditExecution(inventory, None, vulnerability)


def test_computed_run_persists_one_report_and_normalized_package(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from svarog.webui import adapters
    original = adapters._complete_audit
    calls = []

    def complete(value, *, now=None):
        calls.append(now)
        return original(value, now=now)

    monkeypatch.setattr(adapters, "_complete_audit", complete)
    outcome = audit_with_history(
        prepared, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW,
    )

    assert len(calls) == 1 and calls[0] == NOW
    assert outcome.reused is False
    assert outcome.change_summary.classification == "initial_snapshot"
    assert outcome.result["kind"] == "dependency_audit"
    assert outcome.result["report"]["audit_status"] == "completed_clean"
    run = repository.get_run(outcome.run_id)
    assert run.status is RunStatus.COMPLETED_COMPUTED
    assert run.python_version == "3.11.7"
    assert run.snapshot_id == outcome.snapshot_id
    packages = repository.list_snapshot_packages(outcome.snapshot_id, project_id=PROJECT, audit_kind="python_environment")
    assert len(packages.items) == 1
    assert packages.items[0].normalized_name == "demo"


def test_realistic_clock_microseconds_are_normalized_for_history(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    outcome = audit_with_history(
        prepared, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW.replace(microsecond=123456),
    )
    assert repository.get_run(outcome.run_id).started_at == "2026-09-30T08:00:00Z"
    assert outcome.cleanup.skipped is False


def test_exact_hit_skips_report_build_and_attaches_reused_run(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = audit_with_history(prepared, environment=environment, project_id=PROJECT,
                               display_name="Demo", repository=repository,
                               retention_days=180, clock=lambda: NOW)
    from svarog.webui import adapters

    def forbidden(*args, **kwargs):
        raise AssertionError("report builder must not be called on exact hit")

    monkeypatch.setattr(adapters, "_complete_audit", forbidden)
    changed_metadata = replace(prepared.vulnerability.metadata, last_sync_at="2026-09-30T07:01:00Z")
    changed = replace(prepared, vulnerability=replace(prepared.vulnerability, metadata=changed_metadata))
    second = audit_with_history(changed, environment=environment, project_id=PROJECT,
                                display_name="Demo", repository=repository,
                                retention_days=180, clock=lambda: NOW)
    assert second.reused is True
    assert second.change_summary.classification == "no_change"
    assert second.change_summary.metadata_only_change is True
    assert second.snapshot_id == first.snapshot_id
    assert second.run_id != first.run_id
    assert second.result["report"]["audit_status"] == "completed_clean"
    assert repository.get_run(second.run_id).status is RunStatus.COMPLETED_REUSED
    assert repository.get_run(second.run_id).knowledge_metadata_hash != repository.get_run(first.run_id).knowledge_metadata_hash


def test_reused_workbench_wrapper_uses_current_issue_subjects(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    first_inventory = replace(prepared.inventory, issues=(AuditIssue("bad_metadata", "bad_metadata", "old/path"),))
    first = audit_with_history(replace(prepared, inventory=first_inventory),
                               environment=environment, project_id=PROJECT,
                               display_name="Demo", repository=repository,
                               retention_days=180, clock=lambda: NOW)
    current_inventory = replace(first_inventory,
                                issues=(AuditIssue("bad_metadata", "bad_metadata", "new/path"),))
    second = audit_with_history(replace(prepared, inventory=current_inventory),
                                environment=environment, project_id=PROJECT,
                                display_name="Demo", repository=repository,
                                retention_days=180, clock=lambda: NOW)
    assert second.reused is True
    assert second.snapshot_id == first.snapshot_id
    assert second.result["report"]["inventory_issues"][0]["subject"] == "new/path"


def test_advisory_metadata_update_reuses_but_refreshes_display_timestamp(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    advisory = AdvisoryRecord(
        "GHSA-2345-6789-cfgh", "CVE-2026-1234", "published", None,
        "Demo issue", AdvisorySeverity.HIGH, 7.0, "osv",
        "2026-09-29T00:00:00Z", "Demo", "demo", "<2.0", "2.0",
    )
    first_prepared = replace(
        prepared, vulnerability=replace(prepared.vulnerability, advisories=(advisory,))
    )
    first = audit_with_history(
        first_prepared, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW,
    )
    changed = replace(advisory, updated_at="2026-09-30T00:00:00Z")
    second = audit_with_history(
        replace(first_prepared, vulnerability=replace(
            first_prepared.vulnerability, advisories=(changed,)
        )), environment=environment, project_id=PROJECT, display_name="Demo",
        repository=repository, retention_days=180, clock=lambda: NOW,
    )
    assert second.reused is True
    assert second.snapshot_id == first.snapshot_id
    assert first.result["report"]["findings"][0]["advisory_updated_at"] == advisory.updated_at
    assert second.result["report"]["findings"][0]["advisory_updated_at"] == changed.updated_at


def test_reuse_preserves_advisory_selection_before_timestamp_order(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    base = AdvisoryRecord(
        "GHSA-2345-6789-cfgh", "CVE-2026-1234", "published", None,
        "Demo issue", AdvisorySeverity.HIGH, 7.0, "osv",
        "2026-09-30T00:00:00Z", "A Demo", "demo", "<2.0", "2.0",
    )
    later_name = replace(
        base, package_name="Z Demo", updated_at="2026-09-28T00:00:00Z"
    )
    with_duplicates = replace(
        prepared, vulnerability=replace(
            prepared.vulnerability, advisories=(base, later_name)
        )
    )
    first = audit_with_history(
        with_duplicates, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW,
    )
    second = audit_with_history(
        with_duplicates, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW,
    )
    assert second.reused is True
    assert first.result["report"]["findings"][0]["advisory_updated_at"] == base.updated_at
    assert second.result["report"]["findings"][0]["advisory_updated_at"] == base.updated_at


def test_advisory_fingerprint_excludes_metadata_only_update_time() -> None:
    finding = DependencyFinding(
        "Demo", "demo", "1.0", "GHSA-2345-6789-cfgh", "CVE-2026-1234",
        AdvisorySeverity.HIGH, 7.0, "<2.0", "2.0", "Demo issue", "osv",
        "2026-09-29T00:00:00Z",
    )
    assert _fingerprint(finding) == _fingerprint(
        replace(finding, advisory_updated_at="2026-09-30T00:00:00Z")
    )


def test_builder_failure_marks_run_with_stable_code_only(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from svarog.webui import adapters
    monkeypatch.setattr(adapters, "_complete_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret-token")))
    with pytest.raises(HistoryServiceError, match="audit_report_failed"):
        audit_with_history(prepared, environment=environment, project_id=PROJECT,
                           display_name="Demo", repository=repository,
                           retention_days=180, clock=lambda: NOW)
    runs = repository.list_runs(PROJECT, audit_kind="python_environment")
    assert len(runs.items) == 1
    assert runs.items[0].status is RunStatus.FAILED
    assert runs.items[0].failure_code == "audit_report_failed"
    assert "secret-token" not in str(runs.items[0])


def test_snapshot_lookup_failure_is_classified_as_persistence_failure(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_lookup(*_args):
        raise HistoryDatabaseError("history_database_failed")
    monkeypatch.setattr(repository, "find_exact_snapshot_id", fail_lookup)
    with pytest.raises(HistoryServiceError, match="^history_persistence_failed$"):
        audit_with_history(
            prepared, environment=environment, project_id=PROJECT,
            display_name="Demo", repository=repository, retention_days=180,
            clock=lambda: NOW,
        )
    runs = repository.list_runs(PROJECT, audit_kind="python_environment")
    assert runs.items[0].failure_code == "history_persistence_failed"


def test_cleanup_warning_does_not_undo_saved_run(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    outcome = audit_with_history(prepared, environment=environment, project_id=PROJECT,
                                 display_name="Demo", repository=repository,
                                 retention_days=0, clock=lambda: NOW)
    assert outcome.cleanup.skipped is True
    assert outcome.cleanup.warning == "invalid_retention_days"
    assert repository.get_run(outcome.run_id).status is RunStatus.COMPLETED_COMPUTED


def test_unexpected_cleanup_error_is_only_a_warning_after_success(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from svarog.audit_history import service
    monkeypatch.setattr(service, "cleanup_history", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret-token")))
    outcome = audit_with_history(prepared, environment=environment, project_id=PROJECT,
                                 display_name="Demo", repository=repository,
                                 retention_days=180, clock=lambda: NOW)
    assert outcome.cleanup.warning == "history_cleanup_failed"
    assert repository.get_run(outcome.run_id).status is RunStatus.COMPLETED_COMPUTED


def test_post_commit_error_never_transitions_successful_run_to_failed(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from svarog.audit_history import service
    monkeypatch.setattr(service, "_cleanup_after_save", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("post-commit")))
    with pytest.raises(HistoryServiceError, match="history_result_failed"):
        audit_with_history(prepared, environment=environment, project_id=PROJECT,
                           display_name="Demo", repository=repository,
                           retention_days=180, clock=lambda: NOW)
    runs = repository.list_runs(PROJECT, audit_kind="python_environment")
    assert len(runs.items) == 1
    assert runs.items[0].status is RunStatus.COMPLETED_COMPUTED


def test_project_run_hashes_lock_and_saves_resolved_dependency_edge(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    lock = LockSnapshot(
        path=str(environment / "poetry.lock"), lock_format="poetry",
        packages=(
            LockedPackage("Demo", "demo", "1.0", True, "index", None,
                          (LockedDependency("Child", "child", "2.0", "index"),)),
            LockedPackage("Child", "child", "2.0", True, "index"),
        ),
        issues=(), total_package_entries=2, total_issue_count=0,
        truncated_issue_count=0,
    )
    outcome = audit_with_history(replace(prepared, lock=lock), environment=environment,
                                 project_id=PROJECT, display_name="Demo",
                                 repository=repository, retention_days=180,
                                 clock=lambda: NOW)
    run = repository.get_run(outcome.run_id)
    assert run.status is RunStatus.COMPLETED_COMPUTED
    assert run.semantic_lock_hash is not None
    assert outcome.result["kind"] == "project_audit"
    rows = repository.list_snapshot_dependencies(outcome.snapshot_id,
        project_id=PROJECT, audit_kind="python_project")
    assert len(rows.items) == 1
    assert rows.items[0].relationship_source == "lock"


def test_unknown_target_python_version_is_gap_not_host_version(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    (environment / "pyvenv.cfg").write_text("implementation = CPython\n", encoding="utf-8")
    outcome = audit_with_history(prepared, environment=environment, project_id=PROJECT,
                                 display_name="Demo", repository=repository,
                                 retention_days=180, clock=lambda: NOW)
    run = repository.get_run(outcome.run_id)
    assert run.python_version == "unknown"
    assert run.python_version != ".".join(map(str, sys.version_info[:3]))
    assert outcome.result["report"]["audit_status"] == "completed_incomplete"
    assert "target_python_unknown" in {
        item["code"] for item in outcome.result["report"]["inventory_issues"]
    }
    assert outcome.result["report"]["summary"]["inventory_issues"] == 1
    reused = audit_with_history(
        prepared, environment=environment, project_id=PROJECT,
        display_name="Demo", repository=repository, retention_days=180,
        clock=lambda: NOW,
    )
    assert reused.reused is True
    assert "target_python_unknown" in {
        item["code"] for item in reused.result["report"]["inventory_issues"]
    }
    issues = repository.list_snapshot_issues(outcome.snapshot_id, project_id=PROJECT,
                                             audit_kind="python_environment")
    assert "target_python_unknown" in {item.issue_code for item in issues.items}


def test_bad_sync_status_and_stale_time_cannot_reuse_same_warning_state(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    bad = replace(prepared, vulnerability=replace(
        prepared.vulnerability, metadata=replace(prepared.vulnerability.metadata,
                                                  last_sync_status="error")))
    first = audit_with_history(bad, environment=environment, project_id=PROJECT,
                               display_name="Demo", repository=repository,
                               retention_days=180, clock=lambda: NOW)
    stale = replace(bad, vulnerability=replace(
        bad.vulnerability, metadata=replace(bad.vulnerability.metadata,
                                             last_sync_at="2026-09-01T00:00:00Z")))
    second = audit_with_history(stale, environment=environment, project_id=PROJECT,
                                display_name="Demo", repository=repository,
                                retention_days=180, clock=lambda: NOW)
    assert second.reused is False
    assert second.snapshot_id != first.snapshot_id
    assert repository.get_run(second.run_id).evaluation_context_hash != repository.get_run(first.run_id).evaluation_context_hash


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("2026-09-30T07:00:00+00:00", "2026-09-30T07:00:00Z"),
     ("2026-09-30T15:00:00+08:00", "2026-09-30T07:00:00Z"),
     ("not-a-time", None)],
)
def test_sync_timestamp_is_normalized_or_left_as_stable_gap(
    raw: str, expected: str | None, prepared: _AuditExecution,
    environment: Path, repository: HistoryRepository,
) -> None:
    changed = replace(prepared, vulnerability=replace(
        prepared.vulnerability, metadata=replace(prepared.vulnerability.metadata,
                                                  last_sync_at=raw)))
    outcome = audit_with_history(changed, environment=environment, project_id=PROJECT,
                                 display_name="Demo", repository=repository,
                                 retention_days=180, clock=lambda: NOW)
    assert repository.get_run(outcome.run_id).knowledge_last_sync_at == expected


def test_affected_finding_is_normalized_with_advisory_fingerprint(
    prepared: _AuditExecution, environment: Path, repository: HistoryRepository,
) -> None:
    advisory = AdvisoryRecord(
        ghsa_id="GHSA-2345-6789-cfgh", cve_id="CVE-2026-1234",
        state="published", withdrawn_at=None, summary="Demo issue",
        severity=AdvisorySeverity.HIGH, cvss_score=8.0, source="github_api",
        updated_at="2026-09-29T00:00:00Z", package_name="Demo",
        normalized_package_name="demo", version_range="<2.0", fixed_version="2.0",
    )
    changed = replace(prepared, vulnerability=replace(prepared.vulnerability,
                                                      advisories=(advisory,)))
    outcome = audit_with_history(changed, environment=environment, project_id=PROJECT,
                                 display_name="Demo", repository=repository,
                                 retention_days=180, clock=lambda: NOW)
    findings = repository.list_snapshot_findings(outcome.snapshot_id,
        project_id=PROJECT, audit_kind="python_environment")
    assert len(findings.items) == 1
    assert findings.items[0].normalized_name == "demo"
    assert findings.items[0].audited_version == "1.0"
    assert len(findings.items[0].advisory_fingerprint) == 64
