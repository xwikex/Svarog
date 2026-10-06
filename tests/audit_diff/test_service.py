from dataclasses import replace
import json
from pathlib import Path

import pytest

from svarog.audit_diff.service import DiffService, classify_change
from svarog.audit_diff.reporting import render_diff_json
from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.repository import (
    DependencyRow, FindingRow, HistoryRepository, IssueRow, PackageRow, SnapshotInput,
)


PROJECT = "proj_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
OTHER = "proj_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
RUN_1 = "00000000-0000-4000-8000-000000000001"
RUN_2 = "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def repository(tmp_path: Path):
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        yield HistoryRepository(database.connection)


def package(name="demo", version="1.0", *, scope="environment", source="index", applicability="applicable"):
    return PackageRow(scope, name, name, version, True, source, None,
                      f"{scope}:{name}:{version}:{source}", None, applicability)


def finding(name="demo", version="1.0", *, severity="high", status="affected", fingerprint="7" * 64):
    return FindingRow("environment", name, name, version, "GHSA-2345-6789-cfgh", None,
                      "GHSA-2345-6789-cfgh", severity, 8.1, "<2", ("2.0",),
                      status, None, fingerprint)


def snapshot(*, ordinal=1, project_id=PROJECT, kind="python_environment", packages=(),
             findings=(), dependencies=(), issues=(), environment_hash=None,
             knowledge_hash=None, metadata_hash=None, contract="analysis/1",
             schema=None, lock_hash=None):
    h = lambda n: format(n, "x") * 64
    schema = schema or ("svarog-project-audit/1" if kind == "python_project" else "svarog-environment-audit/1")
    return SnapshotInput(
        project_id=project_id, display_name="Demo", audit_kind=kind,
        started_at=f"2026-09-28T00:{ordinal:02d}:00Z",
        completed_at=f"2026-09-28T00:{ordinal:02d}:01Z",
        python_version="3.12.7", environment_hash=environment_hash or h(1),
        semantic_lock_hash=lock_hash if kind == "python_project" else None,
        knowledge_content_hash=knowledge_hash or h(2),
        knowledge_metadata_hash=metadata_hash or h(3),
        evaluation_context_hash=h(4), policy_hash=h(5),
        analysis_contract_version=contract, composite_hash=h(ordinal + 5),
        audit_status="completed_clean", result_schema_version=schema,
        result={"schema_version": schema, "audit_status": "completed_clean"},
        environment_package_count=sum(p.scope.value == "environment" for p in packages),
        lock_package_count=sum(p.scope.value == "lock" for p in packages),
        affected_finding_count=sum(f.finding_status.value == "affected" for f in findings),
        indeterminate_finding_count=sum(f.finding_status.value == "indeterminate" for f in findings),
        issue_count=len(issues), packages=packages, findings=findings,
        dependencies=dependencies, issues=issues,
    )


@pytest.mark.parametrize(("project", "knowledge", "expected"), [
    (False, False, "no_change"), (True, False, "project_changed"),
    (False, True, "knowledge_changed"), (True, True, "project_and_knowledge_changed"),
])
def test_classification(project, knowledge, expected):
    assert classify_change(project_changed=project, knowledge_changed=knowledge) == expected


def test_initial_and_metadata_only_and_engine_flag(repository):
    first = repository.save_run(snapshot(), run_id=RUN_1)
    initial = DiffService(repository).compare_snapshots(PROJECT, "python_environment", None, first.snapshot_id)
    assert initial.classification == "initial_snapshot"
    second = repository.save_run(snapshot(ordinal=2, metadata_hash="8" * 64, contract="analysis/2"), run_id=RUN_2)
    report = DiffService(repository).compare_snapshots(PROJECT, "python_environment", first.snapshot_id, second.snapshot_id)
    assert report.classification == "no_change"
    assert report.analysis_engine_changed is True
    assert "knowledge_metadata_only_changed" in report.warnings
    assert report.causes == ()


def test_packages_findings_dependencies_and_reverse(repository):
    a = package()
    b = package(version="2.0")
    other = package("other")
    edge = DependencyRow(b.component_key, other.component_key, "environment", "resolved")
    old = repository.save_run(snapshot(packages=(a,), findings=(finding(),)), run_id=RUN_1)
    new = repository.save_run(snapshot(ordinal=2, environment_hash="8" * 64,
        packages=(b, other), findings=(finding(severity="critical"), finding("other")),
        dependencies=(edge,)), run_id=RUN_2)
    service = DiffService(repository)
    forward = service.compare_snapshots(PROJECT, "python_environment", old.snapshot_id, new.snapshot_id)
    reverse = service.compare_snapshots(PROJECT, "python_environment", new.snapshot_id, old.snapshot_id)
    assert forward.classification == "project_changed"
    assert [(c.normalized_name, c.change_types) for c in forward.package_changes] == [
        ("demo", ("upgraded",)), ("other", ("added",))]
    assert [(c.normalized_name, c.change_types) for c in reverse.package_changes] == [
        ("demo", ("downgraded",)), ("other", ("removed",))]
    assert [(c.normalized_name, c.change_type) for c in forward.finding_changes] == [
        ("demo", "changed"), ("other", "introduced")]
    assert forward.dependency_changes[0].change_type == "added"
    assert reverse.dependency_changes[0].change_type == "removed"
    assert render_diff_json(forward) == render_diff_json(forward)
    assert json.loads(render_diff_json(forward))["actions_executed"] is False


def test_source_mismatch_ambiguous_version_and_resolved_is_not_fixed(repository):
    old = repository.save_run(snapshot(packages=(package(),), findings=(finding(),)), run_id=RUN_1)
    changed = package(source="git", applicability="mismatch")
    new = repository.save_run(snapshot(ordinal=2, environment_hash="8" * 64,
        packages=(changed, package(version="invalid")), findings=()), run_id=RUN_2)
    report = DiffService(repository).compare_snapshots(PROJECT, "python_environment", old.snapshot_id, new.snapshot_id)
    assert "source_changed" in report.package_changes[0].change_types
    assert "mismatch_changed" in report.package_changes[0].change_types
    assert "ambiguous_version" in report.package_changes[0].change_types
    assert report.finding_changes[0].change_type == "resolved"
    assert '"change_type":"fixed"' not in render_diff_json(report).decode().lower()


def test_scope_schema_and_no_blob_read(repository, monkeypatch):
    old = repository.save_run(snapshot(), run_id=RUN_1)
    new = repository.save_run(snapshot(ordinal=2, schema="other/1"), run_id=RUN_2)
    service = DiffService(repository)
    monkeypatch.setattr(repository, "get_snapshot_result", lambda *a, **kw: pytest.fail("BLOB read"))
    with pytest.raises(ValueError, match="incompatible_schema"):
        service.compare_snapshots(PROJECT, "python_environment", old.snapshot_id, new.snapshot_id)
    with pytest.raises(Exception, match="snapshot_not_found"):
        service.compare_snapshots(OTHER, "python_environment", None, old.snapshot_id)
    assert service.compare_snapshots(PROJECT, "python_environment", old.snapshot_id, old.snapshot_id).classification == "no_change"


def test_fixed_run_diff_is_idempotent_and_manual_is_not_persisted(repository):
    first = repository.save_run(snapshot(), run_id=RUN_1)
    second = repository.save_run(snapshot(ordinal=2, environment_hash="8" * 64), run_id=RUN_2)
    service = DiffService(repository)
    report = service.compare_run(RUN_2)
    assert report.baseline_snapshot_id == first.snapshot_id
    assert report.target_snapshot_id == second.snapshot_id
    assert service.compare_run(RUN_2) == report
    rows = repository._connection.execute("SELECT diff_json_zlib, diff_json_size, diff_json_sha256 FROM run_diffs").fetchall()
    assert len(rows) == 1
    import hashlib, zlib
    raw = zlib.decompress(rows[0][0])
    assert raw == render_diff_json(report)
    assert len(raw) == rows[0][1] and hashlib.sha256(raw).hexdigest() == rows[0][2]
    service.compare_snapshots(PROJECT, "python_environment", second.snapshot_id, first.snapshot_id)
    assert repository._connection.execute("SELECT count(*) FROM run_diffs").fetchone()[0] == 1


def test_multiple_same_advisory_findings_are_all_preserved(repository):
    older = finding(fingerprint="7" * 64)
    second = finding(fingerprint="8" * 64)
    first = repository.save_run(snapshot(findings=(older, second)), run_id=RUN_1)
    latest = repository.save_run(snapshot(ordinal=2, findings=(older,)), run_id=RUN_2)
    report = DiffService(repository).compare_snapshots(
        PROJECT, "python_environment", first.snapshot_id, latest.snapshot_id
    )
    assert len(report.finding_changes) == 1
    change = report.finding_changes[0]
    assert change.change_type == "changed"
    assert {item["advisory_fingerprint"] for item in change.before} == {"7" * 64, "8" * 64}
    assert {item["advisory_fingerprint"] for item in change.after} == {"7" * 64}


def test_python_version_change_is_visible(repository):
    before = repository.save_run(snapshot(), run_id=RUN_1)
    updated = replace(snapshot(ordinal=2, environment_hash="8" * 64), python_version="3.13.1")
    after = repository.save_run(updated, run_id=RUN_2)
    report = DiffService(repository).compare_snapshots(
        PROJECT, "python_environment", before.snapshot_id, after.snapshot_id
    )
    assert report.python_version_before == "3.12.7"
    assert report.python_version_after == "3.13.1"
    assert report.python_version_changed is True
