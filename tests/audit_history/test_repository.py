from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sqlite3

import pytest

from svarog.audit_history import repository as repository_module
from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.models import FindingStatus, PackageScope, RunStatus
from svarog.audit_history.repository import (
    CompatibleRunChoice,
    DependencyRow,
    FindingRow,
    FindingFirstSeen,
    HistoryPage,
    HistoryRepository,
    IssueRow,
    PackageRow,
    SnapshotDetail,
    SnapshotSummary,
    SnapshotInput,
    _first_seen_sql,
    _run_history_sql,
)
from svarog.project_audit.lockfile import load_lock_snapshot


PROJECT = "proj_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
OTHER_PROJECT = "proj_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
RUN_1 = "00000000-0000-4000-8000-000000000001"
RUN_2 = "00000000-0000-4000-8000-000000000002"
RUN_3 = "00000000-0000-4000-8000-000000000003"
T0 = "2026-09-28T00:00:00Z"
T1 = "2026-09-28T00:01:00Z"
T2 = "2026-09-28T00:02:00Z"


def test_exact_reuse_attaches_started_run_without_new_snapshot(
    repository: HistoryRepository,
) -> None:
    initial = _snapshot()
    saved = repository.save_run(initial, run_id=RUN_1)
    repository.start_run(
        run_id=RUN_2, project_id=PROJECT, display_name="Demo project",
        audit_kind="python_project", started_at=T2,
    )

    reused = repository.attach_exact_reuse(
        run_id=RUN_2, project_id=PROJECT, audit_kind="python_project",
        composite_hash=initial.composite_hash, completed_at=T2,
        environment_hash=initial.environment_hash,
        semantic_lock_hash=initial.semantic_lock_hash,
        knowledge_content_hash=initial.knowledge_content_hash,
        evaluation_context_hash=initial.evaluation_context_hash,
        policy_hash=initial.policy_hash,
        analysis_contract_version=initial.analysis_contract_version,
        knowledge_metadata_hash="8" * 64, knowledge_sources=("osv",),
        knowledge_last_sync_at=T1, knowledge_sync_status="ok", warning_count=0,
    )

    assert reused is not None
    assert reused.snapshot_id == saved.snapshot_id
    assert reused.reused is True
    assert reused.baseline_run_id == RUN_1
    run = repository.get_run(RUN_2)
    assert run.knowledge_metadata_hash == "8" * 64
    assert run.knowledge_sources == ("osv",)
    assert run.status is RunStatus.COMPLETED_REUSED


def test_exact_reuse_miss_preserves_started_run(repository: HistoryRepository) -> None:
    repository.start_run(
        run_id=RUN_1, project_id=PROJECT, display_name="Demo project",
        audit_kind="python_project", started_at=T0,
    )
    result = repository.attach_exact_reuse(
        run_id=RUN_1, project_id=PROJECT, audit_kind="python_project",
        composite_hash="9" * 64, completed_at=T1,
        environment_hash="0" * 64, semantic_lock_hash="1" * 64,
        knowledge_content_hash="2" * 64, evaluation_context_hash="4" * 64,
        policy_hash="5" * 64, analysis_contract_version="svarog-analysis/1",
        knowledge_metadata_hash="8" * 64, knowledge_sources=(),
        knowledge_last_sync_at=None, knowledge_sync_status=None, warning_count=0,
    )
    assert result is None
    assert repository.get_run(RUN_1).status is RunStatus.STARTED


def test_exact_reuse_rejects_corrupted_contributing_hashes(repository: HistoryRepository) -> None:
    initial = _snapshot()
    repository.save_run(initial, run_id=RUN_1)
    repository._connection.execute(
        "UPDATE audit_snapshots SET environment_hash = ? WHERE composite_hash = ?",
        ("f" * 64, initial.composite_hash),
    )
    repository.start_run(run_id=RUN_2, project_id=PROJECT, display_name="Demo project",
                         audit_kind="python_project", started_at=T2)
    with pytest.raises(HistoryDatabaseError, match="snapshot_composite_conflict"):
        repository.attach_exact_reuse(
            run_id=RUN_2, project_id=PROJECT, audit_kind="python_project",
            composite_hash=initial.composite_hash, completed_at=T2,
            environment_hash=initial.environment_hash,
            semantic_lock_hash=initial.semantic_lock_hash,
            knowledge_content_hash=initial.knowledge_content_hash,
            evaluation_context_hash=initial.evaluation_context_hash,
            policy_hash=initial.policy_hash,
            analysis_contract_version=initial.analysis_contract_version,
            knowledge_metadata_hash="8" * 64, knowledge_sources=(),
            knowledge_last_sync_at=None, knowledge_sync_status=None, warning_count=0,
        )
    assert repository.get_run(RUN_2).status is RunStatus.STARTED


@pytest.fixture
def database(tmp_path: Path):
    manager = DatabaseManager.open(tmp_path / "history.sqlite3")
    try:
        yield manager
    finally:
        manager.close()


@pytest.fixture
def repository(database: DatabaseManager) -> HistoryRepository:
    return HistoryRepository(database.connection)


def _snapshot(
    *,
    project_id: str = PROJECT,
    started_at: str = T0,
    completed_at: str = T1,
    composite_hash: str = "6" * 64,
    metadata_hash: str = "3" * 64,
) -> SnapshotInput:
    return SnapshotInput(
        project_id=project_id,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=started_at,
        completed_at=completed_at,
        python_version="3.12.7",
        environment_hash="0" * 64,
        semantic_lock_hash="1" * 64,
        knowledge_content_hash="2" * 64,
        knowledge_metadata_hash=metadata_hash,
        evaluation_context_hash="4" * 64,
        policy_hash="5" * 64,
        analysis_contract_version="svarog-analysis/1",
        composite_hash=composite_hash,
        audit_status="completed_with_findings_and_gaps",
        result_schema_version="svarog-project-audit/1",
        result={
            "schema_version": "svarog-project-audit/1",
            "audit_status": "completed_with_findings_and_gaps",
            "items": [1],
        },
        knowledge_sources=("osv", "ghsa"),
        knowledge_last_sync_at="2026-09-27T00:00:00Z",
        knowledge_sync_status="healthy",
        environment_package_count=1,
        lock_package_count=2,
        affected_finding_count=1,
        indeterminate_finding_count=1,
        issue_count=1,
        warning_count=2,
        packages=(
            PackageRow(
                scope=PackageScope.ENVIRONMENT,
                raw_name="Demo_Pkg",
                normalized_name="demo-pkg",
                version="1.0",
                version_valid=True,
                source_kind="index",
                source_identity=None,
                component_key="pkg:pypi/demo-pkg@1.0",
                is_direct=None,
                applicability_status="applicable",
            ),
            PackageRow(
                scope=PackageScope.LOCK,
                raw_name="Demo_Pkg",
                normalized_name="demo-pkg",
                version="1.0",
                version_valid=True,
                source_kind="index",
                source_identity="pypi",
                component_key="pkg:pypi/demo-pkg@1.0?scope=lock",
                is_direct=True,
                applicability_status="applicable",
            ),
            PackageRow(
                scope=PackageScope.LOCK,
                raw_name="Demo_Pkg",
                normalized_name="demo-pkg",
                version="2.0",
                version_valid=True,
                source_kind="index",
                source_identity="pypi",
                component_key="pkg:pypi/demo-pkg@2.0?scope=lock",
                is_direct=False,
                applicability_status="not_applicable",
            ),
        ),
        dependencies=(
            DependencyRow(
                parent_component_key="pkg:pypi/demo-pkg@1.0?scope=lock",
                child_component_key="pkg:pypi/demo-pkg@2.0?scope=lock",
                relationship_source="lock",
                resolution_status="resolved",
            ),
        ),
        findings=(
            FindingRow(
                scope=PackageScope.LOCK,
                raw_name="Demo_Pkg",
                normalized_name="demo-pkg",
                audited_version="1.0",
                ghsa_id="GHSA-2345-6789-cfgh",
                cve_id="CVE-2026-1234",
                advisory_id="GHSA-2345-6789-cfgh",
                severity="high",
                cvss=8.1,
                affected_range="<2",
                fixed_versions=("2.1", "2.0"),
                finding_status=FindingStatus.AFFECTED,
                indeterminate_reason=None,
                advisory_fingerprint="7" * 64,
            ),
            FindingRow(
                scope=PackageScope.LOCK,
                raw_name="Demo_Pkg",
                normalized_name="demo-pkg",
                audited_version="2.0",
                ghsa_id=None,
                cve_id=None,
                advisory_id="LOCAL-1",
                severity=None,
                cvss=None,
                affected_range=None,
                fixed_versions=(),
                finding_status=FindingStatus.INDETERMINATE,
                indeterminate_reason="invalid_version",
                advisory_fingerprint="8" * 64,
            ),
        ),
        issues=(IssueRow("lock_unresolved", "demo-pkg", "bounded detail", 0),),
    )


def test_records_are_immutable_and_input_copies_mutable_result() -> None:
    raw = {
        "schema_version": "svarog-project-audit/1",
        "audit_status": "completed_with_findings_and_gaps",
        "nested": [1],
    }
    value = replace(_snapshot(), result=raw)
    raw["nested"].append(2)

    assert value.result["nested"] == (1,)
    with pytest.raises(FrozenInstanceError):
        value.warning_count = 10  # type: ignore[misc]


def test_save_run_result_is_immutable_and_validated(
    repository: HistoryRepository,
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)

    with pytest.raises(FrozenInstanceError):
        saved.reused = True  # type: ignore[misc]
    with pytest.raises(HistoryDatabaseError, match="invalid_snapshot_id"):
        replace(saved, snapshot_id=0)
    with pytest.raises(HistoryDatabaseError, match="invalid_save_run_result"):
        replace(saved, reused=True)


def test_run_record_is_validated_and_corrupt_storage_is_not_returned(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)
    run = repository.get_run(RUN_1)

    with pytest.raises(FrozenInstanceError):
        run.warning_count = 10  # type: ignore[misc]
    with pytest.raises(HistoryDatabaseError, match="invalid_count"):
        replace(run, warning_count=-1)

    database.connection.execute(
        "UPDATE audit_runs SET python_version = ? WHERE run_id = ?",
        ("bad\u0085version", RUN_1),
    )
    with pytest.raises(HistoryDatabaseError, match="history_database_corrupt"):
        repository.get_run(RUN_1)


def test_start_run_is_persisted_and_exact_retry_is_idempotent(
    repository: HistoryRepository,
) -> None:
    first = repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    second = repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )

    assert first == second == repository.get_run(RUN_1)
    assert first.status is RunStatus.STARTED
    assert first.snapshot_id is None


def test_conflicting_run_id_is_a_stable_error(
    repository: HistoryRepository,
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    with pytest.raises(HistoryDatabaseError, match="run_id_conflict"):
        repository.start_run(
            run_id=RUN_1,
            project_id=PROJECT,
            display_name="Demo project",
            audit_kind="python_project",
            started_at=T2,
        )


def test_project_rename_preserves_identity(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="  Demo project  ",
        audit_kind="python_project",
        started_at=T0,
    )
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Renamed project",
        audit_kind="python_project",
        started_at=T2,
    )

    assert database.connection.execute(
        "SELECT project_id, display_name, created_at, updated_at FROM projects"
    ).fetchall() == [(PROJECT, "Renamed project", T0, T2)]


@pytest.mark.parametrize(
    "display_name",
    ["   ", "x" * 129, "bad\nname", "/tmp/project", r"C:\project"],
)
def test_display_name_matches_runtime_layout_validation(display_name: str) -> None:
    with pytest.raises(HistoryDatabaseError, match="^invalid_display_name$"):
        replace(_snapshot(), display_name=display_name)


def test_display_name_lone_surrogate_is_rejected_before_transaction(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    with pytest.raises(HistoryDatabaseError, match="^invalid_display_name$"):
        repository.start_run(
            run_id=RUN_1,
            project_id=PROJECT,
            display_name="bad\ud800name",
            audit_kind="python_project",
            started_at=T0,
        )

    assert not any(statement.startswith(("BEGIN", "INSERT", "UPDATE")) for statement in statements)


def test_project_id_must_be_a_canonical_version_4_uuid() -> None:
    with pytest.raises(HistoryDatabaseError, match="^invalid_project_id$"):
        replace(
            _snapshot(),
            project_id="proj_123e4567e89b12d3a456426614174000",
        )


@pytest.mark.parametrize(
    ("method", "expected"),
    [("mark_run_failed", RunStatus.FAILED), ("mark_run_interrupted", RunStatus.INTERRUPTED)],
)
def test_failed_and_interrupted_runs_are_terminal(
    repository: HistoryRepository, method: str, expected: RunStatus
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    record = getattr(repository, method)(
        RUN_1, completed_at=T1, failure_code="analysis_failed"
    )
    assert record.status is expected
    assert record.failure_code == "analysis_failed"
    with pytest.raises(HistoryDatabaseError, match="run_state_conflict"):
        getattr(repository, method)(RUN_1, completed_at=T2, failure_code="again")
    with pytest.raises(HistoryDatabaseError, match="run_state_conflict"):
        repository.save_run(_snapshot(), run_id=RUN_1)


@pytest.mark.parametrize("method", ["mark_run_failed", "mark_run_interrupted"])
@pytest.mark.parametrize(
    "corrupt_started_at",
    [pytest.param(b"\x00\xff", id="blob"), pytest.param("not-a-timestamp", id="text")],
)
def test_mark_terminal_rejects_corrupt_stored_started_at_without_mutation(
    repository: HistoryRepository,
    database: DatabaseManager,
    method: str,
    corrupt_started_at: object,
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    database.connection.execute(
        "UPDATE audit_runs SET started_at = ? WHERE run_id = ?",
        (corrupt_started_at, RUN_1),
    )
    before = database.connection.execute(
        "SELECT * FROM audit_runs WHERE run_id = ?", (RUN_1,)
    ).fetchone()

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        getattr(repository, method)(
            RUN_1, completed_at=T1, failure_code="analysis_failed"
        )

    assert database.connection.in_transaction is False
    assert database.connection.execute(
        "SELECT * FROM audit_runs WHERE run_id = ?", (RUN_1,)
    ).fetchone() == before


@pytest.mark.parametrize("operation", ["start_run", "save_run"])
@pytest.mark.parametrize(
    "corrupt_updated_at",
    [pytest.param(b"\x00\xff", id="blob"), pytest.param("not-a-timestamp", id="text")],
)
def test_write_rejects_corrupt_project_updated_at_without_mutation(
    repository: HistoryRepository,
    database: DatabaseManager,
    operation: str,
    corrupt_updated_at: object,
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    database.connection.execute(
        "UPDATE projects SET updated_at = ? WHERE project_id = ?",
        (corrupt_updated_at, PROJECT),
    )
    project_before = database.connection.execute(
        "SELECT * FROM projects WHERE project_id = ?", (PROJECT,)
    ).fetchone()
    runs_before = database.connection.execute(
        "SELECT * FROM audit_runs ORDER BY run_id"
    ).fetchall()

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        if operation == "start_run":
            repository.start_run(
                run_id=RUN_2,
                project_id=PROJECT,
                display_name="Renamed project",
                audit_kind="python_project",
                started_at=T1,
            )
        else:
            repository.save_run(
                _snapshot(started_at=T1, completed_at=T2), run_id=RUN_2
            )

    assert database.connection.in_transaction is False
    assert database.connection.execute(
        "SELECT * FROM projects WHERE project_id = ?", (PROJECT,)
    ).fetchone() == project_before
    assert database.connection.execute(
        "SELECT * FROM audit_runs ORDER BY run_id"
    ).fetchall() == runs_before
    assert database.connection.execute(
        "SELECT COUNT(*) FROM audit_snapshots"
    ).fetchone() == (0,)


def test_save_run_persists_all_rows_and_round_trips_isolated_result(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)

    assert saved.run_id == RUN_1
    assert saved.reused is False
    assert saved.status is RunStatus.COMPLETED_COMPUTED
    run = repository.get_run(RUN_1)
    assert run.snapshot_id == saved.snapshot_id
    assert run.baseline_run_id is None
    assert run.knowledge_sources == ("ghsa", "osv")

    connection = database.connection
    packages = connection.execute(
        "SELECT scope, raw_name, normalized_name, version, version_valid, "
        "source_kind, source_identity, component_key, is_direct, applicability_status "
        "FROM snapshot_packages WHERE snapshot_id = ? ORDER BY scope, component_key, version",
        (saved.snapshot_id,),
    ).fetchall()
    assert len(packages) == 3
    assert {row[3] for row in packages} == {"1.0", "2.0"}
    assert connection.execute(
        "SELECT parent_component_key, child_component_key, relationship_source, resolution_status "
        "FROM snapshot_dependencies WHERE snapshot_id = ?",
        (saved.snapshot_id,),
    ).fetchall() == [
        (
            "pkg:pypi/demo-pkg@1.0?scope=lock",
            "pkg:pypi/demo-pkg@2.0?scope=lock",
            "lock",
            "resolved",
        )
    ]
    findings = connection.execute(
        "SELECT fixed_versions, finding_status FROM snapshot_findings "
        "WHERE snapshot_id = ? ORDER BY finding_status",
        (saved.snapshot_id,),
    ).fetchall()
    assert findings == [('["2.0","2.1"]', "affected"), ("[]", "indeterminate")]
    assert connection.execute(
        "SELECT issue_code, subject, detail, ordinal FROM snapshot_issues "
        "WHERE snapshot_id = ? ORDER BY ordinal",
        (saved.snapshot_id,),
    ).fetchall() == [("lock_unresolved", "demo-pkg", "bounded detail", 0)]

    first = repository.get_snapshot_result(saved.snapshot_id)
    first["items"].append(99)  # type: ignore[union-attr]
    assert repository.get_snapshot_result(saved.snapshot_id) == {
        "schema_version": "svarog-project-audit/1",
        "audit_status": "completed_with_findings_and_gaps",
        "items": [1],
    }


def test_save_run_completes_an_existing_started_run(repository: HistoryRepository) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )

    saved = repository.save_run(_snapshot(), run_id=RUN_1)

    assert saved.status is RunStatus.COMPLETED_COMPUTED
    assert repository.get_run(RUN_1).snapshot_id == saved.snapshot_id


def test_started_run_rejects_snapshot_from_another_project_without_side_effects(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )

    with pytest.raises(HistoryDatabaseError, match="run_scope_conflict"):
        repository.save_run(_snapshot(project_id=OTHER_PROJECT), run_id=RUN_1)

    assert repository.get_run(RUN_1).status is RunStatus.STARTED
    assert database.connection.execute(
        "SELECT project_id FROM projects ORDER BY project_id"
    ).fetchall() == [(PROJECT,)]


def test_completed_run_cannot_be_rewritten(repository: HistoryRepository) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)

    with pytest.raises(HistoryDatabaseError, match="run_state_conflict"):
        repository.save_run(
            _snapshot(composite_hash="a" * 64),
            run_id=RUN_1,
        )
    with pytest.raises(HistoryDatabaseError, match="run_state_conflict"):
        repository.mark_run_failed(
            RUN_1,
            completed_at=T2,
            failure_code="late_failure",
        )


def test_second_identical_run_reuses_snapshot_and_keeps_current_metadata(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    first = repository.save_run(_snapshot(), run_id=RUN_1)
    second_input = replace(
        _snapshot(started_at=T1, completed_at=T2),
        knowledge_metadata_hash="9" * 64,
        knowledge_sources=("nvd",),
    )
    second = repository.save_run(second_input, run_id=RUN_2)

    assert first.reused is False
    assert second.reused is True
    assert first.snapshot_id == second.snapshot_id
    assert repository.get_run(RUN_2).baseline_run_id == RUN_1
    assert repository.get_run(RUN_2).knowledge_metadata_hash == "9" * 64
    assert database.connection.execute("SELECT COUNT(*) FROM audit_snapshots").fetchone() == (1,)
    assert database.connection.execute("SELECT COUNT(*) FROM snapshot_packages").fetchone() == (3,)


def test_delayed_older_reuse_does_not_move_project_or_snapshot_backward(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    first = repository.save_run(
        replace(
            _snapshot(started_at=T1, completed_at=T2),
            display_name="New project name",
        ),
        run_id=RUN_1,
    )

    delayed = repository.save_run(
        replace(_snapshot(), display_name="Old project name"),
        run_id=RUN_2,
    )

    assert delayed.reused is True
    assert delayed.snapshot_id == first.snapshot_id
    assert database.connection.execute(
        "SELECT last_used_at FROM audit_snapshots WHERE snapshot_id = ?",
        (first.snapshot_id,),
    ).fetchone() == (T2,)
    assert database.connection.execute(
        "SELECT display_name, updated_at FROM projects WHERE project_id = ?",
        (PROJECT,),
    ).fetchone() == ("New project name", T2)


def test_baseline_is_latest_prior_success_and_never_changes(
    repository: HistoryRepository,
) -> None:
    repository.save_run(_snapshot(composite_hash="a" * 64), run_id=RUN_1)
    second = repository.save_run(
        _snapshot(started_at=T1, completed_at=T2, composite_hash="b" * 64),
        run_id=RUN_2,
    )
    repository.save_run(
        _snapshot(
            started_at="2026-09-28T00:03:00Z",
            completed_at="2026-09-28T00:04:00Z",
            composite_hash="c" * 64,
        ),
        run_id=RUN_3,
    )

    assert second.baseline_run_id == RUN_1
    assert repository.get_run(RUN_2).baseline_run_id == RUN_1
    assert repository.get_run(RUN_3).baseline_run_id == RUN_2


def test_baseline_follows_serialized_completion_chain_when_timestamps_tie(
    repository: HistoryRepository,
) -> None:
    for run_id in (RUN_1, RUN_2):
        repository.start_run(
            run_id=run_id,
            project_id=PROJECT,
            display_name="Demo project",
            audit_kind="python_project",
            started_at=T0,
        )

    repository.save_run(_snapshot(composite_hash="a" * 64), run_id=RUN_2)
    second_completion = repository.save_run(
        _snapshot(composite_hash="b" * 64),
        run_id=RUN_1,
    )
    third_completion = repository.save_run(
        _snapshot(started_at=T1, completed_at=T2, composite_hash="c" * 64),
        run_id=RUN_3,
    )

    assert second_completion.baseline_run_id == RUN_2
    assert third_completion.baseline_run_id == RUN_1


def test_baseline_scan_is_one_bounded_noncorrelated_query(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(_snapshot(composite_hash="a" * 64), run_id=RUN_2)
    repository.save_run(
        _snapshot(started_at=T1, completed_at=T2, composite_hash="b" * 64),
        run_id=RUN_1,
    )
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    baseline = repository._select_baseline(
        _snapshot(
            started_at="2026-09-28T00:03:00Z",
            completed_at="2026-09-28T00:04:00Z",
        ),
        RUN_3,
    )

    queries = [
        statement
        for statement in statements
        if "FROM audit_runs" in statement and "run_status IN" in statement
    ]
    assert baseline == RUN_1
    assert len(queries) == 1
    assert "NOT EXISTS" not in queries[0].upper()
    assert "LIMIT" in queries[0].upper()
    plan = database.connection.execute(
        f"EXPLAIN QUERY PLAN {queries[0]}"
    ).fetchall()
    assert any(
        "idx_audit_runs_project_kind_completed" in str(row[3])
        for row in plan
    )


def test_excessive_baseline_history_fails_stably(
    repository: HistoryRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository.save_run(_snapshot(composite_hash="a" * 64), run_id=RUN_1)
    repository.save_run(
        _snapshot(started_at=T1, completed_at=T2, composite_hash="b" * 64),
        run_id=RUN_2,
    )
    monkeypatch.setattr(repository_module, "MAX_BASELINE_SCAN", 1, raising=False)

    with pytest.raises(HistoryDatabaseError, match="^baseline_history_too_large$"):
        repository.save_run(
            _snapshot(
                started_at="2026-09-28T00:03:00Z",
                completed_at="2026-09-28T00:04:00Z",
                composite_hash="c" * 64,
            ),
            run_id=RUN_3,
        )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("project_id", "demo", "invalid_project_id"),
        ("audit_kind", "web", "invalid_audit_kind"),
        ("started_at", "2026-09-28T00:00:00+00:00", "invalid_timestamp"),
        ("environment_hash", "A" * 64, "invalid_sha256"),
        ("warning_count", -1, "invalid_count"),
        ("audit_status", "done", "invalid_audit_status"),
        ("display_name", "bad\nname", "invalid_display_name"),
    ],
)
def test_invalid_snapshot_values_are_rejected_before_write(
    database: DatabaseManager, field: str, value: object, code: str
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)
    with pytest.raises(HistoryDatabaseError, match=code):
        replace(_snapshot(), **{field: value})
    assert not any(statement.startswith("BEGIN") for statement in statements)


def test_run_id_accepts_any_canonical_uuid_version(repository: HistoryRepository) -> None:
    record = repository.start_run(
        run_id="123e4567-e89b-12d3-a456-426614174000",
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )

    assert record.run_id == "123e4567-e89b-12d3-a456-426614174000"


def test_invalid_run_id_and_failure_code_are_rejected(repository: HistoryRepository) -> None:
    with pytest.raises(HistoryDatabaseError, match="invalid_run_id"):
        repository.start_run(
            run_id="not-a-uuid",
            project_id=PROJECT,
            display_name="Demo project",
            audit_kind="python_project",
            started_at=T0,
        )
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    with pytest.raises(HistoryDatabaseError, match="invalid_failure_code"):
        repository.mark_run_failed(
            RUN_1, completed_at=T1, failure_code="C:\\secret\\token.txt"
        )


def test_cyclic_authoritative_result_has_a_stable_validation_error() -> None:
    cyclic: dict[str, object] = {
        "schema_version": "svarog-project-audit/1",
        "audit_status": "completed_with_findings_and_gaps",
    }
    cyclic["self"] = cyclic

    with pytest.raises(HistoryDatabaseError, match="invalid_result"):
        replace(_snapshot(), result=cyclic)


def test_branching_result_bomb_hits_global_work_bound_before_writes(
    database: DatabaseManager,
) -> None:
    branch: object = {"leaf": True}
    for _ in range(6):
        branch = [branch] * 10
    result = {
        "schema_version": "svarog-project-audit/1",
        "audit_status": "completed_with_findings_and_gaps",
        "branch": branch,
    }
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    with pytest.raises(HistoryDatabaseError, match="^invalid_result$"):
        replace(_snapshot(), result=result)

    assert not any(statement.startswith(("BEGIN", "INSERT", "UPDATE")) for statement in statements)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment_package_count", 2),
        ("lock_package_count", 1),
        ("affected_finding_count", 0),
        ("indeterminate_finding_count", 0),
        ("issue_count", 0),
    ],
)
def test_snapshot_counts_must_match_normalized_rows(field: str, value: int) -> None:
    with pytest.raises(HistoryDatabaseError, match="^snapshot_count_mismatch$"):
        replace(_snapshot(), **{field: value})


@pytest.mark.parametrize(
    "result",
    [
        {
            "schema_version": "svarog-project-audit/1",
            "audit_status": "completed_clean",
        },
        {
            "schema_version": "svarog-project-audit/2",
            "audit_status": "completed_with_findings_and_gaps",
        },
        {"audit_status": "completed_with_findings_and_gaps"},
        {"schema_version": "svarog-project-audit/1"},
    ],
)
def test_authoritative_result_metadata_must_match_snapshot(result: dict[str, object]) -> None:
    with pytest.raises(HistoryDatabaseError, match="^result_metadata_mismatch$"):
        replace(_snapshot(), result=result)


def test_arbitrary_report_summary_counts_are_not_coupled() -> None:
    value = replace(
        _snapshot(),
        result={
            "schema_version": "svarog-project-audit/1",
            "audit_status": "completed_with_findings_and_gaps",
            "summary": {
                "environment_package_count": 999,
                "issue_count": 999,
            },
        },
    )

    assert value.result["summary"]["issue_count"] == 999


@pytest.mark.parametrize("rows_field", ["packages", "dependencies", "findings", "issues"])
def test_duplicate_row_identities_are_rejected(rows_field: str) -> None:
    value = _snapshot()
    rows = getattr(value, rows_field)
    with pytest.raises(HistoryDatabaseError, match="duplicate_history_row"):
        replace(value, **{rows_field: rows + (rows[0],)})


def test_duplicate_component_keys_are_rejected_even_when_package_fields_differ() -> None:
    value = _snapshot()
    conflicting = replace(
        value.packages[0],
        version="9.9",
        source_kind="local",
    )

    with pytest.raises(HistoryDatabaseError, match="duplicate_history_row"):
        replace(value, packages=value.packages + (conflicting,))


def test_component_key_and_row_limits_are_validated() -> None:
    value = _snapshot()
    with pytest.raises(HistoryDatabaseError, match="invalid_component_key"):
        replace(
            value,
            packages=(replace(value.packages[0], component_key="bad key"),),
        )
    with pytest.raises(HistoryDatabaseError, match="too_many_packages"):
        replace(value, packages=value.packages * 20_001)


@pytest.mark.parametrize(
    ("source_kind", "source_identity"),
    [
        ("path", "/home/alice/private"),
        ("path", r"C:\Users\alice\private"),
        ("path", r"\\server\share\private"),
        ("path", r"\\?\C:\private"),
        ("path", "~/private"),
        ("path", "../private"),
        ("path", "packages/../private"),
        ("path", "packages/con"),
        ("url", "file:///home/alice/private"),
        ("url", "local:///home/alice/private"),
        ("url", "https://alice:secret@example.test/package"),
        ("url", "https://alice%3Asecret@example.test/package"),
        ("url", "https://alice%40example.test/package"),
        ("url", "https://example.test/package?token=secret"),
        ("url", "https://example.test/package#token=secret"),
        ("url", "https://example.test/bad\npath"),
        ("url", "https://example.test/%ZZ"),
        ("url", "https://[::1"),
        ("registry", "a" * 2_049),
    ],
)
def test_package_source_identity_rejects_unsafe_persistence_values(
    source_kind: str, source_identity: str
) -> None:
    with pytest.raises(HistoryDatabaseError, match="^invalid_source_identity$") as raised:
        replace(
            _snapshot().packages[1],
            source_kind=source_kind,
            source_identity=source_identity,
        )

    assert str(raised.value) == "invalid_source_identity"


@pytest.mark.parametrize(
    ("source_kind", "source_identity"),
    [
        ("index", "pypi"),
        ("url", "https://example.test/packages/demo.whl"),
        ("git", "https://example.test/repo.git"),
        ("url", "sha256:" + "a" * 64),
        ("git", "b" * 40),
        ("registry", "artifact-1.2+build_3"),
        ("workspace", "."),
        ("path", "packages/demo"),
        ("editable", "packages/demo"),
    ],
)
def test_package_source_identity_accepts_task5_safe_values(
    source_kind: str, source_identity: str
) -> None:
    package = replace(
        _snapshot().packages[1],
        source_kind=source_kind,
        source_identity=source_identity,
    )

    assert package.source_identity == source_identity


@pytest.mark.parametrize(
    ("filename", "body", "expected_sources"),
    [
        (
            "uv.lock",
            """
version = 1
[[package]]
name = "path-digest"
version = "1.0"
source = { path = "../private", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
[[package]]
name = "percent-url"
version = "1.0"
source = { url = "https://example.test/wheels/demo%20pkg.whl" }
[[package]]
name = "dotdot-url"
version = "1.0"
source = { registry = "https://example.test/a/../b" }
""",
            {
                ("path", "sha256:" + "a" * 64),
                ("url", "https://example.test/wheels/demo%20pkg.whl"),
                ("registry", "https://example.test/a/../b"),
            },
        ),
        (
            "poetry.lock",
            """
[[package]]
name = "editable-digest"
version = "1.0"
source = { type = "directory", url = "../private", develop = true, hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
[[package]]
name = "port-zero"
version = "1.0"
source = { type = "url", url = "https://example.test:0/packages/demo.whl" }
""",
            {
                ("editable", "sha256:" + "b" * 64),
                ("url", "https://example.test:0/packages/demo.whl"),
            },
        ),
    ],
)
def test_task5_source_identities_cross_persistence_boundary(
    tmp_path: Path,
    filename: str,
    body: str,
    expected_sources: set[tuple[str, str]],
) -> None:
    path = tmp_path / filename
    path.write_text(body.strip(), encoding="utf-8")
    lock = load_lock_snapshot(path)
    assert {(package.source_kind, package.source_identity) for package in lock.packages} == expected_sources

    lock_rows = tuple(
        PackageRow(
            scope=PackageScope.LOCK,
            raw_name=package.name,
            normalized_name=package.normalized_name,
            version=package.version,
            version_valid=package.version_valid,
            source_kind=package.source_kind,
            source_identity=package.source_identity,
            component_key=f"pkg:pypi/{package.normalized_name}@{package.version}?scope=lock",
            is_direct=None,
            applicability_status="applicable",
        )
        for package in lock.packages
    )
    value = replace(
        _snapshot(),
        packages=(_snapshot().packages[0], *lock_rows),
        dependencies=(),
        findings=(),
        issues=(),
        lock_package_count=len(lock_rows),
        affected_finding_count=0,
        indeterminate_finding_count=0,
        issue_count=0,
    )

    assert {(row.source_kind, row.source_identity) for row in value.packages[1:]} == expected_sources


@pytest.mark.parametrize(
    ("factory", "code"),
    [
        (
            lambda: replace(_snapshot(), display_name="bad\u0085name"),
            "invalid_display_name",
        ),
        (
            lambda: replace(
                _snapshot().packages[0],
                component_key="pkg:pypi/demo\u0085pkg@1.0",
            ),
            "invalid_component_key",
        ),
    ],
)
def test_unicode_control_characters_are_rejected(factory, code: str) -> None:
    with pytest.raises(HistoryDatabaseError, match=code):
        factory()


def test_dependency_endpoints_must_exist() -> None:
    value = _snapshot()
    with pytest.raises(HistoryDatabaseError, match="invalid_dependency_component"):
        replace(
            value,
            dependencies=(replace(value.dependencies[0], child_component_key="missing@1"),),
        )


class _ExplodingRows:
    def __init__(self, phase: str) -> None:
        self._phase = phase

    def __iter__(self):
        if self._phase == "iter":
            raise ValueError("sensitive row iterable detail")
        return self

    def __next__(self):
        raise ValueError("sensitive row iterator detail")


class _ExplodingMapping(Mapping[str, object]):
    def __init__(self, phase: str) -> None:
        self._phase = phase

    def __getitem__(self, key: str) -> object:
        if key == "value":
            return 1
        raise KeyError(key)

    def __iter__(self):
        return iter(("value",))

    def __len__(self) -> int:
        if self._phase == "len":
            raise ValueError("sensitive mapping length detail")
        return 1

    def items(self):
        if self._phase == "items":
            raise ValueError("sensitive mapping items detail")
        return super().items()


@pytest.mark.parametrize("phase", ["iter", "next"])
def test_adversarial_row_iterable_errors_are_stable_before_write(
    database: DatabaseManager, phase: str
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    with pytest.raises(HistoryDatabaseError, match="^too_many_packages$") as raised:
        replace(_snapshot(), packages=_ExplodingRows(phase))

    assert str(raised.value) == "too_many_packages"
    assert "sensitive" not in str(raised.value)
    assert not any(statement.startswith(("BEGIN", "INSERT", "UPDATE")) for statement in statements)


@pytest.mark.parametrize("phase", ["len", "items"])
def test_adversarial_nested_mapping_errors_are_stable_before_write(
    database: DatabaseManager, phase: str
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)
    result = {
        "schema_version": "svarog-project-audit/1",
        "audit_status": "completed_with_findings_and_gaps",
        "nested": _ExplodingMapping(phase),
    }

    with pytest.raises(HistoryDatabaseError, match="^invalid_result$") as raised:
        replace(_snapshot(), result=result)

    assert str(raised.value) == "invalid_result"
    assert "sensitive" not in str(raised.value)
    assert not any(statement.startswith(("BEGIN", "INSERT", "UPDATE")) for statement in statements)


def test_corrupt_result_is_reported_with_a_stable_code(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    database.connection.execute(
        "UPDATE audit_snapshots SET result_json_sha256 = ? WHERE snapshot_id = ?",
        ("f" * 64, saved.snapshot_id),
    )

    with pytest.raises(HistoryDatabaseError, match="result_corrupt"):
        repository.get_snapshot_result(saved.snapshot_id)


def test_same_composite_with_conflicting_defining_field_is_not_reused(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)
    database.connection.execute(
        "UPDATE audit_snapshots SET policy_hash = ? WHERE composite_hash = ?",
        ("f" * 64, "6" * 64),
    )
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T1,
    )
    select_snapshot = repository._select_snapshot
    calls = 0

    def miss_once(snapshot: SnapshotInput):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return select_snapshot(snapshot)

    monkeypatch.setattr(repository, "_select_snapshot", miss_once)
    with pytest.raises(HistoryDatabaseError, match="snapshot_composite_conflict"):
        repository.save_run(
            _snapshot(started_at=T1, completed_at=T2), run_id=RUN_2
        )
    assert repository.get_run(RUN_2).status is RunStatus.STARTED


def test_unique_snapshot_insert_conflict_reselects_and_reuses_exact_match(
    repository: HistoryRepository, database: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = repository.save_run(_snapshot(), run_id=RUN_1)
    second_input = replace(
        _snapshot(started_at=T1, completed_at=T2),
        knowledge_metadata_hash="9" * 64,
    )
    select_snapshot = repository._select_snapshot
    calls = 0

    def miss_once(snapshot: SnapshotInput):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return select_snapshot(snapshot)

    monkeypatch.setattr(repository, "_select_snapshot", miss_once)

    second = repository.save_run(second_input, run_id=RUN_2)

    assert second.reused is True
    assert second.snapshot_id == first.snapshot_id
    assert second.baseline_run_id == RUN_1
    assert repository.get_run(RUN_2).knowledge_metadata_hash == "9" * 64
    assert database.connection.execute(
        "SELECT COUNT(*) FROM audit_snapshots"
    ).fetchone() == (1,)
    assert database.connection.execute(
        "SELECT updated_at FROM projects WHERE project_id = ?",
        (PROJECT,),
    ).fetchone() == (T2,)


def test_unrelated_unique_constraint_with_stale_lookup_never_reuses_snapshot(
    repository: HistoryRepository, database: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = repository.save_run(_snapshot(), run_id=RUN_1)
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T1,
    )
    database.connection.execute(
        "CREATE UNIQUE INDEX task6_unique_audit_status "
        "ON audit_snapshots(audit_status)"
    )
    select_snapshot = repository._select_snapshot
    calls = 0

    def miss_once(snapshot: SnapshotInput):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return select_snapshot(snapshot)

    monkeypatch.setattr(repository, "_select_snapshot", miss_once)

    with pytest.raises(HistoryDatabaseError, match="^history_database_failed$") as raised:
        repository.save_run(
            _snapshot(started_at=T1, completed_at=T2),
            run_id=RUN_2,
        )

    assert str(raised.value) == "history_database_failed"
    assert repository.get_run(RUN_2).status is RunStatus.STARTED
    assert database.connection.execute(
        "SELECT snapshot_id, last_used_at FROM audit_snapshots"
    ).fetchall() == [(first.snapshot_id, T1)]


def test_trigger_integrity_error_with_stale_lookup_never_reuses_snapshot(
    repository: HistoryRepository, database: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = repository.save_run(_snapshot(), run_id=RUN_1)
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T1,
    )
    database.connection.execute(
        "CREATE TRIGGER task6_reject_snapshot BEFORE INSERT ON audit_snapshots "
        "BEGIN SELECT RAISE(ABORT, 'sensitive trigger detail'); END"
    )
    select_snapshot = repository._select_snapshot
    calls = 0

    def miss_once(snapshot: SnapshotInput):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return select_snapshot(snapshot)

    monkeypatch.setattr(repository, "_select_snapshot", miss_once)

    with pytest.raises(HistoryDatabaseError, match="^history_database_failed$") as raised:
        repository.save_run(
            _snapshot(started_at=T1, completed_at=T2),
            run_id=RUN_2,
        )

    assert str(raised.value) == "history_database_failed"
    assert repository.get_run(RUN_2).status is RunStatus.STARTED
    assert database.connection.execute(
        "SELECT snapshot_id, last_used_at FROM audit_snapshots"
    ).fetchall() == [(first.snapshot_id, T1)]


def test_unrelated_integrity_error_rolls_back_and_never_masquerades_as_reuse(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    database.connection.execute(
        "CREATE TRIGGER task6_reject_issue BEFORE INSERT ON snapshot_issues "
        "BEGIN SELECT RAISE(ABORT, 'forced issue conflict'); END"
    )

    with pytest.raises(HistoryDatabaseError, match="history_database_failed") as raised:
        repository.save_run(_snapshot(), run_id=RUN_1)

    assert not isinstance(raised.value, sqlite3.IntegrityError)
    assert repository.get_run(RUN_1).status is RunStatus.STARTED
    assert database.connection.execute(
        "SELECT COUNT(*) FROM audit_snapshots"
    ).fetchone() == (0,)


def test_unknown_snapshot_and_run_return_stable_errors(repository: HistoryRepository) -> None:
    with pytest.raises(HistoryDatabaseError, match="run_not_found"):
        repository.get_run(RUN_1)
    with pytest.raises(HistoryDatabaseError, match="snapshot_not_found"):
        repository.get_snapshot_result(1)


def test_run_history_is_filtered_counted_and_stably_paginated(
    repository: HistoryRepository,
) -> None:
    repository.save_run(_snapshot(completed_at=T2), run_id=RUN_1)
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T2,
    )
    repository.mark_run_failed(RUN_2, completed_at=T2, failure_code="audit_failed")
    repository.save_run(
        _snapshot(completed_at=T2, metadata_hash="9" * 64),
        run_id=RUN_3,
    )

    page = repository.list_runs(PROJECT, audit_kind="python_project", limit=2)

    assert isinstance(page, HistoryPage)
    assert page.total_count == 3
    assert page.limit == 2
    assert page.offset == 0
    assert tuple(item.run_id for item in page.items) == (RUN_3, RUN_2)
    failed = repository.list_runs(
        PROJECT,
        run_status=RunStatus.FAILED,
        reused=False,
        completed_from=T2,
        completed_to=T2,
    )
    assert failed.total_count == 1
    assert failed.items[0].run_id == RUN_2
    second_page = repository.list_runs(PROJECT, limit=2, offset=2)
    assert second_page.total_count == 3
    assert tuple(item.run_id for item in second_page.items) == (RUN_1,)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"limit": True}, "invalid_limit"),
        ({"limit": 0}, "invalid_limit"),
        ({"limit": 101}, "invalid_limit"),
        ({"offset": True}, "invalid_offset"),
        ({"offset": -1}, "invalid_offset"),
        ({"offset": 100_001}, "invalid_offset"),
        ({"run_status": "unknown"}, "invalid_run_status"),
        ({"reused": 1}, "invalid_reused"),
        ({"completed_from": T2, "completed_to": T1}, "invalid_timestamp_range"),
        ({"started_from": T2, "started_to": T1}, "invalid_timestamp_range"),
    ],
)
def test_run_history_validates_all_inputs_before_sql(
    repository: HistoryRepository,
    database: DatabaseManager,
    kwargs: dict[str, object],
    code: str,
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    with pytest.raises(HistoryDatabaseError, match=f"^{code}$"):
        repository.list_runs(PROJECT, **kwargs)

    assert statements == []


def test_snapshot_summary_detail_compatible_choices_and_normalized_pages(
    repository: HistoryRepository,
) -> None:
    first = repository.save_run(_snapshot(), run_id=RUN_1)
    reused = repository.save_run(
        _snapshot(started_at=T1, completed_at=T2), run_id=RUN_2
    )

    latest = repository.latest_snapshot(PROJECT, "python_project")
    assert isinstance(latest, SnapshotSummary)
    assert latest.snapshot_id == first.snapshot_id
    assert latest.last_used_at == T2
    assert repository.get_snapshot_summary(
        first.snapshot_id, project_id=PROJECT, audit_kind="python_project"
    ) == latest
    detail = repository.get_snapshot_detail(
        first.snapshot_id, project_id=PROJECT, audit_kind="python_project"
    )
    assert isinstance(detail, SnapshotDetail)
    assert detail.summary == latest
    assert detail.environment_hash == "0" * 64
    assert detail.result_json_size > 0

    choices = repository.list_compatible_runs(
        PROJECT,
        "python_project",
        current_snapshot_id=first.snapshot_id,
    )
    assert choices.total_count == 2
    assert all(isinstance(item, CompatibleRunChoice) for item in choices.items)
    assert [(item.run_id, item.reused, item.same_snapshot) for item in choices.items] == [
        (RUN_2, True, True),
        (RUN_1, False, True),
    ]

    packages = repository.list_snapshot_packages(
        first.snapshot_id,
        project_id=PROJECT,
        audit_kind="python_project",
        scope=PackageScope.LOCK,
        normalized_name="demo-pkg",
        limit=1,
    )
    assert packages.total_count == 2
    assert [(row.version, row.scope) for row in packages.items] == [
        ("1.0", PackageScope.LOCK)
    ]
    assert repository.list_snapshot_packages(
        first.snapshot_id,
        project_id=PROJECT,
        audit_kind="python_project",
        scope="lock",
        normalized_name="demo-pkg",
        offset=1,
    ).items[0].version == "2.0"

    findings = repository.list_snapshot_findings(
        first.snapshot_id,
        project_id=PROJECT,
        audit_kind="python_project",
        scope="lock",
        normalized_name="demo-pkg",
        finding_status="affected",
        advisory="CVE-2026-1234",
    )
    assert findings.total_count == 1
    assert findings.items[0].fixed_versions == ("2.0", "2.1")
    dependencies = repository.list_snapshot_dependencies(
        first.snapshot_id,
        project_id=PROJECT,
        audit_kind="python_project",
        parent_component_key="pkg:pypi/demo-pkg@1.0?scope=lock",
        resolution_status="resolved",
    )
    assert dependencies.total_count == 1
    issues = repository.list_snapshot_issues(
        first.snapshot_id,
        project_id=PROJECT,
        audit_kind="python_project",
        issue_code="lock_unresolved",
    )
    assert issues.total_count == 1
    assert issues.items[0].ordinal == 0
    assert reused.snapshot_id == first.snapshot_id


def test_snapshot_scope_is_required_and_cross_project_access_is_hidden(
    repository: HistoryRepository,
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)

    with pytest.raises(HistoryDatabaseError, match="^snapshot_not_found$"):
        repository.get_snapshot_detail(
            saved.snapshot_id,
            project_id=OTHER_PROJECT,
            audit_kind="python_project",
        )
    with pytest.raises(HistoryDatabaseError, match="^snapshot_not_found$"):
        repository.list_snapshot_findings(
            saved.snapshot_id,
            project_id=OTHER_PROJECT,
            audit_kind="python_project",
        )


def test_first_seen_supports_ghsa_cve_package_version_reuse_and_ties(
    repository: HistoryRepository,
) -> None:
    first = repository.save_run(_snapshot(completed_at=T1), run_id=RUN_2)
    repository.save_run(
        _snapshot(started_at=T1, completed_at=T2), run_id=RUN_3
    )
    # A second computed snapshot contains the same advisory/version at the same
    # completion time; the lower run id remains the deterministic first sighting.
    repository.save_run(
        _snapshot(completed_at=T1, composite_hash="a" * 64), run_id=RUN_1
    )

    by_ghsa = repository.find_first_seen(
        PROJECT,
        "python_project",
        ghsa_id="GHSA-2345-6789-cfgh",
        normalized_name="demo-pkg",
    )
    by_cve = repository.find_first_seen(
        PROJECT,
        "python_project",
        cve_id="CVE-2026-1234",
        normalized_name="demo-pkg",
        audited_version="1.0",
    )

    assert isinstance(by_ghsa, FindingFirstSeen)
    assert by_ghsa == by_cve
    assert by_ghsa.run_id == RUN_1
    assert by_ghsa.snapshot_id != first.snapshot_id
    assert by_ghsa.completed_at == T1
    assert by_ghsa.audited_version == "1.0"
    assert repository.find_first_seen(
        OTHER_PROJECT,
        "python_project",
        ghsa_id="GHSA-2345-6789-cfgh",
        normalized_name="demo-pkg",
    ) is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"ghsa_id": "GHSA-1", "cve_id": "CVE-1"},
        {"ghsa_id": ""},
        {"cve_id": "CVE-1", "normalized_name": ""},
    ],
)
def test_first_seen_rejects_missing_ambiguous_or_invalid_identity(
    repository: HistoryRepository, kwargs: dict[str, object]
) -> None:
    values = {"normalized_name": "demo-pkg", **kwargs}
    with pytest.raises(HistoryDatabaseError, match="^invalid_finding_lookup$"):
        repository.find_first_seen(PROJECT, "python_project", **values)


def test_first_seen_excludes_started_and_failed_runs_directly_linked_to_snapshot(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(
        _snapshot(started_at=T1, completed_at=T2), run_id=RUN_3
    )
    repository.start_run(
        run_id=RUN_1,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=T0,
    )
    repository.mark_run_failed(RUN_2, completed_at=T1, failure_code="audit_failed")
    database.connection.execute(
        "UPDATE audit_runs SET snapshot_id = ? WHERE run_id IN (?, ?)",
        (saved.snapshot_id, RUN_1, RUN_2),
    )

    first = repository.find_first_seen(
        PROJECT,
        "python_project",
        ghsa_id="GHSA-2345-6789-cfgh",
        normalized_name="demo-pkg",
    )

    assert first is not None
    assert first.run_id == RUN_3


def test_first_seen_distinguishes_versions_and_totally_orders_rows_in_one_run(
    repository: HistoryRepository,
) -> None:
    snapshot = _snapshot()
    primary = snapshot.findings[0]
    environment_match = replace(
        primary,
        scope=PackageScope.ENVIRONMENT,
        advisory_id="ALT-ENV",
        advisory_fingerprint="9" * 64,
    )
    version_two = replace(
        primary,
        audited_version="2.0",
        advisory_id="ALT-V2",
        advisory_fingerprint="a" * 64,
    )
    value = replace(
        snapshot,
        findings=(primary, environment_match, version_two, snapshot.findings[1]),
        affected_finding_count=3,
    )
    repository.save_run(value, run_id=RUN_1)

    unversioned = repository.find_first_seen(
        PROJECT,
        "python_project",
        ghsa_id="GHSA-2345-6789-cfgh",
        normalized_name="demo-pkg",
    )
    versioned = repository.find_first_seen(
        PROJECT,
        "python_project",
        cve_id="CVE-2026-1234",
        normalized_name="demo-pkg",
        audited_version="2.0",
    )

    assert unversioned is not None
    assert unversioned.scope is PackageScope.ENVIRONMENT
    assert unversioned.advisory_id == "ALT-ENV"
    assert unversioned.advisory_fingerprint == "9" * 64
    assert versioned is not None
    assert versioned.audited_version == "2.0"
    assert versioned.advisory_id == "ALT-V2"


def test_history_queries_use_indexes_and_never_decode_result_blobs(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)

    def explode(*_args, **_kwargs):
        raise AssertionError("result BLOB decoded")

    monkeypatch.setattr(repository_module, "decode_result", explode)
    monkeypatch.setattr(repository, "get_snapshot_result", explode)

    assert repository.list_runs(PROJECT).items
    assert repository.latest_snapshot(PROJECT, "python_project") is not None
    assert repository.get_snapshot_detail(
        saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
    ).summary.snapshot_id == saved.snapshot_id
    assert repository.list_compatible_runs(PROJECT, "python_project").items
    assert repository.list_snapshot_packages(
        saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
    ).items
    assert repository.find_first_seen(
        PROJECT,
        "python_project",
        ghsa_id="GHSA-2345-6789-cfgh",
        normalized_name="demo-pkg",
    ) is not None

    history_plan = database.connection.execute(
        "EXPLAIN QUERY PLAN "
        + _run_history_sql("project_id = ? AND audit_kind = ?"),
        (PROJECT, "python_project", 20, 0),
    ).fetchall()
    ghsa_plan = database.connection.execute(
        "EXPLAIN QUERY PLAN " + _first_seen_sql("ghsa", include_version=False),
        (
            "GHSA-2345-6789-cfgh",
            "demo-pkg",
            PROJECT,
            "python_project",
            RunStatus.COMPLETED_COMPUTED.value,
            RunStatus.COMPLETED_REUSED.value,
        ),
    ).fetchall()
    cve_plan = database.connection.execute(
        "EXPLAIN QUERY PLAN " + _first_seen_sql("cve", include_version=False),
        (
            "CVE-2026-1234",
            "demo-pkg",
            PROJECT,
            "python_project",
            RunStatus.COMPLETED_COMPUTED.value,
            RunStatus.COMPLETED_REUSED.value,
        ),
    ).fetchall()
    history_text = " ".join(str(row[3]) for row in history_plan)
    ghsa_text = " ".join(str(row[3]) for row in ghsa_plan)
    cve_text = " ".join(str(row[3]) for row in cve_plan)
    assert "SEARCH audit_runs USING INDEX idx_audit_runs_project_expiry" in history_text
    assert "USE TEMP B-TREE" not in history_text
    assert "SEARCH f USING INDEX idx_snapshot_findings_advisory_name" in ghsa_text
    assert "SEARCH f USING INDEX idx_snapshot_findings_cve_name" in cve_text
    assert "SEARCH r USING INDEX idx_audit_runs_snapshot" in cve_text
    assert "SCAN f" not in cve_text


def test_query_row_corruption_is_mapped_to_stable_error(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    database.connection.execute(
        "UPDATE snapshot_packages SET raw_name = ? WHERE snapshot_id = ?",
        ("bad\u0085name", saved.snapshot_id),
    )

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        repository.list_snapshot_packages(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )


def test_query_rejects_blob_values_in_text_columns(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    database.connection.execute(
        "UPDATE audit_runs SET knowledge_sources_json = ? WHERE run_id = ?",
        (sqlite3.Binary(b'[\"ghsa\",\"osv\"]'), RUN_1),
    )
    database.connection.execute(
        "UPDATE snapshot_findings SET fixed_versions = ? WHERE snapshot_id = ? "
        "AND ghsa_id IS NOT NULL",
        (sqlite3.Binary(b'[\"2.0\",\"2.1\"]'), saved.snapshot_id),
    )

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        repository.list_runs(PROJECT)
    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        repository.list_snapshot_findings(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )


@pytest.mark.parametrize(
    "case",
    [
        "snapshot_summary",
        "snapshot_detail",
        "compatible_choice",
        "dependency",
        "issue",
        "first_seen",
    ],
)
def test_each_query_record_maps_corruption_and_leaves_connection_usable(
    repository: HistoryRepository,
    database: DatabaseManager,
    case: str,
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    if case == "snapshot_summary":
        database.connection.execute(
            "UPDATE audit_snapshots SET audit_status = ? WHERE snapshot_id = ?",
            ("corrupt", saved.snapshot_id),
        )
        call = lambda: repository.get_snapshot_summary(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )
    elif case == "snapshot_detail":
        database.connection.execute(
            "UPDATE audit_snapshots SET result_json_sha256 = ? WHERE snapshot_id = ?",
            ("corrupt", saved.snapshot_id),
        )
        call = lambda: repository.get_snapshot_detail(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )
    elif case == "compatible_choice":
        database.connection.execute(
            "UPDATE audit_runs SET reused = 1 WHERE run_id = ?", (RUN_1,)
        )
        call = lambda: repository.list_compatible_runs(PROJECT, "python_project")
    elif case == "dependency":
        database.connection.execute(
            "UPDATE snapshot_dependencies SET relationship_source = ? "
            "WHERE snapshot_id = ?",
            ("bad\u0085source", saved.snapshot_id),
        )
        call = lambda: repository.list_snapshot_dependencies(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )
    elif case == "issue":
        database.connection.execute(
            "UPDATE snapshot_issues SET subject = ? WHERE snapshot_id = ?",
            ("bad\u0085subject", saved.snapshot_id),
        )
        call = lambda: repository.list_snapshot_issues(
            saved.snapshot_id, project_id=PROJECT, audit_kind="python_project"
        )
    else:
        database.connection.execute(
            "UPDATE snapshot_findings SET audited_version = ? WHERE snapshot_id = ? "
            "AND ghsa_id IS NOT NULL",
            ("bad\u0085version", saved.snapshot_id),
        )
        call = lambda: repository.find_first_seen(
            PROJECT,
            "python_project",
            ghsa_id="GHSA-2345-6789-cfgh",
            normalized_name="demo-pkg",
        )

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        call()

    assert database.connection.in_transaction is False
    assert database.connection.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.parametrize(
    ("method_name", "bad_filter", "filter_code"),
    [
        ("list_runs", {"run_status": "corrupt"}, "invalid_run_status"),
        (
            "list_compatible_runs",
            {"current_snapshot_id": True},
            "invalid_snapshot_id",
        ),
        (
            "list_snapshot_packages",
            {"scope": "corrupt"},
            "invalid_package_scope",
        ),
        (
            "list_snapshot_findings",
            {"advisory": "bad\u0085advisory"},
            "invalid_text",
        ),
        (
            "list_snapshot_dependencies",
            {"parent_component_key": "bad key"},
            "invalid_component_key",
        ),
        (
            "list_snapshot_issues",
            {"issue_code": "BAD CODE"},
            "invalid_issue_code",
        ),
    ],
)
def test_every_paginated_method_rejects_limit_offset_and_filter_before_sql(
    repository: HistoryRepository,
    database: DatabaseManager,
    method_name: str,
    bad_filter: dict[str, object],
    filter_code: str,
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    if method_name == "list_runs":
        call = lambda kwargs: repository.list_runs(PROJECT, **kwargs)
    elif method_name == "list_compatible_runs":
        call = lambda kwargs: repository.list_compatible_runs(
            PROJECT, "python_project", **kwargs
        )
    else:
        method = getattr(repository, method_name)
        call = lambda kwargs: method(
            saved.snapshot_id,
            project_id=PROJECT,
            audit_kind="python_project",
            **kwargs,
        )

    for kwargs, code in (
        ({"limit": True}, "invalid_limit"),
        ({"limit": 0}, "invalid_limit"),
        ({"limit": 101}, "invalid_limit"),
        ({"offset": True}, "invalid_offset"),
        ({"offset": -1}, "invalid_offset"),
        ({"offset": 100_001}, "invalid_offset"),
        (bad_filter, filter_code),
    ):
        statements: list[str] = []
        database.connection.set_trace_callback(statements.append)
        with pytest.raises(HistoryDatabaseError, match=f"^{code}$"):
            call(kwargs)
        database.connection.set_trace_callback(None)
        assert statements == []
