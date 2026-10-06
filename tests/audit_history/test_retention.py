from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

import pytest

from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.codec import encode_result
from svarog.audit_history import retention as retention_module
from svarog.audit_history.repository import HistoryRepository
from svarog.audit_history.retention import CleanupResult, cleanup_history
from tests.audit_history.test_repository import (
    OTHER_PROJECT,
    PROJECT,
    RUN_1,
    RUN_2,
    RUN_3,
    _snapshot,
)


NOW = datetime(2026, 10, 1, tzinfo=UTC)
OLD_START = "2026-09-26T23:59:00Z"
OLD_DONE = "2026-09-27T00:00:00Z"
CUTOFF = "2026-09-28T00:00:00Z"
NEW = "2026-09-29T00:00:00Z"


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


def _set_run_time(database: DatabaseManager, run_id: str, timestamp: str) -> None:
    database.connection.execute(
        "UPDATE audit_runs SET started_at = ?, completed_at = ? WHERE run_id = ?",
        (timestamp, timestamp, run_id),
    )


def _insert_diff(
    database: DatabaseManager,
    *,
    diff_id: str,
    baseline_run_id: str,
    target_run_id: str,
) -> None:
    database.connection.execute(
        "INSERT INTO run_diffs "
        "(diff_id, project_id, baseline_run_id, target_run_id, diff_contract_version, "
        "classification, package_added_count, package_removed_count, package_changed_count, "
        "finding_introduced_count, finding_resolved_count, finding_changed_count, "
        "issue_added_count, issue_resolved_count, diff_json_zlib, diff_json_size, "
        "diff_json_sha256, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, ?, 2, ?, ?)",
        (
            diff_id,
            PROJECT,
            baseline_run_id,
            target_run_id,
            "svarog-diff/1",
            "no_change",
            b"{}",
            "0" * 64,
            NEW,
        ),
    )


@pytest.mark.parametrize("days", [3, 180, 365])
def test_retention_accepts_inclusive_day_boundaries(
    repository: HistoryRepository, database: DatabaseManager, days: int
) -> None:
    cutoff = NOW - timedelta(days=days)
    timestamps = (
        cutoff - timedelta(seconds=1),
        cutoff,
        cutoff + timedelta(seconds=1),
    )
    run_ids = (
        "00000000-0000-4000-8000-000000000011",
        "00000000-0000-4000-8000-000000000012",
        "00000000-0000-4000-8000-000000000013",
    )
    for run_id, timestamp in zip(run_ids, timestamps, strict=True):
        value = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        repository.start_run(
            run_id=run_id,
            project_id=PROJECT,
            display_name="Demo project",
            audit_kind="python_project",
            started_at=value,
        )
        repository.mark_run_failed(
            run_id, completed_at=value, failure_code="audit_failed"
        )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=days, now=NOW
    )

    assert result == CleanupResult(1, 0, False, None)
    assert database.connection.execute(
        "SELECT run_id FROM audit_runs ORDER BY run_id"
    ).fetchall() == [(run_ids[1],), (run_ids[2],)]
    with pytest.raises(FrozenInstanceError):
        result.deleted_runs = 2  # type: ignore[misc]


@pytest.mark.parametrize("days", [2, 366, True, 3.0, "180"])
def test_invalid_retention_skips_without_any_sql_write(
    repository: HistoryRepository,
    database: DatabaseManager,
    days: object,
) -> None:
    statements: list[str] = []
    database.connection.set_trace_callback(statements.append)

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=days, now=NOW
    )

    assert result == CleanupResult(0, 0, True, "invalid_retention_days")
    assert not any(
        statement.startswith(("BEGIN", "DELETE", "UPDATE")) for statement in statements
    )


def test_cleanup_uses_strict_cutoff_and_run_terminal_or_start_time(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    repository.start_run(
        run_id=RUN_2,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=OLD_START,
    )
    repository.mark_run_failed(
        RUN_2, completed_at=OLD_DONE, failure_code="audit_failed"
    )
    repository.start_run(
        run_id=RUN_3,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=OLD_START,
    )
    equality_run = "00000000-0000-4000-8000-000000000004"
    repository.start_run(
        run_id=equality_run,
        project_id=PROJECT,
        display_name="Demo project",
        audit_kind="python_project",
        started_at=CUTOFF,
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result.deleted_runs == 3
    assert database.connection.execute(
        "SELECT run_id FROM audit_runs ORDER BY run_id"
    ).fetchall() == [(equality_run,)]


def test_cleanup_removes_diffs_nulls_only_deleted_baseline_and_never_retargets(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)
    repository.save_run(
        _snapshot(started_at="2026-09-28T00:01:00Z", completed_at="2026-09-28T00:02:00Z", composite_hash="a" * 64),
        run_id=RUN_2,
    )
    repository.save_run(
        _snapshot(started_at="2026-09-28T00:02:00Z", completed_at="2026-09-28T00:03:00Z", composite_hash="b" * 64),
        run_id=RUN_3,
    )
    _set_run_time(database, RUN_1, OLD_DONE)
    _set_run_time(database, RUN_2, NEW)
    _set_run_time(database, RUN_3, NEW)
    _insert_diff(
        database, diff_id="diff-old", baseline_run_id=RUN_1, target_run_id=RUN_2
    )
    _insert_diff(
        database, diff_id="diff-live", baseline_run_id=RUN_2, target_run_id=RUN_3
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result.deleted_runs == 1
    assert database.connection.execute(
        "SELECT run_id, baseline_run_id FROM audit_runs ORDER BY run_id"
    ).fetchall() == [(RUN_2, None), (RUN_3, RUN_2)]
    assert database.connection.execute(
        "SELECT diff_id, baseline_run_id, target_run_id FROM run_diffs"
    ).fetchall() == [("diff-live", RUN_2, RUN_3)]


def test_cleanup_preserves_latest_per_kind_referenced_and_recently_used_snapshots(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = []
    for run_id, marker in ((RUN_1, "a"), (RUN_2, "b"), (RUN_3, "c")):
        saved.append(
            repository.save_run(
                _snapshot(composite_hash=marker * 64), run_id=run_id
            )
        )
    database.connection.execute(
        "UPDATE audit_runs SET started_at = ?, completed_at = ?",
        (OLD_DONE, OLD_DONE),
    )
    database.connection.execute(
        "UPDATE audit_snapshots SET created_at = ?, last_used_at = ?",
        (OLD_DONE, OLD_DONE),
    )
    # The middle snapshot is orphaned by expired-run cleanup but recently reused.
    database.connection.execute(
        "UPDATE audit_snapshots SET last_used_at = ? WHERE snapshot_id = ?",
        (CUTOFF, saved[1].snapshot_id),
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result.deleted_runs == 3
    assert result.deleted_snapshots == 1
    assert database.connection.execute(
        "SELECT snapshot_id FROM audit_snapshots ORDER BY snapshot_id"
    ).fetchall() == [(saved[1].snapshot_id,), (saved[2].snapshot_id,)]
    assert repository.latest_snapshot(PROJECT, "python_project").snapshot_id == saved[2].snapshot_id


def test_cleanup_is_project_scoped(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    other = repository.save_run(
        _snapshot(
            project_id=OTHER_PROJECT,
            started_at=OLD_START,
            completed_at=OLD_DONE,
            composite_hash="d" * 64,
        ),
        run_id=RUN_2,
    )

    cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)

    assert database.connection.execute(
        "SELECT run_id FROM audit_runs WHERE project_id = ?", (OTHER_PROJECT,)
    ).fetchall() == [(RUN_2,)]
    assert database.connection.execute(
        "SELECT snapshot_id FROM audit_snapshots WHERE project_id = ?", (OTHER_PROJECT,)
    ).fetchall() == [(other.snapshot_id,)]


def test_cleanup_rolls_back_all_changes_and_keeps_cache_on_sql_error(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    repository.get_snapshot_result(saved.snapshot_id)
    database.connection.execute(
        "CREATE TRIGGER task7_fail_cleanup BEFORE DELETE ON audit_runs "
        "BEGIN SELECT RAISE(ABORT, 'sensitive cleanup detail'); END"
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result == CleanupResult(0, 0, True, "history_cleanup_failed")
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (1,)
    assert database.connection.execute("SELECT COUNT(*) FROM audit_snapshots").fetchone() == (1,)
    assert saved.snapshot_id in repository._result_cache._entries


def test_cleanup_validation_failure_rolls_back_without_deleting(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)
    database.connection.execute(
        "UPDATE audit_runs SET started_at = ?, completed_at = ? WHERE run_id = ?",
        (CUTOFF, OLD_DONE, RUN_1),
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result == CleanupResult(0, 0, True, "history_cleanup_failed")
    assert database.connection.execute(
        "SELECT run_id FROM audit_runs"
    ).fetchall() == [(RUN_1,)]


def test_cleanup_delete_ignore_mismatch_rolls_back_prior_fk_repairs(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(_snapshot(), run_id=RUN_1)
    repository.save_run(
        _snapshot(
            started_at="2026-09-28T00:01:00Z",
            completed_at="2026-09-28T00:02:00Z",
            composite_hash="f" * 64,
        ),
        run_id=RUN_2,
    )
    _set_run_time(database, RUN_1, OLD_DONE)
    _set_run_time(database, RUN_2, NEW)
    _insert_diff(
        database, diff_id="diff-ignore", baseline_run_id=RUN_1, target_run_id=RUN_2
    )
    database.connection.execute(
        "CREATE TRIGGER task7_ignore_cleanup BEFORE DELETE ON audit_runs "
        f"WHEN OLD.run_id = '{RUN_1}' BEGIN SELECT RAISE(IGNORE); END"
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result == CleanupResult(0, 0, True, "history_cleanup_failed")
    assert database.connection.execute(
        "SELECT run_id, baseline_run_id FROM audit_runs ORDER BY run_id"
    ).fetchall() == [(RUN_1, None), (RUN_2, RUN_1)]
    assert database.connection.execute(
        "SELECT diff_id FROM run_diffs"
    ).fetchall() == [("diff-ignore",)]


def test_cleanup_begin_failure_returns_warning_without_touching_outer_transaction(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    database.connection.execute("BEGIN")

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result == CleanupResult(0, 0, True, "history_cleanup_failed")
    assert database.connection.in_transaction is True
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (1,)
    database.connection.rollback()


def test_cleanup_commit_failure_rolls_back_and_returns_warning(
    repository: HistoryRepository,
    database: DatabaseManager,
) -> None:
    repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )

    def deny_commit(action, argument, _second, _database, _source):
        if action == sqlite3.SQLITE_TRANSACTION and argument == "COMMIT":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    database.connection.set_authorizer(deny_commit)

    try:
        result = cleanup_history(
            repository, project_id=PROJECT, retention_days=3, now=NOW
        )
    finally:
        database.connection.set_authorizer(None)

    assert result == CleanupResult(0, 0, True, "history_cleanup_failed")
    assert database.connection.in_transaction is False
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (1,)


def test_cleanup_base_exception_propagates_after_transaction_rollback(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )

    def interrupt(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(retention_module, "_expired_run_candidates", interrupt)

    with pytest.raises(KeyboardInterrupt):
        cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)

    assert database.connection.in_transaction is False
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (1,)


def test_cleanup_batches_expired_runs_without_rejecting_larger_projects(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for run_id in (RUN_1, RUN_2):
        repository.start_run(
            run_id=run_id,
            project_id=PROJECT,
            display_name="Demo project",
            audit_kind="python_project",
            started_at=OLD_DONE,
        )
        repository.mark_run_failed(
            run_id, completed_at=OLD_DONE, failure_code="audit_failed"
        )
    monkeypatch.setattr(retention_module, "MAX_RETENTION_CANDIDATES", 1)

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result == CleanupResult(1, 0, False, None)
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (1,)
    second = cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)
    assert second == CleanupResult(1, 0, False, None)
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (0,)


def test_cleanup_does_not_reject_multiple_live_runs(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for run_id in (RUN_1, RUN_2):
        repository.start_run(
            run_id=run_id, project_id=PROJECT, display_name="Demo project",
            audit_kind="python_project", started_at=NEW,
        )
    monkeypatch.setattr(retention_module, "MAX_RETENTION_CANDIDATES", 1)
    result = cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)
    assert result == CleanupResult(0, 0, False, None)
    assert database.connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone() == (2,)


def test_cleanup_evicts_exactly_deleted_snapshots_after_commit(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    first = repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    second = repository.save_run(
        _snapshot(
            started_at=OLD_START,
            completed_at=OLD_DONE,
            composite_hash="e" * 64,
        ),
        run_id=RUN_2,
    )
    repository.get_snapshot_result(first.snapshot_id)
    repository.get_snapshot_result(second.snapshot_id)
    database.connection.execute(
        "UPDATE audit_snapshots SET created_at = ?, last_used_at = ?",
        (OLD_DONE, OLD_DONE),
    )

    result = cleanup_history(
        repository, project_id=PROJECT, retention_days=3, now=NOW
    )

    assert result.deleted_snapshots == 1
    assert first.snapshot_id not in repository._result_cache._entries
    assert second.snapshot_id in repository._result_cache._entries


def test_cleanup_invalidates_other_repository_cached_snapshot(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    first = repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE), run_id=RUN_1
    )
    second = repository.save_run(
        _snapshot(started_at=OLD_START, completed_at=OLD_DONE, composite_hash="e" * 64),
        run_id=RUN_2,
    )
    other_repository = HistoryRepository(database.connection)
    assert other_repository.get_snapshot_result(first.snapshot_id)
    database.connection.execute(
        "UPDATE audit_snapshots SET created_at = ?, last_used_at = ?",
        (OLD_DONE, OLD_DONE),
    )
    result = cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)
    assert result.deleted_snapshots == 1
    from svarog.audit_history.errors import HistoryDatabaseError
    with pytest.raises(HistoryDatabaseError, match="^snapshot_not_found$"):
        other_repository.get_snapshot_result(first.snapshot_id)
    assert other_repository.get_snapshot_result(second.snapshot_id)


def test_snapshot_cache_reloads_changed_database_payload(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    assert repository.get_snapshot_result(saved.snapshot_id)["items"] == [1]
    replacement = encode_result({"items": [2]})
    database.connection.execute(
        "UPDATE audit_snapshots SET result_json_zlib = ?, result_json_size = ?, "
        "result_json_sha256 = ? WHERE snapshot_id = ?",
        (replacement.compressed, replacement.size, replacement.sha256, saved.snapshot_id),
    )
    assert repository.get_snapshot_result(saved.snapshot_id) == {"items": [2]}


def test_snapshot_cache_does_not_hide_corrupt_blob_with_unchanged_metadata(
    repository: HistoryRepository, database: DatabaseManager
) -> None:
    saved = repository.save_run(_snapshot(), run_id=RUN_1)
    repository.get_snapshot_result(saved.snapshot_id)
    database.connection.execute(
        "UPDATE audit_snapshots SET result_json_zlib = ? WHERE snapshot_id = ?",
        (b"not zlib", saved.snapshot_id),
    )
    from svarog.audit_history.errors import HistoryDatabaseError
    with pytest.raises(HistoryDatabaseError, match="^result_corrupt$"):
        repository.get_snapshot_result(saved.snapshot_id)


def test_cleanup_batches_orphaned_snapshots_and_keeps_latest(
    repository: HistoryRepository,
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = [
        repository.save_run(_snapshot(composite_hash=marker * 64), run_id=run_id)
        for run_id, marker in ((RUN_1, "a"), (RUN_2, "b"), (RUN_3, "c"))
    ]
    database.connection.execute(
        "UPDATE audit_runs SET started_at = ?, completed_at = ?",
        (OLD_DONE, OLD_DONE),
    )
    database.connection.execute(
        "UPDATE audit_snapshots SET created_at = ?, last_used_at = ?",
        (OLD_DONE, OLD_DONE),
    )
    monkeypatch.setattr(retention_module, "MAX_RETENTION_CANDIDATES", 1)

    results = [
        cleanup_history(repository, project_id=PROJECT, retention_days=3, now=NOW)
        for _ in range(3)
    ]
    assert sum(result.deleted_runs for result in results) == 3
    assert sum(result.deleted_snapshots for result in results) == 2
    assert database.connection.execute(
        "SELECT snapshot_id FROM audit_snapshots"
    ).fetchall() == [(saved[2].snapshot_id,)]


def test_expired_run_candidate_query_uses_bounded_ordered_index(
    database: DatabaseManager,
) -> None:
    plan = database.connection.execute(
        "EXPLAIN QUERY PLAN SELECT run_id, started_at, completed_at, run_status "
        "FROM audit_runs WHERE project_id = ? "
        "AND COALESCE(completed_at, started_at) < ? "
        "ORDER BY COALESCE(completed_at, started_at), run_id LIMIT ?",
        (PROJECT, CUTOFF, 400),
    ).fetchall()
    details = " ".join(str(row[3]) for row in plan)
    assert "idx_audit_runs_project_expiry" in details
    assert "USE TEMP B-TREE" not in details
