"""Bounded, project-scoped audit-history retention."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import sqlite3

from .database import immediate_transaction
from .errors import HistoryDatabaseError
from .models import RunStatus
from .repository import (
    HistoryRepository,
    _audit_kind,
    _count,
    _project_id,
    _run_id,
    _snapshot_id,
    _stored_timestamp,
)


MIN_RETENTION_DAYS = 3
MAX_RETENTION_DAYS = 365
MAX_RETENTION_CANDIDATES = 400
_VALID_WARNINGS = frozenset({"invalid_retention_days", "history_cleanup_failed"})
_EXPIRED_RUNS = "project_id = ? AND COALESCE(completed_at, started_at) < ?"
_ORPHANED_SNAPSHOTS = (
    "old.project_id = ? AND old.last_used_at < ? "
    "AND NOT EXISTS (SELECT 1 FROM audit_runs AS run "
    "WHERE run.snapshot_id = old.snapshot_id) "
    "AND EXISTS (SELECT 1 FROM audit_snapshots AS newer "
    "WHERE newer.project_id = old.project_id "
    "AND newer.audit_kind = old.audit_kind AND ("
    "newer.created_at > old.created_at OR "
    "(newer.created_at = old.created_at "
    "AND newer.snapshot_id > old.snapshot_id)))"
)


@dataclass(frozen=True, slots=True)
class CleanupResult:
    """Non-sensitive outcome from one independent cleanup attempt."""

    deleted_runs: int
    deleted_snapshots: int
    skipped: bool
    warning: str | None

    def __post_init__(self) -> None:
        _count(self.deleted_runs)
        _count(self.deleted_snapshots)
        if type(self.skipped) is not bool:
            raise HistoryDatabaseError("invalid_cleanup_result")
        if self.warning is not None and self.warning not in _VALID_WARNINGS:
            raise HistoryDatabaseError("invalid_cleanup_result")
        if self.skipped is not (self.warning is not None):
            raise HistoryDatabaseError("invalid_cleanup_result")
        if self.skipped and (self.deleted_runs or self.deleted_snapshots):
            raise HistoryDatabaseError("invalid_cleanup_result")


def cleanup_history(
    repository: HistoryRepository,
    project_id: str,
    retention_days: int,
    now: datetime,
) -> CleanupResult:
    """Delete expired history in a transaction separate from run persistence."""

    if (
        type(retention_days) is not int
        or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS
    ):
        return CleanupResult(0, 0, True, "invalid_retention_days")
    if type(repository) is not HistoryRepository:
        raise HistoryDatabaseError("invalid_history_repository")
    project_id = _project_id(project_id)
    cutoff = _cutoff(now, retention_days)
    connection = repository._connection
    deleted_snapshot_ids: tuple[int, ...] = ()

    try:
        with immediate_transaction(connection):
            candidate_run_ids = _expired_run_candidates(
                connection, project_id, cutoff
            )
            if candidate_run_ids:
                placeholders = ", ".join("?" for _ in candidate_run_ids)
                for column in ("baseline_run_id", "target_run_id"):
                    connection.execute(
                        "DELETE FROM run_diffs WHERE project_id = ? AND "
                        f"{column} IN ({placeholders})",
                        (project_id, *candidate_run_ids),
                    )
                connection.execute(
                    "UPDATE audit_runs SET baseline_run_id = NULL "
                    f"WHERE project_id = ? AND baseline_run_id IN ({placeholders})",
                    (project_id, *candidate_run_ids),
                )
                cursor = connection.execute(
                    "DELETE FROM audit_runs WHERE project_id = ? "
                    f"AND run_id IN ({placeholders})",
                    (project_id, *candidate_run_ids),
                )
                _require_exact_deletion(len(candidate_run_ids), cursor.rowcount)
            deleted_runs = len(candidate_run_ids)
            _count(deleted_runs)

            candidate_snapshot_ids = _orphaned_snapshot_candidates(
                connection, project_id, cutoff
            )
            if candidate_snapshot_ids:
                placeholders = ", ".join("?" for _ in candidate_snapshot_ids)
                cursor = connection.execute(
                    "DELETE FROM audit_snapshots WHERE project_id = ? "
                    f"AND snapshot_id IN ({placeholders})",
                    (project_id, *candidate_snapshot_ids),
                )
                _require_exact_deletion(len(candidate_snapshot_ids), cursor.rowcount)
            deleted_snapshot_ids = candidate_snapshot_ids
            deleted_snapshots = len(deleted_snapshot_ids)
            _count(deleted_snapshots)
    except Exception:
        return CleanupResult(0, 0, True, "history_cleanup_failed")

    for snapshot_id in deleted_snapshot_ids:
        repository._result_cache.discard(snapshot_id)
    return CleanupResult(deleted_runs, deleted_snapshots, False, None)


def _cutoff(now: datetime, retention_days: int) -> str:
    if (
        type(now) is not datetime
        or now.tzinfo is not UTC
        or now.microsecond != 0
    ):
        raise HistoryDatabaseError("invalid_cleanup_now")
    try:
        cutoff = now - timedelta(days=retention_days)
    except (OverflowError, ValueError):
        raise HistoryDatabaseError("invalid_cleanup_now") from None
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _expired_run_candidates(
    connection: sqlite3.Connection, project_id: str, cutoff: str
) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT run_id, started_at, completed_at, run_status FROM audit_runs "
        f"WHERE {_EXPIRED_RUNS} "
        "ORDER BY COALESCE(completed_at, started_at), run_id LIMIT ?",
        (project_id, cutoff, MAX_RETENTION_CANDIDATES),
    ).fetchall()
    candidates: list[str] = []
    for row in rows:
        try:
            run_id = _run_id(row[0])
            started_at = _stored_timestamp(row[1])
            completed_at = None if row[2] is None else _stored_timestamp(row[2])
            status = RunStatus(row[3])
            if (status is RunStatus.STARTED) != (completed_at is None):
                raise HistoryDatabaseError("history_database_corrupt")
            if completed_at is not None and completed_at < started_at:
                raise HistoryDatabaseError("history_database_corrupt")
            candidates.append(run_id)
        except (HistoryDatabaseError, IndexError, TypeError, ValueError):
            raise HistoryDatabaseError("history_database_corrupt") from None
    return tuple(candidates)


def _orphaned_snapshot_candidates(
    connection: sqlite3.Connection, project_id: str, cutoff: str
) -> tuple[int, ...]:
    rows = connection.execute(
        "SELECT old.snapshot_id, old.audit_kind, old.created_at, old.last_used_at "
        "FROM audit_snapshots AS old WHERE "
        + _ORPHANED_SNAPSHOTS
        + " ORDER BY old.snapshot_id LIMIT ?",
        (project_id, cutoff, MAX_RETENTION_CANDIDATES),
    ).fetchall()
    candidates: list[int] = []
    for row in rows:
        try:
            snapshot_id = _snapshot_id(row[0])
            if snapshot_id is None:
                raise ValueError
            _audit_kind(row[1])
            created_at = _stored_timestamp(row[2])
            last_used_at = _stored_timestamp(row[3])
            if last_used_at < created_at:
                raise HistoryDatabaseError("history_database_corrupt")
            candidates.append(snapshot_id)
        except (HistoryDatabaseError, IndexError, TypeError, ValueError):
            raise HistoryDatabaseError("history_database_corrupt") from None
    return tuple(candidates)


def _require_exact_deletion(expected: int, deleted: int) -> None:
    if expected != deleted:
        raise HistoryDatabaseError("history_database_corrupt")
