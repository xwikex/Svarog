"""Read bounded, consistent snapshots from the vulnerability SQLite database."""

from __future__ import annotations

import math
import os
import sqlite3
import stat
from pathlib import Path
from typing import Literal

from packaging.utils import canonicalize_name

from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    AuditIssue,
    DatabaseMetadata,
    VulnerabilitySnapshot,
)

MAX_SUMMARY_CHARS = 500
MAX_SYNC_MESSAGE_CHARS = 500
BUSY_TIMEOUT_MS = 5_000
MAX_LOCK_ATTEMPTS = 3
# The production database currently has about 11,000 pip rows. This leaves ample
# growth room while imposing a hard memory/CPU boundary on an untrusted database.
MAX_PIP_ADVISORY_ROWS = 100_000
_IS_POSIX = os.name == "posix"

_TableName = Literal["advisories", "affected_packages", "sync_meta"]
_REQUIRED_COLUMNS: dict[_TableName, set[str]] = {
    "advisories": {
        "ghsa_id",
        "cve_id",
        "state",
        "summary",
        "severity",
        "cvss_score",
        "updated_at",
        "withdrawn_at",
        "source",
    },
    "affected_packages": {
        "ghsa_id",
        "ecosystem",
        "package_name",
        "version_range",
        "fixed_version",
    },
    "sync_meta": {"key", "value"},
}


class VulnerabilityDatabaseError(ValueError):
    """A fixed, non-sensitive failure to read the vulnerability database."""


def _bounded(value: object, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _severity(value: object) -> tuple[AdvisorySeverity, AuditIssue | None]:
    if value is None or not isinstance(value, str) or not value.strip():
        return (
            AdvisorySeverity.UNKNOWN,
            AuditIssue("invalid_severity", "公告严重度不是支持的枚举值。"),
        )
    normalized = value.strip().lower()
    try:
        return AdvisorySeverity(normalized), None
    except ValueError:
        return (
            AdvisorySeverity.UNKNOWN,
            AuditIssue("invalid_severity", "公告严重度不是支持的枚举值。"),
        )


def _cvss(value: object) -> tuple[float | None, AuditIssue | None]:
    if value is None:
        return None, None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, AuditIssue("invalid_cvss", "公告 CVSS 不是有效数值。")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        return None, AuditIssue("invalid_cvss", "公告 CVSS 超出 0 到 10。")
    return score, None


def _table_columns(connection: sqlite3.Connection, table: _TableName) -> set[str]:
    if table not in _REQUIRED_COLUMNS:
        raise ValueError("unsupported_internal_table")
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})")
    }


def _effective_access(path: Path, mode: int) -> bool:
    return os.access(path, mode, effective_ids=True)


def _sqlite_uses_wal(path: Path) -> bool:
    try:
        with path.open("rb") as database:
            header = database.read(100)
    except OSError as exc:
        raise VulnerabilityDatabaseError("database_unavailable") from exc
    if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
        raise VulnerabilityDatabaseError("database_read_failed")
    format_versions = (header[18], header[19])
    if format_versions == (2, 2):
        return True
    if format_versions == (1, 1):
        return False
    raise VulnerabilityDatabaseError("database_read_failed")


def _validate_posix_database_access(path: Path) -> None:
    """Fail closed unless this effective identity cannot mutate SQLite files."""

    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    sidecars = (wal, shm)
    uses_wal = _sqlite_uses_wal(path)
    try:
        existing_sidecars = tuple(item for item in sidecars if item.exists())
        if uses_wal and len(existing_sidecars) != len(sidecars):
            raise VulnerabilityDatabaseError("database_sidecar_unavailable")
        for item in existing_sidecars:
            if not stat.S_ISREG(item.lstat().st_mode):
                raise VulnerabilityDatabaseError("database_sidecar_unavailable")

        readable = ((path.parent, os.R_OK | os.X_OK), (path, os.R_OK)) + tuple(
            (item, os.R_OK) for item in existing_sidecars
        )
        if any(not _effective_access(item, mode) for item, mode in readable):
            raise VulnerabilityDatabaseError("database_unavailable")

        protected = (path.parent, path) + existing_sidecars
        if any(_effective_access(item, os.W_OK) for item in protected):
            raise VulnerabilityDatabaseError("database_permissions_unsafe")
    except VulnerabilityDatabaseError:
        raise
    except OSError as exc:
        raise VulnerabilityDatabaseError("database_unavailable") from exc


def _sync_metadata(connection: sqlite3.Connection) -> dict[str, str | None]:
    cursor = connection.execute(
        f"""
        SELECT
            CAST(substr(key, 1, 64) AS TEXT),
            CAST(substr(value, 1, {MAX_SYNC_MESSAGE_CHARS}) AS TEXT)
        FROM sync_meta
        WHERE key IN (?, ?, ?)
        LIMIT 4
        """,
        ("last_sync_at", "last_sync_status", "last_sync_message"),
    )
    sync: dict[str, str | None] = {}
    for index, row in enumerate(cursor):
        if index >= 3:
            raise VulnerabilityDatabaseError("invalid_sync_metadata")
        key = _bounded(row[0], 64) or ""
        if key in sync:
            raise VulnerabilityDatabaseError("invalid_sync_metadata")
        sync[key] = _bounded(row[1], MAX_SYNC_MESSAGE_CHARS)
    return sync


def _advisory_sort_key(item: AdvisoryRecord) -> tuple[object, ...]:
    return (
        item.normalized_package_name,
        item.package_name,
        item.ghsa_id,
        item.cve_id or "",
        item.state,
        item.withdrawn_at or "",
        item.summary,
        item.severity.value,
        item.cvss_score is None,
        item.cvss_score if item.cvss_score is not None else 0.0,
        item.source,
        item.updated_at or "",
        item.version_range,
        item.fixed_version or "",
    )


def _load_once(path: Path) -> VulnerabilitySnapshot:
    uri = f"{path.as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        connection.execute("BEGIN")

        check = connection.execute("PRAGMA quick_check(1)").fetchone()
        if check is None or check[0] != "ok":
            raise VulnerabilityDatabaseError("database_corrupt")

        for table, required in _REQUIRED_COLUMNS.items():
            if not required <= _table_columns(connection, table):
                raise VulnerabilityDatabaseError("incompatible_schema")

        sync = _sync_metadata(connection)
        rows = connection.execute(
            f"""
            SELECT
                CAST(substr(a.ghsa_id, 1, 64) AS TEXT),
                CAST(substr(a.cve_id, 1, 64) AS TEXT),
                CAST(substr(a.state, 1, 32) AS TEXT),
                CAST(substr(a.withdrawn_at, 1, 64) AS TEXT),
                CAST(substr(a.summary, 1, {MAX_SUMMARY_CHARS}) AS TEXT),
                CAST(substr(a.severity, 1, 32) AS TEXT),
                CASE
                    WHEN a.cvss_score IS NULL THEN NULL
                    WHEN typeof(a.cvss_score) IN ('integer', 'real') THEN a.cvss_score
                    ELSE CAST(substr(a.cvss_score, 1, 64) AS TEXT)
                END,
                CAST(substr(a.source, 1, 64) AS TEXT),
                CAST(substr(a.updated_at, 1, 64) AS TEXT),
                CAST(substr(p.package_name, 1, 256) AS TEXT),
                CAST(substr(p.version_range, 1, 512) AS TEXT),
                CAST(substr(p.fixed_version, 1, 128) AS TEXT),
                typeof(a.severity)
            FROM affected_packages AS p
            JOIN advisories AS a ON a.ghsa_id = p.ghsa_id
            WHERE p.ecosystem = ?
            LIMIT ?
            """,
            ("pip", MAX_PIP_ADVISORY_ROWS + 1),
        )

        advisories: list[AdvisoryRecord] = []
        issues: list[AuditIssue] = []
        for index, row in enumerate(rows):
            if index >= MAX_PIP_ADVISORY_ROWS:
                raise VulnerabilityDatabaseError("advisory_limit_exceeded")
            package_name = _bounded(row[9], 256) or ""
            normalized_package_name = canonicalize_name(package_name)
            score, score_issue = _cvss(row[6])
            if score_issue is not None:
                issues.append(
                    AuditIssue(
                        score_issue.code,
                        score_issue.message,
                        normalized_package_name,
                    )
                )
            severity_value = row[5] if row[12] == "text" else None
            severity, severity_issue = _severity(severity_value)
            if severity_issue is not None:
                issues.append(
                    AuditIssue(
                        severity_issue.code,
                        severity_issue.message,
                        normalized_package_name,
                    )
                )
            advisories.append(
                AdvisoryRecord(
                    ghsa_id=_bounded(row[0], 64) or "",
                    cve_id=_bounded(row[1], 64),
                    state=_bounded(row[2], 32) or "unknown",
                    withdrawn_at=_bounded(row[3], 64),
                    summary=_bounded(row[4], MAX_SUMMARY_CHARS) or "",
                    severity=severity,
                    cvss_score=score,
                    source=_bounded(row[7], 64) or "unknown",
                    updated_at=_bounded(row[8], 64),
                    package_name=package_name,
                    normalized_package_name=normalized_package_name,
                    version_range=_bounded(row[10], 512) or "",
                    fixed_version=_bounded(row[11], 128),
                )
            )

        advisories.sort(key=_advisory_sort_key)
        issues.sort(key=lambda item: (item.subject or "", item.code, item.message))
        sources = tuple(sorted({item.source for item in advisories}))
        metadata = DatabaseMetadata(
            path=str(path),
            size_bytes=path.stat().st_size,
            sources=sources,
            last_sync_at=_bounded(sync.get("last_sync_at"), 64),
            last_sync_status=_bounded(sync.get("last_sync_status"), 32),
            last_sync_message=_bounded(
                sync.get("last_sync_message"), MAX_SYNC_MESSAGE_CHARS
            ),
        )
        return VulnerabilitySnapshot(metadata, tuple(advisories), tuple(issues))
    finally:
        try:
            if connection.in_transaction:
                connection.rollback()
        finally:
            connection.close()


def _is_lock_error(error: sqlite3.OperationalError) -> bool:
    code = getattr(error, "sqlite_errorcode", 0)
    return (code & 0xFF) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


def load_vulnerability_snapshot(path: Path) -> VulnerabilitySnapshot:
    """Load a read-only snapshot, retrying SQLite lock failures at most three times."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise VulnerabilityDatabaseError("database_unavailable") from exc
    if not resolved.is_file():
        raise VulnerabilityDatabaseError("database_unavailable")
    if _IS_POSIX:
        _validate_posix_database_access(resolved)

    for attempt in range(MAX_LOCK_ATTEMPTS):
        try:
            return _load_once(resolved)
        except sqlite3.OperationalError as exc:
            locked = _is_lock_error(exc)
            if locked and attempt + 1 < MAX_LOCK_ATTEMPTS:
                continue
            code = "database_locked" if locked else "database_read_failed"
            raise VulnerabilityDatabaseError(code) from exc
        except sqlite3.DatabaseError as exc:
            raise VulnerabilityDatabaseError("database_read_failed") from exc
        except OSError as exc:
            raise VulnerabilityDatabaseError("database_unavailable") from exc

    raise VulnerabilityDatabaseError("database_locked")
