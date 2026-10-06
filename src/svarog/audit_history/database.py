"""Safe SQLite opening, validation, backup, and migration."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from typing import Self

from .errors import HistoryDatabaseError
from .migrations import (
    APPLICATION_ID,
    MIGRATION_1,
    MIGRATION_2,
    MIGRATION_REGISTRY,
    MigrationRegistry,
)


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_COPY_CHUNK_SIZE = 1024 * 1024
_OPEN_LOCKS: dict[str, Lock] = {}
_OPEN_LOCKS_GUARD = Lock()

_EXPECTED_COLUMNS = {
    "schema_migrations": ("version", "name", "checksum", "applied_at"),
    "projects": ("project_id", "display_name", "created_at", "updated_at"),
    "audit_snapshots": (
        "snapshot_id",
        "project_id",
        "audit_kind",
        "created_at",
        "last_used_at",
        "python_version",
        "environment_hash",
        "semantic_lock_hash",
        "knowledge_content_hash",
        "knowledge_metadata_hash",
        "evaluation_context_hash",
        "policy_hash",
        "analysis_contract_version",
        "composite_hash",
        "audit_status",
        "environment_package_count",
        "lock_package_count",
        "affected_finding_count",
        "indeterminate_finding_count",
        "issue_count",
        "warning_count",
        "result_json_zlib",
        "result_json_sha256",
        "result_json_size",
        "schema_version",
    ),
    "audit_runs": (
        "run_id",
        "project_id",
        "audit_kind",
        "snapshot_id",
        "baseline_run_id",
        "started_at",
        "completed_at",
        "run_status",
        "reused",
        "python_version",
        "environment_hash",
        "semantic_lock_hash",
        "knowledge_content_hash",
        "knowledge_metadata_hash",
        "evaluation_context_hash",
        "policy_hash",
        "analysis_contract_version",
        "composite_hash",
        "result_schema_version",
        "knowledge_sources_json",
        "knowledge_last_sync_at",
        "knowledge_sync_status",
        "warning_count",
        "failure_code",
    ),
    "snapshot_packages": (
        "snapshot_id",
        "scope",
        "raw_name",
        "normalized_name",
        "version",
        "version_valid",
        "source_kind",
        "source_identity",
        "component_key",
        "is_direct",
        "applicability_status",
    ),
    "snapshot_dependencies": (
        "snapshot_id",
        "parent_component_key",
        "child_component_key",
        "relationship_source",
        "resolution_status",
    ),
    "snapshot_findings": (
        "snapshot_id",
        "scope",
        "raw_name",
        "normalized_name",
        "audited_version",
        "ghsa_id",
        "cve_id",
        "advisory_id",
        "severity",
        "cvss",
        "affected_range",
        "fixed_versions",
        "finding_status",
        "indeterminate_reason",
        "advisory_fingerprint",
    ),
    "snapshot_issues": ("snapshot_id", "issue_code", "subject", "detail", "ordinal"),
    "run_diffs": (
        "diff_id",
        "project_id",
        "baseline_run_id",
        "target_run_id",
        "diff_contract_version",
        "classification",
        "package_added_count",
        "package_removed_count",
        "package_changed_count",
        "finding_introduced_count",
        "finding_resolved_count",
        "finding_changed_count",
        "issue_added_count",
        "issue_resolved_count",
        "diff_json_zlib",
        "diff_json_size",
        "diff_json_sha256",
        "created_at",
    ),
}


def _canonical_sql(value: str) -> str:
    return " ".join(value.split()).casefold()


_EXPECTED_TABLE_SQL = {
    name: _canonical_sql(statement)
    for name, statement in zip(
        _EXPECTED_COLUMNS,
        MIGRATION_1.statements[: len(_EXPECTED_COLUMNS)],
        strict=True,
    )
}
_INDEX_NAMES = (
    "idx_audit_runs_project_kind_completed",
    "idx_audit_runs_snapshot",
    "idx_audit_snapshots_project_kind_created",
    "idx_audit_snapshots_project_kind_composite",
    "idx_snapshot_packages_lookup",
    "idx_snapshot_findings_snapshot_name_ghsa",
    "idx_snapshot_findings_advisory_name",
    "idx_snapshot_dependencies_parent",
    "idx_run_diffs_project_runs",
    "idx_run_diffs_initial_unique",
)
_TRIGGER_NAMES = (
    "trg_run_diffs_scope_insert",
    "trg_run_diffs_scope_update",
    "trg_audit_runs_scope_update",
)
_INDEX_STATEMENT_OFFSET = len(_EXPECTED_COLUMNS)
_TRIGGER_STATEMENT_OFFSET = _INDEX_STATEMENT_OFFSET + len(_INDEX_NAMES)
_EXPECTED_INDEX_SQL = {
    name: _canonical_sql(statement)
    for name, statement in zip(
        _INDEX_NAMES,
        MIGRATION_1.statements[_INDEX_STATEMENT_OFFSET:_TRIGGER_STATEMENT_OFFSET],
        strict=True,
    )
}
_EXPECTED_TRIGGER_SQL = {
    name: _canonical_sql(statement)
    for name, statement in zip(
        _TRIGGER_NAMES,
        MIGRATION_1.statements[_TRIGGER_STATEMENT_OFFSET:],
        strict=True,
    )
}


@dataclass(frozen=True, slots=True)
class _SchemaManifest:
    table_columns: Mapping[str, tuple[str, ...]]
    table_sql: Mapping[str, str]
    index_sql: Mapping[str, str]
    views: frozenset[str]
    triggers: frozenset[str]
    trigger_sql: Mapping[str, str]
    allow_extra_indexes: bool = True


_SCHEMA_MANIFESTS: Mapping[int, _SchemaManifest] = {
    0: _SchemaManifest(
        table_columns={},
        table_sql={},
        index_sql={},
        views=frozenset(),
        triggers=frozenset(),
        trigger_sql={},
        allow_extra_indexes=False,
    ),
    1: _SchemaManifest(
        table_columns=_EXPECTED_COLUMNS,
        table_sql=_EXPECTED_TABLE_SQL,
        index_sql=_EXPECTED_INDEX_SQL,
        views=frozenset(),
        triggers=frozenset(_EXPECTED_TRIGGER_SQL),
        trigger_sql=_EXPECTED_TRIGGER_SQL,
    ),
    2: _SchemaManifest(
        table_columns=_EXPECTED_COLUMNS,
        table_sql=_EXPECTED_TABLE_SQL,
        index_sql={
            **_EXPECTED_INDEX_SQL,
            "idx_snapshot_findings_cve_name": _canonical_sql(MIGRATION_2.statements[0]),
            "idx_audit_runs_project_expiry": _canonical_sql(MIGRATION_2.statements[1]),
        },
        views=frozenset(),
        triggers=frozenset(_EXPECTED_TRIGGER_SQL),
        trigger_sql=_EXPECTED_TRIGGER_SQL,
    ),
}


@contextmanager
def immediate_transaction(
    connection: sqlite3.Connection,
) -> Iterator[sqlite3.Connection]:
    """Commit an immediate transaction, rolling back every exceptional exit."""

    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
        connection.commit()
    except BaseException:
        try:
            connection.rollback()
        except BaseException:
            pass
        raise


def _unsafe(message: str | None = None) -> HistoryDatabaseError:
    del message
    return HistoryDatabaseError("history_database_unsafe")


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _checked_path(value: str | os.PathLike[str]) -> tuple[Path, os.stat_result]:
    try:
        path = Path(value).expanduser()
        if path.name in {"", ".", ".."}:
            raise _unsafe()
        path = Path(os.path.abspath(path))
        for parent in reversed(path.parents):
            metadata = parent.lstat()
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise _unsafe()
            if not stat.S_ISDIR(metadata.st_mode):
                raise _unsafe()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError:
                metadata = path.lstat()
            else:
                try:
                    metadata = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_nlink != 1
        ):
            raise _unsafe()
        return path, metadata
    except HistoryDatabaseError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise _unsafe() from error


def _verify_path(path: Path, expected: os.stat_result) -> None:
    try:
        current = path.lstat()
    except OSError as error:
        raise _unsafe() from error
    if (
        not _same_file(current, expected)
        or not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or _is_reparse(current)
        or current.st_nlink != 1
    ):
        raise _unsafe()


def _bind_sidecars(path: Path) -> dict[str, tuple[Path, os.stat_result]]:
    present: dict[str, tuple[Path, os.stat_result]] = {}
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        try:
            metadata = sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise _unsafe() from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_nlink != 1
        ):
            raise _unsafe()
        present[suffix] = (sidecar, metadata)
    if "-journal" in present and ({"-wal", "-shm"} & present.keys()):
        raise _unsafe()
    if ("-wal" in present) != ("-shm" in present):
        raise _unsafe()
    return present


def _verify_database_files(
    path: Path,
    expected_main: os.stat_result,
    expected_sidecars: Mapping[str, tuple[Path, os.stat_result]],
) -> None:
    _verify_path(path, expected_main)
    current_main = path.lstat()
    if _file_signature(current_main) != _file_signature(expected_main):
        raise _unsafe()
    current_sidecars = _bind_sidecars(path)
    if current_sidecars.keys() != expected_sidecars.keys():
        raise _unsafe()
    for suffix, (_, expected) in expected_sidecars.items():
        _, current = current_sidecars[suffix]
        if not _same_file(current, expected) or _file_signature(
            current
        ) != _file_signature(expected):
            raise _unsafe()


def _file_signature(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_size, metadata.st_mtime_ns


def _copy_bound_file(
    source: Path,
    destination: Path,
    expected: os.stat_result,
) -> None:
    binary = getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    destination_created = False
    try:
        source_descriptor = os.open(source, os.O_RDONLY | binary | nofollow)
        opened = os.fstat(source_descriptor)
        if not _same_file(opened, expected) or _file_signature(opened) != _file_signature(
            expected
        ):
            raise _unsafe()

        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary | nofollow,
            0o600,
        )
        destination_created = True
        destination_opened = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(destination_opened.st_mode)
            or _is_reparse(destination_opened)
            or destination_opened.st_nlink != 1
        ):
            raise _unsafe()

        copied = 0
        with (
            os.fdopen(source_descriptor, "rb", closefd=False) as source_file,
            os.fdopen(destination_descriptor, "wb", closefd=False) as destination_file,
        ):
            while True:
                chunk = source_file.read(_COPY_CHUNK_SIZE)
                if not chunk:
                    break
                if destination_file.write(chunk) != len(chunk):
                    raise OSError("short snapshot write")
                copied += len(chunk)
            destination_file.flush()

        source_after = os.fstat(source_descriptor)
        source_path_after = source.lstat()
        if (
            not _same_file(source_after, expected)
            or _file_signature(source_after) != _file_signature(expected)
            or not _same_file(source_path_after, source_after)
            or _file_signature(source_path_after) != _file_signature(source_after)
        ):
            raise _unsafe()

        destination_after = os.fstat(destination_descriptor)
        destination_path_after = destination.lstat()
        if (
            not _same_file(destination_after, destination_opened)
            or not _same_file(destination_path_after, destination_after)
            or _file_signature(destination_path_after)
            != _file_signature(destination_after)
            or copied != expected.st_size
            or destination_after.st_size != copied
        ):
            raise _unsafe()
    except BaseException:
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
            source_descriptor = None
        if destination_descriptor is not None:
            try:
                os.close(destination_descriptor)
            except OSError:
                pass
            destination_descriptor = None
        if destination_created:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _inspect_snapshot(
    path: Path,
    main_metadata: os.stat_result,
    sidecars: Mapping[str, tuple[Path, os.stat_result]],
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> tuple[int, bool]:
    with TemporaryDirectory(prefix="svarog-history-inspect-") as temporary:
        snapshot_path = Path(temporary) / path.name
        _verify_database_files(path, main_metadata, sidecars)
        _copy_bound_file(path, snapshot_path, main_metadata)
        for suffix, (sidecar, metadata) in sidecars.items():
            _copy_bound_file(sidecar, Path(f"{snapshot_path}{suffix}"), metadata)
        _verify_database_files(path, main_metadata, sidecars)
        connection = sqlite3.connect(snapshot_path, isolation_level=None)
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            return _inspect_database(connection, registry, manifests)
        finally:
            connection.close()


@contextmanager
def _serialized_open(path: Path) -> Iterator[None]:
    key = os.path.normcase(str(path))
    with _OPEN_LOCKS_GUARD:
        lock = _OPEN_LOCKS.setdefault(key, Lock())
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def _readonly_connection(path: Path, *, immutable: bool) -> sqlite3.Connection:
    query = "mode=ro&immutable=1" if immutable else "mode=ro"
    return sqlite3.connect(
        f"{path.as_uri()}?{query}",
        uri=True,
        timeout=5.0,
        isolation_level=None,
    )


def _user_objects(connection: sqlite3.Connection, object_type: str) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = ? AND name NOT LIKE 'sqlite_%'",
        (object_type,),
    ).fetchall()
    return {str(row[0]) for row in rows}


def _has_user_schema_objects(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'view', 'trigger') "
        "LIMIT 1"
    ).fetchone()
    return row is not None


def _validate_schema(
    connection: sqlite3.Connection,
    version: int,
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> None:
    if version < 0 or version > registry.current_version:
        raise HistoryDatabaseError("history_database_corrupt")

    manifest = manifests.get(version)
    if manifest is None:
        raise HistoryDatabaseError("history_database_corrupt")

    tables = _user_objects(connection, "table")
    if tables != set(manifest.table_columns):
        raise HistoryDatabaseError("history_database_corrupt")
    if _user_objects(connection, "view") != manifest.views:
        raise HistoryDatabaseError("history_database_corrupt")
    if _user_objects(connection, "trigger") != manifest.triggers:
        raise HistoryDatabaseError("history_database_corrupt")
    for trigger, expected_sql in manifest.trigger_sql.items():
        stored_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = ? AND name = ?",
            ("trigger", trigger),
        ).fetchone()
        if (
            stored_sql is None
            or not isinstance(stored_sql[0], str)
            or _canonical_sql(stored_sql[0]) != expected_sql
        ):
            raise HistoryDatabaseError("history_database_corrupt")
    for table, expected_columns in manifest.table_columns.items():
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if tuple(str(row[1]) for row in rows) != expected_columns:
            raise HistoryDatabaseError("history_database_corrupt")
        stored_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = ? AND name = ?",
            ("table", table),
        ).fetchone()
        if (
            stored_sql is None
            or not isinstance(stored_sql[0], str)
            or _canonical_sql(stored_sql[0]) != manifest.table_sql[table]
        ):
            raise HistoryDatabaseError("history_database_corrupt")
    indexes = _user_objects(connection, "index")
    expected_indexes = set(manifest.index_sql)
    if not expected_indexes <= indexes:
        raise HistoryDatabaseError("history_database_corrupt")
    if not manifest.allow_extra_indexes and indexes != expected_indexes:
        raise HistoryDatabaseError("history_database_corrupt")
    for index, expected_sql in manifest.index_sql.items():
        stored_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = ? AND name = ?",
            ("index", index),
        ).fetchone()
        if (
            stored_sql is None
            or not isinstance(stored_sql[0], str)
            or _canonical_sql(stored_sql[0]) != expected_sql
        ):
            raise HistoryDatabaseError("history_database_corrupt")

    if version == 0:
        return

    rows = connection.execute(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    expected_ledger = [
        (number, registry.version(number).name, registry.version(number).checksum)
        for number in range(1, version + 1)
    ]
    if rows != expected_ledger:
        raise HistoryDatabaseError("history_database_corrupt")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise HistoryDatabaseError("history_database_corrupt")


def _inspect_database(
    connection: sqlite3.Connection,
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> tuple[int, bool]:
    try:
        if connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise HistoryDatabaseError("history_database_corrupt")
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        has_schema = _has_user_schema_objects(connection)
        if application_id == 0 and version == 0 and not has_schema:
            return 0, True
        if application_id != APPLICATION_ID:
            raise HistoryDatabaseError("history_database_unrelated")
        if version > registry.current_version:
            raise HistoryDatabaseError("history_schema_too_new")
        _validate_schema(connection, version, registry, manifests)
        return version, False
    except HistoryDatabaseError:
        raise
    except sqlite3.DatabaseError as error:
        raise HistoryDatabaseError("history_database_corrupt") from error


def _inspect_readonly(
    path: Path,
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> tuple[int, bool]:
    connection = _readonly_connection(path, immutable=True)
    try:
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN")
        return _inspect_database(connection, registry, manifests)
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def _inspect_preflight(
    path: Path,
    main_metadata: os.stat_result,
    sidecars: Mapping[str, tuple[Path, os.stat_result]],
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> tuple[int, bool]:
    if "-journal" in sidecars:
        result = _inspect_readonly(path, registry, manifests)
        del result
        raise _unsafe()
    if "-wal" in sidecars:
        return _inspect_snapshot(
            path,
            main_metadata,
            sidecars,
            registry,
            manifests,
        )
    return _inspect_readonly(path, registry, manifests)


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA trusted_schema = OFF")


def _require_pending_manifests(
    version: int,
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> None:
    if any(
        pending not in manifests
        for pending in range(version + 1, registry.current_version + 1)
    ):
        raise HistoryDatabaseError("history_database_corrupt")


def _configure_journal(connection: sqlite3.Connection) -> None:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            mode = str(
                connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
            break
        except sqlite3.OperationalError as error:
            if "locked" not in str(error).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
    if mode != "wal":
        raise sqlite3.DatabaseError("journal mode")
    connection.execute("PRAGMA synchronous = FULL")


def _safe_backup_directory(path: Path) -> Path:
    directory = path.parent / "backups"
    try:
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            raise _unsafe()
        return directory
    except HistoryDatabaseError:
        raise
    except OSError as error:
        raise _unsafe() from error


def _create_backup(
    source: sqlite3.Connection,
    path: Path,
    version: int,
    registry: MigrationRegistry,
    manifests: Mapping[int, _SchemaManifest],
) -> Path:
    directory = _safe_backup_directory(path)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / (
        f"{path.stem}.v{version}.{timestamp}.{uuid.uuid4().hex}.sqlite3"
    )
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    source_connection: sqlite3.Connection | None = None
    destination_connection: sqlite3.Connection | None = None
    try:
        if not source.in_transaction:
            raise sqlite3.DatabaseError("migration lock missing")
        descriptor = os.open(destination, flags, 0o600)
        os.close(descriptor)
        descriptor = None
        source_connection = _readonly_connection(path, immutable=False)
        destination_connection = sqlite3.connect(destination, isolation_level=None)
        source_connection.backup(destination_connection)
        if destination_connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise sqlite3.DatabaseError("backup integrity")
        if int(destination_connection.execute("PRAGMA application_id").fetchone()[0]) != APPLICATION_ID:
            raise sqlite3.DatabaseError("backup identity")
        if int(destination_connection.execute("PRAGMA user_version").fetchone()[0]) != version:
            raise sqlite3.DatabaseError("backup version")
        _validate_schema(destination_connection, version, registry, manifests)
        return destination
    except (OSError, sqlite3.DatabaseError, HistoryDatabaseError) as error:
        if destination_connection is not None:
            destination_connection.close()
            destination_connection = None
        if source_connection is not None:
            source_connection.close()
            source_connection = None
        if descriptor is not None:
            os.close(descriptor)
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise HistoryDatabaseError("history_migration_failed") from error
    finally:
        if source_connection is not None:
            source_connection.close()
        if destination_connection is not None:
            destination_connection.close()


def _apply_migrations(
    connection: sqlite3.Connection,
    registry: MigrationRegistry,
) -> int:
    try:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        if current >= registry.current_version:
            if application_id != APPLICATION_ID:
                raise sqlite3.DatabaseError("identity changed")
            return current
        if application_id not in (0, APPLICATION_ID):
            raise sqlite3.DatabaseError("identity changed")
        migration = registry.version(current + 1)
        for statement in migration.statements:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations "
            "(version, name, checksum, applied_at) "
            "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            (migration.version, migration.name, migration.checksum),
        )
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {migration.version}")
        return migration.version
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise HistoryDatabaseError("history_migration_failed") from error


class DatabaseManager:
    """Own one configured and validated audit-history connection."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_path: Path,
        schema_version: int,
    ) -> None:
        self.connection = connection
        self._database_path = database_path
        self.schema_version = schema_version
        self._closed = False

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        _migration_registry: MigrationRegistry | None = None,
        _schema_manifests: Mapping[int, _SchemaManifest] | None = None,
    ) -> Self:
        """Safely open, validate, configure, and if needed migrate a database."""

        registry = _migration_registry or MIGRATION_REGISTRY
        manifests = _SCHEMA_MANIFESTS if _schema_manifests is None else _schema_manifests
        connection: sqlite3.Connection | None = None
        try:
            database_path, metadata = _checked_path(path)
            with _serialized_open(database_path):
                _verify_path(database_path, metadata)
                metadata = database_path.lstat()
                sidecars = _bind_sidecars(database_path)
                version, _ = _inspect_preflight(
                    database_path,
                    metadata,
                    sidecars,
                    registry,
                    manifests,
                )
                _require_pending_manifests(version, registry, manifests)
                _verify_database_files(database_path, metadata, sidecars)
                connection = sqlite3.connect(
                    database_path,
                    timeout=5.0,
                    isolation_level=None,
                )
                _verify_database_files(database_path, metadata, sidecars)
                _configure_connection(connection)
                _verify_database_files(database_path, metadata, sidecars)
                with immediate_transaction(connection):
                    version, _ = _inspect_database(connection, registry, manifests)
                    _require_pending_manifests(version, registry, manifests)
                    _verify_path(database_path, metadata)

                _verify_path(database_path, metadata)
                _configure_journal(connection)
                _verify_path(database_path, metadata)

                backup_created = False
                while True:
                    complete = False
                    with immediate_transaction(connection):
                        version, fresh = _inspect_database(
                            connection,
                            registry,
                            manifests,
                        )
                        _require_pending_manifests(version, registry, manifests)
                        if version >= registry.current_version:
                            _validate_schema(connection, version, registry, manifests)
                            complete = True
                        else:
                            if not backup_created and not fresh:
                                _create_backup(
                                    connection,
                                    database_path,
                                    version,
                                    registry,
                                    manifests,
                                )
                            backup_created = True
                            version = _apply_migrations(connection, registry)
                            _validate_schema(connection, version, registry, manifests)
                        _verify_path(database_path, metadata)
                    if complete:
                        break

                _verify_path(database_path, metadata)
                return cls(
                    connection,
                    database_path=database_path,
                    schema_version=version,
                )
        except HistoryDatabaseError as error:
            if connection is not None:
                connection.close()
            raise HistoryDatabaseError(error.code) from None
        except sqlite3.DatabaseError:
            if connection is not None:
                connection.close()
            raise HistoryDatabaseError("history_database_corrupt") from None
        except (OSError, RuntimeError):
            if connection is not None:
                connection.close()
            raise HistoryDatabaseError("history_database_unsafe") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with _serialized_open(self._database_path):
            self.connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
