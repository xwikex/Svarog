from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event, Lock

import pytest

import svarog.audit_history.database as database_module
from svarog.audit_history.database import (
    DatabaseManager,
    _canonical_sql,
    _SchemaManifest,
    _SCHEMA_MANIFESTS,
    immediate_transaction,
)
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.migrations import (
    APPLICATION_ID,
    CURRENT_SCHEMA_VERSION,
    MIGRATION_1,
    MIGRATION_2,
    Migration,
    MigrationRegistry,
)


EXPECTED_TABLES = {
    "schema_migrations",
    "projects",
    "audit_snapshots",
    "audit_runs",
    "snapshot_packages",
    "snapshot_dependencies",
    "snapshot_findings",
    "snapshot_issues",
    "run_diffs",
}

EXPECTED_INDEXES = {
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
    "idx_snapshot_findings_cve_name",
    "idx_audit_runs_project_expiry",
}


def _object_names(connection: sqlite3.Connection, object_type: str) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = ? AND name NOT LIKE 'sqlite_%'",
        (object_type,),
    ).fetchall()
    return {str(row[0]) for row in rows}


def _create_sqlite(path: Path, *, application_id: int, user_version: int) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA application_id = {application_id}")
        connection.execute(f"PRAGMA user_version = {user_version}")
        connection.commit()
    finally:
        connection.close()


def _create_v1_database(path: Path) -> None:
    with DatabaseManager.open(
        path,
        _migration_registry=MigrationRegistry((MIGRATION_1,)),
        _schema_manifests={0: _SCHEMA_MANIFESTS[0], 1: _SCHEMA_MANIFESTS[1]},
    ) as database:
        assert database.schema_version == 1


def _manifests_with_added_table(
    table: str,
    create_sql: str,
) -> dict[int, _SchemaManifest]:
    v1 = _SCHEMA_MANIFESTS[1]
    v2 = _SchemaManifest(
        table_columns={**v1.table_columns, table: ("value",)},
        table_sql={**v1.table_sql, table: _canonical_sql(create_sql)},
        index_sql=v1.index_sql,
        views=v1.views,
        triggers=v1.triggers,
        trigger_sql=v1.trigger_sql,
    )
    return {1: v1, 2: v2}


def _manifest_with_added_table(
    base: _SchemaManifest,
    table: str,
    create_sql: str,
) -> _SchemaManifest:
    return _SchemaManifest(
        table_columns={**base.table_columns, table: ("value",)},
        table_sql={**base.table_sql, table: _canonical_sql(create_sql)},
        index_sql=base.index_sql,
        views=base.views,
        triggers=base.triggers,
        trigger_sql=base.trigger_sql,
    )


def _file_hashes(paths: tuple[Path, ...]) -> dict[Path, str]:
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def _insert_project(
    connection: sqlite3.Connection,
    project_id: str = "project",
) -> None:
    connection.execute(
        "INSERT INTO projects (project_id, display_name, created_at, updated_at) "
        "VALUES (?, ?, ?, ?)",
        (project_id, "Project", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )


def _insert_snapshot(
    connection: sqlite3.Connection,
    *,
    project_id: str = "project",
    audit_kind: str = "python_project",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO audit_snapshots (
            project_id, audit_kind, created_at, last_used_at, python_version,
            environment_hash, semantic_lock_hash, knowledge_content_hash,
            knowledge_metadata_hash, evaluation_context_hash, policy_hash,
            analysis_contract_version, composite_hash, audit_status,
            environment_package_count, lock_package_count,
            affected_finding_count, indeterminate_finding_count,
            issue_count, warning_count, result_json_zlib,
            result_json_sha256, result_json_size, schema_version
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            project_id,
            audit_kind,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "3.11.9",
            "e" * 64,
            None,
            "k" * 64,
            "m" * 64,
            "c" * 64,
            "p" * 64,
            "1",
            "x" * 64,
            "completed_clean",
            1,
            0,
            0,
            0,
            0,
            0,
            b"payload",
            "d" * 64,
            7,
            "1",
        ),
    )
    return int(cursor.lastrowid)


def _insert_run(
    connection: sqlite3.Connection,
    run_id: str,
    snapshot_id: int | None,
    *,
    project_id: str = "project",
    audit_kind: str = "python_project",
    baseline_run_id: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_runs (
            run_id, project_id, audit_kind, snapshot_id, baseline_run_id,
            started_at, completed_at, run_status, reused, python_version,
            environment_hash, semantic_lock_hash, knowledge_content_hash,
            knowledge_metadata_hash, evaluation_context_hash, policy_hash,
            analysis_contract_version, composite_hash, result_schema_version,
            knowledge_sources_json, knowledge_last_sync_at,
            knowledge_sync_status, warning_count, failure_code
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            run_id,
            project_id,
            audit_kind,
            snapshot_id,
            baseline_run_id,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            "completed_computed",
            0,
            "3.11.9",
            "e" * 64,
            None,
            "k" * 64,
            "m" * 64,
            "c" * 64,
            "p" * 64,
            "1",
            "x" * 64,
            "1",
            "[]",
            None,
            "healthy",
            0,
            None,
        ),
    )


def _insert_diff(
    connection: sqlite3.Connection,
    diff_id: str,
    *,
    project_id: str,
    baseline_run_id: str | None,
    target_run_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO run_diffs (
            diff_id, project_id, baseline_run_id, target_run_id,
            diff_contract_version, classification, package_added_count,
            package_removed_count, package_changed_count,
            finding_introduced_count, finding_resolved_count,
            finding_changed_count, issue_added_count, issue_resolved_count,
            diff_json_zlib, diff_json_size, diff_json_sha256, created_at
        ) VALUES (?, ?, ?, ?, '1', 'changed', 0, 0, 0, 0, 0, 0, 0, 0,
                  ?, 2, ?, '2026-01-01T00:00:02Z')
        """,
        (
            diff_id,
            project_id,
            baseline_run_id,
            target_run_id,
            b"{}",
            "d" * 64,
        ),
    )


def test_database_create_close_reopen_and_validate(tmp_path: Path) -> None:
    path = tmp_path / "audit-history.sqlite3"

    with DatabaseManager.open(path) as first:
        assert first.schema_version == 2

    with DatabaseManager.open(path) as second:
        assert second.schema_version == 2
        assert second.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert second.connection.execute("PRAGMA foreign_key_check").fetchall() == []

    assert path.is_file()


def test_schema_has_exact_tables_required_indexes_and_valid_ledger(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    with DatabaseManager.open(path) as database:
        connection = database.connection
        assert _object_names(connection, "table") == EXPECTED_TABLES
        assert EXPECTED_INDEXES <= _object_names(connection, "index")
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall() == [
            (1, MIGRATION_1.name, MIGRATION_1.checksum),
            (2, MIGRATION_2.name, MIGRATION_2.checksum),
        ]


def test_v1_database_migrates_to_v2_without_changing_rows(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    _create_v1_database(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_project(connection)
        snapshot_id = _insert_snapshot(connection)
        _insert_run(connection, "old-run", snapshot_id)
        connection.execute(
            "INSERT INTO snapshot_findings (snapshot_id, scope, raw_name, "
            "normalized_name, audited_version, cve_id, advisory_id, "
            "finding_status, advisory_fingerprint) "
            "VALUES (?, 'environment', 'Example', 'example', '1.0', "
            "'CVE-2026-0001', 'advisory', 'affected', 'fingerprint')",
            (snapshot_id,),
        )
        connection.commit()
    finally:
        connection.close()

    with DatabaseManager.open(path) as database:
        assert database.schema_version == 2
        assert EXPECTED_INDEXES <= _object_names(database.connection, "index")
        assert database.connection.execute(
            "SELECT run_id FROM audit_runs"
        ).fetchall() == [("old-run",)]
        assert database.connection.execute(
            "SELECT cve_id, normalized_name FROM snapshot_findings"
        ).fetchall() == [("CVE-2026-0001", "example")]
    with DatabaseManager.open(path) as reopened:
        assert reopened.schema_version == 2
        assert reopened.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    backups = list((tmp_path / "backups").glob("*.sqlite3"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
        assert backup.execute("SELECT run_id FROM audit_runs").fetchall() == [("old-run",)]


def test_v2_query_plans_use_new_indexes(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        cve_plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT snapshot_id FROM snapshot_findings "
            "WHERE cve_id = ? AND normalized_name = ?",
            ("CVE-2026-0001", "example"),
        ).fetchall()
        retention_plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT run_id, started_at, completed_at, "
            "run_status FROM audit_runs WHERE project_id = ? "
            "AND COALESCE(completed_at, started_at) < ? "
            "ORDER BY COALESCE(completed_at, started_at), run_id LIMIT ?",
            ("project", "2026-02-01T00:00:00Z", 400),
        ).fetchall()
        assert any("idx_snapshot_findings_cve_name" in row[3] for row in cve_plan)
        assert any("idx_audit_runs_project_expiry" in row[3] for row in retention_plan)


@pytest.mark.parametrize(
    "index_name",
    ("idx_snapshot_findings_cve_name", "idx_audit_runs_project_expiry"),
)
def test_v2_missing_required_index_is_rejected(tmp_path: Path, index_name: str) -> None:
    path = tmp_path / "history.sqlite3"
    with DatabaseManager.open(path):
        pass
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"DROP INDEX {index_name}")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        DatabaseManager.open(path)


def test_required_foreign_keys_and_delete_actions_exist(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        expected = {
            "audit_snapshots": {("projects", "project_id", "project_id", "RESTRICT")},
            "audit_runs": {
                ("projects", "project_id", "project_id", "RESTRICT"),
                ("audit_snapshots", "snapshot_id", "snapshot_id", "RESTRICT"),
                ("audit_runs", "baseline_run_id", "run_id", "RESTRICT"),
            },
            "snapshot_packages": {
                ("audit_snapshots", "snapshot_id", "snapshot_id", "CASCADE")
            },
            "snapshot_dependencies": {
                ("audit_snapshots", "snapshot_id", "snapshot_id", "CASCADE")
            },
            "snapshot_findings": {
                ("audit_snapshots", "snapshot_id", "snapshot_id", "CASCADE")
            },
            "snapshot_issues": {
                ("audit_snapshots", "snapshot_id", "snapshot_id", "CASCADE")
            },
            "run_diffs": {
                ("projects", "project_id", "project_id", "RESTRICT"),
                ("audit_runs", "baseline_run_id", "run_id", "RESTRICT"),
                ("audit_runs", "target_run_id", "run_id", "RESTRICT"),
            },
        }
        for table, required in expected.items():
            rows = connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            actual = {(row[2], row[3], row[4], row[6]) for row in rows}
            assert required <= actual


def test_cross_project_and_audit_kind_links_are_rejected(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        _insert_project(connection, "alpha")
        _insert_project(connection, "beta")
        alpha_python = _insert_snapshot(
            connection,
            project_id="alpha",
            audit_kind="python_project",
        )
        alpha_other = _insert_snapshot(
            connection,
            project_id="alpha",
            audit_kind="other_audit",
        )
        beta_python = _insert_snapshot(
            connection,
            project_id="beta",
            audit_kind="python_project",
        )

        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(
                connection,
                "bad-snapshot-project",
                alpha_python,
                project_id="beta",
            )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(
                connection,
                "bad-snapshot-kind",
                alpha_python,
                project_id="alpha",
                audit_kind="other_audit",
            )

        _insert_run(
            connection,
            "alpha-python",
            alpha_python,
            project_id="alpha",
        )
        _insert_run(
            connection,
            "alpha-other",
            alpha_other,
            project_id="alpha",
            audit_kind="other_audit",
        )
        _insert_run(
            connection,
            "beta-python",
            beta_python,
            project_id="beta",
        )

        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(
                connection,
                "bad-baseline-project",
                beta_python,
                project_id="beta",
                baseline_run_id="alpha-python",
            )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_run(
                connection,
                "bad-baseline-kind",
                alpha_other,
                project_id="alpha",
                audit_kind="other_audit",
                baseline_run_id="alpha-python",
            )

        with pytest.raises(sqlite3.IntegrityError):
            _insert_diff(
                connection,
                "bad-diff-target-project",
                project_id="alpha",
                baseline_run_id=None,
                target_run_id="beta-python",
            )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_diff(
                connection,
                "bad-diff-baseline-project",
                project_id="beta",
                baseline_run_id="alpha-python",
                target_run_id="beta-python",
            )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_diff(
                connection,
                "bad-diff-kind",
                project_id="alpha",
                baseline_run_id="alpha-python",
                target_run_id="alpha-other",
            )

        _insert_run(
            connection,
            "unscoped-baseline",
            None,
            project_id="alpha",
        )
        _insert_run(
            connection,
            "unscoped-project-target",
            None,
            project_id="alpha",
        )
        _insert_run(
            connection,
            "unscoped-kind-target",
            None,
            project_id="alpha",
        )
        _insert_diff(
            connection,
            "valid-project-diff",
            project_id="alpha",
            baseline_run_id=None,
            target_run_id="unscoped-project-target",
        )
        _insert_diff(
            connection,
            "valid-kind-diff",
            project_id="alpha",
            baseline_run_id="unscoped-baseline",
            target_run_id="unscoped-kind-target",
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE audit_runs SET project_id = 'beta' "
                "WHERE run_id = 'unscoped-project-target'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE audit_runs SET audit_kind = 'other_audit' "
                "WHERE run_id = 'unscoped-kind-target'"
            )


def test_schema_checks_reject_invalid_values_and_enforces_foreign_keys(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        _insert_project(connection)
        snapshot_id = _insert_snapshot(connection)
        _insert_run(connection, "run-1", snapshot_id)

        statements = [
            (
                "UPDATE audit_snapshots SET warning_count = -1 WHERE snapshot_id = ?",
                (snapshot_id,),
            ),
            (
                "UPDATE audit_runs SET run_status = 'unknown' WHERE run_id = ?",
                ("run-1",),
            ),
            ("UPDATE audit_runs SET reused = 2 WHERE run_id = ?", ("run-1",)),
            (
                "INSERT INTO snapshot_packages (snapshot_id, scope, raw_name, "
                "normalized_name, version, version_valid, source_kind, source_identity, "
                "component_key, is_direct, applicability_status) "
                "VALUES (?, 'other', 'Demo', 'demo', '1', 1, 'registry', NULL, 'key', NULL, 'known')",
                (snapshot_id,),
            ),
            (
                "INSERT INTO snapshot_packages (snapshot_id, scope, raw_name, "
                "normalized_name, version, version_valid, source_kind, source_identity, "
                "component_key, is_direct, applicability_status) "
                "VALUES (?, 'lock', 'Demo', 'demo', '1', 3, 'registry', NULL, 'key', NULL, 'known')",
                (snapshot_id,),
            ),
            (
                "INSERT INTO snapshot_findings (snapshot_id, scope, raw_name, normalized_name, "
                "audited_version, ghsa_id, cve_id, advisory_id, severity, cvss, affected_range, "
                "fixed_versions, finding_status, indeterminate_reason, advisory_fingerprint) "
                "VALUES (?, 'environment', 'Demo', 'demo', '1', NULL, NULL, 'ADV', NULL, NULL, "
                "NULL, NULL, 'unknown', NULL, 'fingerprint')",
                (snapshot_id,),
            ),
            (
                "INSERT INTO snapshot_issues (snapshot_id, issue_code, subject, detail, ordinal) "
                "VALUES (?, 'issue', NULL, NULL, -1)",
                (snapshot_id,),
            ),
            (
                "INSERT INTO audit_runs (run_id, project_id, audit_kind, started_at, run_status, "
                "reused, warning_count) VALUES ('missing-project-run', 'missing', 'kind', 'now', "
                "'started', 0, 0)",
                (),
            ),
        ]
        for sql, parameters in statements:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(sql, parameters)


def test_run_diff_null_baseline_is_logically_unique(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        _insert_project(connection)
        snapshot_id = _insert_snapshot(connection)
        _insert_run(connection, "target", snapshot_id)
        values = (
            "project",
            None,
            "target",
            "1",
            "initial",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            b"{}",
            2,
            "d" * 64,
            "2026-01-01T00:00:02Z",
        )
        sql = """
            INSERT INTO run_diffs (
                diff_id, project_id, baseline_run_id, target_run_id,
                diff_contract_version, classification, package_added_count,
                package_removed_count, package_changed_count,
                finding_introduced_count, finding_resolved_count,
                finding_changed_count, issue_added_count, issue_resolved_count,
                diff_json_zlib, diff_json_size, diff_json_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        connection.execute(sql, ("diff-1", *values))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(sql, ("diff-2", *values))


def test_connection_security_pragmas_are_effective(tmp_path: Path) -> None:
    with DatabaseManager.open(tmp_path / "history.sqlite3") as database:
        connection = database.connection
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert connection.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_close_is_idempotent(tmp_path: Path) -> None:
    database = DatabaseManager.open(tmp_path / "history.sqlite3")
    database.close()
    database.close()
    with pytest.raises(sqlite3.ProgrammingError):
        database.connection.execute("SELECT 1")


class DeliberateBaseException(BaseException):
    pass


def test_immediate_transaction_commits_and_rolls_back_base_exception() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("CREATE TABLE values_table (value INTEGER NOT NULL)")
    with immediate_transaction(connection):
        connection.execute("INSERT INTO values_table (value) VALUES (?)", (1,))
    assert connection.execute("SELECT value FROM values_table").fetchall() == [(1,)]

    with pytest.raises(DeliberateBaseException):
        with immediate_transaction(connection):
            connection.execute("INSERT INTO values_table (value) VALUES (?)", (2,))
            raise DeliberateBaseException
    assert connection.execute("SELECT value FROM values_table").fetchall() == [(1,)]


def test_immediate_transaction_rolls_back_commit_failure_and_is_reusable() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("CREATE TABLE parents (parent_id INTEGER PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE children ("
        "parent_id INTEGER NOT NULL, "
        "FOREIGN KEY (parent_id) REFERENCES parents(parent_id) "
        "DEFERRABLE INITIALLY DEFERRED)"
    )

    with pytest.raises(sqlite3.IntegrityError):
        with immediate_transaction(connection):
            connection.execute("INSERT INTO children (parent_id) VALUES (1)")

    assert connection.in_transaction is False
    with immediate_transaction(connection):
        connection.execute("INSERT INTO parents (parent_id) VALUES (1)")
        connection.execute("INSERT INTO children (parent_id) VALUES (1)")
    assert connection.execute("SELECT parent_id FROM children").fetchall() == [(1,)]


@pytest.mark.parametrize("payload", [b"not sqlite", b"SQLite format 3\x00broken"])
def test_corrupt_database_is_rejected_without_replacement(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "private-location.sqlite3"
    path.write_bytes(payload)
    before = path.read_bytes()

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(path)

    assert caught.value.code == "history_database_corrupt"
    assert str(caught.value) == "history_database_corrupt"
    assert "private-location" not in str(caught.value)
    assert path.read_bytes() == before


def test_public_error_traceback_suppresses_sqlite_details_and_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "private-trace.sqlite3"
    with DatabaseManager.open(path):
        pass
    raw_detail = f"raw sqlite failure at {path}"

    def fail_journal_configuration(_connection: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError(raw_detail)

    monkeypatch.setattr(
        database_module,
        "_configure_journal",
        fail_journal_configuration,
    )

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(path)

    formatted = "".join(traceback.format_exception(caught.value))
    assert caught.value.code == "history_database_corrupt"
    assert raw_detail not in formatted
    assert str(path) not in formatted


@pytest.mark.parametrize("application_id", [0, 12345])
def test_unrelated_sqlite_database_is_rejected_and_unchanged(
    tmp_path: Path, application_id: int
) -> None:
    path = tmp_path / "unrelated.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE unrelated (value TEXT)")
    connection.execute(f"PRAGMA application_id = {application_id}")
    connection.commit()
    connection.close()
    before = path.read_bytes()

    with pytest.raises(HistoryDatabaseError, match="^history_database_unrelated$"):
        DatabaseManager.open(path)

    assert path.read_bytes() == before
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"
    finally:
        connection.close()


def test_unrelated_database_hot_journal_is_rejected_without_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private-unrelated.sqlite3"
    crash_script = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA journal_mode = DELETE")
connection.execute("PRAGMA synchronous = FULL")
connection.execute("PRAGMA cache_size = 4")
connection.execute("CREATE TABLE unrelated (value BLOB NOT NULL)")
connection.executemany(
    "INSERT INTO unrelated (value) VALUES (?)",
    [(b"x" * 2000,) for _ in range(500)],
)
connection.execute("BEGIN IMMEDIATE")
connection.execute("UPDATE unrelated SET value = randomblob(2000)")
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", crash_script, str(path)], check=True)

    sidecars = [Path(f"{path}{suffix}") for suffix in ("-journal", "-wal", "-shm")]
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    before = {
        candidate: candidate.read_bytes()
        for candidate in (path, *sidecars)
        if candidate.exists()
    }

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(path)

    assert caught.value.code == "history_database_unrelated"
    assert str(caught.value) == "history_database_unrelated"
    assert "private-unrelated" not in str(caught.value)
    assert {candidate for candidate in (path, *sidecars) if candidate.exists()} == set(
        before
    )
    assert {candidate: candidate.read_bytes() for candidate in before} == before


@pytest.mark.parametrize(
    ("database_kind", "expected_code"),
    [
        ("unrelated", "history_database_unrelated"),
        ("too-new", "history_schema_too_new"),
    ],
)
def test_live_wal_database_is_classified_without_touching_original_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    database_kind: str,
    expected_code: str,
) -> None:
    path = tmp_path / f"private-{database_kind}.sqlite3"
    if database_kind == "too-new":
        with DatabaseManager.open(path):
            pass

    live = sqlite3.connect(path, isolation_level=None)
    try:
        assert live.execute("PRAGMA journal_mode = WAL").fetchone()[0].lower() == "wal"
        live.execute("PRAGMA wal_autocheckpoint = 0")
        if database_kind == "unrelated":
            live.execute("PRAGMA application_id = 12345")
            live.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        else:
            live.execute("CREATE TABLE future_table (value TEXT NOT NULL)")
            live.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION + 1}")

        files = (
            path,
            Path(f"{path}-wal"),
            Path(f"{path}-shm"),
        )
        assert all(candidate.is_file() for candidate in files)
        before = _file_hashes(files)
        original_connect = database_module.sqlite3.connect
        writable_original_opens = 0

        def tracked_connect(database: object, *args: object, **kwargs: object) -> sqlite3.Connection:
            nonlocal writable_original_opens
            if database == path and not kwargs.get("uri", False):
                writable_original_opens += 1
            return original_connect(database, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(database_module.sqlite3, "connect", tracked_connect)

        with pytest.raises(HistoryDatabaseError) as caught:
            DatabaseManager.open(path)

        assert caught.value.code == expected_code
        assert str(caught.value) == expected_code
        assert writable_original_opens == 0
        assert _file_hashes(files) == before
    finally:
        live.close()


def test_wal_sidecar_identity_swap_before_rw_validation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "history.sqlite3"
    with DatabaseManager.open(path) as database:
        database.connection.execute("PRAGMA wal_autocheckpoint = 0")
        _insert_project(database.connection, "wal-project")
        wal_bytes = Path(f"{path}-wal").read_bytes()
        shm_bytes = Path(f"{path}-shm").read_bytes()

    wal_path = Path(f"{path}-wal")
    shm_path = Path(f"{path}-shm")
    wal_path.write_bytes(wal_bytes)
    shm_path.write_bytes(shm_bytes)
    original_connect = database_module.sqlite3.connect
    swapped = False

    def swapping_connect(database: object, *args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal swapped
        if database == path and not kwargs.get("uri", False) and not swapped:
            replacement = tmp_path / "replacement-shm"
            replacement.write_bytes(shm_path.read_bytes())
            os.replace(replacement, shm_path)
            swapped = True
        return original_connect(database, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(database_module.sqlite3, "connect", swapping_connect)

    with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
        DatabaseManager.open(path)

    assert swapped is True


def test_wal_sidecar_swap_after_connection_configuration_fails_before_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "history.sqlite3"
    with DatabaseManager.open(path) as database:
        database.connection.execute("PRAGMA wal_autocheckpoint = 0")
        _insert_project(database.connection, "wal-project")
        wal_bytes = Path(f"{path}-wal").read_bytes()
        shm_bytes = Path(f"{path}-shm").read_bytes()

    wal_path = Path(f"{path}-wal")
    shm_path = Path(f"{path}-shm")
    wal_path.write_bytes(wal_bytes)
    shm_path.write_bytes(shm_bytes)
    original_configure = database_module._configure_connection
    original_transaction = database_module.immediate_transaction
    transaction_attempted = False

    def swapping_configure(connection: sqlite3.Connection) -> None:
        original_configure(connection)
        replacement = tmp_path / "replacement-shm"
        replacement.write_bytes(shm_path.read_bytes())
        os.replace(replacement, shm_path)

    def tracked_transaction(
        connection: sqlite3.Connection,
    ) -> object:
        nonlocal transaction_attempted
        transaction_attempted = True
        return original_transaction(connection)

    monkeypatch.setattr(database_module, "_configure_connection", swapping_configure)
    monkeypatch.setattr(database_module, "immediate_transaction", tracked_transaction)

    with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
        DatabaseManager.open(path)

    assert transaction_attempted is False


def test_snapshot_copy_reads_in_bounded_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.sqlite3-wal"
    destination = tmp_path / "snapshot.sqlite3-wal"
    payload = b"a" * (2 * 1024 * 1024 + 17)
    source.write_bytes(payload)
    expected = source.stat()
    original_fdopen = database_module.os.fdopen
    read_sizes: list[int] = []

    class BoundedReader:
        def __init__(self, wrapped: object) -> None:
            self._wrapped = wrapped

        def __enter__(self) -> BoundedReader:
            self._wrapped.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, *args: object) -> object:
            return self._wrapped.__exit__(*args)  # type: ignore[attr-defined]

        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 1024 * 1024
            read_sizes.append(size)
            return self._wrapped.read(size)  # type: ignore[attr-defined,no-any-return]

    def guarded_fdopen(
        descriptor: int,
        mode: str,
        *args: object,
        **kwargs: object,
    ) -> object:
        opened = original_fdopen(descriptor, mode, *args, **kwargs)
        if mode == "rb":
            return BoundedReader(opened)
        return opened

    monkeypatch.setattr(database_module.os, "fdopen", guarded_fdopen)

    database_module._copy_bound_file(source, destination, expected)

    assert len(read_sizes) >= 3
    assert destination.read_bytes() == payload


def test_database_with_only_an_unrelated_view_is_not_initialized(tmp_path: Path) -> None:
    path = tmp_path / "unrelated-view.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE VIEW unrelated_view AS SELECT 1 AS value")
    connection.commit()
    connection.close()
    before = path.read_bytes()

    with pytest.raises(HistoryDatabaseError, match="^history_database_unrelated$"):
        DatabaseManager.open(path)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "unexpected_schema_sql",
    [
        ("CREATE VIEW unexpected_view AS SELECT 1 AS value",),
        (
            "CREATE VIEW trigger_target AS SELECT 1 AS value",
            (
                "CREATE TRIGGER unexpected_trigger INSTEAD OF INSERT ON "
                "trigger_target BEGIN SELECT 1; END"
            ),
        ),
    ],
    ids=("view", "trigger"),
)
def test_malformed_recognized_v0_is_rejected_before_migration_side_effects(
    tmp_path: Path,
    unexpected_schema_sql: tuple[str, ...],
) -> None:
    path = tmp_path / "private-v0-history.sqlite3"
    _create_sqlite(path, application_id=APPLICATION_ID, user_version=0)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        for statement in unexpected_schema_sql:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    before = path.read_bytes()

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(path)

    assert caught.value.code == "history_database_corrupt"
    assert str(caught.value) == "history_database_corrupt"
    assert "private-v0-history" not in str(caught.value)
    assert path.read_bytes() == before
    assert not (tmp_path / "backups").exists()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert _object_names(connection, "table") == set()
    finally:
        connection.close()


def test_too_new_schema_is_rejected_before_journal_change(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite3"
    _create_sqlite(
        path,
        application_id=APPLICATION_ID,
        user_version=CURRENT_SCHEMA_VERSION + 1,
    )
    with pytest.raises(HistoryDatabaseError, match="^history_schema_too_new$"):
        DatabaseManager.open(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"
    finally:
        connection.close()


def test_malformed_recognized_database_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "malformed.sqlite3"
    _create_sqlite(path, application_id=APPLICATION_ID, user_version=1)

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        DatabaseManager.open(path)


def test_recognized_database_with_altered_constraints_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "altered.sqlite3"
    with DatabaseManager.open(path):
        pass
    connection = sqlite3.connect(path)
    try:
        original = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'audit_runs'"
        ).fetchone()[0]
        altered = original.replace("CHECK (reused IN (0, 1))", "")
        assert altered != original
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql = ? WHERE type = 'table' AND name = 'audit_runs'",
            (altered,),
        )
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
        connection.execute("PRAGMA writable_schema = OFF")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        DatabaseManager.open(path)


def test_bad_migration_ledger_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    with DatabaseManager.open(path) as database:
        database.connection.execute(
            "UPDATE schema_migrations SET checksum = ? WHERE version = ?",
            ("0" * 64, 1),
        )

    with pytest.raises(HistoryDatabaseError, match="^history_database_corrupt$"):
        DatabaseManager.open(path)


@pytest.mark.parametrize(
    "unexpected_schema_sql",
    [
        "CREATE TABLE unexpected_table (value INTEGER NOT NULL)",
        "CREATE VIEW unexpected_view AS SELECT project_id FROM projects",
        (
            "CREATE TRIGGER unexpected_trigger AFTER INSERT ON projects "
            "BEGIN SELECT 1; END"
        ),
    ],
    ids=("extra-table", "view", "trigger"),
)
def test_malformed_v1_is_rejected_before_v2_migration_side_effects(
    tmp_path: Path,
    unexpected_schema_sql: str,
) -> None:
    path = tmp_path / "private-history.sqlite3"
    _create_v1_database(path)

    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(unexpected_schema_sql)
        connection.commit()
    finally:
        connection.close()
    before = path.read_bytes()

    migration_2 = Migration.build(
        version=2,
        name="test_add_probe",
        statements=("CREATE TABLE migration_probe (value INTEGER NOT NULL)",),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2))

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(path, _migration_registry=registry)

    assert caught.value.code == "history_database_corrupt"
    assert str(caught.value) == "history_database_corrupt"
    assert "private-history" not in str(caught.value)
    assert path.read_bytes() == before
    assert not (tmp_path / "backups").exists()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert "migration_probe" not in _object_names(connection, "table")
    finally:
        connection.close()


def test_recognized_version_without_schema_manifest_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private-v2-history.sqlite3"
    _create_v1_database(path)
    migration_2 = Migration.build(
        version=2,
        name="test_add_probe",
        statements=("CREATE TABLE migration_probe (value INTEGER NOT NULL)",),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2))

    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(migration_2.statements[0])
        connection.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (2, migration_2.name, migration_2.checksum, "2026-01-01T00:00:00Z"),
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    finally:
        connection.close()
    before = path.read_bytes()

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(
            path,
            _migration_registry=registry,
            _schema_manifests={1: _SCHEMA_MANIFESTS[1]},
        )

    assert caught.value.code == "history_database_corrupt"
    assert str(caught.value) == "history_database_corrupt"
    assert "private-v2-history" not in str(caught.value)
    assert path.read_bytes() == before
    assert not (tmp_path / "backups").exists()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    finally:
        connection.close()


def test_symlink_and_hardlink_targets_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.sqlite3"
    with DatabaseManager.open(real):
        pass

    symlink = tmp_path / "link.sqlite3"
    try:
        symlink.symlink_to(real)
    except (OSError, NotImplementedError):
        symlink = None
    if symlink is not None:
        with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
            DatabaseManager.open(symlink)

    hardlink = tmp_path / "hard.sqlite3"
    try:
        os.link(real, hardlink)
    except (OSError, NotImplementedError):
        pytest.skip("hard links are unavailable")
    with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
        DatabaseManager.open(hardlink)
    with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
        DatabaseManager.open(real)


def test_directory_is_rejected_as_unsafe(tmp_path: Path) -> None:
    with pytest.raises(HistoryDatabaseError, match="^history_database_unsafe$"):
        DatabaseManager.open(tmp_path)


def test_successful_test_migration_creates_and_validates_backup(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    _create_v1_database(path)
    migration_2 = Migration.build(
        version=2,
        name="test_add_probe",
        statements=("CREATE TABLE migration_probe (value INTEGER NOT NULL)",),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2))
    manifests = _manifests_with_added_table(
        "migration_probe",
        migration_2.statements[0],
    )

    with DatabaseManager.open(
        path,
        _migration_registry=registry,
        _schema_manifests=manifests,
    ) as database:
        assert database.schema_version == 2
        assert "migration_probe" in _object_names(database.connection, "table")

    backups = list((tmp_path / "backups").glob("*.sqlite3"))
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    try:
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert backup.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
        assert backup.execute(
            "SELECT checksum FROM schema_migrations WHERE version = 1"
        ).fetchone()[0] == MIGRATION_1.checksum
    finally:
        backup.close()


def test_failed_migration_rolls_back_and_preserves_original_and_backup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "secret-history.sqlite3"
    _create_v1_database(path)
    migration_2 = Migration.build(
        version=2,
        name="test_failure",
        statements=(
            "CREATE TABLE must_roll_back (value INTEGER NOT NULL)",
            "THIS IS NOT SQLITE",
        ),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2))
    manifests = _manifests_with_added_table(
        "must_roll_back",
        migration_2.statements[0],
    )

    with pytest.raises(HistoryDatabaseError) as caught:
        DatabaseManager.open(
            path,
            _migration_registry=registry,
            _schema_manifests=manifests,
        )
    assert caught.value.code == "history_migration_failed"
    assert str(caught.value) == "history_migration_failed"
    assert "secret-history" not in str(caught.value)
    assert "syntax" not in str(caught.value).lower()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert "must_roll_back" not in _object_names(connection, "table")
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    backups = list((tmp_path / "backups").glob("*.sqlite3"))
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    try:
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        backup.close()


def test_each_migration_commits_before_the_next_version_starts(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    _create_v1_database(path)
    migration_2 = Migration.build(
        version=2,
        name="test_add_v2_probe",
        statements=("CREATE TABLE migration_probe_v2 (value INTEGER NOT NULL)",),
    )
    migration_3 = Migration.build(
        version=3,
        name="test_fail_v3",
        statements=(
            "CREATE TABLE migration_probe_v3 (value INTEGER NOT NULL)",
            "THIS IS NOT SQLITE",
        ),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2, migration_3))
    v1 = _SCHEMA_MANIFESTS[1]
    v2 = _manifest_with_added_table(
        v1,
        "migration_probe_v2",
        migration_2.statements[0],
    )
    v3 = _manifest_with_added_table(
        v2,
        "migration_probe_v3",
        migration_3.statements[0],
    )
    manifests = {1: v1, 2: v2, 3: v3}

    with pytest.raises(HistoryDatabaseError, match="^history_migration_failed$"):
        DatabaseManager.open(
            path,
            _migration_registry=registry,
            _schema_manifests=manifests,
        )

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert "migration_probe_v2" in _object_names(connection, "table")
        assert "migration_probe_v3" not in _object_names(connection, "table")
        assert connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall() == [
            (1, MIGRATION_1.name, MIGRATION_1.checksum),
            (2, migration_2.name, migration_2.checksum),
        ]
    finally:
        connection.close()
    assert len(list((tmp_path / "backups").glob("*.sqlite3"))) == 1


def test_two_openers_initialize_one_complete_database(tmp_path: Path) -> None:
    path = tmp_path / "history.sqlite3"
    barrier = Barrier(2)

    def open_database() -> tuple[int, set[str]]:
        barrier.wait(timeout=5)
        with DatabaseManager.open(path) as database:
            return database.schema_version, _object_names(database.connection, "table")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: open_database(), range(2)))

    assert results == [(2, EXPECTED_TABLES), (2, EXPECTED_TABLES)]
    with DatabaseManager.open(path) as database:
        assert database.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_two_openers_serialize_one_v1_to_v2_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "history.sqlite3"
    _create_v1_database(path)
    migration_2 = Migration.build(
        version=2,
        name="test_add_probe",
        statements=("CREATE TABLE migration_probe (value INTEGER NOT NULL)",),
    )
    registry = MigrationRegistry((MIGRATION_1, migration_2))
    manifests = _manifests_with_added_table(
        "migration_probe",
        migration_2.statements[0],
    )
    start = Barrier(2)
    second_backup_entered = Event()
    migration_finished = Event()
    call_lock = Lock()
    backup_calls = 0
    original_backup = database_module._create_backup
    original_apply = database_module._apply_migrations

    def staged_backup(*args: object, **kwargs: object) -> Path:
        nonlocal backup_calls
        with call_lock:
            backup_calls += 1
            call_number = backup_calls
        if call_number == 1:
            second_backup_entered.wait(timeout=0.5)
        else:
            second_backup_entered.set()
            assert migration_finished.wait(timeout=5)
        return original_backup(*args, **kwargs)  # type: ignore[arg-type]

    def observed_migration(*args: object, **kwargs: object) -> int:
        try:
            return original_apply(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            migration_finished.set()

    monkeypatch.setattr(database_module, "_create_backup", staged_backup)
    monkeypatch.setattr(database_module, "_apply_migrations", observed_migration)

    def upgrade() -> int:
        start.wait(timeout=5)
        with DatabaseManager.open(
            path,
            _migration_registry=registry,
            _schema_manifests=manifests,
        ) as database:
            return database.schema_version

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: upgrade(), range(2)))

    assert results == [2, 2]
    assert backup_calls == 1
    assert len(list((tmp_path / "backups").glob("*.sqlite3"))) == 1
    with DatabaseManager.open(
        path,
        _migration_registry=registry,
        _schema_manifests=manifests,
    ) as database:
        assert database.schema_version == 2
        assert "migration_probe" in _object_names(database.connection, "table")
