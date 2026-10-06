"""Fixed SQLite schema migrations for audit history."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


APPLICATION_ID = 0x53564152
CURRENT_SCHEMA_VERSION = 2


def _checksum(statements: tuple[str, ...]) -> str:
    payload = "\n-- svarog migration statement --\n".join(statements).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class Migration:
    """One ordered migration with an integrity-protected SQL statement set."""

    version: int
    name: str
    statements: tuple[str, ...]
    checksum: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version < 1:
            raise ValueError("invalid migration version")
        if not self.name or not self.name.isascii():
            raise ValueError("invalid migration name")
        if not self.statements or any(not statement.strip() for statement in self.statements):
            raise ValueError("invalid migration statements")
        if self.checksum != _checksum(self.statements):
            raise ValueError("invalid migration checksum")

    @classmethod
    def build(
        cls,
        *,
        version: int,
        name: str,
        statements: tuple[str, ...],
    ) -> Migration:
        """Build a validated migration; intended for fixed registries and tests."""

        frozen_statements = tuple(statements)
        return cls(version, name, frozen_statements, _checksum(frozen_statements))


@dataclass(frozen=True, slots=True)
class MigrationRegistry:
    """A contiguous, immutable migration registry."""

    migrations: tuple[Migration, ...]

    def __post_init__(self) -> None:
        frozen = tuple(self.migrations)
        if tuple(item.version for item in frozen) != tuple(range(1, len(frozen) + 1)):
            raise ValueError("migration versions must be contiguous")
        object.__setattr__(self, "migrations", frozen)

    @property
    def current_version(self) -> int:
        return len(self.migrations)

    def version(self, number: int) -> Migration:
        if number < 1 or number > len(self.migrations):
            raise KeyError(number)
        return self.migrations[number - 1]


_MIGRATION_1_STATEMENTS = (
    """
    CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE projects (
        project_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE audit_snapshots (
        snapshot_id INTEGER PRIMARY KEY,
        project_id TEXT NOT NULL
            REFERENCES projects(project_id) ON DELETE RESTRICT,
        audit_kind TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT NOT NULL,
        python_version TEXT NOT NULL,
        environment_hash TEXT NOT NULL,
        semantic_lock_hash TEXT NULL,
        knowledge_content_hash TEXT NOT NULL,
        knowledge_metadata_hash TEXT NOT NULL,
        evaluation_context_hash TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        analysis_contract_version TEXT NOT NULL,
        composite_hash TEXT NOT NULL,
        audit_status TEXT NOT NULL,
        environment_package_count INTEGER NOT NULL
            CHECK (environment_package_count >= 0),
        lock_package_count INTEGER NOT NULL CHECK (lock_package_count >= 0),
        affected_finding_count INTEGER NOT NULL CHECK (affected_finding_count >= 0),
        indeterminate_finding_count INTEGER NOT NULL
            CHECK (indeterminate_finding_count >= 0),
        issue_count INTEGER NOT NULL CHECK (issue_count >= 0),
        warning_count INTEGER NOT NULL CHECK (warning_count >= 0),
        result_json_zlib BLOB NOT NULL,
        result_json_sha256 TEXT NOT NULL,
        result_json_size INTEGER NOT NULL CHECK (result_json_size >= 0),
        schema_version TEXT NOT NULL,
        UNIQUE (project_id, audit_kind, composite_hash),
        UNIQUE (snapshot_id, project_id, audit_kind)
    )
    """,
    """
    CREATE TABLE audit_runs (
        run_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL
            REFERENCES projects(project_id) ON DELETE RESTRICT,
        audit_kind TEXT NOT NULL,
        snapshot_id INTEGER NULL,
        baseline_run_id TEXT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NULL,
        run_status TEXT NOT NULL CHECK (
            run_status IN (
                'started', 'completed_computed', 'completed_reused',
                'failed', 'interrupted'
            )
        ),
        reused INTEGER NOT NULL CHECK (reused IN (0, 1)),
        python_version TEXT NULL,
        environment_hash TEXT NULL,
        semantic_lock_hash TEXT NULL,
        knowledge_content_hash TEXT NULL,
        knowledge_metadata_hash TEXT NULL,
        evaluation_context_hash TEXT NULL,
        policy_hash TEXT NULL,
        analysis_contract_version TEXT NULL,
        composite_hash TEXT NULL,
        result_schema_version TEXT NULL,
        knowledge_sources_json TEXT NULL,
        knowledge_last_sync_at TEXT NULL,
        knowledge_sync_status TEXT NULL,
        warning_count INTEGER NOT NULL CHECK (warning_count >= 0),
        failure_code TEXT NULL,
        UNIQUE (run_id, project_id, audit_kind),
        FOREIGN KEY (snapshot_id, project_id, audit_kind)
            REFERENCES audit_snapshots(snapshot_id, project_id, audit_kind)
            ON DELETE RESTRICT,
        FOREIGN KEY (baseline_run_id, project_id, audit_kind)
            REFERENCES audit_runs(run_id, project_id, audit_kind)
            ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE snapshot_packages (
        snapshot_id INTEGER NOT NULL
            REFERENCES audit_snapshots(snapshot_id) ON DELETE CASCADE,
        scope TEXT NOT NULL CHECK (scope IN ('environment', 'lock')),
        raw_name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        version TEXT NOT NULL,
        version_valid INTEGER NOT NULL CHECK (version_valid IN (0, 1)),
        source_kind TEXT NOT NULL,
        source_identity TEXT NULL,
        component_key TEXT NOT NULL,
        is_direct INTEGER NULL CHECK (is_direct IS NULL OR is_direct IN (0, 1)),
        applicability_status TEXT NOT NULL,
        PRIMARY KEY (
            snapshot_id, scope, component_key, version, source_kind
        )
    )
    """,
    """
    CREATE TABLE snapshot_dependencies (
        snapshot_id INTEGER NOT NULL
            REFERENCES audit_snapshots(snapshot_id) ON DELETE CASCADE,
        parent_component_key TEXT NOT NULL,
        child_component_key TEXT NOT NULL,
        relationship_source TEXT NOT NULL,
        resolution_status TEXT NOT NULL,
        PRIMARY KEY (
            snapshot_id, parent_component_key, child_component_key,
            relationship_source, resolution_status
        )
    )
    """,
    """
    CREATE TABLE snapshot_findings (
        snapshot_id INTEGER NOT NULL
            REFERENCES audit_snapshots(snapshot_id) ON DELETE CASCADE,
        scope TEXT NOT NULL CHECK (scope IN ('environment', 'lock')),
        raw_name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        audited_version TEXT NOT NULL,
        ghsa_id TEXT NULL,
        cve_id TEXT NULL,
        advisory_id TEXT NOT NULL,
        severity TEXT NULL,
        cvss REAL NULL,
        affected_range TEXT NULL,
        fixed_versions TEXT NULL,
        finding_status TEXT NOT NULL
            CHECK (finding_status IN ('affected', 'indeterminate')),
        indeterminate_reason TEXT NULL,
        advisory_fingerprint TEXT NOT NULL,
        PRIMARY KEY (
            snapshot_id, scope, normalized_name, audited_version,
            advisory_id, advisory_fingerprint, finding_status
        )
    )
    """,
    """
    CREATE TABLE snapshot_issues (
        snapshot_id INTEGER NOT NULL
            REFERENCES audit_snapshots(snapshot_id) ON DELETE CASCADE,
        issue_code TEXT NOT NULL,
        subject TEXT NULL,
        detail TEXT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (snapshot_id, ordinal)
    )
    """,
    """
    CREATE TABLE run_diffs (
        diff_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL
            REFERENCES projects(project_id) ON DELETE RESTRICT,
        baseline_run_id TEXT NULL
            REFERENCES audit_runs(run_id) ON DELETE RESTRICT,
        target_run_id TEXT NOT NULL
            REFERENCES audit_runs(run_id) ON DELETE RESTRICT,
        diff_contract_version TEXT NOT NULL,
        classification TEXT NOT NULL,
        package_added_count INTEGER NOT NULL CHECK (package_added_count >= 0),
        package_removed_count INTEGER NOT NULL CHECK (package_removed_count >= 0),
        package_changed_count INTEGER NOT NULL CHECK (package_changed_count >= 0),
        finding_introduced_count INTEGER NOT NULL
            CHECK (finding_introduced_count >= 0),
        finding_resolved_count INTEGER NOT NULL CHECK (finding_resolved_count >= 0),
        finding_changed_count INTEGER NOT NULL CHECK (finding_changed_count >= 0),
        issue_added_count INTEGER NOT NULL CHECK (issue_added_count >= 0),
        issue_resolved_count INTEGER NOT NULL CHECK (issue_resolved_count >= 0),
        diff_json_zlib BLOB NOT NULL,
        diff_json_size INTEGER NOT NULL CHECK (diff_json_size >= 0),
        diff_json_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (baseline_run_id, target_run_id, diff_contract_version)
    )
    """,
    """
    CREATE INDEX idx_audit_runs_project_kind_completed
        ON audit_runs(project_id, audit_kind, completed_at DESC)
    """,
    "CREATE INDEX idx_audit_runs_snapshot ON audit_runs(snapshot_id)",
    """
    CREATE INDEX idx_audit_snapshots_project_kind_created
        ON audit_snapshots(project_id, audit_kind, created_at DESC)
    """,
    """
    CREATE INDEX idx_audit_snapshots_project_kind_composite
        ON audit_snapshots(project_id, audit_kind, composite_hash)
    """,
    """
    CREATE INDEX idx_snapshot_packages_lookup
        ON snapshot_packages(snapshot_id, scope, normalized_name, version)
    """,
    """
    CREATE INDEX idx_snapshot_findings_snapshot_name_ghsa
        ON snapshot_findings(snapshot_id, normalized_name, ghsa_id)
    """,
    """
    CREATE INDEX idx_snapshot_findings_advisory_name
        ON snapshot_findings(ghsa_id, cve_id, normalized_name)
    """,
    """
    CREATE INDEX idx_snapshot_dependencies_parent
        ON snapshot_dependencies(snapshot_id, parent_component_key)
    """,
    """
    CREATE INDEX idx_run_diffs_project_runs
        ON run_diffs(project_id, baseline_run_id, target_run_id)
    """,
    """
    CREATE UNIQUE INDEX idx_run_diffs_initial_unique
        ON run_diffs(target_run_id, diff_contract_version)
        WHERE baseline_run_id IS NULL
    """,
    """
    CREATE TRIGGER trg_run_diffs_scope_insert
    BEFORE INSERT ON run_diffs
    FOR EACH ROW
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM audit_runs AS target
            WHERE target.run_id = NEW.target_run_id
              AND target.project_id = NEW.project_id
        ) THEN RAISE(ABORT, 'run diff target scope mismatch') END;
        SELECT CASE WHEN NEW.baseline_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM audit_runs AS baseline
            JOIN audit_runs AS target ON target.run_id = NEW.target_run_id
            WHERE baseline.run_id = NEW.baseline_run_id
              AND baseline.project_id = NEW.project_id
              AND target.project_id = NEW.project_id
              AND baseline.audit_kind = target.audit_kind
        ) THEN RAISE(ABORT, 'run diff baseline scope mismatch') END;
    END
    """,
    """
    CREATE TRIGGER trg_run_diffs_scope_update
    BEFORE UPDATE OF project_id, baseline_run_id, target_run_id ON run_diffs
    FOR EACH ROW
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM audit_runs AS target
            WHERE target.run_id = NEW.target_run_id
              AND target.project_id = NEW.project_id
        ) THEN RAISE(ABORT, 'run diff target scope mismatch') END;
        SELECT CASE WHEN NEW.baseline_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM audit_runs AS baseline
            JOIN audit_runs AS target ON target.run_id = NEW.target_run_id
            WHERE baseline.run_id = NEW.baseline_run_id
              AND baseline.project_id = NEW.project_id
              AND target.project_id = NEW.project_id
              AND baseline.audit_kind = target.audit_kind
        ) THEN RAISE(ABORT, 'run diff baseline scope mismatch') END;
    END
    """,
    """
    CREATE TRIGGER trg_audit_runs_scope_update
    BEFORE UPDATE OF project_id, audit_kind ON audit_runs
    FOR EACH ROW
    WHEN (
        NEW.project_id IS NOT OLD.project_id
        OR NEW.audit_kind IS NOT OLD.audit_kind
    ) AND EXISTS (
        SELECT 1 FROM run_diffs
        WHERE baseline_run_id = OLD.run_id OR target_run_id = OLD.run_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'referenced run scope is immutable');
    END
    """,
)


MIGRATION_1 = Migration(
    version=1,
    name="create_audit_history_schema",
    statements=_MIGRATION_1_STATEMENTS,
    checksum="474bb679acdb05ef8599af81e489ec184b3804afe64a1765206e5c24b06cb565",
)
MIGRATION_2 = Migration(
    version=2,
    name="add_cve_and_expiry_indexes",
    statements=(
        """
        CREATE INDEX idx_snapshot_findings_cve_name
            ON snapshot_findings(cve_id, normalized_name)
        """,
        """
        CREATE INDEX idx_audit_runs_project_expiry
            ON audit_runs(
                project_id, COALESCE(completed_at, started_at), run_id
            )
        """,
    ),
    checksum="68eb0f09115b6a74b99497f7b74851574b84c5fa6d57d43f1a4913c9b8c6d7de",
)
MIGRATIONS = (MIGRATION_1, MIGRATION_2)
MIGRATION_REGISTRY = MigrationRegistry(MIGRATIONS)
