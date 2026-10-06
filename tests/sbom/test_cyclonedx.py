"""A saved project audit produces a reproducible, conservative CycloneDX BOM."""

from dataclasses import asdict
import hashlib
import json

import pytest

from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.repository import HistoryRepository, PackageRow, SnapshotInput
from svarog.project_audit.models import LockedDependency, LockedPackage
from svarog.sbom.cyclonedx import export_snapshot_sbom
from svarog.sbom.validation import validate_sbom


PROJECT = "proj_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
RUN = "00000000-0000-4000-8000-000000000001"
SCHEMA = "svarog-project-audit/1"


def _saved_repository(tmp_path, packages, *, lock_issues=()):
    database = DatabaseManager.open(tmp_path / "history.sqlite3")
    repository = HistoryRepository(database.connection)
    rows = tuple(PackageRow(
        "lock", item.name, item.normalized_name, item.version, item.version_valid,
        item.source_kind, item.source_identity,
        "lock:" + hashlib.sha256(repr((item.name, item.version, item.source_kind, item.source_identity)).encode()).hexdigest(),
        None, "unverified",
    ) for item in packages)
    saved = repository.save_run(SnapshotInput(
        project_id=PROJECT, display_name="Example", audit_kind="python_project",
        started_at="2026-09-28T00:00:00Z", completed_at="2026-09-28T00:00:01Z",
        python_version="3.12.7", environment_hash="1" * 64, semantic_lock_hash="2" * 64,
        knowledge_content_hash="3" * 64, knowledge_metadata_hash="4" * 64,
        evaluation_context_hash="5" * 64, policy_hash="6" * 64,
        analysis_contract_version="analysis/1", composite_hash="7" * 64,
        audit_status="completed_clean", result_schema_version=SCHEMA,
        result={"schema_version": SCHEMA, "audit_status": "completed_clean",
                "locked_packages": [asdict(item) for item in packages],
                "lock_issues": list(lock_issues)},
        lock_package_count=len(rows), packages=rows,
    ), run_id=RUN)
    return database, repository, saved.snapshot_id


def test_export_is_deterministic_valid_and_does_not_invent_root_edges(tmp_path):
    parent = LockedPackage("parent", "parent", "1.0", True, "registry", None,
                           (LockedDependency("child", "child", None, None),))
    child = LockedPackage("child", "child", "2.0", True, "registry")
    database, repository, snapshot_id = _saved_repository(tmp_path, (parent, child))
    try:
        bom = export_snapshot_sbom(repository, PROJECT, snapshot_id)
        assert bom == export_snapshot_sbom(repository, PROJECT, snapshot_id)
        payload = json.loads(bom)
        assert payload["specVersion"] == "1.7"
        assert "vulnerabilities" not in payload
        assert payload["metadata"]["timestamp"] == "2026-09-28T00:00:01Z"
        assert payload["dependencies"] == [
            {"ref": "pkg:pypi/child@2.0", "dependsOn": []},
            {"ref": "pkg:pypi/parent@1.0", "dependsOn": ["pkg:pypi/child@2.0"]},
        ]
        assert not any(item["ref"] == payload["metadata"]["component"]["bom-ref"]
                       for item in payload["dependencies"])
        assert hashlib.sha256(bom).hexdigest() == "07d450b709bbd2003af09af02387ee1db2497edbe8087e0dbd85809633fcbebf"
        validate_sbom(bom)
    finally:
        database.close()


def test_environment_and_empty_project_are_rejected(tmp_path):
    database, repository, snapshot_id = _saved_repository(tmp_path, ())
    try:
        with pytest.raises(ValueError, match="empty_sbom"):
            export_snapshot_sbom(repository, PROJECT, snapshot_id)
        with pytest.raises(Exception, match="snapshot_not_found"):
            export_snapshot_sbom(repository, "proj_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb", snapshot_id)
    finally:
        database.close()


def test_unresolved_relationship_is_marked_incomplete(tmp_path):
    parent = LockedPackage("parent", "parent", "1.0", True, "registry", None,
                           (LockedDependency("missing", "missing", None, None),))
    database, repository, snapshot_id = _saved_repository(tmp_path, (parent,))
    try:
        payload = json.loads(export_snapshot_sbom(repository, PROJECT, snapshot_id))
        assert {"aggregate": "incomplete", "dependencies": ["pkg:pypi/parent@1.0"]} in payload["compositions"]
        assert payload["dependencies"] == [{"ref": "pkg:pypi/parent@1.0"}]
    finally:
        database.close()


def test_validation_rejects_dangling_reference_and_absolute_path():
    base = {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"component": {"type": "application", "name": "demo", "bom-ref": "root"}},
        "components": [{"type": "library", "name": "demo", "bom-ref": "child"}],
        "dependencies": [{"ref": "root", "dependsOn": ["missing"]}],
    }
    with pytest.raises(ValueError, match="invalid_sbom_reference"):
        validate_sbom(json.dumps(base).encode())
    base["dependencies"][0]["dependsOn"] = ["child"]
    base["components"][0]["name"] = "C:\\Users\\secret"
    with pytest.raises(ValueError, match="unsafe_sbom_content"):
        validate_sbom(json.dumps(base).encode())


def test_malformed_lock_declarations_mark_unknown_dependencies(tmp_path):
    package = LockedPackage("demo", "demo", "1.0", True, "registry")
    database, repository, snapshot_id = _saved_repository(
        tmp_path, (package,),
        lock_issues=({"code": "invalid_lock_dependency", "subject": "demo", "message": "bad"},),
    )
    try:
        bom = json.loads(export_snapshot_sbom(repository, PROJECT, snapshot_id))
        assert bom["dependencies"] == [{"ref": "pkg:pypi/demo@1.0"}]
        assert {"aggregate": "incomplete", "dependencies": ["pkg:pypi/demo@1.0"]} in bom["compositions"]
    finally:
        database.close()


def test_source_less_lock_component_exports_with_non_pypi_ref(tmp_path):
    package = LockedPackage("unknown", "unknown", "1.0", True, "unknown")
    database, repository, snapshot_id = _saved_repository(tmp_path, (package,))
    try:
        bom = json.loads(export_snapshot_sbom(repository, PROJECT, snapshot_id))
        assert bom["components"][0]["bom-ref"].startswith("urn:svarog:component:sha256:")
    finally:
        database.close()


def test_merged_source_warning_is_visible_in_export(tmp_path):
    first = LockedPackage("private", "private", "1.0", True, "path", "relative/one")
    second = LockedPackage("private", "private", "1.0", True, "path", "relative/two")
    database, repository, snapshot_id = _saved_repository(tmp_path, (first, second))
    try:
        bom = json.loads(export_snapshot_sbom(repository, PROJECT, snapshot_id))
        assert len(bom["components"]) == 1
        assert {"name": "svarog:warning", "value": "merged_undistinguishable_components"} in bom["metadata"]["properties"]
    finally:
        database.close()
