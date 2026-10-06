"""Reproducible CycloneDX 1.7 export from an immutable project-audit snapshot."""

from __future__ import annotations

from dataclasses import asdict
import json
import re
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from svarog.audit_history.repository import HistoryRepository
from svarog.project_audit.models import LockedDependency, LockedPackage

from .dependency_graph import build_dependency_graph
from .validation import validate_sbom


SBOM_CONTRACT_VERSION = "svarog-sbom/1"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z", re.ASCII)
_SOURCE_KINDS = frozenset({"registry", "git", "url", "path", "editable", "virtual", "workspace", "unknown"})


def _packages(result: dict[str, object]) -> tuple[LockedPackage, ...]:
    raw = result.get("locked_packages")
    if not isinstance(raw, list) or len(raw) > 50_000:
        raise ValueError("invalid_lock_packages")
    packages = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("invalid_lock_packages")
        try:
            dependencies = item["dependencies"]
            if not isinstance(dependencies, list):
                raise TypeError
            if len(dependencies) > 10_000:
                raise TypeError
            children = []
            for child in dependencies:
                if not isinstance(child, dict):
                    raise TypeError
                if not all(type(child.get(key)) is str for key in ("name", "normalized_name")):
                    raise TypeError
                if not _NAME.fullmatch(child["name"]) or not _NAME.fullmatch(child["normalized_name"]):
                    raise TypeError
                if child.get("version") is not None and type(child["version"]) is not str:
                    raise TypeError
                if child.get("source_kind") is not None and type(child["source_kind"]) is not str:
                    raise TypeError
                children.append(LockedDependency(**child))
            if any(type(item.get(key)) is not str for key in ("name", "normalized_name", "version", "source_kind")):
                raise TypeError
            if (not _NAME.fullmatch(item["name"]) or not _NAME.fullmatch(item["normalized_name"])
                    or item["source_kind"] not in _SOURCE_KINDS
                    or not 0 < len(item["version"]) <= 128
                    or any(char in item["version"] for char in ("/", "\\", ":"))
                    or any(ord(char) < 0x20 or ord(char) == 0x7F for char in item["version"])):
                raise TypeError
            if type(item.get("version_valid")) is not bool:
                raise TypeError
            if item.get("source_identity") is not None and type(item["source_identity"]) is not str:
                raise TypeError
            packages.append(LockedPackage(
                item["name"], item["normalized_name"], item["version"],
                item["version_valid"], item["source_kind"],
                item.get("source_identity"), tuple(children),
            ))
        except (TypeError, KeyError, ValueError):
            raise ValueError("invalid_lock_packages") from None
    return tuple(packages)


def _normalized_rows(repository: HistoryRepository, snapshot_id: int, project_id: str):
    rows = []
    offset = 0
    while True:
        page = repository.list_snapshot_packages(
            snapshot_id, project_id=project_id, audit_kind="python_project",
            scope="lock", limit=100, offset=offset,
        )
        rows.extend(page.items)
        offset += len(page.items)
        if offset >= page.total_count:
            return tuple(rows)
        if not page.items or offset > 100_000:
            raise ValueError("invalid_lock_packages")


def export_snapshot_sbom(repository: HistoryRepository, project_id: str, snapshot_id: int) -> bytes:
    """Export lock components and only provably resolved graph edges."""

    detail = repository.get_snapshot_detail(snapshot_id, project_id=project_id, audit_kind="python_project")
    result = repository.get_snapshot_result(snapshot_id)
    packages = _packages(result)
    if not packages:
        raise ValueError("empty_sbom")
    rows = _normalized_rows(repository, snapshot_id, project_id)
    authoritative = {(row.raw_name, row.normalized_name, row.version, row.source_kind, row.source_identity) for row in rows}
    from_result = {(item.name, item.normalized_name, item.version, item.source_kind, item.source_identity) for item in packages}
    if authoritative != from_result or len(rows) != len(packages):
        raise ValueError("lock_package_mismatch")
    lock_issues = result.get("lock_issues", [])
    if not isinstance(lock_issues, list):
        raise ValueError("invalid_lock_issues")
    unknown_relationships = any(
        isinstance(issue, dict)
        and isinstance(issue.get("code"), str)
        and issue["code"].startswith("invalid_lock_depend")
        for issue in lock_issues
    )
    graph = build_dependency_graph(packages, unknown_relationships=unknown_relationships)
    root_ref = f"urn:svarog:project:{project_id[5:]}"
    components = []
    for ref, package in graph.components:
        component: dict[str, Any] = {
            "type": "library", "name": package.name,
            "version": package.version, "bom-ref": ref,
        }
        if ref.startswith("pkg:pypi/"):
            component["purl"] = ref
        components.append(component)
    by_parent: dict[str, set[str]] = {ref: set() for ref, _ in graph.components}
    for parent, child in graph.edges:
        by_parent[parent].add(child)
    incomplete_parents = {item.parent_ref for item in graph.unresolved}
    dependencies = []
    for parent, children in sorted(by_parent.items()):
        entry: dict[str, Any] = {"ref": parent}
        if children or parent not in incomplete_parents:
            entry["dependsOn"] = sorted(children)
        dependencies.append(entry)
    compositions: list[dict[str, Any]] = [
        {"aggregate": "unknown", "dependencies": [root_ref]}
    ]
    if graph.unresolved:
        compositions.append({
            "aggregate": "incomplete",
            "dependencies": sorted(incomplete_parents),
        })
    serial = uuid5(NAMESPACE_URL, json.dumps(
        (project_id, detail.composite_hash, "1.7", SBOM_CONTRACT_VERSION),
        separators=(",", ":"),
    ))
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": detail.summary.created_at,
            "component": {
                "type": "application", "name": project_id, "bom-ref": root_ref,
            },
        },
        "components": components,
        "dependencies": dependencies,
        "compositions": compositions,
    }
    if graph.warnings:
        bom["metadata"]["properties"] = [
            {"name": "svarog:warning", "value": warning}
            for warning in graph.warnings
        ]
    payload = (json.dumps(bom, ensure_ascii=False, sort_keys=True, indent=2,
                          allow_nan=False) + "\n").encode("utf-8")
    validate_sbom(payload)
    return payload
