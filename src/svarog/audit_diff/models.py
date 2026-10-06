"""Immutable, JSON-renderable audit difference records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PackageChange:
    scope: str
    normalized_name: str
    before: tuple[dict[str, Any], ...]
    after: tuple[dict[str, Any], ...]
    change_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FindingChange:
    scope: str
    normalized_name: str
    audited_version: str
    advisory_id: str
    change_type: str
    before: tuple[dict[str, Any], ...]
    after: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class DependencyChange:
    parent_component_key: str
    child_component_key: str
    relationship_source: str
    resolution_status: str
    change_type: str


@dataclass(frozen=True, slots=True)
class IssueChange:
    issue_code: str
    subject: str | None
    change_type: str


@dataclass(frozen=True, slots=True)
class DiffReport:
    project_id: str
    audit_kind: str
    baseline_snapshot_id: int | None
    target_snapshot_id: int
    classification: str
    causes: tuple[str, ...]
    analysis_engine_changed: bool
    python_version_before: str | None
    python_version_after: str
    python_version_changed: bool
    package_changes: tuple[PackageChange, ...]
    finding_changes: tuple[FindingChange, ...]
    dependency_changes: tuple[DependencyChange, ...]
    issue_changes: tuple[IssueChange, ...]
    warnings: tuple[str, ...]
