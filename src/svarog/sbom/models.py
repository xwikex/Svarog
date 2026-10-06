"""Bounded dependency-graph result types."""

from __future__ import annotations

from dataclasses import dataclass

from svarog.project_audit.models import LockedPackage


@dataclass(frozen=True, slots=True)
class UnresolvedDependency:
    parent_ref: str
    child_name: str
    reason: str


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    components: tuple[tuple[str, LockedPackage], ...]
    edges: tuple[tuple[str, str], ...]
    unresolved: tuple[UnresolvedDependency, ...]
    known_leaves: tuple[str, ...]
    warnings: tuple[str, ...]
    completeness: str
    root_edges: tuple[str, ...] = ()
    root_completeness: str = "unknown"

    @property
    def component_count(self) -> int:
        return len(self.components)
