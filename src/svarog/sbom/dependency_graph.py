"""Conservative non-recursive dependency resolution for Poetry/uv lock rows."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import quote

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from svarog.project_audit.models import LockedDependency, LockedPackage

from .models import DependencyGraph, UnresolvedDependency


_SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*\Z", re.ASCII)
_FULL_REVISION = re.compile(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\Z", re.ASCII)
_ARTIFACT_DIGEST = re.compile(r"sha256:[a-fA-F0-9]{64}\Z", re.ASCII)
_PYPI_KINDS = frozenset({"registry", "index", "metadata"})


def component_ref(package: LockedPackage) -> str:
    """Do not derive global identity from a local pathname or mutable URL."""

    name = canonicalize_name(package.normalized_name)
    if (package.source_kind in _PYPI_KINDS and package.source_identity is None
            and package.version_valid and _SAFE_NAME.fullmatch(name)):
        try:
            Version(package.version)
        except InvalidVersion:
            pass
        else:
            return f"pkg:pypi/{name}@{quote(package.version, safe='')}"
    immutable = package.source_identity if package.source_identity and (
        _FULL_REVISION.fullmatch(package.source_identity)
        or _ARTIFACT_DIGEST.fullmatch(package.source_identity)
    ) else None
    canonical = json.dumps((name, package.version, package.source_kind, immutable),
                           ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"urn:svarog:component:sha256:{digest}"


def _version_matches(spec: str | None, version: str) -> bool | None:
    if spec is None:
        return True
    try:
        exact = Version(spec)
    except InvalidVersion:
        try:
            constraint = SpecifierSet(spec)
            if not constraint:
                return None
            return Version(version) in constraint
        except (InvalidSpecifier, InvalidVersion):
            return None
    try:
        return Version(version) == exact
    except InvalidVersion:
        return version == spec


def _resolve_child(dependency: LockedDependency, by_name: dict[str, tuple[tuple[str, LockedPackage], ...]]) -> tuple[str | None, str | None]:
    candidates = by_name.get(dependency.normalized_name, ())
    if not candidates:
        return None, "missing_child"
    if dependency.source_kind is not None:
        candidates = tuple(item for item in candidates if item[1].source_kind == dependency.source_kind)
        if not candidates:
            return None, "source_conflict"
    matches = tuple(item for item in candidates if _version_matches(dependency.version, item[1].version) is True)
    if not matches and dependency.version is not None and any(
        _version_matches(dependency.version, item[1].version) is None for item in candidates
    ):
        return None, "unknown_constraint"
    if not matches:
        return None, "missing_child"
    refs = {ref for ref, _ in matches}
    if len(refs) != 1:
        return None, "ambiguous_child"
    return next(iter(refs)), None


def build_dependency_graph(
    packages: tuple[LockedPackage, ...], *, unknown_relationships: bool = False
) -> DependencyGraph:
    """Resolve only proven unique children; root direct dependencies remain unknown."""

    if len(packages) > 50_000:
        raise ValueError("too_many_components")
    grouped: dict[str, list[LockedPackage]] = {}
    for package in packages:
        grouped.setdefault(component_ref(package), []).append(package)
    components: list[tuple[str, LockedPackage]] = []
    warnings: set[str] = set()
    declarations: dict[str, set[LockedDependency]] = {}
    unresolved: set[UnresolvedDependency] = set()
    uncertain_refs: set[str] = set()
    for ref, members in sorted(grouped.items()):
        representative = sorted(members, key=lambda p: (p.normalized_name, p.version, p.source_kind, p.source_identity or ""))[0]
        components.append((ref, representative))
        sets = [set(member.dependencies) for member in members]
        common = set.intersection(*sets)
        declarations[ref] = common
        if len(members) > 1:
            warnings.add("merged_undistinguishable_components")
        uncertain = set.union(*sets) - common
        if uncertain:
            uncertain_refs.add(ref)
            for dependency in uncertain:
                unresolved.add(UnresolvedDependency(ref, dependency.normalized_name, "merged_source_conflict"))
    by_name: dict[str, list[tuple[str, LockedPackage]]] = {}
    for ref, package in components:
        by_name.setdefault(package.normalized_name, []).append((ref, package))
    frozen_by_name = {name: tuple(items) for name, items in by_name.items()}
    edges: set[tuple[str, str]] = set()
    leaves = []
    for parent_ref, _ in components:
        children = declarations[parent_ref]
        if unknown_relationships:
            unresolved.add(UnresolvedDependency(parent_ref, "", "unknown_relationships"))
        if not children and parent_ref not in uncertain_refs and not unknown_relationships:
            leaves.append(parent_ref)
        for dependency in sorted(children, key=lambda d: (d.normalized_name, d.version or "", d.source_kind or "")):
            child_ref, reason = _resolve_child(dependency, frozen_by_name)
            if reason is None:
                edges.add((parent_ref, child_ref))
            else:
                unresolved.add(UnresolvedDependency(parent_ref, dependency.normalized_name, reason))
    return DependencyGraph(
        tuple(components), tuple(sorted(edges)),
        tuple(sorted(unresolved, key=lambda d: (d.parent_ref, d.child_name, d.reason))),
        tuple(sorted(leaves)), tuple(sorted(warnings)),
        "incomplete" if unresolved else "complete",
    )
