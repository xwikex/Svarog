"""Stable, privacy-preserving hashes for audit history inputs."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math
import ntpath
import posixpath
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from packaging.utils import canonicalize_name


HASH_SCHEMA_VERSION = "svarog-hash/1"
_MAX_CANONICAL_DEPTH = 256
_MAX_CANONICAL_BYTES = 16 * 1024 * 1024
_MAX_COLLECTION_ITEMS = 10_000
_MAX_TOTAL_NODES = 100_000
_MAX_LOCK_GRAPH_WORK = 100_000
_MAX_TEXT_LENGTH = 1_000_000
_MAX_OPAQUE_SOURCE_IDENTITY_LENGTH = 256
_MISSING = object()
_NO_DEFAULT = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", flags=re.ASCII)
_ISSUE_CODE = re.compile(r"[a-z0-9][a-z0-9_.-]*\Z", flags=re.ASCII)
_PACKAGE_NAME = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z", flags=re.ASCII
)
_GHSA_ID = re.compile(
    r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-"
    r"[23456789CFGHJMPQRVWX]{4}\Z",
    flags=re.ASCII | re.IGNORECASE,
)
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z", flags=re.ASCII | re.IGNORECASE)
_GENERIC_ADVISORY_ID = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", flags=re.ASCII
)
_PUBLIC_SOURCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", flags=re.ASCII)
_OPAQUE_SOURCE_IDENTITY = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z", flags=re.ASCII
)
_SOURCE_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}\Z", flags=re.ASCII)
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_WINDOWS_DRIVE_PREFIX = re.compile(r"[A-Za-z]:")
_GIT_URL_SCHEMES = frozenset({"git+https", "git+ssh", "ssh"})
_HEALTH_GROUPS = frozenset(
    {
        "healthy", "stale", "future_skew", "invalid_sync_time", "sync_failed",
        "sync_failed_stale", "sync_failed_future_skew",
        "sync_failed_invalid_sync_time",
    }
)
_ENVIRONMENT_AUDIT_KINDS = frozenset({"environment", "python_environment"})
_PROJECT_AUDIT_KINDS = frozenset({"project", "python_project"})
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "token",
        "username",
    }
)
_LAYOUT_KEYS = frozenset(
    {
        "byte_layout",
        "database_bytes",
        "db_bytes",
        "page_count",
        "page_size",
        "size_bytes",
        "wal_bytes",
    }
)


class HashingError(ValueError):
    """A hashing failure with a stable, path-free public error code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HashPackage:
    """Path-free package identity used by environment and lock hashing."""

    normalized_name: str
    version: str
    version_valid: bool
    source_kind: str
    ambiguity: bool = False
    source_identity: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized_name", _package_name(self.normalized_name))
        object.__setattr__(self, "version", _required_text(self.version, "invalid_package"))
        if type(self.version_valid) is not bool or type(self.ambiguity) is not bool:
            raise HashingError("invalid_package")
        source_kind = _source_kind(self.source_kind)
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(
            self,
            "source_identity",
            _source_identity(self.source_identity, source_kind),
        )


def canonical_json_bytes(value: object) -> bytes:
    """Encode an exact JSON value as deterministic UTF-8 bytes."""

    try:
        budget = [0, 0]
        _validate_canonical_value(value, depth=0, active=set(), budget=budget)
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        if len(encoded) > _MAX_CANONICAL_BYTES:
            raise HashingError("invalid_canonical_value")
        return encoded
    except HashingError:
        raise
    except Exception:
        raise HashingError("invalid_canonical_value") from None


def environment_hash(
    implementation: object,
    version: object,
    packages: Iterable[object],
    issues: Iterable[object] = (),
) -> str:
    """Hash only target-runtime and package facts relevant to evaluation."""

    implementation_value = _required_text(
        implementation, "invalid_python_implementation"
    ).casefold()
    version_value = _python_version(version)
    package_values: list[dict[str, object]] = []
    for package in _items(packages, "invalid_packages"):
        if isinstance(package, Mapping):
            _privacy_scan(package)
        package_values.append(_environment_package(package))
    payload = {
        "implementation": implementation_value,
        "issues": _issue_multiset(issues),
        "packages": _sorted_unique_objects(package_values),
        "python_version": version_value,
    }
    return _domain_hash("environment", payload)


def semantic_lock_hash(lock_snapshot: object) -> str:
    """Hash parsed lock semantics while deliberately excluding file representation."""

    lock_format = _required_text(
        _read(lock_snapshot, "lock_format", "format"), "invalid_lock_snapshot"
    ).casefold()
    raw_packages = _items(
        _read(lock_snapshot, "packages"), "invalid_lock_snapshot"
    )
    graph_work = [0]
    _consume_lock_graph_work(graph_work, len(raw_packages))
    packages: list[dict[str, object]] = []
    package_pairs: list[tuple[object, dict[str, object]]] = []
    for raw_package in raw_packages:
        package = _lock_package(raw_package)
        packages.append(package)
        package_pairs.append((raw_package, package))
    normalized_packages = _sorted_unique_objects(packages)
    edges = _lock_edges(package_pairs, normalized_packages, graph_work)
    raw_issues = _items(
        _read(lock_snapshot, "issues", default=()), "invalid_issues"
    )
    payload: dict[str, object] = {
        "format": lock_format,
        "issues": _issue_multiset(raw_issues),
        "marker_policy": "ignored",
        "packages": normalized_packages,
        "dependencies": edges,
        "version_policy": "all_distinct_versions",
    }
    issue_counts = _issue_counts(lock_snapshot, len(raw_issues))
    if issue_counts is not None:
        payload["issue_counts"] = issue_counts
    _privacy_scan(payload)
    return _domain_hash("semantic_lock", payload)


def knowledge_content_hash(snapshot: object, relevant_names: Iterable[object]) -> str:
    """Hash report-affecting advisory content for relevant packages only."""

    names = {
        _package_name(name)
        for name in _items(relevant_names, "invalid_relevant_names", scalar_string=True)
    }
    raw_advisories = _advisory_items(snapshot)
    if not isinstance(snapshot, (list, tuple, set, frozenset)):
        _privacy_scan(
            snapshot,
            allowed_path_keys=frozenset({"path"}),
            allowed_timestamp_keys=frozenset(
                {"last_sync_at", "updated_at", "withdrawn_at"}
            ),
            allowed_layout_keys=frozenset({"size_bytes"}),
            ignored_keys=frozenset({"advisories", "issues"}),
        )
    advisories: list[dict[str, object]] = []
    for raw_advisory in raw_advisories:
        normalized_name = _advisory_package_name(raw_advisory)
        if normalized_name not in names:
            continue
        _privacy_scan(
            raw_advisory,
            allowed_timestamp_keys=frozenset({"updated_at", "withdrawn_at"}),
        )
        advisories.append(_content_advisory(raw_advisory, normalized_name))
    payload: dict[str, object] = {
        "advisories": _sorted_unique_objects(advisories)
    }
    raw_issues = _read(snapshot, "issues", default=_MISSING)
    if raw_issues is not _MISSING:
        issues = _knowledge_issue_multiset(raw_issues, names)
        if issues:
            payload["issues"] = issues
    return _domain_hash("knowledge_content", payload)


def knowledge_metadata_hash(
    metadata: object,
    advisory_updates: Iterable[object] = (),
) -> str:
    """Hash operational knowledge metadata independently from advisory content."""

    raw_updates = _items(advisory_updates, "invalid_advisory_updates")
    _privacy_scan(
        metadata,
        allowed_path_keys=frozenset({"path"}),
        allowed_timestamp_keys=frozenset(
            {"last_sync_at", "sync_time", "updated_at"}
        ),
        allowed_layout_keys=frozenset({"size_bytes"}),
    )
    _privacy_scan(
        raw_updates,
        allowed_timestamp_keys=frozenset({"updated_at", "withdrawn_at"}),
    )
    sources = _read(metadata, "sources", "source_set", default=())
    source_value_set: set[str] = set()
    for source in _items(
        sources, "invalid_knowledge_metadata", scalar_string=True
    ):
        source_value = _normalized_text(source, "invalid_knowledge_metadata")
        _validate_public_url(source_value)
        source_value_set.add(source_value)
    source_values = sorted(source_value_set)
    updates = [
        _advisory_update(item)
        for item in raw_updates
    ]
    payload = {
        "advisory_updates": _sorted_unique_objects(updates),
        "note": _optional_normalized_text(
            _read(
                metadata,
                "last_sync_message",
                "sync_note",
                "note",
                default=None,
            ),
            "invalid_knowledge_metadata",
        ),
        "sources": source_values,
        "status": _optional_casefold_text(
            _read(
                metadata,
                "last_sync_status",
                "sync_status",
                "status",
                default=None,
            ),
            "invalid_knowledge_metadata",
        ),
        "sync_time": _optional_normalized_text(
            _read(
                metadata,
                "last_sync_at",
                "sync_time",
                default=None,
            ),
            "invalid_knowledge_metadata",
        ),
    }
    return _domain_hash("knowledge_metadata", payload)


def evaluation_context_hash(health_state: object) -> str:
    """Hash a stable knowledge-health group, never a raw observation time."""

    _privacy_scan(health_state)
    if isinstance(health_state, str):
        raw_group: object = health_state
    else:
        raw_group = _read(
            health_state,
            "group",
            "health_group",
            "status",
            default=_MISSING,
        )
    if raw_group is _MISSING:
        raise HashingError("invalid_health_state")
    group = _required_text(raw_group, "invalid_health_state").casefold().replace("-", "_")
    if group not in _HEALTH_GROUPS:
        raise HashingError("invalid_health_state")
    return _domain_hash("evaluation_context", {"health_group": group})


def policy_hash(policy: object) -> str:
    """Hash stable matching, reporting, and freshness policy semantics."""

    _privacy_scan(policy)
    payload = {
        "detail_limits": _semantic_json_value(
            _read(policy, "detail_limits", "limits"), "invalid_policy"
        ),
        "freshness_threshold": _semantic_json_value(
            _read(policy, "freshness_threshold", "freshness"), "invalid_policy"
        ),
        "marker_handling": _required_text(
            _read(policy, "marker_handling", "marker_policy"), "invalid_policy"
        ).casefold(),
        "version_handling": _required_text(
            _read(policy, "version_handling", "version_policy"), "invalid_policy"
        ).casefold(),
        "withdrawn_handling": _required_text(
            _read(policy, "withdrawn_handling", "withdrawn_policy"),
            "invalid_policy",
        ).casefold(),
    }
    return _domain_hash("policy", payload)


def composite_hash(
    *,
    audit_kind: object,
    environment: object,
    lock: object = None,
    knowledge: object,
    context: object,
    policy: object,
    contract: object,
) -> str:
    """Combine component hashes without incorporating knowledge metadata."""

    kind = _required_text(audit_kind, "invalid_audit_kind").casefold()
    if kind not in _ENVIRONMENT_AUDIT_KINDS | _PROJECT_AUDIT_KINDS:
        raise HashingError("invalid_audit_kind")
    is_environment = kind in _ENVIRONMENT_AUDIT_KINDS
    if is_environment and lock is not None:
        raise HashingError("unexpected_lock_hash")
    if kind in _PROJECT_AUDIT_KINDS and lock is None:
        raise HashingError("missing_lock_hash")
    payload: dict[str, object] = {
        "analysis_contract": _required_text(contract, "invalid_analysis_contract"),
        "audit_kind": kind,
        "environment_hash": _digest_value(environment),
        "evaluation_context_hash": _digest_value(context),
        "knowledge_content_hash": _digest_value(knowledge),
        "policy_hash": _digest_value(policy),
    }
    if not is_environment:
        payload["semantic_lock_hash"] = _digest_value(lock)
    return _domain_hash("composite", payload)


def _domain_hash(domain: str, value: object) -> str:
    envelope = {
        "domain": f"svarog.audit_history.{domain}",
        "hash_schema_version": HASH_SCHEMA_VERSION,
        "value": value,
    }
    return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()


def _validate_canonical_value(
    value: object,
    *,
    depth: int,
    active: set[int],
    budget: list[int],
) -> None:
    if depth > _MAX_CANONICAL_DEPTH:
        raise HashingError("invalid_canonical_value")
    budget[0] += 1
    if budget[0] > _MAX_TOTAL_NODES:
        raise HashingError("invalid_canonical_value")
    value_type = type(value)
    if value is None or value_type in (str, bool, int):
        if value_type is str:
            budget[1] += _canonical_string_size(value)
        elif value_type is int:
            if value.bit_length() > _MAX_CANONICAL_BYTES * 4:
                raise HashingError("invalid_canonical_value")
            try:
                budget[1] += len(str(value))
            except (ValueError, OverflowError):
                raise HashingError("invalid_canonical_value") from None
        else:
            budget[1] += 4 if value is None or value is True else 5
        if budget[1] > _MAX_CANONICAL_BYTES:
            raise HashingError("invalid_canonical_value")
        return
    if value_type is float:
        if not math.isfinite(value):
            raise HashingError("invalid_canonical_value")
        budget[1] += 32
        if budget[1] > _MAX_CANONICAL_BYTES:
            raise HashingError("invalid_canonical_value")
        return
    if value_type not in (dict, list):
        raise HashingError("invalid_canonical_value")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise HashingError("invalid_canonical_value")
    identity = id(value)
    if identity in active:
        raise HashingError("invalid_canonical_value")
    active.add(identity)
    try:
        if value_type is dict:
            for key, child in value.items():  # type: ignore[union-attr]
                if type(key) is not str:
                    raise HashingError("invalid_canonical_value")
                budget[1] += _canonical_string_size(key)
                if budget[1] > _MAX_CANONICAL_BYTES:
                    raise HashingError("invalid_canonical_value")
                _validate_canonical_value(
                    child, depth=depth + 1, active=active, budget=budget
                )
        else:
            for child in value:  # type: ignore[union-attr]
                _validate_canonical_value(
                    child, depth=depth + 1, active=active, budget=budget
                )
    finally:
        active.remove(identity)


def _canonical_string_size(value: str) -> int:
    if len(value) > _MAX_TEXT_LENGTH:
        raise HashingError("invalid_canonical_value")
    total = 2
    try:
        for character in value:
            codepoint = ord(character)
            if 0xD800 <= codepoint <= 0xDFFF:
                raise HashingError("invalid_canonical_value")
            if character in {'"', "\\"} or character in "\b\t\n\f\r":
                total += 2
            elif codepoint < 0x20:
                total += 6
            elif codepoint < 0x80:
                total += 1
            elif codepoint < 0x800:
                total += 2
            elif codepoint < 0x10000:
                total += 3
            else:
                total += 4
            if total > _MAX_CANONICAL_BYTES:
                raise HashingError("invalid_canonical_value")
    except HashingError:
        raise
    except Exception:
        raise HashingError("invalid_canonical_value") from None
    return total


def _read(value: object, *names: str, default: object = _NO_DEFAULT) -> object:
    if isinstance(value, Mapping):
        for name in names:
            try:
                return value[name]
            except KeyError:
                continue
            except Exception:
                raise HashingError("invalid_hash_input") from None
    else:
        for name in names:
            try:
                result = getattr(value, name, _MISSING)
            except Exception:
                raise HashingError("invalid_hash_input") from None
            if result is not _MISSING:
                return result
    if default is not _NO_DEFAULT:
        return default
    raise HashingError("missing_hash_field")


def _items(
    value: object,
    code: str,
    *,
    scalar_string: bool = False,
) -> list[object]:
    return list(_bounded_items(value, code, scalar_string=scalar_string))


def _bounded_items(
    value: object,
    code: str,
    *,
    scalar_string: bool = False,
    graph_work: list[int] | None = None,
) -> Iterable[object]:
    if scalar_string and isinstance(value, str):
        yield value
        return
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise HashingError(code)
    try:
        iterator = iter(value)
    except Exception:
        raise HashingError(code) from None
    for index in range(_MAX_COLLECTION_ITEMS + 1):
        try:
            item = next(iterator)
        except StopIteration:
            return
        except Exception:
            raise HashingError(code) from None
        if index == _MAX_COLLECTION_ITEMS:
            raise HashingError(code)
        if graph_work is not None:
            _consume_lock_graph_work(graph_work, 1)
        yield item


def _required_text(value: object, code: str) -> str:
    if isinstance(value, Enum):
        try:
            value = value.value
        except Exception:
            raise HashingError(code) from None
    if type(value) is not str:
        raise HashingError(code)
    if len(value) > _MAX_TEXT_LENGTH:
        raise HashingError(code)
    normalized = _normalize_line_endings(value).strip()
    if not normalized:
        raise HashingError(code)
    try:
        normalized.encode("utf-8", errors="strict")
    except Exception:
        raise HashingError(code) from None
    return normalized


def _normalized_text(value: object, code: str) -> str:
    return _required_text(value, code)


def _optional_normalized_text(value: object, code: str) -> str | None:
    if value is None:
        return None
    return _normalized_text(value, code)


def _optional_casefold_text(value: object, code: str) -> str | None:
    normalized = _optional_normalized_text(value, code)
    return None if normalized is None else normalized.casefold()


def _normalize_line_endings(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _package_name(value: object) -> str:
    raw = _required_text(value, "invalid_package_name")
    if _looks_absolute_path(raw):
        raise HashingError("forbidden_path")
    if _PACKAGE_NAME.fullmatch(raw) is None:
        raise HashingError("invalid_package_name")
    try:
        normalized = canonicalize_name(raw)
    except Exception:
        raise HashingError("invalid_package_name") from None
    if not normalized:
        raise HashingError("invalid_package_name")
    return normalized


def _source_kind(value: object) -> str:
    return _required_text(value, "invalid_source_kind").casefold()


def _source_identity(value: object, source_kind: str | None) -> str | None:
    if value is None:
        return None
    identity = _required_text(value, "invalid_source_identity")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in identity):
        raise HashingError("invalid_source_identity")
    if _looks_absolute_path(identity) or _WINDOWS_DRIVE_PREFIX.match(identity):
        raise HashingError("unsafe_source_identity")
    if source_kind == "path":
        raise HashingError("unsafe_source_identity")
    slash_identity = identity.replace("\\", "/")
    normalized_path = posixpath.normpath(slash_identity)
    if (
        slash_identity.startswith("./")
        or normalized_path in {".", ".."}
        or normalized_path.startswith("../")
        or any(part == ".." for part in normalized_path.split("/"))
    ):
        raise HashingError("unsafe_source_identity")
    if _SOURCE_DIGEST.fullmatch(identity) is not None:
        return identity
    try:
        parsed = urlsplit(identity)
    except Exception:
        raise HashingError("invalid_source_identity") from None
    if parsed.scheme:
        _validate_split_url(parsed, "invalid_source_identity")
        allowed_schemes = (
            _GIT_URL_SCHEMES | {"http", "https"} if source_kind == "git"
            else {"http", "https"} if source_kind in {"registry", "url"}
            else frozenset()
        )
        if parsed.scheme.casefold() not in allowed_schemes:
            raise HashingError("invalid_source_identity")
        return identity
    if (
        len(identity) > _MAX_OPAQUE_SOURCE_IDENTITY_LENGTH
        or _OPAQUE_SOURCE_IDENTITY.fullmatch(identity) is None
        or _is_sensitive_key(identity)
    ):
        raise HashingError("invalid_source_identity")
    return identity


def _python_version(value: object) -> list[int] | str:
    if value is None:
        return "unknown"
    if type(value) is str:
        if value.strip().casefold() == "unknown":
            return "unknown"
        raise HashingError("invalid_python_version")
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise HashingError("invalid_python_version")
    parts = _items(value, "invalid_python_version")
    if len(parts) != 3 or any(type(part) is not int or part < 0 for part in parts):
        raise HashingError("invalid_python_version")
    return parts  # type: ignore[return-value]


def _environment_package(package: object) -> dict[str, object]:
    normalized_name = _package_name(
        _read(package, "normalized_name", "name")
    )
    version = _required_text(_read(package, "version"), "invalid_package")
    version_valid = _read(package, "version_valid")
    ambiguity = _read(package, "ambiguity", "ambiguous", default=False)
    if type(version_valid) is not bool or type(ambiguity) is not bool:
        raise HashingError("invalid_package")
    source_kind = _source_kind(
        _read(package, "source_kind", "source_type", default="metadata")
    )
    payload: dict[str, object] = {
        "ambiguity": ambiguity,
        "normalized_name": normalized_name,
        "source_kind": source_kind,
        "version": version,
        "version_valid": version_valid,
    }
    _privacy_scan(payload)
    return payload


def _lock_package(package: object) -> dict[str, object]:
    normalized_name = _package_name(
        _read(package, "normalized_name", "name")
    )
    version = _required_text(_read(package, "version"), "invalid_lock_package")
    version_valid = _read(package, "version_valid")
    if type(version_valid) is not bool:
        raise HashingError("invalid_lock_package")
    source_kind = _source_kind(
        _read(package, "source_kind", "source_type", default="unknown")
    )
    payload: dict[str, object] = {
        "normalized_name": normalized_name,
        "source_identity": _source_identity(
            _read(package, "source_identity", default=None), source_kind
        ),
        "source_kind": source_kind,
        "version": version,
        "version_valid": version_valid,
    }
    _privacy_scan(payload)
    return payload


def _lock_edges(
    package_pairs: list[tuple[object, dict[str, object]]],
    packages: list[dict[str, object]],
    graph_work: list[int],
) -> list[dict[str, object]]:
    edges: list[dict[str, object]] = []
    component_indexes, source_kinds_by_component = _lock_package_indexes(packages)
    for raw_parent, parent in package_pairs:
        dependencies = _read(raw_parent, "dependencies", default=())
        for dependency in _bounded_items(
            dependencies,
            "invalid_lock_dependency",
            graph_work=graph_work,
        ):
            child_name = _package_name(
                _read(dependency, "normalized_name", "name")
            )
            component_values: list[object] = [child_name]
            component_mask = 0
            raw_version = _read(dependency, "version", default=None)
            raw_source_kind = _read(
                dependency, "source_kind", "source_type", default=None
            )
            raw_source_identity = _read(
                dependency, "source_identity", default=None
            )
            if raw_version is not None:
                version = _required_text(raw_version, "invalid_lock_dependency")
                component_mask |= 1
                component_values.append(version)
            if raw_source_kind is not None:
                source_kind = _source_kind(raw_source_kind)
                component_mask |= 2
                component_values.append(source_kind)
            if raw_source_identity is not None:
                kind_key = tuple(component_values[: 2 if component_mask & 1 else 1])
                candidate_kinds = source_kinds_by_component.get(kind_key, frozenset())
                identity_kind = (
                    source_kind
                    if raw_source_kind is not None
                    else next(iter(candidate_kinds))
                    if len(candidate_kinds) == 1
                    else None
                )
                source_identity = _source_identity(raw_source_identity, identity_kind)
                component_mask |= 4
                component_values.append(source_identity)
            candidates = component_indexes[component_mask].get(
                tuple(component_values), ()
            )
            if len(candidates) == 1:
                _consume_lock_graph_work(graph_work, 1)
                edges.append({"from": parent, "to": candidates[0]})
    return _sorted_unique_objects(edges)


def _lock_package_indexes(
    packages: list[dict[str, object]],
) -> tuple[
    dict[int, dict[tuple[object, ...], list[dict[str, object]]]],
    dict[tuple[object, ...], frozenset[str]],
]:
    indexes: dict[
        int, dict[tuple[object, ...], list[dict[str, object]]]
    ] = {mask: {} for mask in range(8)}
    mutable_source_kinds: dict[tuple[object, ...], set[str]] = {}
    for package in packages:
        name = package["normalized_name"]
        version = package["version"]
        source_kind = package["source_kind"]
        source_identity = package["source_identity"]
        components = (version, source_kind, source_identity)
        for mask in range(8):
            key = (name,) + tuple(
                component
                for bit, component in enumerate(components)
                if mask & (1 << bit)
            )
            indexes[mask].setdefault(key, []).append(package)
        for key in ((name,), (name, version)):
            mutable_source_kinds.setdefault(key, set()).add(str(source_kind))
    source_kinds = {
        key: frozenset(values) for key, values in mutable_source_kinds.items()
    }
    return indexes, source_kinds


def _consume_lock_graph_work(budget: list[int], amount: int) -> None:
    budget[0] += amount
    if budget[0] > _MAX_LOCK_GRAPH_WORK:
        raise HashingError("lock_graph_budget_exceeded")


def _issue_multiset(issues: object) -> list[dict[str, object]]:
    values: Counter[str] = Counter()
    for issue in _items(issues, "invalid_issues"):
        code = issue if isinstance(issue, str) else _read(issue, "code")
        raw_code = _required_text(code, "invalid_issue_code")
        if not raw_code.isascii():
            raise HashingError("invalid_issue_code")
        normalized = raw_code.casefold()
        if _ISSUE_CODE.fullmatch(normalized) is None:
            raise HashingError("invalid_issue_code")
        values[normalized] += 1
    return [
        {"code": code, "count": values[code]}
        for code in sorted(values)
    ]


def _knowledge_issue_multiset(
    issues: object,
    relevant_names: set[str],
) -> list[dict[str, object]]:
    values: Counter[tuple[str, str | None]] = Counter()
    for issue in _items(issues, "invalid_issues"):
        subject: str | None = None
        if not isinstance(issue, str):
            raw_subject = _read(issue, "subject", default=_MISSING)
            if raw_subject is not _MISSING and raw_subject is not None:
                try:
                    candidate = _package_name(raw_subject)
                except HashingError:
                    continue
                if candidate not in relevant_names:
                    continue
                subject = candidate
        code_value = issue if isinstance(issue, str) else _read(issue, "code")
        raw_code = _required_text(code_value, "invalid_issue_code")
        if not raw_code.isascii():
            raise HashingError("invalid_issue_code")
        code = raw_code.casefold()
        if _ISSUE_CODE.fullmatch(code) is None:
            raise HashingError("invalid_issue_code")
        values[(code, subject)] += 1
    return [
        {"code": code, "count": count, "subject": subject}
        for (code, subject), count in sorted(
            values.items(), key=lambda item: (item[0][0], item[0][1] or "")
        )
    ]


def _issue_counts(snapshot: object, retained_count: int) -> dict[str, int] | None:
    total = _read(snapshot, "total_issue_count", default=_MISSING)
    truncated = _read(snapshot, "truncated_issue_count", default=_MISSING)
    if total is _MISSING and truncated is _MISSING:
        return None
    if (
        total is _MISSING
        or truncated is _MISSING
        or type(total) is not int
        or type(truncated) is not int
        or total < retained_count
        or truncated < 0
        or truncated > total
        or total - retained_count != truncated
    ):
        raise HashingError("invalid_issue_counts")
    return {"total": total, "truncated": truncated}


def _advisory_items(snapshot: object) -> list[object]:
    if isinstance(snapshot, (list, tuple, set, frozenset)):
        return _items(snapshot, "invalid_knowledge_snapshot")
    return _items(
        _read(snapshot, "advisories"), "invalid_knowledge_snapshot"
    )


def _advisory_package_name(advisory: object) -> str:
    return _package_name(
        _read(
            advisory,
            "normalized_package_name",
            "package_name",
            "package",
            "name",
        )
    )


def _content_advisory(
    advisory: object, normalized_name: str | None = None
) -> dict[str, object]:
    if normalized_name is None:
        normalized_name = _advisory_package_name(advisory)
    raw_withdrawn = _read(advisory, "withdrawn", default=_MISSING)
    if raw_withdrawn is _MISSING:
        withdrawn = _read(advisory, "withdrawn_at", default=None) is not None
    elif type(raw_withdrawn) is bool:
        withdrawn = raw_withdrawn
    else:
        raise HashingError("invalid_advisory")
    raw_cvss = _read(advisory, "cvss_score", "cvss", default=None)
    if raw_cvss is None:
        cvss: float | None = None
    elif isinstance(raw_cvss, bool):
        raise HashingError("invalid_advisory")
    else:
        try:
            cvss = float(raw_cvss)
        except Exception:
            raise HashingError("invalid_advisory") from None
        if not math.isfinite(cvss):
            raise HashingError("invalid_advisory")
    ranges = _text_set(
        _read(
            advisory,
            "affected_ranges",
            "ranges",
            "version_range",
            default=(),
        ),
        "invalid_advisory",
    )
    fixed_versions = _text_set(
        _read(
            advisory,
            "fixed_versions",
            "fixed_version",
            default=(),
        ),
        "invalid_advisory",
        allow_none=True,
    )
    source = _optional_normalized_text(
        _read(advisory, "source", default=None), "invalid_advisory"
    )
    if source is not None:
        _validate_public_url(source)
    return {
        "advisory_id": _optional_advisory_id(
            _read(advisory, "advisory_id", "id", default=None),
            "generic",
        ),
        "cve_id": _optional_advisory_id(
            _read(advisory, "cve_id", "cve", default=None),
            "cve",
        ),
        "cvss": cvss,
        "fixed_versions": fixed_versions,
        "ghsa_id": _optional_advisory_id(
            _read(advisory, "ghsa_id", "ghsa", default=None),
            "ghsa",
        ),
        "package": normalized_name,
        "ranges": ranges,
        "severity": _optional_casefold_text(
            _read(advisory, "severity", default=None), "invalid_advisory"
        ),
        "source": source,
        "status": _optional_casefold_text(
            _read(advisory, "state", "status", default=None),
            "invalid_advisory",
        ),
        "summary": _optional_normalized_text(
            _read(advisory, "summary", default=None), "invalid_advisory"
        ),
        "withdrawn": withdrawn,
    }


def _advisory_update(update: object) -> dict[str, object]:
    if isinstance(update, str):
        return {
            "advisory_id": None,
            "updated_at": _normalized_text(update, "invalid_advisory_update"),
        }
    identity = _read(update, "advisory_id", default=_MISSING)
    identity_kind = "generic"
    if identity is _MISSING:
        identity = _read(update, "ghsa_id", default=_MISSING)
        identity_kind = "ghsa"
    if identity is _MISSING:
        identity = _read(update, "cve_id", default=_MISSING)
        identity_kind = "cve"
    if identity is _MISSING:
        identity = _read(update, "id", default=None)
        identity_kind = "generic"
    return {
        "advisory_id": _optional_advisory_id(identity, identity_kind),
        "updated_at": _optional_normalized_text(
            _read(update, "updated_at", default=None),
            "invalid_advisory_update",
        ),
    }


def _optional_advisory_id(value: object, identity_kind: str) -> str | None:
    normalized = _optional_normalized_text(value, "invalid_advisory_id")
    if normalized is None:
        return None
    if not normalized.isascii():
        raise HashingError("invalid_advisory_id")
    if identity_kind == "ghsa":
        pattern = _GHSA_ID
    elif identity_kind == "cve":
        pattern = _CVE_ID
    elif normalized[:5].casefold() == "ghsa-":
        pattern = _GHSA_ID
    elif normalized[:4].casefold() == "cve-":
        pattern = _CVE_ID
    else:
        pattern = _GENERIC_ADVISORY_ID
    if pattern.fullmatch(normalized) is None:
        raise HashingError("invalid_advisory_id")
    return normalized.upper()


def _text_set(value: object, code: str, *, allow_none: bool = False) -> list[str]:
    if value is None and allow_none:
        return []
    values = _items(value, code, scalar_string=True)
    return sorted({_normalized_text(item, code) for item in values})


def _sorted_unique_objects(values: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    unique: dict[bytes, dict[str, object]] = {}
    for value in values:
        key = canonical_json_bytes(value)
        unique[key] = value
    return [unique[key] for key in sorted(unique)]


def _semantic_json_value(
    value: object,
    code: str,
    *,
    depth: int = 0,
    active: set[int] | None = None,
    node_count: list[int] | None = None,
) -> object:
    if depth > _MAX_CANONICAL_DEPTH:
        raise HashingError(code)
    if active is None:
        active = set()
    if node_count is None:
        node_count = [0]
    node_count[0] += 1
    if node_count[0] > _MAX_TOTAL_NODES:
        raise HashingError(code)
    if isinstance(value, Enum):
        try:
            enum_value = value.value
        except Exception:
            raise HashingError(code) from None
        return _semantic_json_value(
            enum_value,
            code,
            depth=depth,
            active=active,
            node_count=node_count,
        )
    if value is None or type(value) in (str, bool, int, float):
        if isinstance(value, str):
            return _required_text(value, code)
        if isinstance(value, float) and not math.isfinite(value):
            raise HashingError(code)
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise HashingError(code)
        items = _bounded_mapping_items(value, code)
        active.add(identity)
        result: dict[str, object] = {}
        try:
            for key, child in items:
                if type(key) is not str or len(key) > _MAX_TEXT_LENGTH:
                    raise HashingError(code)
                result[key] = _semantic_json_value(
                    child,
                    code,
                    depth=depth + 1,
                    active=active,
                    node_count=node_count,
                )
        finally:
            active.remove(identity)
        return result
    if isinstance(value, (list, tuple)):
        values = _items(value, code)
        identity = id(value)
        if identity in active:
            raise HashingError(code)
        active.add(identity)
        try:
            return [
                _semantic_json_value(
                    child,
                    code,
                    depth=depth + 1,
                    active=active,
                    node_count=node_count,
                )
                for child in values
            ]
        finally:
            active.remove(identity)
    raise HashingError(code)


def _bounded_mapping_items(
    value: Mapping[object, object], code: str
) -> list[tuple[object, object]]:
    result: list[tuple[object, object]] = []
    try:
        iterator = iter(value.items())
        for _ in range(_MAX_COLLECTION_ITEMS + 1):
            try:
                item = next(iterator)
            except StopIteration:
                return result
            if not isinstance(item, tuple) or len(item) != 2:
                raise HashingError(code)
            result.append(item)
    except Exception:
        raise HashingError(code) from None
    raise HashingError(code)


def _digest_value(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _SHA256.fullmatch(value) is None
    ):
        raise HashingError("invalid_component_hash")
    return value


def _privacy_scan(
    root: object,
    *,
    allowed_path_keys: frozenset[str] = frozenset(),
    allowed_timestamp_keys: frozenset[str] = frozenset(),
    allowed_layout_keys: frozenset[str] = frozenset(),
    ignored_keys: frozenset[str] = frozenset(),
) -> None:
    active: set[int] = set()
    node_count = 0

    def visit(value: object, key_name: str | None, depth: int) -> None:
        nonlocal node_count
        if depth > _MAX_CANONICAL_DEPTH:
            raise HashingError("invalid_hash_input")
        node_count += 1
        if node_count > _MAX_TOTAL_NODES:
            raise HashingError("invalid_hash_input")
        if key_name is not None:
            normalized_key = key_name.casefold()
            if normalized_key in ignored_keys:
                return
            if _is_sensitive_key(normalized_key):
                raise HashingError("forbidden_sensitive_field")
            if _is_timestamp_key(normalized_key) and normalized_key not in allowed_timestamp_keys:
                raise HashingError("forbidden_timestamp")
            if _is_path_key(normalized_key) and normalized_key not in allowed_path_keys:
                if normalized_key in {
                    "environment_path",
                    "executable",
                    "metadata_path",
                    "site_packages",
                }:
                    raise HashingError("forbidden_path_field")
                if type(value) is str and _looks_absolute_path(value):
                    raise HashingError("forbidden_path")
                raise HashingError("forbidden_path_field")
            if normalized_key in _LAYOUT_KEYS and normalized_key not in allowed_layout_keys:
                raise HashingError("forbidden_database_layout")
        if type(value) is str:
            if len(value) > _MAX_TEXT_LENGTH:
                raise HashingError("invalid_hash_input")
            if _looks_absolute_path(value) and key_name not in allowed_path_keys:
                raise HashingError("forbidden_path")
            return
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in active:
                raise HashingError("invalid_hash_input")
            items = _bounded_mapping_items(value, "invalid_hash_input")
            active.add(identity)
            try:
                for key, child in items:
                    if type(key) is not str or len(key) > _MAX_TEXT_LENGTH:
                        raise HashingError("invalid_hash_input")
                    visit(child, key.casefold(), depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(value, (list, tuple, set, frozenset)):
            values = _items(value, "invalid_hash_input")
            identity = id(value)
            if identity in active:
                raise HashingError("invalid_hash_input")
            active.add(identity)
            try:
                for child in values:
                    visit(child, key_name, depth + 1)
            finally:
                active.remove(identity)
            return
        if is_dataclass(value) and not isinstance(value, type):
            identity = id(value)
            if identity in active:
                raise HashingError("invalid_hash_input")
            active.add(identity)
            try:
                try:
                    dataclass_fields = fields(value)
                except Exception:
                    raise HashingError("invalid_hash_input") from None
                if len(dataclass_fields) > _MAX_COLLECTION_ITEMS:
                    raise HashingError("invalid_hash_input")
                for field in dataclass_fields:
                    try:
                        child = getattr(value, field.name)
                    except Exception:
                        raise HashingError("invalid_hash_input") from None
                    visit(child, field.name.casefold(), depth + 1)
            finally:
                active.remove(identity)

    visit(root, None, 0)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.replace("-", "_").casefold()
    if normalized in _SENSITIVE_KEY_PARTS:
        return True
    if any(part in _SENSITIVE_KEY_PARTS for part in normalized.split("_")):
        return True
    compact = re.sub(r"[^a-z0-9]", "", normalized, flags=re.ASCII)
    return compact.startswith("sig") or any(
        part in compact
        for part in (
            "apikey",
            "authorization",
            "bearer",
            "credential",
            "passwd",
            "password",
            "secret",
            "signature",
            "token",
            "username",
        )
    )


def _is_timestamp_key(key: str) -> bool:
    normalized = key.replace("-", "_").casefold()
    return (
        normalized.endswith("_at")
        or normalized.endswith("_time")
        or "timestamp" in normalized
        or normalized in {"datetime", "time"}
    )


def _is_path_key(key: str) -> bool:
    normalized = key.replace("-", "_").casefold()
    return (
        normalized == "path"
        or normalized.endswith("_path")
        or normalized.startswith("path_")
        or normalized in {"executable", "site_packages"}
    )


def _looks_absolute_path(value: str) -> bool:
    candidate = value.strip()
    if not candidate:
        return False
    if _WINDOWS_DRIVE.match(candidate) is not None:
        return True
    if _URL.match(candidate):
        return False
    if (
        posixpath.isabs(candidate)
        or ntpath.isabs(candidate)
    ):
        return True
    return False


def _validate_public_url(value: str) -> None:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise HashingError("invalid_public_url")
    try:
        parsed = urlsplit(value)
    except Exception:
        raise HashingError("invalid_public_url") from None
    if not parsed.scheme:
        if _PUBLIC_SOURCE_NAME.fullmatch(value) is None:
            raise HashingError("invalid_public_url")
        return
    if parsed.scheme.casefold() not in {"http", "https"}:
        raise HashingError("invalid_public_url")
    _validate_split_url(parsed, "invalid_public_url")


def _validate_split_url(parsed: object, code: str) -> None:
    try:
        scheme = parsed.scheme  # type: ignore[attr-defined]
        netloc = parsed.netloc  # type: ignore[attr-defined]
        hostname = parsed.hostname  # type: ignore[attr-defined]
        username = parsed.username  # type: ignore[attr-defined]
        password = parsed.password  # type: ignore[attr-defined]
        query = parsed.query  # type: ignore[attr-defined]
        fragment = parsed.fragment  # type: ignore[attr-defined]
        path = parsed.path  # type: ignore[attr-defined]
        parsed.port  # type: ignore[attr-defined]
    except Exception:
        raise HashingError(code) from None
    if not scheme or not netloc or hostname is None:
        raise HashingError(code)
    if username is not None or password is not None:
        raise HashingError("forbidden_sensitive_field")
    try:
        query_fields = parse_qsl(query, keep_blank_values=True)
    except Exception:
        raise HashingError(code) from None
    if any(_is_sensitive_key(key) for key, _ in query_fields):
        raise HashingError("forbidden_sensitive_field")
    if query or fragment:
        raise HashingError(code)
    try:
        decoded_path = unquote(path)
    except Exception:
        raise HashingError(code) from None
    normalized_path = decoded_path.replace("\\", "/")
    if any(part in {".", ".."} for part in normalized_path.split("/")):
        raise HashingError(code)
