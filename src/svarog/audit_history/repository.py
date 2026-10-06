"""Validated, race-safe persistence for audit runs and immutable snapshots.

``HistoryRepository`` owns no connection lifecycle.  Callers provide one configured
SQLite connection (normally ``DatabaseManager.connection``) and may use:

* :meth:`start_run` before analysis;
* :meth:`mark_run_failed` or :meth:`mark_run_interrupted` on terminal failure; and
* :meth:`save_run` to atomically create/finish, or finish an existing started run.

All public records are frozen.  Snapshot inputs are completely validated and their
authoritative JSON value is copied before any repository write transaction begins.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import ipaddress
import json
import math
import posixpath
from pathlib import PurePosixPath, PureWindowsPath
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Generic, TypeVar
import unicodedata
from urllib.parse import unquote, urlsplit
from uuid import UUID

from .codec import HistoryCodecError, SnapshotResultCache, decode_result, encode_result
from .database import immediate_transaction
from .errors import HistoryDatabaseError
from .models import FindingStatus, PackageScope, RunStatus


_AUDIT_KINDS = frozenset({"python_environment", "python_project"})
_AUDIT_STATUSES = frozenset(
    {
        "completed_clean",
        "completed_with_findings",
        "completed_incomplete",
        "completed_with_findings_and_gaps",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROJECT_ID = re.compile(r"proj_[0-9a-f]{32}\Z", re.ASCII)
_FAILURE_CODE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z", re.ASCII)
_COMPONENT_KEY = re.compile(r"\S{1,512}\Z", re.ASCII)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_SQLITE_UNIQUE_PREFIX = "UNIQUE constraint failed: "
_SNAPSHOT_COMPOSITE_UNIQUE_COLUMNS = frozenset(
    {
        "audit_snapshots.project_id",
        "audit_snapshots.audit_kind",
        "audit_snapshots.composite_hash",
    }
)
_SOURCE_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}\Z", re.ASCII)
_FULL_GIT_REVISION = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z", re.ASCII)
_OPAQUE_SOURCE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}\Z", re.ASCII)
_WINDOWS_DRIVE_PREFIX = re.compile(r"[A-Za-z]:", re.ASCII)
_DNS_LABEL = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII
)
_LOCAL_SOURCE_KINDS = frozenset({"path", "editable", "virtual", "workspace"})
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_SENSITIVE_IDENTITY_PARTS = frozenset(
    {
        "auth",
        "authorization",
        "credential",
        "credentials",
        "password",
        "secret",
        "token",
        "username",
    }
)

MAX_PACKAGES = 50_000
MAX_DEPENDENCIES = 100_000
MAX_FINDINGS = 10_000
MAX_ISSUES = 10_000
MAX_COUNT = 1_000_000
MAX_TEXT = 4_096
MAX_DETAIL = 16_384
MAX_KNOWLEDGE_SOURCES = 256
MAX_RESULT_NODES = 100_000
MAX_SOURCE_IDENTITY = 2_048
MAX_BASELINE_SCAN = 10_000
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
MAX_PAGE_OFFSET = 100_000

_T = TypeVar("_T")


def _error(code: str) -> HistoryDatabaseError:
    return HistoryDatabaseError(code)


def _required_text(value: object, *, limit: int = MAX_TEXT) -> str:
    if type(value) is not str or not value or len(value) > limit:
        raise _error("invalid_text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise _error("invalid_text") from None
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise _error("invalid_text")
    return value


def _optional_text(value: object, *, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    return _required_text(value, limit=limit)


def _project_id(value: object) -> str:
    if type(value) is not str or _PROJECT_ID.fullmatch(value) is None:
        raise _error("invalid_project_id")
    try:
        parsed = UUID(value[5:])
    except (ValueError, AttributeError):
        raise _error("invalid_project_id") from None
    if parsed.hex != value[5:] or parsed.version != 4:
        raise _error("invalid_project_id")
    return value


def _run_id(value: object) -> str:
    if type(value) is not str:
        raise _error("invalid_run_id")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise _error("invalid_run_id") from None
    if str(parsed) != value:
        raise _error("invalid_run_id")
    return value


def _optional_run_id(value: object) -> str | None:
    if value is None:
        return None
    return _run_id(value)


def _display_name(value: object) -> str:
    if type(value) is not str:
        raise _error("invalid_display_name")
    display_name = value.strip()
    if not display_name or len(display_name) > 128:
        raise _error("invalid_display_name")
    try:
        display_name.encode("utf-8", errors="strict")
    except UnicodeError:
        raise _error("invalid_display_name") from None
    if any(unicodedata.category(character) == "Cc" for character in display_name):
        raise _error("invalid_display_name")
    if PurePosixPath(display_name).is_absolute() or PureWindowsPath(display_name).is_absolute():
        raise _error("invalid_display_name")
    return display_name


def _is_snapshot_composite_unique_conflict(error: sqlite3.IntegrityError) -> bool:
    if getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_CONSTRAINT_UNIQUE:
        return False
    message = str(error)
    if not message.startswith(_SQLITE_UNIQUE_PREFIX):
        return False
    columns = tuple(
        column.strip() for column in message[len(_SQLITE_UNIQUE_PREFIX) :].split(",")
    )
    return (
        len(columns) == len(_SNAPSHOT_COMPOSITE_UNIQUE_COLUMNS)
        and frozenset(columns) == _SNAPSHOT_COMPOSITE_UNIQUE_COLUMNS
    )


def _source_identity(value: object, source_kind: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value or len(value) > MAX_SOURCE_IDENTITY:
        raise _error("invalid_source_identity")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise _error("invalid_source_identity") from None
    if value != value.strip() or any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        raise _error("invalid_source_identity")

    kind = source_kind.casefold()
    if _SOURCE_DIGEST.fullmatch(value) is not None:
        return value
    if kind == "git" and _FULL_GIT_REVISION.fullmatch(value) is not None:
        return value
    if kind in _LOCAL_SOURCE_KINDS:
        if not _is_normalized_relative_source_identity(value):
            raise _error("invalid_source_identity")
        return value
    if "://" in value or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", value):
        if not _is_safe_source_url(value):
            raise _error("invalid_source_identity")
        return value
    if (
        _OPAQUE_SOURCE_IDENTITY.fullmatch(value) is None
        or any(
            part.casefold() in _SENSITIVE_IDENTITY_PARTS
            for part in re.split(r"[._+-]+", value)
        )
    ):
        raise _error("invalid_source_identity")
    return value


def _is_normalized_relative_source_identity(value: str) -> bool:
    slash_path = value.replace("\\", "/")
    if (
        slash_path != value
        or slash_path.startswith(("/", "~"))
        or slash_path.casefold().startswith(("file:", "local:"))
        or _WINDOWS_DRIVE_PREFIX.match(slash_path) is not None
        or ":" in slash_path
    ):
        return False
    normalized = posixpath.normpath(slash_path)
    if normalized != slash_path or normalized == ".." or normalized.startswith("../"):
        return False
    if any(part in {"", ".."} for part in normalized.split("/")):
        return False
    return not any(
        part.split(".", 1)[0].rstrip(" ").casefold() in _WINDOWS_RESERVED_NAMES
        for part in normalized.split("/")
    )


def _is_safe_source_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except (UnicodeError, ValueError):
        return False
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in parsed.netloc
        or "\\" in parsed.path
        or parsed.netloc.count("@")
    ):
        return False
    if not _has_safe_url_encoding(
        parsed.netloc, reject_at=True, reject_whitespace=True
    ):
        return False
    if not _has_safe_url_encoding(
        parsed.path, reject_at=False, reject_whitespace=False
    ):
        return False
    if not _is_safe_source_hostname(hostname):
        return False
    return True


def _has_safe_url_encoding(
    value: str, *, reject_at: bool, reject_whitespace: bool
) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in "0123456789abcdefABCDEF"
            or value[index + 2] not in "0123456789abcdefABCDEF"
        ):
            return False
        index += 3
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except (UnicodeError, ValueError):
        return False
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or reject_whitespace and character.isspace()
        for character in decoded
    ):
        return False
    return not reject_at or "@" not in decoded


def _is_safe_source_hostname(hostname: str) -> bool:
    if "%" in hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    trailing_dot = hostname.endswith(".")
    dns_name = hostname[:-1] if trailing_dot else hostname
    try:
        ascii_name = dns_name.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return (
        bool(ascii_name)
        and len(ascii_name) <= 253
        and all(_DNS_LABEL.fullmatch(label) is not None for label in ascii_name.split("."))
    )


def _snapshot_id(value: object, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if type(value) is not int or value <= 0:
        raise _error("invalid_snapshot_id")
    return value


def _sha256(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _error("invalid_sha256")
    return value


def _timestamp(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise _error("invalid_timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _error("invalid_timestamp") from None
    return value


def _stored_timestamp(value: object) -> str:
    try:
        timestamp = _timestamp(value)
    except HistoryDatabaseError:
        raise _error("history_database_corrupt") from None
    if timestamp is None:  # defensive; stored timestamps validated here are required
        raise _error("history_database_corrupt")
    return timestamp


def _audit_kind(value: object) -> str:
    if type(value) is not str or value not in _AUDIT_KINDS:
        raise _error("invalid_audit_kind")
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        raise _error("invalid_count")
    return value


def _enum_value(value: object, enum_type: type[Any], code: str) -> str:
    if isinstance(value, enum_type):
        return str(value.value)
    if type(value) is str:
        try:
            return str(enum_type(value).value)
        except ValueError:
            pass
    raise _error(code)


def _component_key(value: object) -> str:
    if type(value) is not str or _COMPONENT_KEY.fullmatch(value) is None:
        raise _error("invalid_component_key")
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise _error("invalid_component_key")
    return value


def _failure_code(value: object) -> str:
    if type(value) is not str or _FAILURE_CODE.fullmatch(value) is None:
        raise _error("invalid_failure_code")
    return value


def _issue_code(value: object) -> str:
    try:
        return _failure_code(value)
    except HistoryDatabaseError:
        raise _error("invalid_issue_code") from None


def _page_limit(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_PAGE_SIZE:
        raise _error("invalid_limit")
    return value


def _page_offset(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_PAGE_OFFSET:
        raise _error("invalid_offset")
    return value


def _timestamp_range(
    lower: object, upper: object
) -> tuple[str | None, str | None]:
    start = _timestamp(lower, optional=True)
    end = _timestamp(upper, optional=True)
    if start is not None and end is not None and end < start:
        raise _error("invalid_timestamp_range")
    return start, end


def _stored_bool(value: object) -> bool:
    if type(value) is not int or value not in (0, 1):
        raise _error("history_database_corrupt")
    return bool(value)


def _bounded_tuple(value: object, limit: int, code: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise _error(code)
    try:
        iterator = iter(value)  # type: ignore[arg-type]
        items: list[object] = []
        for index in range(limit + 1):
            try:
                item = next(iterator)
            except StopIteration:
                return tuple(items)
            if index == limit:
                raise _error(code)
            items.append(item)
    except HistoryDatabaseError:
        raise
    except Exception:
        raise _error(code) from None
    raise _error(code)


def _freeze_json(
    value: object, *, depth: int = 0, work: list[int] | None = None
) -> object:
    try:
        return _freeze_json_value(value, depth=depth, work=work)
    except HistoryDatabaseError:
        raise
    except Exception:
        raise _error("invalid_result") from None


def _freeze_json_value(
    value: object, *, depth: int = 0, work: list[int] | None = None
) -> object:
    if work is None:
        work = [0]
    work[0] += 1
    if work[0] > MAX_RESULT_NODES:
        raise _error("invalid_result")
    if depth > 256:
        raise _error("invalid_result")
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise _error("invalid_result")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        if len(value) > 100_000:
            raise _error("invalid_result")
        for key, child in value.items():
            if type(key) is not str:
                raise _error("invalid_result")
            frozen[key] = _freeze_json(child, depth=depth + 1, work=work)
        return MappingProxyType(frozen)
    if value_type in (list, tuple):
        if len(value) > 100_000:
            raise _error("invalid_result")
        return tuple(_freeze_json(child, depth=depth + 1, work=work) for child in value)
    raise _error("invalid_result")


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


@dataclass(frozen=True, slots=True)
class PackageRow:
    """One normalized package row, including a version-specific component key."""

    scope: PackageScope | str
    raw_name: str
    normalized_name: str
    version: str
    version_valid: bool
    source_kind: str
    source_identity: str | None
    component_key: str
    is_direct: bool | None
    applicability_status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", PackageScope(_enum_value(self.scope, PackageScope, "invalid_package_scope")))
        for name in ("raw_name", "normalized_name", "version", "source_kind", "applicability_status"):
            object.__setattr__(self, name, _required_text(getattr(self, name)))
        object.__setattr__(
            self,
            "source_identity",
            _source_identity(self.source_identity, self.source_kind),
        )
        object.__setattr__(self, "component_key", _component_key(self.component_key))
        if type(self.version_valid) is not bool:
            raise _error("invalid_package_row")
        if self.is_direct is not None and type(self.is_direct) is not bool:
            raise _error("invalid_package_row")


@dataclass(frozen=True, slots=True)
class DependencyRow:
    """One normalized dependency edge."""

    parent_component_key: str
    child_component_key: str
    relationship_source: str
    resolution_status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "parent_component_key", _component_key(self.parent_component_key))
        object.__setattr__(self, "child_component_key", _component_key(self.child_component_key))
        object.__setattr__(self, "relationship_source", _required_text(self.relationship_source))
        object.__setattr__(self, "resolution_status", _required_text(self.resolution_status))


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One normalized vulnerability finding."""

    scope: PackageScope | str
    raw_name: str
    normalized_name: str
    audited_version: str
    ghsa_id: str | None
    cve_id: str | None
    advisory_id: str
    severity: str | None
    cvss: float | None
    affected_range: str | None
    fixed_versions: Sequence[str] | None
    finding_status: FindingStatus | str
    indeterminate_reason: str | None
    advisory_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", PackageScope(_enum_value(self.scope, PackageScope, "invalid_package_scope")))
        object.__setattr__(self, "finding_status", FindingStatus(_enum_value(self.finding_status, FindingStatus, "invalid_finding_status")))
        for name in ("raw_name", "normalized_name", "audited_version", "advisory_id"):
            object.__setattr__(self, name, _required_text(getattr(self, name)))
        for name in ("ghsa_id", "cve_id", "severity", "affected_range", "indeterminate_reason"):
            object.__setattr__(self, name, _optional_text(getattr(self, name)))
        if self.cvss is not None and (
            type(self.cvss) not in (int, float)
            or not math.isfinite(float(self.cvss))
            or not 0 <= float(self.cvss) <= 10
        ):
            raise _error("invalid_cvss")
        if self.cvss is not None:
            object.__setattr__(self, "cvss", float(self.cvss))
        if self.fixed_versions is None:
            versions = None
        else:
            versions = tuple(
                sorted({_required_text(item) for item in _bounded_tuple(self.fixed_versions, 10_000, "invalid_fixed_versions")})
            )
        object.__setattr__(self, "fixed_versions", versions)
        object.__setattr__(self, "advisory_fingerprint", _sha256(self.advisory_fingerprint))


@dataclass(frozen=True, slots=True)
class IssueRow:
    """One stable, bounded issue emitted while producing a snapshot."""

    issue_code: str
    subject: str | None
    detail: str | None
    ordinal: int

    def __post_init__(self) -> None:
        if type(self.issue_code) is not str or _FAILURE_CODE.fullmatch(self.issue_code) is None:
            raise _error("invalid_issue_code")
        object.__setattr__(self, "subject", _optional_text(self.subject))
        object.__setattr__(self, "detail", _optional_text(self.detail, limit=MAX_DETAIL))
        _count(self.ordinal)


@dataclass(frozen=True, slots=True)
class SnapshotInput:
    """Complete validated input needed to persist one authoritative audit result."""

    project_id: str
    display_name: str
    audit_kind: str
    started_at: str
    completed_at: str
    python_version: str
    environment_hash: str
    semantic_lock_hash: str | None
    knowledge_content_hash: str
    knowledge_metadata_hash: str
    evaluation_context_hash: str
    policy_hash: str
    analysis_contract_version: str
    composite_hash: str
    audit_status: str
    result_schema_version: str
    result: Mapping[str, object]
    knowledge_sources: Sequence[str] = ()
    knowledge_last_sync_at: str | None = None
    knowledge_sync_status: str | None = None
    environment_package_count: int = 0
    lock_package_count: int = 0
    affected_finding_count: int = 0
    indeterminate_finding_count: int = 0
    issue_count: int = 0
    warning_count: int = 0
    packages: Sequence[PackageRow] = ()
    dependencies: Sequence[DependencyRow] = ()
    findings: Sequence[FindingRow] = ()
    issues: Sequence[IssueRow] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_id", _project_id(self.project_id))
        object.__setattr__(self, "display_name", _display_name(self.display_name))
        kind = _audit_kind(self.audit_kind)
        object.__setattr__(self, "audit_kind", kind)
        started = _timestamp(self.started_at)
        completed = _timestamp(self.completed_at)
        if completed < started:  # canonical strings have chronological ordering
            raise _error("invalid_timestamp")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "python_version", _required_text(self.python_version, limit=128))
        for name in (
            "environment_hash",
            "knowledge_content_hash",
            "knowledge_metadata_hash",
            "evaluation_context_hash",
            "policy_hash",
            "composite_hash",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name)))
        lock_hash = _sha256(self.semantic_lock_hash, optional=True)
        if (kind == "python_project") != (lock_hash is not None):
            raise _error("invalid_semantic_lock_hash")
        object.__setattr__(self, "semantic_lock_hash", lock_hash)
        object.__setattr__(self, "analysis_contract_version", _required_text(self.analysis_contract_version, limit=128))
        if type(self.audit_status) is not str or self.audit_status not in _AUDIT_STATUSES:
            raise _error("invalid_audit_status")
        object.__setattr__(self, "result_schema_version", _required_text(self.result_schema_version, limit=128))
        if not isinstance(self.result, Mapping):
            raise _error("invalid_result")
        frozen_result = _freeze_json(self.result)
        if (
            frozen_result.get("audit_status") != self.audit_status
            or frozen_result.get("schema_version") != self.result_schema_version
        ):
            raise _error("result_metadata_mismatch")
        try:
            encode_result(_thaw_json(frozen_result))
        except HistoryCodecError as error:
            raise _error(error.code) from None
        object.__setattr__(self, "result", frozen_result)

        sources = _bounded_tuple(self.knowledge_sources, MAX_KNOWLEDGE_SOURCES, "invalid_knowledge_sources")
        object.__setattr__(self, "knowledge_sources", tuple(sorted({_required_text(item) for item in sources})))
        object.__setattr__(self, "knowledge_last_sync_at", _timestamp(self.knowledge_last_sync_at, optional=True))
        object.__setattr__(self, "knowledge_sync_status", _optional_text(self.knowledge_sync_status, limit=128))
        for name in (
            "environment_package_count",
            "lock_package_count",
            "affected_finding_count",
            "indeterminate_finding_count",
            "issue_count",
            "warning_count",
        ):
            _count(getattr(self, name))

        packages = _typed_rows(self.packages, PackageRow, MAX_PACKAGES, "too_many_packages")
        dependencies = _typed_rows(self.dependencies, DependencyRow, MAX_DEPENDENCIES, "too_many_dependencies")
        findings = _typed_rows(self.findings, FindingRow, MAX_FINDINGS, "too_many_findings")
        issues = _typed_rows(self.issues, IssueRow, MAX_ISSUES, "too_many_issues")
        _require_unique(packages, _package_identity)
        _require_unique(packages, lambda row: row.component_key)
        _require_unique(dependencies, _dependency_identity)
        _require_unique(findings, _finding_identity)
        _require_unique(issues, lambda row: row.ordinal)
        component_keys = {row.component_key for row in packages}
        if any(
            row.parent_component_key not in component_keys
            or row.child_component_key not in component_keys
            for row in dependencies
        ):
            raise _error("invalid_dependency_component")
        actual_counts = (
            sum(row.scope is PackageScope.ENVIRONMENT for row in packages),
            sum(row.scope is PackageScope.LOCK for row in packages),
            sum(row.finding_status is FindingStatus.AFFECTED for row in findings),
            sum(row.finding_status is FindingStatus.INDETERMINATE for row in findings),
            len(issues),
        )
        declared_counts = (
            self.environment_package_count,
            self.lock_package_count,
            self.affected_finding_count,
            self.indeterminate_finding_count,
            self.issue_count,
        )
        if actual_counts != declared_counts:
            raise _error("snapshot_count_mismatch")
        object.__setattr__(self, "packages", packages)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "issues", issues)


def _typed_rows(value: object, row_type: type[Any], limit: int, code: str) -> tuple[Any, ...]:
    rows = _bounded_tuple(value, limit, code)
    if not all(type(row) is row_type for row in rows):
        raise _error("invalid_history_row")
    return rows


def _require_unique(rows: Sequence[Any], identity: Any) -> None:
    seen: set[object] = set()
    for row in rows:
        key = identity(row)
        if key in seen:
            raise _error("duplicate_history_row")
        seen.add(key)


def _package_identity(row: PackageRow) -> tuple[object, ...]:
    return row.scope.value, row.component_key, row.version, row.source_kind


def _dependency_identity(row: DependencyRow) -> tuple[str, str, str, str]:
    return (
        row.parent_component_key,
        row.child_component_key,
        row.relationship_source,
        row.resolution_status,
    )


def _finding_identity(row: FindingRow) -> tuple[object, ...]:
    return (
        row.scope.value,
        row.normalized_name,
        row.audited_version,
        row.advisory_id,
        row.advisory_fingerprint,
        row.finding_status.value,
    )


@dataclass(frozen=True, slots=True)
class SaveRunResult:
    """Identity and reuse outcome of a successful :meth:`save_run`."""

    run_id: str
    snapshot_id: int
    reused: bool
    baseline_run_id: str | None
    status: RunStatus

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _run_id(self.run_id))
        object.__setattr__(self, "snapshot_id", _snapshot_id(self.snapshot_id))
        if type(self.reused) is not bool:
            raise _error("invalid_save_run_result")
        baseline = _optional_run_id(self.baseline_run_id)
        if baseline == self.run_id:
            raise _error("invalid_save_run_result")
        object.__setattr__(self, "baseline_run_id", baseline)
        try:
            status = RunStatus(self.status)
        except (TypeError, ValueError):
            raise _error("invalid_save_run_result") from None
        expected = (
            RunStatus.COMPLETED_REUSED
            if self.reused
            else RunStatus.COMPLETED_COMPUTED
        )
        if status is not expected:
            raise _error("invalid_save_run_result")
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Immutable public representation of an ``audit_runs`` row."""

    run_id: str
    project_id: str
    audit_kind: str
    snapshot_id: int | None
    baseline_run_id: str | None
    started_at: str
    completed_at: str | None
    status: RunStatus
    reused: bool
    python_version: str | None
    environment_hash: str | None
    semantic_lock_hash: str | None
    knowledge_content_hash: str | None
    knowledge_metadata_hash: str | None
    evaluation_context_hash: str | None
    policy_hash: str | None
    analysis_contract_version: str | None
    composite_hash: str | None
    result_schema_version: str | None
    knowledge_sources: tuple[str, ...]
    knowledge_last_sync_at: str | None
    knowledge_sync_status: str | None
    warning_count: int
    failure_code: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _run_id(self.run_id))
        object.__setattr__(self, "project_id", _project_id(self.project_id))
        object.__setattr__(self, "audit_kind", _audit_kind(self.audit_kind))
        object.__setattr__(
            self, "snapshot_id", _snapshot_id(self.snapshot_id, optional=True)
        )
        baseline = _optional_run_id(self.baseline_run_id)
        if baseline == self.run_id:
            raise _error("invalid_run_record")
        object.__setattr__(self, "baseline_run_id", baseline)
        started_at = _timestamp(self.started_at)
        completed_at = _timestamp(self.completed_at, optional=True)
        if completed_at is not None and completed_at < started_at:
            raise _error("invalid_run_record")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "completed_at", completed_at)
        try:
            status = RunStatus(self.status)
        except (TypeError, ValueError):
            raise _error("invalid_run_record") from None
        object.__setattr__(self, "status", status)
        if type(self.reused) is not bool:
            raise _error("invalid_run_record")

        object.__setattr__(
            self, "python_version", _optional_text(self.python_version, limit=128)
        )
        for name in (
            "environment_hash",
            "semantic_lock_hash",
            "knowledge_content_hash",
            "knowledge_metadata_hash",
            "evaluation_context_hash",
            "policy_hash",
            "composite_hash",
        ):
            object.__setattr__(
                self, name, _sha256(getattr(self, name), optional=True)
            )
        object.__setattr__(
            self,
            "analysis_contract_version",
            _optional_text(self.analysis_contract_version, limit=128),
        )
        object.__setattr__(
            self,
            "result_schema_version",
            _optional_text(self.result_schema_version, limit=128),
        )
        sources = tuple(
            _required_text(item)
            for item in _bounded_tuple(
                self.knowledge_sources,
                MAX_KNOWLEDGE_SOURCES,
                "invalid_knowledge_sources",
            )
        )
        if sources != tuple(sorted(set(sources))):
            raise _error("invalid_run_record")
        object.__setattr__(self, "knowledge_sources", sources)
        object.__setattr__(
            self,
            "knowledge_last_sync_at",
            _timestamp(self.knowledge_last_sync_at, optional=True),
        )
        object.__setattr__(
            self,
            "knowledge_sync_status",
            _optional_text(self.knowledge_sync_status, limit=128),
        )
        _count(self.warning_count)
        if self.failure_code is not None:
            object.__setattr__(self, "failure_code", _failure_code(self.failure_code))

        detail_values = (
            self.python_version,
            self.environment_hash,
            self.knowledge_content_hash,
            self.knowledge_metadata_hash,
            self.evaluation_context_hash,
            self.policy_hash,
            self.analysis_contract_version,
            self.composite_hash,
            self.result_schema_version,
        )
        if status is RunStatus.STARTED:
            if (
                self.snapshot_id is not None
                or self.baseline_run_id is not None
                or completed_at is not None
                or self.reused
                or any(value is not None for value in detail_values)
                or self.semantic_lock_hash is not None
                or sources
                or self.knowledge_last_sync_at is not None
                or self.knowledge_sync_status is not None
                or self.warning_count != 0
                or self.failure_code is not None
            ):
                raise _error("invalid_run_record")
            return

        if status in (RunStatus.FAILED, RunStatus.INTERRUPTED):
            if (
                self.snapshot_id is not None
                or self.baseline_run_id is not None
                or completed_at is None
                or self.reused
                or any(value is not None for value in detail_values)
                or self.semantic_lock_hash is not None
                or sources
                or self.knowledge_last_sync_at is not None
                or self.knowledge_sync_status is not None
                or self.warning_count != 0
                or self.failure_code is None
            ):
                raise _error("invalid_run_record")
            return

        expected_reused = status is RunStatus.COMPLETED_REUSED
        if (
            status not in (RunStatus.COMPLETED_COMPUTED, RunStatus.COMPLETED_REUSED)
            or self.snapshot_id is None
            or completed_at is None
            or self.reused is not expected_reused
            or any(value is None for value in detail_values)
            or self.failure_code is not None
            or (self.audit_kind == "python_project")
            != (self.semantic_lock_hash is not None)
        ):
            raise _error("invalid_run_record")

    @property
    def run_status(self) -> RunStatus:
        """Storage-name alias retained for callers that mirror the schema."""

        return self.status


@dataclass(frozen=True, slots=True)
class HistoryPage(Generic[_T]):
    """One immutable, bounded query page with its stable filtered total."""

    items: tuple[_T, ...]
    total_count: int
    limit: int
    offset: int

    def __post_init__(self) -> None:
        if type(self.items) is not tuple:
            raise _error("invalid_history_page")
        _count(self.total_count)
        _page_limit(self.limit)
        _page_offset(self.offset)
        if len(self.items) > self.limit or self.total_count < len(self.items):
            raise _error("invalid_history_page")


@dataclass(frozen=True, slots=True)
class SnapshotSummary:
    """Small snapshot metadata used by history lists; never contains result bytes."""

    snapshot_id: int
    project_id: str
    audit_kind: str
    created_at: str
    last_used_at: str
    python_version: str
    audit_status: str
    environment_package_count: int
    lock_package_count: int
    affected_finding_count: int
    indeterminate_finding_count: int
    issue_count: int
    warning_count: int
    result_schema_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _snapshot_id(self.snapshot_id))
        object.__setattr__(self, "project_id", _project_id(self.project_id))
        object.__setattr__(self, "audit_kind", _audit_kind(self.audit_kind))
        created_at = _timestamp(self.created_at)
        last_used_at = _timestamp(self.last_used_at)
        if last_used_at < created_at:
            raise _error("invalid_snapshot_summary")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "last_used_at", last_used_at)
        object.__setattr__(
            self, "python_version", _required_text(self.python_version, limit=128)
        )
        if type(self.audit_status) is not str or self.audit_status not in _AUDIT_STATUSES:
            raise _error("invalid_snapshot_summary")
        for name in (
            "environment_package_count",
            "lock_package_count",
            "affected_finding_count",
            "indeterminate_finding_count",
            "issue_count",
            "warning_count",
        ):
            _count(getattr(self, name))
        object.__setattr__(
            self,
            "result_schema_version",
            _required_text(self.result_schema_version, limit=128),
        )


@dataclass(frozen=True, slots=True)
class SnapshotDetail:
    """Validated snapshot metadata excluding the compressed authoritative result."""

    summary: SnapshotSummary
    environment_hash: str
    semantic_lock_hash: str | None
    knowledge_content_hash: str
    knowledge_metadata_hash: str
    evaluation_context_hash: str
    policy_hash: str
    analysis_contract_version: str
    composite_hash: str
    result_json_sha256: str
    result_json_size: int

    def __post_init__(self) -> None:
        if type(self.summary) is not SnapshotSummary:
            raise _error("invalid_snapshot_detail")
        for name in (
            "environment_hash",
            "knowledge_content_hash",
            "knowledge_metadata_hash",
            "evaluation_context_hash",
            "policy_hash",
            "composite_hash",
            "result_json_sha256",
        ):
            object.__setattr__(self, name, _sha256(getattr(self, name)))
        lock_hash = _sha256(self.semantic_lock_hash, optional=True)
        if (self.summary.audit_kind == "python_project") != (lock_hash is not None):
            raise _error("invalid_snapshot_detail")
        object.__setattr__(self, "semantic_lock_hash", lock_hash)
        object.__setattr__(
            self,
            "analysis_contract_version",
            _required_text(self.analysis_contract_version, limit=128),
        )
        if (
            type(self.result_json_size) is not int
            or not 0 <= self.result_json_size <= 16 * 1024 * 1024
        ):
            raise _error("invalid_snapshot_detail")


@dataclass(frozen=True, slots=True)
class CompatibleRunChoice:
    """A successful run choice, including reuse and same-snapshot semantics."""

    run_id: str
    snapshot_id: int
    completed_at: str
    status: RunStatus
    reused: bool
    same_snapshot: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _run_id(self.run_id))
        object.__setattr__(self, "snapshot_id", _snapshot_id(self.snapshot_id))
        object.__setattr__(self, "completed_at", _timestamp(self.completed_at))
        try:
            status = RunStatus(self.status)
        except (TypeError, ValueError):
            raise _error("invalid_compatible_run") from None
        if status not in (RunStatus.COMPLETED_COMPUTED, RunStatus.COMPLETED_REUSED):
            raise _error("invalid_compatible_run")
        object.__setattr__(self, "status", status)
        if type(self.reused) is not bool or type(self.same_snapshot) is not bool:
            raise _error("invalid_compatible_run")
        if self.reused is not (status is RunStatus.COMPLETED_REUSED):
            raise _error("invalid_compatible_run")


@dataclass(frozen=True, slots=True)
class FindingFirstSeen:
    """The deterministic earliest successful run containing one finding."""

    project_id: str
    audit_kind: str
    ghsa_id: str | None
    cve_id: str | None
    scope: PackageScope
    normalized_name: str
    audited_version: str
    advisory_id: str
    advisory_fingerprint: str
    finding_status: FindingStatus
    run_id: str
    snapshot_id: int
    completed_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_id", _project_id(self.project_id))
        object.__setattr__(self, "audit_kind", _audit_kind(self.audit_kind))
        object.__setattr__(self, "ghsa_id", _optional_text(self.ghsa_id))
        object.__setattr__(self, "cve_id", _optional_text(self.cve_id))
        if (self.ghsa_id is None) == (self.cve_id is None):
            # Stored findings may legitimately have both identities.  The returned
            # record keeps both, but it must have at least one advisory identity.
            if self.ghsa_id is None:
                raise _error("invalid_first_seen")
        object.__setattr__(
            self,
            "scope",
            PackageScope(
                _enum_value(self.scope, PackageScope, "invalid_package_scope")
            ),
        )
        object.__setattr__(self, "normalized_name", _required_text(self.normalized_name))
        object.__setattr__(self, "audited_version", _required_text(self.audited_version))
        object.__setattr__(self, "advisory_id", _required_text(self.advisory_id))
        object.__setattr__(
            self, "advisory_fingerprint", _sha256(self.advisory_fingerprint)
        )
        object.__setattr__(
            self,
            "finding_status",
            FindingStatus(
                _enum_value(
                    self.finding_status,
                    FindingStatus,
                    "invalid_finding_status",
                )
            ),
        )
        object.__setattr__(self, "run_id", _run_id(self.run_id))
        object.__setattr__(self, "snapshot_id", _snapshot_id(self.snapshot_id))
        object.__setattr__(self, "completed_at", _timestamp(self.completed_at))


_RUN_COLUMNS = (
    "run_id, project_id, audit_kind, snapshot_id, baseline_run_id, started_at, "
    "completed_at, run_status, reused, python_version, environment_hash, "
    "semantic_lock_hash, knowledge_content_hash, knowledge_metadata_hash, "
    "evaluation_context_hash, policy_hash, analysis_contract_version, composite_hash, "
    "result_schema_version, knowledge_sources_json, knowledge_last_sync_at, "
    "knowledge_sync_status, warning_count, failure_code"
)

_SNAPSHOT_MATCH_COLUMNS = (
    "snapshot_id, environment_hash, semantic_lock_hash, knowledge_content_hash, "
    "evaluation_context_hash, policy_hash, analysis_contract_version"
)

_SNAPSHOT_SUMMARY_COLUMNS = (
    "snapshot_id, project_id, audit_kind, created_at, last_used_at, python_version, "
    "audit_status, environment_package_count, lock_package_count, "
    "affected_finding_count, indeterminate_finding_count, issue_count, warning_count, "
    "schema_version"
)

_SNAPSHOT_DETAIL_COLUMNS = (
    f"{_SNAPSHOT_SUMMARY_COLUMNS}, environment_hash, semantic_lock_hash, "
    "knowledge_content_hash, knowledge_metadata_hash, evaluation_context_hash, "
    "policy_hash, analysis_contract_version, composite_hash, result_json_sha256, "
    "result_json_size"
)

_FIRST_SEEN_COLUMNS = (
    "r.project_id, r.audit_kind, f.ghsa_id, f.cve_id, f.scope, "
    "f.normalized_name, f.audited_version, f.advisory_id, "
    "f.advisory_fingerprint, f.finding_status, r.run_id, r.snapshot_id, "
    "r.completed_at"
)
_FIRST_SEEN_ORDER = (
    "r.completed_at ASC, r.run_id ASC, f.scope ASC, f.normalized_name ASC, "
    "f.audited_version ASC, f.advisory_id ASC, f.advisory_fingerprint ASC, "
    "f.finding_status ASC, r.snapshot_id ASC LIMIT 1"
)


def _run_history_sql(where: str) -> str:
    """Build the exact production run-page statement for plan assertions."""

    return (
        f"SELECT {_RUN_COLUMNS} FROM audit_runs WHERE {where} "
        "ORDER BY COALESCE(completed_at, started_at) DESC, run_id DESC "
        "LIMIT ? OFFSET ?"
    )


def _first_seen_sql(advisory_kind: str, *, include_version: bool) -> str:
    """Return one of the two index-specific production first-seen statements."""

    version = " AND f.audited_version = ?" if include_version else ""
    if advisory_kind == "ghsa":
        return (
            f"SELECT {_FIRST_SEEN_COLUMNS} FROM snapshot_findings AS f INDEXED BY "
            "idx_snapshot_findings_advisory_name "
            "JOIN audit_runs AS r ON r.snapshot_id = f.snapshot_id "
            "WHERE f.ghsa_id = ? AND f.normalized_name = ? "
            "AND r.project_id = ? AND r.audit_kind = ? "
            "AND r.run_status IN (?, ?) AND r.completed_at IS NOT NULL"
            + version
            + f" ORDER BY {_FIRST_SEEN_ORDER}"
        )
    if advisory_kind == "cve":
        return (
            f"SELECT {_FIRST_SEEN_COLUMNS} FROM snapshot_findings AS f INDEXED BY "
            "idx_snapshot_findings_cve_name "
            "CROSS JOIN audit_runs AS r INDEXED BY idx_audit_runs_snapshot "
            "ON r.snapshot_id = f.snapshot_id "
            "WHERE f.cve_id = ? AND f.normalized_name = ? "
            "AND r.project_id = ? AND r.audit_kind = ? "
            "AND r.run_status IN (?, ?) AND r.completed_at IS NOT NULL"
            + version
            + f" ORDER BY {_FIRST_SEEN_ORDER}"
        )
    raise _error("invalid_finding_lookup")


class HistoryRepository:
    """Persist validated audit history using one caller-owned connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise _error("invalid_history_connection")
        self._connection = connection
        self._result_cache = SnapshotResultCache(capacity=5)
        self._result_signatures: OrderedDict[int, tuple[int, str, bytes]] = OrderedDict()

    def start_run(
        self,
        *,
        run_id: str,
        project_id: str,
        display_name: str,
        audit_kind: str,
        started_at: str,
    ) -> RunRecord:
        """Persist a started run; an exact retry is idempotent."""

        run_id = _run_id(run_id)
        project_id = _project_id(project_id)
        display_name = _display_name(display_name)
        audit_kind = _audit_kind(audit_kind)
        started_at = _timestamp(started_at)  # type: ignore[assignment]
        try:
            with immediate_transaction(self._connection):
                self._ensure_project(project_id, display_name, started_at)
                row = self._select_run(run_id)
                if row is None:
                    self._connection.execute(
                        "INSERT INTO audit_runs "
                        "(run_id, project_id, audit_kind, snapshot_id, baseline_run_id, "
                        "started_at, completed_at, run_status, reused, python_version, "
                        "environment_hash, semantic_lock_hash, knowledge_content_hash, "
                        "knowledge_metadata_hash, evaluation_context_hash, policy_hash, "
                        "analysis_contract_version, composite_hash, result_schema_version, "
                        "knowledge_sources_json, knowledge_last_sync_at, knowledge_sync_status, "
                        "warning_count, failure_code) "
                        "VALUES (?, ?, ?, NULL, NULL, ?, NULL, ?, 0, NULL, NULL, NULL, "
                        "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL)",
                        (run_id, project_id, audit_kind, started_at, RunStatus.STARTED.value),
                    )
                elif not self._same_started_scope(
                    row, project_id=project_id, audit_kind=audit_kind, started_at=started_at
                ):
                    raise _error("run_id_conflict")
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        return self.get_run(run_id)

    def mark_run_failed(
        self, run_id: str, *, completed_at: str, failure_code: str
    ) -> RunRecord:
        """Finish a started run as failed with a stable non-sensitive code."""

        return self._mark_terminal(
            run_id,
            completed_at=completed_at,
            failure_code=failure_code,
            status=RunStatus.FAILED,
        )

    def mark_run_interrupted(
        self,
        run_id: str,
        *,
        completed_at: str,
        failure_code: str = "interrupted",
    ) -> RunRecord:
        """Finish a started run as interrupted with a stable non-sensitive code."""

        return self._mark_terminal(
            run_id,
            completed_at=completed_at,
            failure_code=failure_code,
            status=RunStatus.INTERRUPTED,
        )

    def _mark_terminal(
        self,
        run_id: str,
        *,
        completed_at: str,
        failure_code: str,
        status: RunStatus,
    ) -> RunRecord:
        run_id = _run_id(run_id)
        completed_at = _timestamp(completed_at)  # type: ignore[assignment]
        failure_code = _failure_code(failure_code)
        try:
            with immediate_transaction(self._connection):
                row = self._select_run(run_id)
                if row is None:
                    raise _error("run_not_found")
                started_at = _stored_timestamp(row[5])
                if row[7] != RunStatus.STARTED.value or completed_at < started_at:
                    raise _error("run_state_conflict")
                cursor = self._connection.execute(
                    "UPDATE audit_runs SET snapshot_id = NULL, baseline_run_id = NULL, "
                    "completed_at = ?, run_status = ?, reused = 0, failure_code = ? "
                    "WHERE run_id = ? AND run_status = ?",
                    (completed_at, status.value, failure_code, run_id, RunStatus.STARTED.value),
                )
                if cursor.rowcount != 1:
                    raise _error("run_state_conflict")
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        return self.get_run(run_id)

    def save_run(self, snapshot: SnapshotInput, *, run_id: str) -> SaveRunResult:
        """Atomically save/reuse a snapshot and complete one run."""

        if type(snapshot) is not SnapshotInput:
            raise _error("invalid_snapshot_input")
        run_id = _run_id(run_id)
        # Encoding is deliberately before BEGIN IMMEDIATE: result validation and the
        # bounded compression work never hold the writer lock.
        try:
            encoded = encode_result(_thaw_json(snapshot.result))
        except HistoryCodecError as error:
            raise _error(error.code) from None
        sources_json = json.dumps(
            list(snapshot.knowledge_sources), ensure_ascii=False, separators=(",", ":")
        )
        snapshot_insert_conflict_candidate = False
        try:
            with immediate_transaction(self._connection):
                self._prepare_started_run(snapshot, run_id)
                baseline = self._select_baseline(snapshot, run_id)
                existing = self._select_snapshot(snapshot)
                if existing is not None:
                    snapshot_id = self._verified_snapshot_id(existing, snapshot)
                    self._touch_snapshot(snapshot_id, snapshot.completed_at)
                    reused = True
                else:
                    snapshot_insert_conflict_candidate = True
                    snapshot_id = self._insert_snapshot(snapshot, encoded)
                    snapshot_insert_conflict_candidate = False
                    self._insert_normalized_rows(snapshot_id, snapshot)
                    reused = False
                self._complete_run(
                    snapshot,
                    run_id,
                    snapshot_id=snapshot_id,
                    baseline_run_id=baseline,
                    reused=reused,
                    sources_json=sources_json,
                )
                self._complete_project(snapshot)
        except HistoryDatabaseError:
            raise
        except sqlite3.IntegrityError as error:
            if (
                not snapshot_insert_conflict_candidate
                or not _is_snapshot_composite_unique_conflict(error)
            ):
                raise _error("history_database_failed") from None
            return self._recover_snapshot_insert_conflict(
                snapshot, run_id=run_id, sources_json=sources_json
            )
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

        status = RunStatus.COMPLETED_REUSED if reused else RunStatus.COMPLETED_COMPUTED
        return SaveRunResult(run_id, snapshot_id, reused, baseline, status)

    def find_exact_snapshot_id(
        self, project_id: str, audit_kind: str, composite_hash: str
    ) -> int | None:
        """Check for an exact result without loading or computing its report."""

        project_id = _project_id(project_id)
        audit_kind = _audit_kind(audit_kind)
        composite_hash = _sha256(composite_hash)  # type: ignore[assignment]
        try:
            row = self._connection.execute(
                "SELECT snapshot_id FROM audit_snapshots WHERE project_id = ? "
                "AND audit_kind = ? AND composite_hash = ?",
                (project_id, audit_kind, composite_hash),
            ).fetchone()
            return None if row is None else _snapshot_id(row[0])
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def attach_exact_reuse(
        self, *, run_id: str, project_id: str, audit_kind: str,
        composite_hash: str, completed_at: str, knowledge_metadata_hash: str,
        environment_hash: str, semantic_lock_hash: str | None,
        knowledge_content_hash: str, evaluation_context_hash: str,
        policy_hash: str, analysis_contract_version: str,
        knowledge_sources: Sequence[str], knowledge_last_sync_at: str | None,
        knowledge_sync_status: str | None, warning_count: int,
    ) -> SaveRunResult | None:
        """Atomically attach a started run to an existing exact snapshot."""

        run_id = _run_id(run_id)
        project_id = _project_id(project_id)
        audit_kind = _audit_kind(audit_kind)
        composite_hash = _sha256(composite_hash)  # type: ignore[assignment]
        expected = (
            _sha256(environment_hash), _sha256(semantic_lock_hash, optional=True),
            _sha256(knowledge_content_hash), _sha256(evaluation_context_hash),
            _sha256(policy_hash), _required_text(analysis_contract_version, limit=128),
        )
        if (audit_kind == "python_project") != (expected[1] is not None):
            raise _error("invalid_semantic_lock_hash")
        completed_at = _timestamp(completed_at)  # type: ignore[assignment]
        knowledge_metadata_hash = _sha256(knowledge_metadata_hash)  # type: ignore[assignment]
        sources = tuple(sorted({_required_text(item) for item in _bounded_tuple(
            knowledge_sources, MAX_KNOWLEDGE_SOURCES, "invalid_knowledge_sources"
        )}))
        knowledge_last_sync_at = _timestamp(knowledge_last_sync_at, optional=True)
        knowledge_sync_status = _optional_text(knowledge_sync_status, limit=128)
        warning_count = _count(warning_count)
        try:
            with immediate_transaction(self._connection):
                started = self._select_run(run_id)
                if started is None or started[1] != project_id or started[2] != audit_kind:
                    raise _error("run_scope_conflict")
                if started[7] != RunStatus.STARTED.value or completed_at < _stored_timestamp(started[5]):
                    raise _error("run_state_conflict")
                row = self._connection.execute(
                    "SELECT snapshot_id, python_version, environment_hash, semantic_lock_hash, "
                    "knowledge_content_hash, evaluation_context_hash, policy_hash, "
                    "analysis_contract_version, schema_version FROM audit_snapshots "
                    "WHERE project_id = ? AND audit_kind = ? AND composite_hash = ?",
                    (project_id, audit_kind, composite_hash),
                ).fetchone()
                if row is None:
                    return None
                if tuple(row[2:8]) != expected:
                    raise _error("snapshot_composite_conflict")
                snapshot_id = _snapshot_id(row[0])
                baseline = self._select_baseline_for(project_id, audit_kind, run_id)
                self._touch_snapshot(snapshot_id, completed_at)
                cursor = self._connection.execute(
                    "UPDATE audit_runs SET snapshot_id = ?, baseline_run_id = ?, completed_at = ?, "
                    "run_status = ?, reused = 1, python_version = ?, environment_hash = ?, "
                    "semantic_lock_hash = ?, knowledge_content_hash = ?, knowledge_metadata_hash = ?, "
                    "evaluation_context_hash = ?, policy_hash = ?, analysis_contract_version = ?, "
                    "composite_hash = ?, result_schema_version = ?, knowledge_sources_json = ?, "
                    "knowledge_last_sync_at = ?, knowledge_sync_status = ?, warning_count = ?, "
                    "failure_code = NULL WHERE run_id = ? AND run_status = ?",
                    (snapshot_id, baseline, completed_at, RunStatus.COMPLETED_REUSED.value,
                     *row[1:5], knowledge_metadata_hash, *row[5:8], composite_hash,
                     row[8], json.dumps(sources, ensure_ascii=False, separators=(",", ":")),
                     knowledge_last_sync_at, knowledge_sync_status, warning_count,
                     run_id, RunStatus.STARTED.value),
                )
                if cursor.rowcount != 1:
                    raise _error("run_state_conflict")
                self._connection.execute(
                    "UPDATE projects SET updated_at = CASE WHEN updated_at < ? THEN ? "
                    "ELSE updated_at END WHERE project_id = ?",
                    (completed_at, completed_at, project_id),
                )
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        return SaveRunResult(run_id, snapshot_id, True, baseline, RunStatus.COMPLETED_REUSED)

    def get_run(self, run_id: str) -> RunRecord:
        """Return one immutable run record."""

        run_id = _run_id(run_id)
        try:
            row = self._select_run(run_id)
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        if row is None:
            raise _error("run_not_found")
        return _run_record(row)

    def get_snapshot_result(self, snapshot_id: int) -> dict[str, object]:
        """Return a verified, caller-isolated authoritative result value."""

        snapshot_id = _snapshot_id(snapshot_id)  # type: ignore[assignment]
        try:
            row = self._connection.execute(
                "SELECT result_json_zlib, result_json_size, result_json_sha256 "
                "FROM audit_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if row is None:
                self._result_cache.discard(snapshot_id)
                self._result_signatures.pop(snapshot_id, None)
                raise _error("snapshot_not_found")
            compressed = bytes(row[0]) if isinstance(row[0], (bytes, bytearray)) else row[0]
            if not isinstance(compressed, bytes):
                raise _error("result_corrupt")
            signature = (row[1], row[2], hashlib.sha256(compressed).digest())
            if self._result_signatures.get(snapshot_id) == signature:
                cached = self._result_cache.get(snapshot_id)
                if cached is not None:
                    self._result_signatures.move_to_end(snapshot_id)
                    return cached
            self._result_cache.discard(snapshot_id)
            self._result_signatures.pop(snapshot_id, None)
            value = decode_result(compressed, row[1], row[2])
            self._result_cache.put(snapshot_id, value)
            self._result_signatures[snapshot_id] = signature
            if len(self._result_signatures) > 5:
                self._result_signatures.popitem(last=False)
            isolated = self._result_cache.get(snapshot_id)
            if isolated is None:  # defensive; put/get are synchronous
                raise _error("history_database_failed")
            return isolated
        except HistoryDatabaseError:
            raise
        except HistoryCodecError as error:
            raise _error(error.code) from None
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_runs(
        self,
        project_id: str,
        *,
        audit_kind: str | None = None,
        run_status: RunStatus | str | None = None,
        reused: bool | None = None,
        completed_from: str | None = None,
        completed_to: str | None = None,
        started_from: str | None = None,
        started_to: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[RunRecord]:
        """Return a deterministic, bounded page of runs for one project."""

        project_id = _project_id(project_id)
        if audit_kind is not None:
            audit_kind = _audit_kind(audit_kind)
        if run_status is not None:
            status_value = _enum_value(run_status, RunStatus, "invalid_run_status")
        else:
            status_value = None
        if reused is not None and type(reused) is not bool:
            raise _error("invalid_reused")
        completed_from, completed_to = _timestamp_range(completed_from, completed_to)
        started_from, started_to = _timestamp_range(started_from, started_to)
        limit = _page_limit(limit)
        offset = _page_offset(offset)

        predicates = ["project_id = ?"]
        parameters: list[object] = [project_id]
        for predicate, value in (
            ("audit_kind = ?", audit_kind),
            ("run_status = ?", status_value),
            ("reused = ?", None if reused is None else int(reused)),
            ("completed_at >= ?", completed_from),
            ("completed_at <= ?", completed_to),
            ("started_at >= ?", started_from),
            ("started_at <= ?", started_to),
        ):
            if value is not None:
                predicates.append(predicate)
                parameters.append(value)
        where = " AND ".join(predicates)
        try:
            with _stable_read(self._connection):
                total = self._count_query(f"audit_runs WHERE {where}", parameters)
                rows = self._connection.execute(
                    _run_history_sql(where),
                    (*parameters, limit, offset),
                ).fetchall()
            items = tuple(_run_record(row) for row in rows)
            return HistoryPage(items, total, limit, offset)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def latest_snapshot(
        self, project_id: str, audit_kind: str
    ) -> SnapshotSummary | None:
        """Return the newest retained snapshot for a project and audit kind."""

        project_id = _project_id(project_id)
        audit_kind = _audit_kind(audit_kind)
        try:
            row = self._connection.execute(
                f"SELECT {_SNAPSHOT_SUMMARY_COLUMNS} FROM audit_snapshots "
                "WHERE project_id = ? AND audit_kind = ? "
                "ORDER BY created_at DESC, snapshot_id DESC LIMIT 1",
                (project_id, audit_kind),
            ).fetchone()
            return None if row is None else _snapshot_summary(row)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def get_snapshot_summary(
        self, snapshot_id: int, *, project_id: str, audit_kind: str
    ) -> SnapshotSummary:
        """Return scoped summary metadata without reading result bytes."""

        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        try:
            row = self._connection.execute(
                f"SELECT {_SNAPSHOT_SUMMARY_COLUMNS} FROM audit_snapshots "
                "WHERE snapshot_id = ? AND project_id = ? AND audit_kind = ?",
                (snapshot_id, project_id, audit_kind),
            ).fetchone()
            if row is None:
                raise _error("snapshot_not_found")
            return _snapshot_summary(row)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def get_snapshot_detail(
        self, snapshot_id: int, *, project_id: str, audit_kind: str
    ) -> SnapshotDetail:
        """Return scoped complete metadata while deliberately excluding the result BLOB."""

        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        try:
            row = self._connection.execute(
                f"SELECT {_SNAPSHOT_DETAIL_COLUMNS} FROM audit_snapshots "
                "WHERE snapshot_id = ? AND project_id = ? AND audit_kind = ?",
                (snapshot_id, project_id, audit_kind),
            ).fetchone()
            if row is None:
                raise _error("snapshot_not_found")
            return _snapshot_detail(row)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_compatible_runs(
        self,
        project_id: str,
        audit_kind: str,
        *,
        current_snapshot_id: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[CompatibleRunChoice]:
        """List successful same-scope runs, retaining reused duplicate choices."""

        project_id = _project_id(project_id)
        audit_kind = _audit_kind(audit_kind)
        current_snapshot_id = _snapshot_id(current_snapshot_id, optional=True)
        limit = _page_limit(limit)
        offset = _page_offset(offset)
        statuses = (
            RunStatus.COMPLETED_COMPUTED.value,
            RunStatus.COMPLETED_REUSED.value,
        )
        parameters = (project_id, audit_kind, *statuses)
        where = (
            "project_id = ? AND audit_kind = ? AND run_status IN (?, ?) "
            "AND snapshot_id IS NOT NULL AND completed_at IS NOT NULL"
        )
        try:
            with _stable_read(self._connection):
                if current_snapshot_id is not None:
                    self._require_snapshot_scope(
                        current_snapshot_id, project_id, audit_kind
                    )
                total = self._count_query(f"audit_runs WHERE {where}", parameters)
                rows = self._connection.execute(
                    "SELECT run_id, snapshot_id, completed_at, run_status, reused "
                    f"FROM audit_runs WHERE {where} "
                    "ORDER BY completed_at DESC, run_id DESC LIMIT ? OFFSET ?",
                    (*parameters, limit, offset),
                ).fetchall()
            items = tuple(
                _compatible_run(row, current_snapshot_id=current_snapshot_id)
                for row in rows
            )
            return HistoryPage(items, total, limit, offset)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_snapshot_packages(
        self,
        snapshot_id: int,
        *,
        project_id: str,
        audit_kind: str,
        scope: PackageScope | str | None = None,
        normalized_name: str | None = None,
        applicability_status: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[PackageRow]:
        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        scope_value = (
            None
            if scope is None
            else _enum_value(scope, PackageScope, "invalid_package_scope")
        )
        normalized_name = _optional_query_text(normalized_name)
        applicability_status = _optional_query_text(applicability_status)
        limit = _page_limit(limit)
        offset = _page_offset(offset)
        filters, parameters = _row_filters(
            snapshot_id,
            (("scope", scope_value), ("normalized_name", normalized_name), ("applicability_status", applicability_status)),
        )
        try:
            with _stable_read(self._connection):
                self._require_snapshot_scope(snapshot_id, project_id, audit_kind)
                total = self._count_query(
                    f"snapshot_packages WHERE {filters}", parameters
                )
                rows = self._connection.execute(
                    "SELECT scope, raw_name, normalized_name, version, version_valid, "
                    "source_kind, source_identity, component_key, is_direct, applicability_status "
                    f"FROM snapshot_packages WHERE {filters} "
                    "ORDER BY scope, normalized_name, version, component_key, source_kind "
                    "LIMIT ? OFFSET ?",
                    (*parameters, limit, offset),
                ).fetchall()
            return HistoryPage(
                tuple(_package_row(row) for row in rows), total, limit, offset
            )
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_snapshot_findings(
        self,
        snapshot_id: int,
        *,
        project_id: str,
        audit_kind: str,
        scope: PackageScope | str | None = None,
        normalized_name: str | None = None,
        finding_status: FindingStatus | str | None = None,
        advisory: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[FindingRow]:
        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        scope_value = (
            None
            if scope is None
            else _enum_value(scope, PackageScope, "invalid_package_scope")
        )
        status_value = (
            None
            if finding_status is None
            else _enum_value(
                finding_status, FindingStatus, "invalid_finding_status"
            )
        )
        normalized_name = _optional_query_text(normalized_name)
        advisory = _optional_query_text(advisory)
        limit = _page_limit(limit)
        offset = _page_offset(offset)
        predicates = ["snapshot_id = ?"]
        parameters: list[object] = [snapshot_id]
        for column, value in (
            ("scope", scope_value),
            ("normalized_name", normalized_name),
            ("finding_status", status_value),
        ):
            if value is not None:
                predicates.append(f"{column} = ?")
                parameters.append(value)
        if advisory is not None:
            predicates.append("(ghsa_id = ? OR cve_id = ? OR advisory_id = ?)")
            parameters.extend((advisory, advisory, advisory))
        filters = " AND ".join(predicates)
        try:
            with _stable_read(self._connection):
                self._require_snapshot_scope(snapshot_id, project_id, audit_kind)
                total = self._count_query(
                    f"snapshot_findings WHERE {filters}", parameters
                )
                rows = self._connection.execute(
                    "SELECT scope, raw_name, normalized_name, audited_version, ghsa_id, "
                    "cve_id, advisory_id, severity, cvss, affected_range, fixed_versions, "
                    "finding_status, indeterminate_reason, advisory_fingerprint "
                    f"FROM snapshot_findings WHERE {filters} "
                    "ORDER BY scope, normalized_name, audited_version, advisory_id, "
                    "advisory_fingerprint, finding_status LIMIT ? OFFSET ?",
                    (*parameters, limit, offset),
                ).fetchall()
            return HistoryPage(
                tuple(_finding_row(row) for row in rows), total, limit, offset
            )
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_snapshot_dependencies(
        self,
        snapshot_id: int,
        *,
        project_id: str,
        audit_kind: str,
        parent_component_key: str | None = None,
        resolution_status: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[DependencyRow]:
        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        if parent_component_key is not None:
            parent_component_key = _component_key(parent_component_key)
        resolution_status = _optional_query_text(resolution_status)
        limit = _page_limit(limit)
        offset = _page_offset(offset)
        filters, parameters = _row_filters(
            snapshot_id,
            (("parent_component_key", parent_component_key), ("resolution_status", resolution_status)),
        )
        try:
            with _stable_read(self._connection):
                self._require_snapshot_scope(snapshot_id, project_id, audit_kind)
                total = self._count_query(
                    f"snapshot_dependencies WHERE {filters}", parameters
                )
                rows = self._connection.execute(
                    "SELECT parent_component_key, child_component_key, relationship_source, "
                    f"resolution_status FROM snapshot_dependencies WHERE {filters} "
                    "ORDER BY parent_component_key, child_component_key, relationship_source, "
                    "resolution_status LIMIT ? OFFSET ?",
                    (*parameters, limit, offset),
                ).fetchall()
            return HistoryPage(
                tuple(_dependency_row(row) for row in rows), total, limit, offset
            )
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def list_snapshot_issues(
        self,
        snapshot_id: int,
        *,
        project_id: str,
        audit_kind: str,
        issue_code: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> HistoryPage[IssueRow]:
        snapshot_id, project_id, audit_kind = _snapshot_scope(
            snapshot_id, project_id, audit_kind
        )
        if issue_code is not None:
            issue_code = _issue_code(issue_code)
        limit = _page_limit(limit)
        offset = _page_offset(offset)
        filters, parameters = _row_filters(
            snapshot_id, (("issue_code", issue_code),)
        )
        try:
            with _stable_read(self._connection):
                self._require_snapshot_scope(snapshot_id, project_id, audit_kind)
                total = self._count_query(f"snapshot_issues WHERE {filters}", parameters)
                rows = self._connection.execute(
                    f"SELECT issue_code, subject, detail, ordinal FROM snapshot_issues WHERE {filters} "
                    "ORDER BY ordinal, issue_code LIMIT ? OFFSET ?",
                    (*parameters, limit, offset),
                ).fetchall()
            return HistoryPage(
                tuple(_issue_row(row) for row in rows), total, limit, offset
            )
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def find_first_seen(
        self,
        project_id: str,
        audit_kind: str,
        *,
        normalized_name: str,
        ghsa_id: str | None = None,
        cve_id: str | None = None,
        audited_version: str | None = None,
    ) -> FindingFirstSeen | None:
        """Find the earliest successful run for exactly one advisory identity."""

        project_id = _project_id(project_id)
        audit_kind = _audit_kind(audit_kind)
        try:
            normalized_name = _required_text(normalized_name)
            if (ghsa_id is None) == (cve_id is None):
                raise _error("invalid_finding_lookup")
            if ghsa_id is not None:
                advisory_kind = "ghsa"
                advisory_value = _required_text(ghsa_id)
            else:
                advisory_kind = "cve"
                advisory_value = _required_text(cve_id)
            audited_version = _optional_text(audited_version)
        except HistoryDatabaseError:
            raise _error("invalid_finding_lookup") from None

        if advisory_kind == "ghsa":
            parameters: list[object] = [
                advisory_value,
                normalized_name,
                project_id,
                audit_kind,
                RunStatus.COMPLETED_COMPUTED.value,
                RunStatus.COMPLETED_REUSED.value,
            ]
        else:
            parameters = [
                advisory_value,
                normalized_name,
                project_id,
                audit_kind,
                RunStatus.COMPLETED_COMPUTED.value,
                RunStatus.COMPLETED_REUSED.value,
            ]
        if audited_version is not None:
            parameters.append(audited_version)
        try:
            row = self._connection.execute(
                _first_seen_sql(
                    advisory_kind, include_version=audited_version is not None
                ),
                parameters,
            ).fetchone()
            return None if row is None else _first_seen(row)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None

    def _require_snapshot_scope(
        self, snapshot_id: int, project_id: str, audit_kind: str
    ) -> None:
        try:
            row = self._connection.execute(
                "SELECT snapshot_id FROM audit_snapshots "
                "WHERE snapshot_id = ? AND project_id = ? AND audit_kind = ?",
                (snapshot_id, project_id, audit_kind),
            ).fetchone()
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        if row is None:
            raise _error("snapshot_not_found")
        try:
            if _snapshot_id(row[0]) != snapshot_id:
                raise _error("history_database_corrupt")
        except (HistoryDatabaseError, IndexError, TypeError):
            raise _error("history_database_corrupt") from None

    def _count_query(self, source: str, parameters: Sequence[object]) -> int:
        row = self._connection.execute(
            f"SELECT COUNT(*) FROM {source}", parameters
        ).fetchone()
        try:
            if row is None:
                raise ValueError
            return _count(row[0])
        except (HistoryDatabaseError, IndexError, TypeError, ValueError):
            raise _error("history_database_corrupt") from None

    def _ensure_project(self, project_id: str, display_name: str, timestamp: str) -> None:
        row = self._connection.execute(
            "SELECT display_name, updated_at FROM projects WHERE project_id = ?", (project_id,)
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO projects (project_id, display_name, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (project_id, display_name, timestamp, timestamp),
            )
        elif timestamp >= _stored_timestamp(row[1]):
            self._connection.execute(
                "UPDATE projects SET display_name = ?, updated_at = ? WHERE project_id = ?",
                (display_name, timestamp, project_id),
            )

    def _select_run(self, run_id: str) -> tuple[Any, ...] | None:
        return self._connection.execute(
            f"SELECT {_RUN_COLUMNS} FROM audit_runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    @staticmethod
    def _same_started_scope(
        row: tuple[Any, ...], *, project_id: str, audit_kind: str, started_at: str
    ) -> bool:
        stored_started_at = _stored_timestamp(row[5])
        return (
            row[1] == project_id
            and row[2] == audit_kind
            and stored_started_at == started_at
            and row[7] == RunStatus.STARTED.value
        )

    def _prepare_started_run(self, snapshot: SnapshotInput, run_id: str) -> None:
        self._ensure_project(snapshot.project_id, snapshot.display_name, snapshot.started_at)
        row = self._select_run(run_id)
        if row is None:
            self._connection.execute(
                "INSERT INTO audit_runs "
                "(run_id, project_id, audit_kind, snapshot_id, baseline_run_id, started_at, "
                "completed_at, run_status, reused, python_version, environment_hash, "
                "semantic_lock_hash, knowledge_content_hash, knowledge_metadata_hash, "
                "evaluation_context_hash, policy_hash, analysis_contract_version, "
                "composite_hash, result_schema_version, knowledge_sources_json, "
                "knowledge_last_sync_at, knowledge_sync_status, warning_count, failure_code) "
                "VALUES (?, ?, ?, NULL, NULL, ?, NULL, ?, 0, NULL, NULL, NULL, NULL, NULL, "
                "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL)",
                (
                    run_id,
                    snapshot.project_id,
                    snapshot.audit_kind,
                    snapshot.started_at,
                    RunStatus.STARTED.value,
                ),
            )
            return
        if row[7] != RunStatus.STARTED.value:
            raise _error("run_state_conflict")
        if not self._same_started_scope(
            row,
            project_id=snapshot.project_id,
            audit_kind=snapshot.audit_kind,
            started_at=snapshot.started_at,
        ):
            raise _error("run_scope_conflict")

    def _select_baseline(self, snapshot: SnapshotInput, run_id: str) -> str | None:
        return self._select_baseline_for(snapshot.project_id, snapshot.audit_kind, run_id)

    def _select_baseline_for(self, project_id: str, audit_kind: str, run_id: str) -> str | None:
        rows = self._connection.execute(
            "SELECT run_id, baseline_run_id, completed_at FROM audit_runs "
            "WHERE project_id = ? AND audit_kind = ? AND run_id <> ? "
            "AND run_status IN (?, ?) "
            "ORDER BY completed_at DESC, run_id DESC LIMIT ?",
            (
                project_id,
                audit_kind,
                run_id,
                RunStatus.COMPLETED_COMPUTED.value,
                RunStatus.COMPLETED_REUSED.value,
                MAX_BASELINE_SCAN + 1,
            ),
        ).fetchall()
        if len(rows) > MAX_BASELINE_SCAN:
            raise _error("baseline_history_too_large")
        if not rows:
            return None

        successful: list[tuple[str, str | None]] = []
        seen_run_ids: set[str] = set()
        try:
            for row in rows:
                candidate_id = _run_id(row[0])
                baseline_id = _optional_run_id(row[1])
                _timestamp(row[2])
                if candidate_id in seen_run_ids or candidate_id == baseline_id:
                    raise _error("baseline_history_corrupt")
                seen_run_ids.add(candidate_id)
                successful.append((candidate_id, baseline_id))
        except (HistoryDatabaseError, IndexError, TypeError):
            raise _error("baseline_history_corrupt") from None

        referenced = {
            baseline_id
            for _, baseline_id in successful
            if baseline_id is not None
        }
        for candidate_id, _ in successful:
            if candidate_id not in referenced:
                return candidate_id
        # Cycles and old branch corruption have no chain head.  The query order
        # gives a deterministic fallback without another database scan.
        return successful[0][0]

    def _select_snapshot(self, snapshot: SnapshotInput) -> tuple[Any, ...] | None:
        return self._connection.execute(
            f"SELECT {_SNAPSHOT_MATCH_COLUMNS} FROM audit_snapshots "
            "WHERE project_id = ? AND audit_kind = ? AND composite_hash = ?",
            (snapshot.project_id, snapshot.audit_kind, snapshot.composite_hash),
        ).fetchone()

    def _touch_snapshot(self, snapshot_id: int, timestamp: str) -> None:
        self._connection.execute(
            "UPDATE audit_snapshots SET last_used_at = "
            "CASE WHEN last_used_at < ? THEN ? ELSE last_used_at END "
            "WHERE snapshot_id = ?",
            (timestamp, timestamp, snapshot_id),
        )

    def _complete_project(self, snapshot: SnapshotInput) -> None:
        self._connection.execute(
            "UPDATE projects SET updated_at = "
            "CASE WHEN updated_at < ? THEN ? ELSE updated_at END "
            "WHERE project_id = ?",
            (snapshot.completed_at, snapshot.completed_at, snapshot.project_id),
        )

    @staticmethod
    def _verified_snapshot_id(row: tuple[Any, ...], snapshot: SnapshotInput) -> int:
        expected = (
            snapshot.environment_hash,
            snapshot.semantic_lock_hash,
            snapshot.knowledge_content_hash,
            snapshot.evaluation_context_hash,
            snapshot.policy_hash,
            snapshot.analysis_contract_version,
        )
        if tuple(row[1:]) != expected:
            raise _error("snapshot_composite_conflict")
        return int(row[0])

    def _insert_snapshot(self, snapshot: SnapshotInput, encoded: Any) -> int:
        cursor = self._connection.execute(
            "INSERT INTO audit_snapshots "
            "(project_id, audit_kind, created_at, last_used_at, python_version, "
            "environment_hash, semantic_lock_hash, knowledge_content_hash, "
            "knowledge_metadata_hash, evaluation_context_hash, policy_hash, "
            "analysis_contract_version, composite_hash, audit_status, "
            "environment_package_count, lock_package_count, affected_finding_count, "
            "indeterminate_finding_count, issue_count, warning_count, result_json_zlib, "
            "result_json_sha256, result_json_size, schema_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                snapshot.project_id,
                snapshot.audit_kind,
                snapshot.completed_at,
                snapshot.completed_at,
                snapshot.python_version,
                snapshot.environment_hash,
                snapshot.semantic_lock_hash,
                snapshot.knowledge_content_hash,
                snapshot.knowledge_metadata_hash,
                snapshot.evaluation_context_hash,
                snapshot.policy_hash,
                snapshot.analysis_contract_version,
                snapshot.composite_hash,
                snapshot.audit_status,
                snapshot.environment_package_count,
                snapshot.lock_package_count,
                snapshot.affected_finding_count,
                snapshot.indeterminate_finding_count,
                snapshot.issue_count,
                snapshot.warning_count,
                encoded.compressed,
                encoded.sha256,
                encoded.size,
                snapshot.result_schema_version,
            ),
        )
        return int(cursor.lastrowid)

    def _insert_normalized_rows(self, snapshot_id: int, snapshot: SnapshotInput) -> None:
        self._connection.executemany(
            "INSERT INTO snapshot_packages "
            "(snapshot_id, scope, raw_name, normalized_name, version, version_valid, "
            "source_kind, source_identity, component_key, is_direct, applicability_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    snapshot_id,
                    row.scope.value,
                    row.raw_name,
                    row.normalized_name,
                    row.version,
                    int(row.version_valid),
                    row.source_kind,
                    row.source_identity,
                    row.component_key,
                    None if row.is_direct is None else int(row.is_direct),
                    row.applicability_status,
                )
                for row in sorted(snapshot.packages, key=_package_identity)
            ],
        )
        self._connection.executemany(
            "INSERT INTO snapshot_dependencies "
            "(snapshot_id, parent_component_key, child_component_key, relationship_source, "
            "resolution_status) VALUES (?, ?, ?, ?, ?)",
            [
                (snapshot_id, *(_dependency_identity(row)))
                for row in sorted(snapshot.dependencies, key=_dependency_identity)
            ],
        )
        self._connection.executemany(
            "INSERT INTO snapshot_findings "
            "(snapshot_id, scope, raw_name, normalized_name, audited_version, ghsa_id, "
            "cve_id, advisory_id, severity, cvss, affected_range, fixed_versions, "
            "finding_status, indeterminate_reason, advisory_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    snapshot_id,
                    row.scope.value,
                    row.raw_name,
                    row.normalized_name,
                    row.audited_version,
                    row.ghsa_id,
                    row.cve_id,
                    row.advisory_id,
                    row.severity,
                    row.cvss,
                    row.affected_range,
                    None
                    if row.fixed_versions is None
                    else json.dumps(list(row.fixed_versions), separators=(",", ":")),
                    row.finding_status.value,
                    row.indeterminate_reason,
                    row.advisory_fingerprint,
                )
                for row in sorted(snapshot.findings, key=_finding_identity)
            ],
        )
        self._connection.executemany(
            "INSERT INTO snapshot_issues (snapshot_id, issue_code, subject, detail, ordinal) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (snapshot_id, row.issue_code, row.subject, row.detail, row.ordinal)
                for row in sorted(snapshot.issues, key=lambda item: item.ordinal)
            ],
        )

    def _complete_run(
        self,
        snapshot: SnapshotInput,
        run_id: str,
        *,
        snapshot_id: int,
        baseline_run_id: str | None,
        reused: bool,
        sources_json: str,
    ) -> None:
        status = RunStatus.COMPLETED_REUSED if reused else RunStatus.COMPLETED_COMPUTED
        cursor = self._connection.execute(
            "UPDATE audit_runs SET snapshot_id = ?, baseline_run_id = ?, completed_at = ?, "
            "run_status = ?, reused = ?, python_version = ?, environment_hash = ?, "
            "semantic_lock_hash = ?, knowledge_content_hash = ?, knowledge_metadata_hash = ?, "
            "evaluation_context_hash = ?, policy_hash = ?, analysis_contract_version = ?, "
            "composite_hash = ?, result_schema_version = ?, knowledge_sources_json = ?, "
            "knowledge_last_sync_at = ?, knowledge_sync_status = ?, warning_count = ?, "
            "failure_code = NULL WHERE run_id = ? AND project_id = ? AND audit_kind = ? "
            "AND run_status = ?",
            (
                snapshot_id,
                baseline_run_id,
                snapshot.completed_at,
                status.value,
                int(reused),
                snapshot.python_version,
                snapshot.environment_hash,
                snapshot.semantic_lock_hash,
                snapshot.knowledge_content_hash,
                snapshot.knowledge_metadata_hash,
                snapshot.evaluation_context_hash,
                snapshot.policy_hash,
                snapshot.analysis_contract_version,
                snapshot.composite_hash,
                snapshot.result_schema_version,
                sources_json,
                snapshot.knowledge_last_sync_at,
                snapshot.knowledge_sync_status,
                snapshot.warning_count,
                run_id,
                snapshot.project_id,
                snapshot.audit_kind,
                RunStatus.STARTED.value,
            ),
        )
        if cursor.rowcount != 1:
            raise _error("run_state_conflict")

    def _recover_snapshot_insert_conflict(
        self, snapshot: SnapshotInput, *, run_id: str, sources_json: str
    ) -> SaveRunResult:
        try:
            with immediate_transaction(self._connection):
                self._prepare_started_run(snapshot, run_id)
                row = self._select_snapshot(snapshot)
                if row is None:
                    raise _error("history_database_failed")
                snapshot_id = self._verified_snapshot_id(row, snapshot)
                baseline = self._select_baseline(snapshot, run_id)
                self._touch_snapshot(snapshot_id, snapshot.completed_at)
                self._complete_run(
                    snapshot,
                    run_id,
                    snapshot_id=snapshot_id,
                    baseline_run_id=baseline,
                    reused=True,
                    sources_json=sources_json,
                )
                self._complete_project(snapshot)
        except HistoryDatabaseError:
            raise
        except sqlite3.DatabaseError:
            raise _error("history_database_failed") from None
        return SaveRunResult(
            run_id,
            snapshot_id,
            True,
            baseline,
            RunStatus.COMPLETED_REUSED,
        )


@contextmanager
def _stable_read(connection: sqlite3.Connection) -> Iterator[None]:
    """Hold one SQLite read snapshot across count and page statements."""

    owns_transaction = not connection.in_transaction
    if owns_transaction:
        connection.execute("BEGIN")
    try:
        yield
        if owns_transaction:
            connection.commit()
    except BaseException:
        if owns_transaction:
            try:
                connection.rollback()
            except BaseException:
                pass
        raise


def _optional_query_text(value: object) -> str | None:
    if value is None:
        return None
    return _required_text(value)


def _snapshot_scope(
    snapshot_id: object, project_id: object, audit_kind: object
) -> tuple[int, str, str]:
    checked_snapshot = _snapshot_id(snapshot_id)
    if checked_snapshot is None:  # required above; narrows the runtime type
        raise _error("invalid_snapshot_id")
    return checked_snapshot, _project_id(project_id), _audit_kind(audit_kind)


def _row_filters(
    snapshot_id: int, filters: Sequence[tuple[str, object | None]]
) -> tuple[str, list[object]]:
    predicates = ["snapshot_id = ?"]
    parameters: list[object] = [snapshot_id]
    for column, value in filters:
        if value is not None:
            predicates.append(f"{column} = ?")
            parameters.append(value)
    return " AND ".join(predicates), parameters


def _snapshot_summary(row: tuple[Any, ...]) -> SnapshotSummary:
    try:
        return SnapshotSummary(
            snapshot_id=row[0],
            project_id=row[1],
            audit_kind=row[2],
            created_at=row[3],
            last_used_at=row[4],
            python_version=row[5],
            audit_status=row[6],
            environment_package_count=row[7],
            lock_package_count=row[8],
            affected_finding_count=row[9],
            indeterminate_finding_count=row[10],
            issue_count=row[11],
            warning_count=row[12],
            result_schema_version=row[13],
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _snapshot_detail(row: tuple[Any, ...]) -> SnapshotDetail:
    try:
        return SnapshotDetail(
            summary=_snapshot_summary(tuple(row[:14])),
            environment_hash=row[14],
            semantic_lock_hash=row[15],
            knowledge_content_hash=row[16],
            knowledge_metadata_hash=row[17],
            evaluation_context_hash=row[18],
            policy_hash=row[19],
            analysis_contract_version=row[20],
            composite_hash=row[21],
            result_json_sha256=row[22],
            result_json_size=row[23],
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _compatible_run(
    row: tuple[Any, ...], *, current_snapshot_id: int | None
) -> CompatibleRunChoice:
    try:
        snapshot_id = _snapshot_id(row[1])
        if snapshot_id is None:
            raise ValueError
        return CompatibleRunChoice(
            run_id=row[0],
            snapshot_id=snapshot_id,
            completed_at=row[2],
            status=RunStatus(row[3]),
            reused=_stored_bool(row[4]),
            same_snapshot=(
                current_snapshot_id is not None and snapshot_id == current_snapshot_id
            ),
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _package_row(row: tuple[Any, ...]) -> PackageRow:
    try:
        is_direct = None if row[8] is None else _stored_bool(row[8])
        return PackageRow(
            scope=row[0],
            raw_name=row[1],
            normalized_name=row[2],
            version=row[3],
            version_valid=_stored_bool(row[4]),
            source_kind=row[5],
            source_identity=row[6],
            component_key=row[7],
            is_direct=is_direct,
            applicability_status=row[9],
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _dependency_row(row: tuple[Any, ...]) -> DependencyRow:
    try:
        return DependencyRow(
            parent_component_key=row[0],
            child_component_key=row[1],
            relationship_source=row[2],
            resolution_status=row[3],
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _finding_row(row: tuple[Any, ...]) -> FindingRow:
    try:
        if row[10] is None:
            fixed_versions = None
        else:
            if type(row[10]) is not str:
                raise ValueError
            decoded = json.loads(row[10])
            if (
                type(decoded) is not list
                or not all(type(item) is str for item in decoded)
                or decoded != sorted(set(decoded))
            ):
                raise ValueError
            fixed_versions = tuple(decoded)
        return FindingRow(
            scope=row[0],
            raw_name=row[1],
            normalized_name=row[2],
            audited_version=row[3],
            ghsa_id=row[4],
            cve_id=row[5],
            advisory_id=row[6],
            severity=row[7],
            cvss=row[8],
            affected_range=row[9],
            fixed_versions=fixed_versions,
            finding_status=row[11],
            indeterminate_reason=row[12],
            advisory_fingerprint=row[13],
        )
    except (
        HistoryDatabaseError,
        IndexError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        raise _error("history_database_corrupt") from None


def _issue_row(row: tuple[Any, ...]) -> IssueRow:
    try:
        return IssueRow(
            issue_code=row[0], subject=row[1], detail=row[2], ordinal=row[3]
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _first_seen(row: tuple[Any, ...]) -> FindingFirstSeen:
    try:
        return FindingFirstSeen(
            project_id=row[0],
            audit_kind=row[1],
            ghsa_id=row[2],
            cve_id=row[3],
            scope=row[4],
            normalized_name=row[5],
            audited_version=row[6],
            advisory_id=row[7],
            advisory_fingerprint=row[8],
            finding_status=row[9],
            run_id=row[10],
            snapshot_id=row[11],
            completed_at=row[12],
        )
    except (HistoryDatabaseError, IndexError, TypeError, ValueError):
        raise _error("history_database_corrupt") from None


def _run_record(row: tuple[Any, ...]) -> RunRecord:
    try:
        if row[19] is not None and type(row[19]) is not str:
            raise ValueError
        raw_sources = [] if row[19] is None else json.loads(row[19])
        if type(raw_sources) is not list or not all(type(item) is str for item in raw_sources):
            raise ValueError
        if type(row[8]) is not int or row[8] not in (0, 1):
            raise ValueError
        return RunRecord(
            run_id=row[0],
            project_id=row[1],
            audit_kind=row[2],
            snapshot_id=row[3],
            baseline_run_id=row[4],
            started_at=row[5],
            completed_at=row[6],
            status=RunStatus(row[7]),
            reused=bool(row[8]),
            python_version=row[9],
            environment_hash=row[10],
            semantic_lock_hash=row[11],
            knowledge_content_hash=row[12],
            knowledge_metadata_hash=row[13],
            evaluation_context_hash=row[14],
            policy_hash=row[15],
            analysis_contract_version=row[16],
            composite_hash=row[17],
            result_schema_version=row[18],
            knowledge_sources=tuple(raw_sources),
            knowledge_last_sync_at=row[20],
            knowledge_sync_status=row[21],
            warning_count=row[22],
            failure_code=row[23],
        )
    except (
        HistoryDatabaseError,
        IndexError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):
        raise _error("history_database_corrupt") from None
