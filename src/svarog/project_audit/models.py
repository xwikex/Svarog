"""Immutable project-audit input models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Sequence

from svarog.dependency_audit.models import (
    AdvisorySeverity,
    AuditIssue,
    AuditStatus,
    DatabaseMetadata,
    DependencyFinding,
    IndeterminateFinding,
    InstalledPackage,
    MatchStatus,
)


@dataclass(frozen=True, slots=True)
class LockedDependency:
    name: str
    normalized_name: str
    version: str | None
    source_kind: str | None


@dataclass(frozen=True, slots=True)
class LockedPackage:
    name: str
    normalized_name: str
    version: str
    version_valid: bool
    source_kind: str
    source_identity: str | None = None
    dependencies: Sequence[LockedDependency] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "dependencies", tuple(self.dependencies))


@dataclass(frozen=True, slots=True)
class LockIssue:
    code: str
    message: str
    subject: str | None = None


@dataclass(frozen=True, slots=True)
class LockSnapshot:
    path: str
    lock_format: str
    packages: tuple[LockedPackage, ...]
    issues: tuple[LockIssue, ...]
    total_package_entries: int
    total_issue_count: int
    truncated_issue_count: int
    marker_policy: str = "ignored"
    version_policy: str = "all_distinct_versions"
    applicability: str = "unverified"
    warnings: tuple[str, ...] = ()


class DifferenceStatus(str, Enum):
    MATCHED = "matched"
    VERSION_MISMATCH = "version_mismatch"
    MISSING = "missing"
    UNEXPECTED = "unexpected"
    AMBIGUOUS = "ambiguous"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class VersionDifference:
    name: str
    normalized_name: str
    installed_versions: tuple[str, ...]
    locked_versions: tuple[str, ...]
    status: DifferenceStatus


@dataclass(frozen=True, slots=True)
class LockFinding:
    package_name: str
    normalized_package_name: str
    locked_version: str
    ghsa_id: str
    cve_id: str | None
    severity: AdvisorySeverity
    cvss_score: float | None
    affected_range: str
    fixed_version: str | None
    summary: str
    source: str
    advisory_updated_at: str | None
    applicability: str = "unverified"
    status: MatchStatus = MatchStatus.AFFECTED


@dataclass(frozen=True, slots=True)
class LockIndeterminateFinding:
    package_name: str
    normalized_package_name: str
    locked_version: str
    ghsa_id: str
    cve_id: str | None
    affected_range: str
    fixed_version: str | None
    reason_code: str
    applicability: str = "unverified"
    status: MatchStatus = MatchStatus.INDETERMINATE


@dataclass(frozen=True, slots=True)
class ProjectDependencyAuditReport:
    report_type: str
    schema_version: str
    generated_at: str
    audit_status: AuditStatus
    target: Mapping[str, object]
    database: DatabaseMetadata
    lock_evaluation: Mapping[str, str]
    summary: Mapping[str, int]
    installed_packages: tuple[InstalledPackage, ...]
    locked_packages: tuple[LockedPackage, ...]
    version_differences: tuple[VersionDifference, ...]
    environment_findings: tuple[DependencyFinding, ...]
    environment_indeterminate_findings: tuple[IndeterminateFinding, ...]
    lock_findings: tuple[LockFinding, ...]
    lock_indeterminate_findings: tuple[LockIndeterminateFinding, ...]
    environment_issues: tuple[AuditIssue, ...] = ()
    lock_issues: tuple[LockIssue, ...] = ()
    warnings: tuple[str, ...] = ()
    actions_executed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "target",
            MappingProxyType(
                {key: _freeze_target_value(value) for key, value in self.target.items()}
            ),
        )
        object.__setattr__(
            self,
            "lock_evaluation",
            MappingProxyType(dict(self.lock_evaluation)),
        )
        object.__setattr__(self, "summary", MappingProxyType(dict(self.summary)))


def _freeze_target_value(value: object) -> str | tuple[str, ...]:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise TypeError("target values must be strings or sequences of strings")
