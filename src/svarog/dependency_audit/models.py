"""Immutable data models for dependency vulnerability auditing."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class AdvisorySeverity(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MatchStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    INDETERMINATE = "indeterminate"


class AuditStatus(str, Enum):
    COMPLETED_CLEAN = "completed_clean"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    COMPLETED_INCOMPLETE = "completed_incomplete"
    COMPLETED_WITH_FINDINGS_AND_GAPS = "completed_with_findings_and_gaps"


@dataclass(frozen=True, slots=True)
class AuditIssue:
    code: str
    message: str
    subject: str | None = None


@dataclass(frozen=True, slots=True)
class InstalledPackage:
    name: str
    normalized_name: str
    version: str
    version_valid: bool
    metadata_path: str


@dataclass(frozen=True, slots=True)
class InventoryResult:
    environment_path: str
    site_packages: tuple[str, ...]
    packages: tuple[InstalledPackage, ...]
    ambiguous_names: frozenset[str]
    issues: tuple[AuditIssue, ...]
    total_metadata_dirs: int
    truncated_metadata_dirs: int


@dataclass(frozen=True, slots=True)
class AdvisoryRecord:
    ghsa_id: str
    cve_id: str | None
    state: str
    withdrawn_at: str | None
    summary: str
    severity: AdvisorySeverity
    cvss_score: float | None
    source: str
    updated_at: str | None
    package_name: str
    normalized_package_name: str
    version_range: str
    fixed_version: str | None


@dataclass(frozen=True, slots=True)
class DatabaseMetadata:
    path: str
    size_bytes: int
    sources: tuple[str, ...]
    last_sync_at: str | None = None
    last_sync_status: str | None = None
    last_sync_message: str | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilitySnapshot:
    metadata: DatabaseMetadata
    advisories: tuple[AdvisoryRecord, ...]
    issues: tuple[AuditIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyFinding:
    package_name: str
    normalized_package_name: str
    installed_version: str
    ghsa_id: str
    cve_id: str | None
    severity: AdvisorySeverity
    cvss_score: float | None
    affected_range: str
    fixed_version: str | None
    summary: str
    source: str
    advisory_updated_at: str | None
    status: MatchStatus = MatchStatus.AFFECTED


@dataclass(frozen=True, slots=True)
class IndeterminateFinding:
    package_name: str
    normalized_package_name: str
    installed_versions: tuple[str, ...]
    ghsa_id: str
    cve_id: str | None
    affected_range: str
    fixed_version: str | None
    reason_code: str
    status: MatchStatus = MatchStatus.INDETERMINATE


@dataclass(frozen=True, slots=True)
class DependencyAuditReport:
    report_type: str
    schema_version: str
    generated_at: str
    audit_status: AuditStatus
    target: Mapping[str, object]
    database: DatabaseMetadata
    summary: Mapping[str, int]
    installed_packages: tuple[InstalledPackage, ...]
    findings: tuple[DependencyFinding, ...]
    indeterminate_findings: tuple[IndeterminateFinding, ...]
    inventory_issues: tuple[AuditIssue, ...] = ()
    warnings: tuple[str, ...] = ()
    actions_executed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", MappingProxyType({key: _freeze_target_value(value) for key, value in self.target.items()}))
        object.__setattr__(self, "summary", MappingProxyType(dict(self.summary)))


def _freeze_target_value(value: object) -> str | tuple[str, ...]:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise TypeError("target values must be strings or sequences of strings")
