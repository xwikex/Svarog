"""Deterministically match installed packages against vulnerability advisories."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    AuditStatus,
    DependencyAuditReport,
    DependencyFinding,
    IndeterminateFinding,
    InstalledPackage,
    InventoryResult,
    MatchStatus,
    VulnerabilitySnapshot,
)
from svarog.dependency_audit.versioning import evaluate_version_range


MAX_REPORT_DETAILS = 10_000
MAX_DATABASE_AGE = timedelta(days=7)
MAX_FUTURE_SKEW = timedelta(minutes=5)

_SEVERITY_ORDER = {
    AdvisorySeverity.CRITICAL: 0,
    AdvisorySeverity.HIGH: 1,
    AdvisorySeverity.MEDIUM: 2,
    AdvisorySeverity.LOW: 3,
    AdvisorySeverity.UNKNOWN: 4,
}


def _parse_utc(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _database_warnings(snapshot: VulnerabilitySnapshot, now: datetime) -> list[str]:
    warnings: list[str] = []
    status = (snapshot.metadata.last_sync_status or "").strip().lower()
    if status != "ok":
        warnings.append("漏洞库最后同步状态异常。")
    synced = _parse_utc(snapshot.metadata.last_sync_at)
    if synced is None:
        warnings.append("漏洞库最后同步时间缺失或无效。")
        return warnings
    try:
        age = now - synced
    except (ValueError, OverflowError):
        warnings.append("漏洞库最后同步时间缺失或无效。")
        return warnings
    if age < -MAX_FUTURE_SKEW:
        warnings.append("漏洞库最后同步时间位于允许的未来偏差之外。")
    elif age > MAX_DATABASE_AGE:
        warnings.append("漏洞库已超过 7 天未成功同步。")
    return warnings


def _advisory_key(advisory: AdvisoryRecord) -> tuple[str, str, str | None]:
    return (
        advisory.normalized_package_name,
        advisory.ghsa_id,
        advisory.cve_id,
    )


def _logical_key_sort(
    key: tuple[str, str, str | None],
) -> tuple[str, str, bool, str]:
    return key[0], key[1], key[2] is not None, key[2] or ""


def _advisory_choice_key(advisory: AdvisoryRecord) -> tuple[object, ...]:
    return (
        advisory.version_range,
        _SEVERITY_ORDER[advisory.severity],
        advisory.package_name,
        advisory.fixed_version or "",
        advisory.summary,
        advisory.source,
        advisory.updated_at or "",
    )


def _package_choice_key(package: InstalledPackage) -> tuple[str, str, str, str]:
    return (
        package.version,
        package.name,
        package.normalized_name,
        package.metadata_path,
    )


@dataclass(frozen=True, slots=True)
class _InstalledGroup:
    package: InstalledPackage
    installed_versions: tuple[str, ...]
    ambiguous: bool
    any_invalid: bool


def _installed_group(
    packages: list[InstalledPackage],
    explicitly_ambiguous: bool,
) -> _InstalledGroup:
    stable_packages = sorted(packages, key=_package_choice_key)
    installed_versions = tuple(
        sorted({package.version for package in stable_packages})
    )
    return _InstalledGroup(
        package=stable_packages[0],
        installed_versions=installed_versions,
        ambiguous=explicitly_ambiguous or len(installed_versions) > 1,
        any_invalid=any(not package.version_valid for package in stable_packages),
    )


def _indeterminate(
    package: InstalledPackage,
    installed_versions: tuple[str, ...],
    advisory: AdvisoryRecord,
    reason_code: str,
) -> IndeterminateFinding:
    return IndeterminateFinding(
        package_name=package.name,
        normalized_package_name=package.normalized_name,
        installed_versions=installed_versions,
        ghsa_id=advisory.ghsa_id,
        cve_id=advisory.cve_id,
        affected_range=advisory.version_range,
        fixed_version=advisory.fixed_version,
        reason_code=reason_code,
    )


def _confirmed(
    package: InstalledPackage,
    advisory: AdvisoryRecord,
) -> DependencyFinding:
    return DependencyFinding(
        package_name=package.name,
        normalized_package_name=package.normalized_name,
        installed_version=package.version,
        ghsa_id=advisory.ghsa_id,
        cve_id=advisory.cve_id,
        severity=advisory.severity,
        cvss_score=advisory.cvss_score,
        affected_range=advisory.version_range,
        fixed_version=advisory.fixed_version,
        summary=advisory.summary,
        source=advisory.source,
        advisory_updated_at=advisory.updated_at,
    )


def _confirmed_sort_key(finding: DependencyFinding) -> tuple[object, ...]:
    return (
        _SEVERITY_ORDER[finding.severity],
        finding.normalized_package_name,
        finding.installed_version,
        finding.ghsa_id,
        finding.cve_id is not None,
        finding.cve_id or "",
        finding.affected_range,
    )


def _indeterminate_sort_key(finding: IndeterminateFinding) -> tuple[object, ...]:
    return (
        finding.normalized_package_name,
        finding.ghsa_id,
        finding.cve_id is not None,
        finding.cve_id or "",
        finding.installed_versions,
        finding.affected_range,
        finding.reason_code,
    )


def _logical_results(
    installed_by_name: dict[str, _InstalledGroup],
    snapshot: VulnerabilitySnapshot,
) -> tuple[list[DependencyFinding], list[IndeterminateFinding], int]:
    grouped: dict[tuple[str, str, str | None], list[AdvisoryRecord]] = defaultdict(list)
    for advisory in snapshot.advisories:
        if advisory.normalized_package_name in installed_by_name:
            grouped[_advisory_key(advisory)].append(advisory)

    findings: list[DependencyFinding] = []
    indeterminate: list[IndeterminateFinding] = []
    withdrawn_count = 0
    for key in sorted(grouped, key=_logical_key_sort):
        advisories = sorted(grouped[key], key=_advisory_choice_key)
        if any(
            advisory.state.strip().lower() == "withdrawn"
            or bool(advisory.withdrawn_at and advisory.withdrawn_at.strip())
            for advisory in advisories
        ):
            withdrawn_count += 1
            continue

        installed = installed_by_name[key[0]]
        package = installed.package
        if installed.ambiguous:
            indeterminate.append(
                _indeterminate(
                    package,
                    installed.installed_versions,
                    advisories[0],
                    "ambiguous_installed_versions",
                )
            )
            continue
        if installed.any_invalid:
            indeterminate.append(
                _indeterminate(
                    package,
                    installed.installed_versions,
                    advisories[0],
                    "invalid_installed_version",
                )
            )
            continue

        affected: list[AdvisoryRecord] = []
        uncertain: list[tuple[AdvisoryRecord, str]] = []
        for advisory in advisories:
            result = evaluate_version_range(package.version, advisory.version_range)
            if result.status is MatchStatus.AFFECTED:
                affected.append(advisory)
            elif result.status is MatchStatus.INDETERMINATE:
                uncertain.append(
                    (advisory, result.reason_code or "unsupported_version_range")
                )
        if affected:
            findings.append(_confirmed(package, affected[0]))
        elif uncertain:
            advisory, reason_code = uncertain[0]
            indeterminate.append(
                _indeterminate(
                    package,
                    installed.installed_versions,
                    advisory,
                    reason_code,
                )
            )

    findings.sort(key=_confirmed_sort_key)
    indeterminate.sort(key=_indeterminate_sort_key)
    return findings, indeterminate, withdrawn_count


def build_dependency_audit_report(
    inventory: InventoryResult,
    snapshot: VulnerabilitySnapshot,
    *,
    now: datetime | None = None,
    max_details: int = MAX_REPORT_DETAILS,
) -> DependencyAuditReport:
    """Build a bounded report without executing packages or taking any action."""

    if isinstance(max_details, bool) or not isinstance(max_details, int) or max_details <= 0:
        raise ValueError("max_details must be a positive integer")
    if now is None:
        generated_at = datetime.now(timezone.utc)
    else:
        try:
            offset = now.utcoffset()
        except (ValueError, OverflowError) as exc:
            raise ValueError("now must be a valid timezone-aware datetime") from exc
        if offset is None:
            raise ValueError("now must be timezone-aware")
        try:
            generated_at = now.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise ValueError("now must be a valid timezone-aware datetime") from exc

    packages_by_name: dict[str, list[InstalledPackage]] = defaultdict(list)
    for package in inventory.packages:
        packages_by_name[package.normalized_name].append(package)
    installed_by_name = {
        name: _installed_group(
            packages_by_name[name],
            name in inventory.ambiguous_names,
        )
        for name in sorted(packages_by_name)
    }
    installed_names = set(installed_by_name)
    relevant_database_issues = tuple(
        issue
        for issue in snapshot.issues
        if issue.subject is None or issue.subject in installed_names
    )

    findings, indeterminate, withdrawn_count = _logical_results(
        installed_by_name, snapshot
    )
    confirmed_count = len(findings)
    indeterminate_count = len(indeterminate)
    detail_count = confirmed_count + indeterminate_count
    truncated_details = max(0, detail_count - max_details)
    retained_findings = findings[:max_details]
    remaining = max_details - len(retained_findings)
    retained_indeterminate = indeterminate[:remaining]

    warnings = _database_warnings(snapshot, generated_at)
    if inventory.truncated_metadata_dirs:
        warnings.append("Python 包元数据目录数量已达到上限，部分目录未检查。")
    if truncated_details:
        warnings.append("审计报告明细已达到上限，部分结果未保留。")

    has_findings = confirmed_count > 0
    has_gaps = bool(
        indeterminate_count
        or inventory.issues
        or relevant_database_issues
        or inventory.truncated_metadata_dirs
        or truncated_details
        or warnings
    )
    if has_findings and has_gaps:
        status = AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS
    elif has_findings:
        status = AuditStatus.COMPLETED_WITH_FINDINGS
    elif has_gaps:
        status = AuditStatus.COMPLETED_INCOMPLETE
    else:
        status = AuditStatus.COMPLETED_CLEAN

    severity_counts = Counter(finding.severity for finding in findings)
    all_issues = tuple((*inventory.issues, *relevant_database_issues))
    summary = {
        "installed_packages": len(inventory.packages),
        "packages_with_findings": len(
            {finding.normalized_package_name for finding in findings}
        ),
        "confirmed_findings": confirmed_count,
        "indeterminate_findings": indeterminate_count,
        "inventory_issues": len(all_issues),
        "critical_findings": severity_counts[AdvisorySeverity.CRITICAL],
        "high_findings": severity_counts[AdvisorySeverity.HIGH],
        "medium_findings": severity_counts[AdvisorySeverity.MEDIUM],
        "low_findings": severity_counts[AdvisorySeverity.LOW],
        "unknown_findings": severity_counts[AdvisorySeverity.UNKNOWN],
        "withdrawn_advisories_excluded": withdrawn_count,
        "truncated_details": truncated_details,
    }
    return DependencyAuditReport(
        report_type="dependency_audit",
        schema_version="0.1.0",
        generated_at=generated_at.isoformat(),
        audit_status=status,
        target={
            "environment_path": inventory.environment_path,
            "site_packages": inventory.site_packages,
        },
        database=snapshot.metadata,
        summary=summary,
        installed_packages=inventory.packages,
        findings=tuple(retained_findings),
        indeterminate_findings=tuple(retained_indeterminate),
        inventory_issues=all_issues,
        warnings=tuple(warnings),
        actions_executed=False,
    )
