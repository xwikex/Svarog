"""Build the combined environment and lockfile vulnerability audit report."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    AuditStatus,
    InventoryResult,
    MatchStatus,
    VulnerabilitySnapshot,
)
from svarog.dependency_audit.service import (
    MAX_REPORT_DETAILS,
    build_dependency_audit_report,
)
from svarog.dependency_audit.versioning import evaluate_version_range

from .models import (
    DifferenceStatus,
    LockedPackage,
    LockFinding,
    LockIndeterminateFinding,
    LockSnapshot,
    ProjectDependencyAuditReport,
)
from .reconcile import reconcile_environment_with_lock


MAX_LOCK_MATCH_EVALUATIONS = 1_000_000

_SEVERITY_ORDER = {
    AdvisorySeverity.CRITICAL: 0,
    AdvisorySeverity.HIGH: 1,
    AdvisorySeverity.MEDIUM: 2,
    AdvisorySeverity.LOW: 3,
    AdvisorySeverity.UNKNOWN: 4,
}


def _now_utc(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    try:
        offset = now.utcoffset()
    except (ValueError, OverflowError) as exc:
        raise ValueError("now must be a valid timezone-aware datetime") from exc
    if offset is None:
        raise ValueError("now must be timezone-aware")
    try:
        return now.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("now must be a valid timezone-aware datetime") from exc


def _logical_key(advisory: AdvisoryRecord) -> tuple[str, str, str | None]:
    return advisory.normalized_package_name, advisory.ghsa_id, advisory.cve_id


def _logical_sort(key: tuple[str, str, str | None]) -> tuple[str, str, bool, str]:
    return key[0], key[1], key[2] is not None, key[2] or ""


def _advisory_sort(advisory: AdvisoryRecord) -> tuple[object, ...]:
    return (
        advisory.version_range,
        _SEVERITY_ORDER[advisory.severity],
        advisory.package_name,
        advisory.fixed_version or "",
        advisory.summary,
        advisory.source,
        advisory.updated_at or "",
    )


def _candidate_sort(package: LockedPackage) -> tuple[str, str, str, str]:
    return (
        package.normalized_name,
        package.version,
        package.name,
        package.source_kind,
    )


def _distinct_version_candidates(lock: LockSnapshot) -> tuple[LockedPackage, ...]:
    selected: dict[tuple[str, str], LockedPackage] = {}
    for package in sorted(lock.packages, key=_candidate_sort):
        selected.setdefault((package.normalized_name, package.version), package)
    return tuple(selected[key] for key in sorted(selected))


def _lock_finding(package: LockedPackage, advisory: AdvisoryRecord) -> LockFinding:
    return LockFinding(
        package_name=package.name,
        normalized_package_name=package.normalized_name,
        locked_version=package.version,
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


def _lock_indeterminate(
    package: LockedPackage,
    advisory: AdvisoryRecord,
    reason_code: str,
) -> LockIndeterminateFinding:
    return LockIndeterminateFinding(
        package_name=package.name,
        normalized_package_name=package.normalized_name,
        locked_version=package.version,
        ghsa_id=advisory.ghsa_id,
        cve_id=advisory.cve_id,
        affected_range=advisory.version_range,
        fixed_version=advisory.fixed_version,
        reason_code=reason_code,
    )


def _finding_sort(finding: LockFinding) -> tuple[object, ...]:
    return (
        _SEVERITY_ORDER[finding.severity],
        finding.normalized_package_name,
        finding.locked_version,
        finding.ghsa_id,
        finding.cve_id is not None,
        finding.cve_id or "",
        finding.affected_range,
    )


def _indeterminate_sort(finding: LockIndeterminateFinding) -> tuple[object, ...]:
    return (
        finding.normalized_package_name,
        finding.locked_version,
        finding.ghsa_id,
        finding.cve_id is not None,
        finding.cve_id or "",
        finding.affected_range,
        finding.reason_code,
    )


def _audit_lock_candidates(
    lock: LockSnapshot,
    snapshot: VulnerabilitySnapshot,
) -> tuple[
    list[LockFinding],
    list[LockIndeterminateFinding],
    int,
    bool,
]:
    candidates = _distinct_version_candidates(lock)
    candidate_names = {item.normalized_name for item in candidates}
    groups: dict[tuple[str, str, str | None], list[AdvisoryRecord]] = defaultdict(list)
    for advisory in snapshot.advisories:
        if advisory.normalized_package_name in candidate_names:
            groups[_logical_key(advisory)].append(advisory)

    active_by_name: dict[str, list[list[AdvisoryRecord]]] = defaultdict(list)
    withdrawn_count = 0
    for key in sorted(groups, key=_logical_sort):
        rows = sorted(groups[key], key=_advisory_sort)
        if any(
            row.state.strip().lower() == "withdrawn"
            or bool(row.withdrawn_at and row.withdrawn_at.strip())
            for row in rows
        ):
            withdrawn_count += 1
        else:
            active_by_name[key[0]].append(rows)

    findings: list[LockFinding] = []
    indeterminate: list[LockIndeterminateFinding] = []
    evaluations = 0
    evaluation_limit_reached = False
    for package in candidates:
        for advisories in active_by_name.get(package.normalized_name, ()):
            if evaluations >= MAX_LOCK_MATCH_EVALUATIONS:
                evaluation_limit_reached = True
                break
            if not package.version_valid:
                evaluations += 1
                indeterminate.append(
                    _lock_indeterminate(package, advisories[0], "invalid_locked_version")
                )
                continue

            affected: list[AdvisoryRecord] = []
            uncertain: list[tuple[AdvisoryRecord, str]] = []
            for advisory in advisories:
                if evaluations >= MAX_LOCK_MATCH_EVALUATIONS:
                    evaluation_limit_reached = True
                    break
                evaluations += 1
                result = evaluate_version_range(package.version, advisory.version_range)
                if result.status is MatchStatus.AFFECTED:
                    affected.append(advisory)
                elif result.status is MatchStatus.INDETERMINATE:
                    uncertain.append(
                        (advisory, result.reason_code or "unsupported_version_range")
                    )
            if evaluation_limit_reached:
                break
            if affected:
                findings.append(_lock_finding(package, affected[0]))
            elif uncertain:
                advisory, reason_code = uncertain[0]
                indeterminate.append(
                    _lock_indeterminate(package, advisory, reason_code)
                )
        if evaluation_limit_reached:
            break

    findings.sort(key=_finding_sort)
    indeterminate.sort(key=_indeterminate_sort)
    return findings, indeterminate, withdrawn_count, evaluation_limit_reached


def build_project_audit_report(
    inventory: InventoryResult,
    lock: LockSnapshot,
    snapshot: VulnerabilitySnapshot,
    *,
    now: datetime | None = None,
    max_details: int = MAX_REPORT_DETAILS,
) -> ProjectDependencyAuditReport:
    """Build one immutable report while preserving evidence-layer boundaries."""

    if isinstance(max_details, bool) or not isinstance(max_details, int) or max_details <= 0:
        raise ValueError("max_details must be a positive integer")
    generated_at = _now_utc(now)
    environment = build_dependency_audit_report(
        inventory,
        snapshot,
        now=generated_at,
        max_details=max_details,
    )
    differences = reconcile_environment_with_lock(inventory, lock)
    lock_findings, lock_indeterminate, lock_withdrawn, evaluation_limit = (
        _audit_lock_candidates(lock, snapshot)
    )

    environment_total = (
        environment.summary["confirmed_findings"]
        + environment.summary["indeterminate_findings"]
    )
    retained_environment = len(environment.findings) + len(
        environment.indeterminate_findings
    )
    remaining = max(0, max_details - retained_environment)
    retained_lock_findings = lock_findings[:remaining]
    remaining -= len(retained_lock_findings)
    retained_lock_indeterminate = lock_indeterminate[:remaining]
    lock_total = len(lock_findings) + len(lock_indeterminate)
    truncated_details = max(
        0,
        environment_total + lock_total - (
            retained_environment
            + len(retained_lock_findings)
            + len(retained_lock_indeterminate)
        ),
    )

    warnings = list(dict.fromkeys((*environment.warnings, *lock.warnings)))
    if truncated_details:
        warnings.append("项目审计报告明细已达到上限，部分结果未保留。")
    if evaluation_limit:
        warnings.append("锁文件漏洞匹配次数已达到安全上限，部分候选版本未完成审计。")

    difference_counts = Counter(item.status for item in differences)
    environment_has_gaps = environment.audit_status in {
        AuditStatus.COMPLETED_INCOMPLETE,
        AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS,
    }
    has_confirmed = bool(environment.summary["confirmed_findings"])
    has_gaps = bool(
        environment_has_gaps
        or lock_findings
        or lock_indeterminate
        or lock.issues
        or lock.truncated_issue_count
        or any(item.status is not DifferenceStatus.MATCHED for item in differences)
        or truncated_details
        or evaluation_limit
    )
    if has_confirmed and has_gaps:
        audit_status = AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS
    elif has_confirmed:
        audit_status = AuditStatus.COMPLETED_WITH_FINDINGS
    elif has_gaps:
        audit_status = AuditStatus.COMPLETED_INCOMPLETE
    else:
        audit_status = AuditStatus.COMPLETED_CLEAN

    summary = {
        "installed_packages": len(inventory.packages),
        "locked_packages": len(_distinct_version_candidates(lock)),
        "version_differences": len(differences),
        "matched": difference_counts[DifferenceStatus.MATCHED],
        "version_mismatch": difference_counts[DifferenceStatus.VERSION_MISMATCH],
        "missing": difference_counts[DifferenceStatus.MISSING],
        "unexpected": difference_counts[DifferenceStatus.UNEXPECTED],
        "ambiguous": difference_counts[DifferenceStatus.AMBIGUOUS],
        "indeterminate_differences": difference_counts[DifferenceStatus.INDETERMINATE],
        "confirmed_environment_findings": environment.summary["confirmed_findings"],
        "environment_indeterminate_findings": environment.summary[
            "indeterminate_findings"
        ],
        "potential_lock_findings": len(lock_findings),
        "lock_indeterminate_findings": len(lock_indeterminate),
        "environment_withdrawn_advisories_excluded": environment.summary[
            "withdrawn_advisories_excluded"
        ],
        "lock_withdrawn_advisories_excluded": lock_withdrawn,
        "environment_issues": len(environment.inventory_issues),
        "lock_issues": lock.total_issue_count,
        "truncated_details": truncated_details,
        "lock_match_evaluation_limit_reached": int(evaluation_limit),
    }
    return ProjectDependencyAuditReport(
        report_type="project_dependency_audit",
        schema_version="0.1.0",
        generated_at=generated_at.isoformat(),
        audit_status=audit_status,
        target={
            "environment_path": inventory.environment_path,
            "site_packages": inventory.site_packages,
            "lock_file_path": lock.path,
            "lock_format": lock.lock_format,
        },
        database=snapshot.metadata,
        lock_evaluation={
            "marker_policy": lock.marker_policy,
            "version_policy": lock.version_policy,
            "applicability": lock.applicability,
        },
        summary=summary,
        installed_packages=inventory.packages,
        locked_packages=lock.packages,
        version_differences=differences,
        environment_findings=environment.findings,
        environment_indeterminate_findings=environment.indeterminate_findings,
        lock_findings=tuple(retained_lock_findings),
        lock_indeterminate_findings=tuple(retained_lock_indeterminate),
        environment_issues=environment.inventory_issues,
        lock_issues=lock.issues,
        warnings=tuple(warnings),
        actions_executed=False,
    )
