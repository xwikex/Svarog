"""Run prepared Python audits with deterministic, reusable history snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path
from typing import Callable
from uuid import uuid4

from svarog.dependency_audit.service import MAX_DATABASE_AGE, MAX_FUTURE_SKEW, MAX_REPORT_DETAILS
from svarog.webui.adapters import _AuditExecution

from .errors import HistoryDatabaseError
from .hashers import (
    HashPackage, canonical_json_bytes, composite_hash, environment_hash,
    evaluation_context_hash, knowledge_content_hash, knowledge_metadata_hash,
    policy_hash, semantic_lock_hash,
)
from .models import FindingStatus, PackageScope
from .repository import (
    DependencyRow, FindingRow, HistoryRepository, IssueRow, PackageRow, SnapshotInput,
)
from .retention import CleanupResult, cleanup_history
from .target_python import read_target_python


ANALYSIS_CONTRACT_VERSION = "svarog-analysis/1"


class HistoryServiceError(RuntimeError):
    """Stable public failure; never wraps raw audit or persistence details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HistoryAuditResult:
    result: dict[str, object]
    run_id: str
    snapshot_id: int
    reused: bool
    baseline_run_id: str | None
    change_summary: ChangeSummary
    cleanup: CleanupResult


@dataclass(frozen=True, slots=True)
class ChangeSummary:
    classification: str
    metadata_only_change: bool
    analysis_contract_changed: bool
    policy_changed: bool


def _change_summary(
    repository: HistoryRepository, baseline_run_id: str | None, *,
    environment_digest: str, lock_digest: str | None, content_digest: str,
    context_digest: str, metadata_digest: str, policy_digest: str,
) -> ChangeSummary:
    if baseline_run_id is None:
        return ChangeSummary("initial_snapshot", False, False, False)
    baseline = repository.get_run(baseline_run_id)
    project_changed = (baseline.environment_hash != environment_digest or
                       baseline.semantic_lock_hash != lock_digest)
    knowledge_changed = (baseline.knowledge_content_hash != content_digest or
                         baseline.evaluation_context_hash != context_digest)
    classification = (
        "project_and_knowledge_changed" if project_changed and knowledge_changed
        else "project_changed" if project_changed
        else "knowledge_changed" if knowledge_changed
        else "no_change"
    )
    contract_changed = baseline.analysis_contract_version != ANALYSIS_CONTRACT_VERSION
    policy_changed = baseline.policy_hash != policy_digest
    metadata_only = (
        classification == "no_change" and not contract_changed and not policy_changed
        and baseline.knowledge_metadata_hash != metadata_digest
    )
    return ChangeSummary(classification, metadata_only, contract_changed, policy_changed)


def _utc_second(now: datetime) -> datetime:
    if type(now) is not datetime:
        raise HistoryServiceError("invalid_audit_clock")
    try:
        if now.utcoffset() is None:
            raise HistoryServiceError("invalid_audit_clock")
        return now.astimezone(UTC).replace(microsecond=0)
    except (OverflowError, TypeError, ValueError):
        raise HistoryServiceError("invalid_audit_clock") from None


def _timestamp(now: datetime) -> str:
    return _utc_second(now).strftime("%Y-%m-%dT%H:%M:%SZ")


def _health_group(metadata: object, now: datetime) -> str:
    failed = (getattr(metadata, "last_sync_status", None) or "").strip().lower() != "ok"
    raw = getattr(metadata, "last_sync_at", None)
    try:
        synced = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if synced.utcoffset() is None:
            raise ValueError("invalid_sync_time")
        age = now - synced.astimezone(UTC)
    except (AttributeError, TypeError, ValueError, OverflowError):
        time_group = "invalid_sync_time"
    else:
        if age < -MAX_FUTURE_SKEW:
            time_group = "future_skew"
        elif age > MAX_DATABASE_AGE:
            time_group = "stale"
        else:
            time_group = "healthy"
    if failed:
        return "sync_failed" if time_group == "healthy" else f"sync_failed_{time_group}"
    return time_group


def _canonical_sync_time(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def _component_key(scope: PackageScope, name: str, version: str,
                   source_kind: str, source_identity: str | None) -> str:
    value = [scope.value, name, version, source_kind, source_identity]
    return "pkg:svarog/" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _packages(prepared: _AuditExecution) -> tuple[PackageRow, ...]:
    rows: dict[str, PackageRow] = {}
    for item in prepared.inventory.packages:
        key = _component_key(PackageScope.ENVIRONMENT, item.normalized_name,
                             item.version, "metadata", None)
        rows.setdefault(key, PackageRow(
            PackageScope.ENVIRONMENT, item.name, item.normalized_name, item.version,
            item.version_valid, "metadata", None, key, None, "applicable",
        ))
    if prepared.lock is not None:
        for item in prepared.lock.packages:
            key = _component_key(PackageScope.LOCK, item.normalized_name,
                                 item.version, item.source_kind, item.source_identity)
            rows.setdefault(key, PackageRow(
                PackageScope.LOCK, item.name, item.normalized_name, item.version,
                item.version_valid, item.source_kind, item.source_identity, key,
                None, "unverified",
            ))
    return tuple(sorted(rows.values(), key=lambda row: row.component_key))


def _dependencies(prepared: _AuditExecution, packages: tuple[PackageRow, ...]) -> tuple[DependencyRow, ...]:
    if prepared.lock is None:
        return ()
    by_name: dict[str, list[PackageRow]] = {}
    for row in packages:
        if row.scope is PackageScope.LOCK:
            by_name.setdefault(row.normalized_name, []).append(row)
    edges: dict[tuple[str, str], DependencyRow] = {}
    for parent in prepared.lock.packages:
        parent_key = _component_key(PackageScope.LOCK, parent.normalized_name,
                                    parent.version, parent.source_kind, parent.source_identity)
        for dependency in parent.dependencies:
            candidates = [row for row in by_name.get(dependency.normalized_name, ())
                          if (dependency.version is None or row.version == dependency.version)
                          and (dependency.source_kind is None or row.source_kind == dependency.source_kind)]
            if len(candidates) == 1:
                child_key = candidates[0].component_key
                edges[(parent_key, child_key)] = DependencyRow(
                    parent_key, child_key, "lock", "resolved")
    return tuple(edges[key] for key in sorted(edges))


def _fingerprint(item: object) -> str:
    value = {
        "name": item.normalized_package_name,
        "ghsa": item.ghsa_id,
        "cve": item.cve_id,
        "range": item.affected_range,
        "fixed": item.fixed_version,
        "severity": getattr(getattr(item, "severity", None), "value", None),
        "cvss": getattr(item, "cvss_score", None),
        "summary": getattr(item, "summary", None),
        "source": getattr(item, "source", None),
    }
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _findings(report: object) -> tuple[FindingRow, ...]:
    groups = (
        (PackageScope.ENVIRONMENT, getattr(report, "findings", getattr(report, "environment_findings", ())), FindingStatus.AFFECTED),
        (PackageScope.ENVIRONMENT, getattr(report, "indeterminate_findings", getattr(report, "environment_indeterminate_findings", ())), FindingStatus.INDETERMINATE),
        (PackageScope.LOCK, getattr(report, "lock_findings", ()), FindingStatus.AFFECTED),
        (PackageScope.LOCK, getattr(report, "lock_indeterminate_findings", ()), FindingStatus.INDETERMINATE),
    )
    rows: dict[tuple[object, ...], FindingRow] = {}
    for scope, items, status in groups:
        for item in items:
            versions = (getattr(item, "installed_version", None) or getattr(item, "locked_version", None),)
            if versions == (None,):
                versions = tuple(getattr(item, "installed_versions", ())) or ("unknown",)
            for version in versions:
                fingerprint = _fingerprint(item)
                row = FindingRow(
                    scope, item.package_name, item.normalized_package_name, version,
                    item.ghsa_id, item.cve_id, item.ghsa_id,
                    getattr(getattr(item, "severity", None), "value", None),
                    getattr(item, "cvss_score", None), item.affected_range,
                    (item.fixed_version,) if item.fixed_version else (), status,
                    getattr(item, "reason_code", None), fingerprint,
                )
                key = (scope.value, row.normalized_name, version, row.advisory_id,
                       fingerprint, status.value)
                rows[key] = row
    return tuple(rows[key] for key in sorted(rows))


def _issues(prepared: _AuditExecution, report: object, unknown_python: bool) -> tuple[IssueRow, ...]:
    values = list(getattr(report, "inventory_issues", getattr(report, "environment_issues", ())))
    values.extend(getattr(report, "lock_issues", ()))
    if unknown_python:
        values.append("target_python_unknown")
    # Persist codes only. Existing issue messages and subjects may contain local paths.
    return tuple(IssueRow(item if isinstance(item, str) else item.code, None, None, i)
                 for i, item in enumerate(values))


def _current_result(cached: dict[str, object], prepared: _AuditExecution,
                    now: datetime, *, unknown_python: bool) -> dict[str, object]:
    report = dict(cached)
    report["generated_at"] = now.isoformat()
    target = dict(report.get("target", {}))
    target["environment_path"] = prepared.inventory.environment_path
    target["site_packages"] = list(prepared.inventory.site_packages)
    if prepared.lock is not None:
        target["lock_file_path"] = prepared.lock.path
    report["target"] = target
    report["database"] = asdict(prepared.vulnerability.metadata)
    _refresh_advisory_timestamps(report, prepared)
    report["installed_packages"] = [asdict(item) for item in prepared.inventory.packages]
    installed_names = {item.normalized_name for item in prepared.inventory.packages}
    current_issues = (*prepared.inventory.issues, *(
        issue for issue in prepared.vulnerability.issues
        if issue.subject is None or issue.subject in installed_names
    ))
    issue_field = "environment_issues" if prepared.lock is not None else "inventory_issues"
    report[issue_field] = [asdict(item) for item in current_issues]
    if unknown_python:
        report[issue_field].append({
            "code": "target_python_unknown", "message": "Target Python version is unknown.",
            "subject": None,
        })
        summary = dict(report["summary"])
        summary[issue_field] = len(report[issue_field])
        report["summary"] = summary
    if prepared.lock is not None:
        report["locked_packages"] = [asdict(item) for item in prepared.lock.packages]
        report["lock_issues"] = [asdict(item) for item in prepared.lock.issues]
    return report


def _refresh_advisory_timestamps(
    report: dict[str, object], prepared: _AuditExecution
) -> None:
    updates: dict[tuple[object, ...], list[tuple[str, str | None]]] = {}
    for advisory in prepared.vulnerability.advisories:
        key = (
            advisory.normalized_package_name, advisory.ghsa_id, advisory.cve_id,
            advisory.version_range, advisory.fixed_version, advisory.summary,
            advisory.source, advisory.severity.value, advisory.cvss_score,
        )
        updates.setdefault(key, []).append((advisory.package_name, advisory.updated_at))
    for field in ("findings", "environment_findings", "lock_findings"):
        items = report.get(field)
        if not isinstance(items, list):
            continue
        refreshed: list[object] = []
        for item in items:
            if not isinstance(item, Mapping):
                refreshed.append(item)
                continue
            row = dict(item)
            key = (
                row.get("normalized_package_name"), row.get("ghsa_id"), row.get("cve_id"),
                row.get("affected_range"), row.get("fixed_version"), row.get("summary"),
                row.get("source"), row.get("severity"), row.get("cvss_score"),
            )
            candidates = updates.get(key)
            if candidates:
                row["advisory_updated_at"] = min(
                    candidates, key=lambda value: (value[0], value[1] or "")
                )[1]
            refreshed.append(row)
        report[field] = refreshed


def _cleanup_after_save(repository: HistoryRepository, project_id: str,
                        retention_days: int, clock: Callable[[], datetime]) -> CleanupResult:
    try:
        return cleanup_history(repository, project_id, retention_days, _utc_second(clock()))
    except Exception:
        return CleanupResult(0, 0, True, "history_cleanup_failed")


def audit_with_history(
    prepared: _AuditExecution, *, environment: Path, project_id: str,
    display_name: str, repository: HistoryRepository, retention_days: int,
    clock: Callable[[], datetime],
) -> HistoryAuditResult:
    """Compute layered hashes before matching, then save or attach one run."""

    if prepared.report is not None or prepared.result is not None:
        raise HistoryServiceError("audit_already_completed")
    now = _utc_second(clock())
    started_at = _timestamp(now)
    run_id = str(uuid4())
    kind = "python_project" if prepared.lock is not None else "python_environment"
    try:
        repository.start_run(run_id=run_id, project_id=project_id,
                             display_name=display_name, audit_kind=kind,
                             started_at=started_at)
    except HistoryDatabaseError:
        raise HistoryServiceError("history_persistence_failed") from None

    failure_code = "history_hash_failed"
    committed = False
    try:
        implementation, version = read_target_python(environment)
        unknown_python = version == "unknown"
        package_hash_inputs = tuple(HashPackage(
            item.normalized_name, item.version, item.version_valid, "metadata",
            item.normalized_name in prepared.inventory.ambiguous_names,
        ) for item in prepared.inventory.packages)
        names = {item.normalized_name for item in prepared.inventory.packages}
        if prepared.lock is not None:
            names.update(item.normalized_name for item in prepared.lock.packages)
        environment_digest = environment_hash(
            implementation, version, package_hash_inputs,
            (*prepared.inventory.issues, *(("target_python_unknown",) if unknown_python else ())),
        )
        lock_digest = None if prepared.lock is None else semantic_lock_hash(prepared.lock)
        content_digest = knowledge_content_hash(prepared.vulnerability, names)
        metadata_digest = knowledge_metadata_hash(
            prepared.vulnerability.metadata, prepared.vulnerability.advisories)
        context_digest = evaluation_context_hash(_health_group(prepared.vulnerability.metadata, now))
        policy_digest = policy_hash({
            "detail_limits": {"max_report_details": MAX_REPORT_DETAILS},
            "freshness_threshold": {"max_age_seconds": int(MAX_DATABASE_AGE.total_seconds()),
                                    "future_skew_seconds": int(MAX_FUTURE_SKEW.total_seconds())},
            "marker_handling": "ignored", "version_handling": "all_distinct_versions",
            "withdrawn_handling": "exclude",
        })
        digest = composite_hash(
            audit_kind=kind, environment=environment_digest, lock=lock_digest,
            knowledge=content_digest, context=context_digest, policy=policy_digest,
            contract=ANALYSIS_CONTRACT_VERSION,
        )
        python_version = "unknown" if unknown_python else ".".join(map(str, version))
        failure_code = "history_persistence_failed"
        existing_id = repository.find_exact_snapshot_id(project_id, kind, digest)
        if existing_id is not None:
            failure_code = "history_result_failed"
            cached = repository.get_snapshot_result(existing_id)
            result = {"kind": "project_audit" if prepared.lock else "dependency_audit",
                      "report": _current_result(cached, prepared, now, unknown_python=unknown_python)}
            failure_code = "history_persistence_failed"
            finished_at = _timestamp(clock())
            saved = repository.attach_exact_reuse(
                run_id=run_id, project_id=project_id, audit_kind=kind,
                composite_hash=digest, completed_at=finished_at,
                environment_hash=environment_digest, semantic_lock_hash=lock_digest,
                knowledge_content_hash=content_digest,
                evaluation_context_hash=context_digest, policy_hash=policy_digest,
                analysis_contract_version=ANALYSIS_CONTRACT_VERSION,
                knowledge_metadata_hash=metadata_digest,
                knowledge_sources=prepared.vulnerability.metadata.sources,
                knowledge_last_sync_at=_canonical_sync_time(prepared.vulnerability.metadata.last_sync_at),
                knowledge_sync_status=prepared.vulnerability.metadata.last_sync_status,
                warning_count=len(cached.get("warnings", ())),
            )
            if saved is not None:
                committed = True
                changes = _change_summary(
                    repository, saved.baseline_run_id,
                    environment_digest=environment_digest, lock_digest=lock_digest,
                    content_digest=content_digest, context_digest=context_digest,
                    metadata_digest=metadata_digest, policy_digest=policy_digest,
                )
                cleanup = _cleanup_after_save(repository, project_id, retention_days, clock)
                return HistoryAuditResult(result, run_id, saved.snapshot_id, True,
                                          saved.baseline_run_id, changes, cleanup)

        failure_code = "audit_report_failed"
        from svarog.webui import adapters
        completed = adapters._complete_audit(prepared, now=now)
        if completed.report is None or completed.result is None:
            raise RuntimeError("audit_result_missing")
        report = completed.report
        report_result = dict(completed.result["report"])
        packages = _packages(prepared)
        dependencies = _dependencies(prepared, packages)
        findings = _findings(report)
        issues = _issues(prepared, report, unknown_python)
        if unknown_python:
            status = report_result["audit_status"]
            report_result["audit_status"] = (
                "completed_with_findings_and_gaps" if status == "completed_with_findings"
                else "completed_incomplete" if status == "completed_clean" else status
            )
            report_result["warnings"] = [*report_result.get("warnings", ()), "Target Python version is unknown."]
            issue_field = "environment_issues" if prepared.lock is not None else "inventory_issues"
            report_result[issue_field] = [
                *report_result.get(issue_field, ()),
                {"code": "target_python_unknown", "message": "Target Python version is unknown.", "subject": None},
            ]
            summary = dict(report_result["summary"])
            summary[issue_field] = len(report_result[issue_field])
            report_result["summary"] = summary
        result = {"kind": completed.result["kind"], "report": report_result}
        failure_code = "history_persistence_failed"
        snapshot = SnapshotInput(
            project_id=project_id, display_name=display_name, audit_kind=kind,
            started_at=started_at, completed_at=_timestamp(clock()),
            python_version=python_version, environment_hash=environment_digest,
            semantic_lock_hash=lock_digest, knowledge_content_hash=content_digest,
            knowledge_metadata_hash=metadata_digest, evaluation_context_hash=context_digest,
            policy_hash=policy_digest, analysis_contract_version=ANALYSIS_CONTRACT_VERSION,
            composite_hash=digest, audit_status=report_result["audit_status"],
            result_schema_version=report_result["schema_version"], result=report_result,
            knowledge_sources=prepared.vulnerability.metadata.sources,
            knowledge_last_sync_at=_canonical_sync_time(prepared.vulnerability.metadata.last_sync_at),
            knowledge_sync_status=prepared.vulnerability.metadata.last_sync_status,
            environment_package_count=sum(row.scope is PackageScope.ENVIRONMENT for row in packages),
            lock_package_count=sum(row.scope is PackageScope.LOCK for row in packages),
            affected_finding_count=sum(row.finding_status is FindingStatus.AFFECTED for row in findings),
            indeterminate_finding_count=sum(row.finding_status is FindingStatus.INDETERMINATE for row in findings),
            issue_count=len(issues), warning_count=len(report_result.get("warnings", ())),
            packages=packages, dependencies=dependencies, findings=findings, issues=issues,
        )
        saved = repository.save_run(snapshot, run_id=run_id)
        committed = True
        changes = _change_summary(
            repository, saved.baseline_run_id,
            environment_digest=environment_digest, lock_digest=lock_digest,
            content_digest=content_digest, context_digest=context_digest,
            metadata_digest=metadata_digest, policy_digest=policy_digest,
        )
        cleanup = _cleanup_after_save(repository, project_id, retention_days, clock)
        return HistoryAuditResult(result, run_id, saved.snapshot_id, saved.reused,
                                  saved.baseline_run_id, changes, cleanup)
    except Exception:
        if committed:
            raise HistoryServiceError("history_result_failed") from None
        try:
            repository.mark_run_failed(run_id, completed_at=_timestamp(clock()),
                                       failure_code=failure_code)
        except (HistoryDatabaseError, HistoryServiceError):
            raise HistoryServiceError("history_persistence_failed") from None
        raise HistoryServiceError(failure_code) from None
