"""Set-based, scoped comparisons over normalized history tables only."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import sqlite3
from typing import Callable
from uuid import NAMESPACE_URL, uuid5
import zlib

from packaging.version import InvalidVersion, Version

from svarog.audit_history.database import immediate_transaction
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.repository import (
    DependencyRow, FindingRow, HistoryRepository, IssueRow, PackageRow,
)

from .models import DependencyChange, DiffReport, FindingChange, IssueChange, PackageChange
from .reporting import DIFF_CONTRACT_VERSION, diff_payload, render_diff_json


def classify_change(*, project_changed: bool, knowledge_changed: bool) -> str:
    if project_changed and knowledge_changed:
        return "project_and_knowledge_changed"
    if project_changed:
        return "project_changed"
    if knowledge_changed:
        return "knowledge_changed"
    return "no_change"


def _all_rows(fetch: Callable[..., object]) -> tuple[object, ...]:
    rows: list[object] = []
    offset = 0
    while True:
        page = fetch(limit=100, offset=offset)
        rows.extend(page.items)
        offset += len(page.items)
        if offset >= page.total_count:
            return tuple(rows)
        if not page.items or offset > 100_000:
            raise HistoryDatabaseError("history_database_corrupt")


def _package_value(row: PackageRow) -> dict[str, object]:
    return {
        "version": row.version,
        "version_valid": row.version_valid,
        "source_kind": row.source_kind,
        "source_identity": row.source_identity,
        "component_key": row.component_key,
        "is_direct": row.is_direct,
        "applicability_status": row.applicability_status,
    }


def _finding_value(row: FindingRow) -> dict[str, object]:
    return {
        "ghsa_id": row.ghsa_id,
        "cve_id": row.cve_id,
        "severity": row.severity,
        "cvss": row.cvss,
        "affected_range": row.affected_range,
        "fixed_versions": row.fixed_versions,
        "finding_status": row.finding_status.value,
        "indeterminate_reason": row.indeterminate_reason,
        "advisory_fingerprint": row.advisory_fingerprint,
    }


def _version_direction(before: str, after: str) -> str:
    try:
        left, right = Version(before), Version(after)
    except InvalidVersion:
        return "ambiguous_version"
    if right > left:
        return "upgraded"
    if right < left:
        return "downgraded"
    return "ambiguous_version"


def _package_changes(before: tuple[PackageRow, ...], after: tuple[PackageRow, ...]) -> tuple[PackageChange, ...]:
    groups: dict[tuple[str, str], tuple[list[PackageRow], list[PackageRow]]] = defaultdict(lambda: ([], []))
    for row in before:
        groups[(row.scope.value, row.normalized_name)][0].append(row)
    for row in after:
        groups[(row.scope.value, row.normalized_name)][1].append(row)
    changes = []
    for (scope, name), (old, new) in sorted(groups.items()):
        old_values = tuple(sorted((_package_value(row) for row in old), key=lambda x: (x["version"], x["component_key"])))
        new_values = tuple(sorted((_package_value(row) for row in new), key=lambda x: (x["version"], x["component_key"])))
        if old_values == new_values:
            continue
        types: list[str] = []
        if not old:
            types.append("added")
        elif not new:
            types.append("removed")
        else:
            old_versions = {row.version for row in old}
            new_versions = {row.version for row in new}
            if old_versions != new_versions:
                if len(old) == len(new) == 1:
                    types.append(_version_direction(old[0].version, new[0].version))
                else:
                    types.append("ambiguous_version")
            if {(row.source_kind, row.source_identity) for row in old} != {(row.source_kind, row.source_identity) for row in new}:
                types.append("source_changed")
            if {row.applicability_status for row in old} != {row.applicability_status for row in new}:
                types.append("mismatch_changed")
            if not types:
                types.append("metadata_changed")
        changes.append(PackageChange(scope, name, old_values, new_values, tuple(types)))
    return tuple(changes)


def _finding_changes(before: tuple[FindingRow, ...], after: tuple[FindingRow, ...]) -> tuple[FindingChange, ...]:
    old: dict[tuple[str, str, str, str], list[FindingRow]] = defaultdict(list)
    new: dict[tuple[str, str, str, str], list[FindingRow]] = defaultdict(list)
    for row in before:
        old[(row.scope.value, row.normalized_name, row.audited_version, row.advisory_id)].append(row)
    for row in after:
        new[(row.scope.value, row.normalized_name, row.audited_version, row.advisory_id)].append(row)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        order = lambda row: (row.advisory_fingerprint, row.finding_status.value)
        left = tuple(_finding_value(row) for row in sorted(old.get(key, ()), key=order))
        right = tuple(_finding_value(row) for row in sorted(new.get(key, ()), key=order))
        if left == right:
            continue
        change = "introduced" if not left else "resolved" if not right else "changed"
        changes.append(FindingChange(*key, change, left, right))
    return tuple(changes)


def _dependency_changes(before: tuple[DependencyRow, ...], after: tuple[DependencyRow, ...]) -> tuple[DependencyChange, ...]:
    identity = lambda row: (row.parent_component_key, row.child_component_key, row.relationship_source, row.resolution_status)
    old, new = {identity(row) for row in before}, {identity(row) for row in after}
    return tuple(DependencyChange(*edge, "removed" if edge in old else "added") for edge in sorted(old ^ new))


def _issue_changes(before: tuple[IssueRow, ...], after: tuple[IssueRow, ...]) -> tuple[IssueChange, ...]:
    identity = lambda row: (row.issue_code, row.subject, row.detail)
    old, new = {identity(row) for row in before}, {identity(row) for row in after}
    return tuple(IssueChange(code, subject, "resolved" if item in old else "added") for item in sorted(old ^ new, key=repr) for code, subject, _ in (item,))


class DiffService:
    def __init__(self, repository: HistoryRepository) -> None:
        self.repository = repository

    def classifications_for_runs(self, project_id: str, run_ids: tuple[str, ...]) -> dict[str, str]:
        """Fetch a bounded history page's saved classifications without decoding reports."""
        if not run_ids:
            return {}
        if len(run_ids) > 100:
            raise ValueError("too_many_runs")
        placeholders = ",".join("?" for _ in run_ids)
        try:
            rows = self.repository._connection.execute(
                "SELECT target_run_id, classification FROM run_diffs "
                f"WHERE project_id=? AND diff_contract_version=? AND target_run_id IN ({placeholders})",
                (project_id, DIFF_CONTRACT_VERSION, *run_ids),
            ).fetchall()
        except sqlite3.DatabaseError:
            raise HistoryDatabaseError("history_database_failed") from None
        return {run_id: classification for run_id, classification in rows}

    def compare_snapshots(self, project_id: str, audit_kind: str,
                          baseline_snapshot_id: int | None, target_snapshot_id: int) -> DiffReport:
        target = self.repository.get_snapshot_detail(target_snapshot_id, project_id=project_id, audit_kind=audit_kind)
        baseline = (self.repository.get_snapshot_detail(baseline_snapshot_id, project_id=project_id, audit_kind=audit_kind)
                    if baseline_snapshot_id is not None else None)
        if baseline is not None and baseline.summary.result_schema_version != target.summary.result_schema_version:
            raise ValueError("incompatible_schema")

        def rows(snapshot_id: int | None, method: str):
            if snapshot_id is None:
                return ()
            fetch = getattr(self.repository, method)
            return _all_rows(lambda **kw: fetch(snapshot_id, project_id=project_id, audit_kind=audit_kind, **kw))

        packages = _package_changes(rows(baseline_snapshot_id, "list_snapshot_packages"), rows(target_snapshot_id, "list_snapshot_packages"))
        findings = _finding_changes(rows(baseline_snapshot_id, "list_snapshot_findings"), rows(target_snapshot_id, "list_snapshot_findings"))
        dependencies = _dependency_changes(rows(baseline_snapshot_id, "list_snapshot_dependencies"), rows(target_snapshot_id, "list_snapshot_dependencies"))
        issues = _issue_changes(rows(baseline_snapshot_id, "list_snapshot_issues"), rows(target_snapshot_id, "list_snapshot_issues"))

        if baseline is None:
            classification, causes, engine_changed, warnings = "initial_snapshot", (), False, ()
        else:
            project_changed = (baseline.environment_hash != target.environment_hash
                               or baseline.semantic_lock_hash != target.semantic_lock_hash
                               or baseline.summary.python_version != target.summary.python_version)
            knowledge_changed = baseline.knowledge_content_hash != target.knowledge_content_hash
            classification = classify_change(project_changed=project_changed, knowledge_changed=knowledge_changed)
            causes = tuple(name for name, changed in (("project", project_changed), ("knowledge", knowledge_changed)) if changed)
            engine_changed = baseline.analysis_contract_version != target.analysis_contract_version
            warnings = (("knowledge_metadata_only_changed",) if baseline.knowledge_metadata_hash != target.knowledge_metadata_hash and not knowledge_changed else ())
        warnings += (("resolved_does_not_imply_fixed",) if any(item.change_type == "resolved" for item in findings) else ())
        return DiffReport(project_id, audit_kind, baseline_snapshot_id, target_snapshot_id,
                          classification, causes, engine_changed,
                          baseline.summary.python_version if baseline else None,
                          target.summary.python_version,
                          baseline is not None and baseline.summary.python_version != target.summary.python_version,
                          packages, findings, dependencies, issues, warnings)

    def compare_run(self, run_id: str) -> DiffReport:
        run = self.repository.get_run(run_id)
        if run.snapshot_id is None:
            raise ValueError("run_not_completed")
        baseline = self.repository.get_run(run.baseline_run_id) if run.baseline_run_id else None
        if baseline is not None and (baseline.project_id != run.project_id or baseline.audit_kind != run.audit_kind or baseline.snapshot_id is None):
            raise ValueError("incompatible_baseline")
        report = self.compare_snapshots(run.project_id, run.audit_kind,
                                        baseline.snapshot_id if baseline else None, run.snapshot_id)
        raw = render_diff_json(report)
        summary = diff_payload(report)["summary"]
        diff_id = str(uuid5(NAMESPACE_URL, f"{DIFF_CONTRACT_VERSION}:{run.baseline_run_id}:{run.run_id}"))
        digest = hashlib.sha256(raw).hexdigest()
        try:
            with immediate_transaction(self.repository._connection) as connection:
                existing = connection.execute(
                    "SELECT diff_json_sha256 FROM run_diffs WHERE target_run_id = ? "
                    "AND diff_contract_version = ? AND baseline_run_id IS ?",
                    (run.run_id, DIFF_CONTRACT_VERSION, run.baseline_run_id),
                ).fetchone()
                if existing is not None:
                    if existing[0] != digest:
                        raise HistoryDatabaseError("historical_diff_conflict")
                    return report
                connection.execute(
                    "INSERT INTO run_diffs (diff_id, project_id, baseline_run_id, target_run_id, "
                    "diff_contract_version, classification, package_added_count, package_removed_count, "
                    "package_changed_count, finding_introduced_count, finding_resolved_count, "
                    "finding_changed_count, issue_added_count, issue_resolved_count, diff_json_zlib, "
                    "diff_json_size, diff_json_sha256, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (diff_id, run.project_id, run.baseline_run_id, run.run_id, DIFF_CONTRACT_VERSION,
                     report.classification, summary["package_added_count"], summary["package_removed_count"],
                     summary["package_changed_count"], summary["finding_introduced_count"],
                     summary["finding_resolved_count"], summary["finding_changed_count"],
                     summary["issue_added_count"], summary["issue_resolved_count"],
                     zlib.compress(raw), len(raw), digest, run.completed_at),
                )
        except sqlite3.DatabaseError:
            raise HistoryDatabaseError("history_database_failed") from None
        return report
