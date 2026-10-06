"""Deterministic authoritative JSON for semantic differences."""

from __future__ import annotations

from dataclasses import asdict
import json

from .models import DiffReport


DIFF_CONTRACT_VERSION = "svarog-diff/1"


def diff_payload(report: DiffReport) -> dict[str, object]:
    package_changes = [asdict(item) for item in report.package_changes]
    finding_changes = [asdict(item) for item in report.finding_changes]
    issue_changes = [asdict(item) for item in report.issue_changes]
    return {
        "schema_version": DIFF_CONTRACT_VERSION,
        "project_id": report.project_id,
        "audit_kind": report.audit_kind,
        "baseline_snapshot_id": report.baseline_snapshot_id,
        "target_snapshot_id": report.target_snapshot_id,
        "classification": report.classification,
        "causes": report.causes,
        "analysis_engine_changed": report.analysis_engine_changed,
        "python_runtime": {
            "version_before": report.python_version_before,
            "version_after": report.python_version_after,
            "version_changed": report.python_version_changed,
            "implementation": "unknown",
        },
        "summary": {
            "package_added_count": sum("added" in item.change_types for item in report.package_changes),
            "package_removed_count": sum("removed" in item.change_types for item in report.package_changes),
            "package_changed_count": sum("added" not in item.change_types and "removed" not in item.change_types for item in report.package_changes),
            "finding_introduced_count": sum(item.change_type == "introduced" for item in report.finding_changes),
            "finding_resolved_count": sum(item.change_type == "resolved" for item in report.finding_changes),
            "finding_changed_count": sum(item.change_type == "changed" for item in report.finding_changes),
            "issue_added_count": sum(item.change_type == "added" for item in report.issue_changes),
            "issue_resolved_count": sum(item.change_type == "resolved" for item in report.issue_changes),
        },
        "package_changes": package_changes,
        "finding_changes": finding_changes,
        "dependency_changes": [asdict(item) for item in report.dependency_changes],
        "issue_changes": issue_changes,
        "warnings": report.warnings,
        "actions_executed": False,
    }


def render_diff_json(report: DiffReport) -> bytes:
    return (json.dumps(diff_payload(report), ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
