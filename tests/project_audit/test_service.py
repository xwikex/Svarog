from __future__ import annotations

from datetime import datetime, timezone

from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    AuditStatus,
    DatabaseMetadata,
    InstalledPackage,
    InventoryResult,
    VulnerabilitySnapshot,
)
from svarog.project_audit.models import LockedPackage, LockSnapshot
from svarog.project_audit.service import build_project_audit_report


NOW = datetime(2026, 9, 2, 3, 0, tzinfo=timezone.utc)


def _inventory(*items: tuple[str, str, bool]) -> InventoryResult:
    packages = tuple(
        InstalledPackage(
            name=name,
            normalized_name=name,
            version=version,
            version_valid=valid,
            metadata_path=f"C:/project/.venv/Lib/site-packages/{name}.dist-info/METADATA",
        )
        for name, version, valid in items
    )
    return InventoryResult(
        environment_path="C:/project/.venv",
        site_packages=("C:/project/.venv/Lib/site-packages",),
        packages=packages,
        ambiguous_names=frozenset(),
        issues=(),
        total_metadata_dirs=len(packages),
        truncated_metadata_dirs=0,
    )


def _lock(*items: tuple[str, str, bool]) -> LockSnapshot:
    return LockSnapshot(
        path="C:/project/uv.lock",
        lock_format="uv",
        packages=tuple(
            LockedPackage(
                name=name,
                normalized_name=name,
                version=version,
                version_valid=valid,
                source_kind="registry",
            )
            for name, version, valid in items
        ),
        issues=(),
        total_package_entries=len(items),
        total_issue_count=0,
        truncated_issue_count=0,
        warnings=("marker policy warning",),
    )


def _advisory(
    package: str,
    affected_range: str,
    *,
    ghsa_id: str = "GHSA-test-0001",
    state: str = "published",
    withdrawn_at: str | None = None,
) -> AdvisoryRecord:
    return AdvisoryRecord(
        ghsa_id=ghsa_id,
        cve_id="CVE-2026-0001",
        state=state,
        withdrawn_at=withdrawn_at,
        summary="test advisory",
        severity=AdvisorySeverity.HIGH,
        cvss_score=8.0,
        source="github_api",
        updated_at="2026-09-02T02:00:00Z",
        package_name=package,
        normalized_package_name=package,
        version_range=affected_range,
        fixed_version="2.0",
    )


def _snapshot(*advisories: AdvisoryRecord) -> VulnerabilitySnapshot:
    return VulnerabilitySnapshot(
        metadata=DatabaseMetadata(
            path="C:/data/vulnerabilities.db",
            size_bytes=1024,
            sources=("github_api",),
            last_sync_at="2026-09-02T03:00:00Z",
            last_sync_status="ok",
            last_sync_message="complete",
        ),
        advisories=advisories,
    )


def test_report_keeps_confirmed_environment_and_unverified_lock_results_separate() -> None:
    report = build_project_audit_report(
        _inventory(("demo", "3.0", True)),
        _lock(("demo", "1.0", True), ("demo", "3.0", True)),
        _snapshot(_advisory("demo", "< 2.0")),
        now=NOW,
    )

    assert report.report_type == "project_dependency_audit"
    assert report.schema_version == "0.1.0"
    assert report.generated_at == "2026-09-02T03:00:00+00:00"
    assert report.environment_findings == ()
    assert len(report.lock_findings) == 1
    assert report.lock_findings[0].locked_version == "1.0"
    assert report.lock_findings[0].applicability == "unverified"
    assert report.summary["confirmed_environment_findings"] == 0
    assert report.summary["potential_lock_findings"] == 1
    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert report.actions_executed is False


def test_environment_finding_remains_confirmed_when_lock_also_matches() -> None:
    report = build_project_audit_report(
        _inventory(("demo", "1.0", True)),
        _lock(("demo", "1.0", True)),
        _snapshot(_advisory("demo", "< 2.0")),
        now=NOW,
    )

    assert len(report.environment_findings) == 1
    assert len(report.lock_findings) == 1
    assert report.audit_status is AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS


def test_lock_candidate_invalid_version_is_indeterminate() -> None:
    report = build_project_audit_report(
        _inventory(),
        _lock(("demo", "not-a-version", False)),
        _snapshot(_advisory("demo", "< 2.0")),
        now=NOW,
    )

    assert report.lock_findings == ()
    assert len(report.lock_indeterminate_findings) == 1
    assert report.lock_indeterminate_findings[0].reason_code == "invalid_locked_version"
    assert report.lock_indeterminate_findings[0].applicability == "unverified"


def test_unsupported_advisory_range_is_a_lock_indeterminate_result() -> None:
    report = build_project_audit_report(
        _inventory(),
        _lock(("demo", "1.0", True)),
        _snapshot(_advisory("demo", "< 0.8.3ubuntu7.5")),
        now=NOW,
    )

    assert report.lock_findings == ()
    assert report.lock_indeterminate_findings[0].reason_code == "unsupported_version_range"


def test_affected_range_wins_over_unsupported_range_for_same_advisory() -> None:
    report = build_project_audit_report(
        _inventory(),
        _lock(("demo", "1.0", True)),
        _snapshot(
            _advisory("demo", "< 0.8.3ubuntu7.5"),
            _advisory("demo", "< 2.0"),
        ),
        now=NOW,
    )

    assert len(report.lock_findings) == 1
    assert report.lock_indeterminate_findings == ()


def test_withdrawn_logical_advisory_is_excluded_from_both_layers() -> None:
    report = build_project_audit_report(
        _inventory(("demo", "1.0", True)),
        _lock(("demo", "1.0", True)),
        _snapshot(
            _advisory("demo", "< 2.0"),
            _advisory("demo", ">= 9", state="withdrawn"),
        ),
        now=NOW,
    )

    assert report.environment_findings == ()
    assert report.lock_findings == ()
    assert report.summary["environment_withdrawn_advisories_excluded"] == 1
    assert report.summary["lock_withdrawn_advisories_excluded"] == 1


def test_report_contains_fixed_lock_policy_and_version_difference_counts() -> None:
    report = build_project_audit_report(
        _inventory(("demo", "2.0", True), ("extra", "1", True)),
        _lock(("demo", "1.0", True), ("missing", "1", True)),
        _snapshot(),
        now=NOW,
    )

    assert report.lock_evaluation == {
        "marker_policy": "ignored",
        "version_policy": "all_distinct_versions",
        "applicability": "unverified",
    }
    assert report.summary["version_mismatch"] == 1
    assert report.summary["missing"] == 1
    assert report.summary["unexpected"] == 1
    assert "marker policy warning" in report.warnings


def test_project_detail_limit_is_shared_by_environment_and_lock_layers() -> None:
    report = build_project_audit_report(
        _inventory(("demo", "1.0", True)),
        _lock(("demo", "1.0", True), ("other", "1.0", True)),
        _snapshot(
            _advisory("demo", "< 2.0"),
            _advisory("other", "< 2.0", ghsa_id="GHSA-test-0002"),
        ),
        now=NOW,
        max_details=1,
    )

    assert len(report.environment_findings) == 1
    assert report.lock_findings == ()
    assert report.summary["potential_lock_findings"] == 2
    assert report.summary["truncated_details"] == 2
    assert any("明细" in warning for warning in report.warnings)
