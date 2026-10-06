from datetime import datetime, timezone

import pytest

from svarog.dependency_audit import service
from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    AuditIssue,
    AuditStatus,
    DatabaseMetadata,
    InstalledPackage,
    InventoryResult,
    VulnerabilitySnapshot,
)
from svarog.dependency_audit.service import (
    MAX_REPORT_DETAILS,
    build_dependency_audit_report,
)


NOW = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


def _package(
    name: str,
    version: str,
    *,
    normalized_name: str | None = None,
    version_valid: bool = True,
) -> InstalledPackage:
    normalized = normalized_name or name.lower().replace("_", "-")
    return InstalledPackage(
        name=name,
        normalized_name=normalized,
        version=version,
        version_valid=version_valid,
        metadata_path=f"/venv/lib/python3.11/site-packages/{name}.dist-info/METADATA",
    )


def _inventory(
    *packages: InstalledPackage,
    ambiguous_names: frozenset[str] = frozenset(),
    issues: tuple[AuditIssue, ...] = (),
    truncated_metadata_dirs: int = 0,
) -> InventoryResult:
    return InventoryResult(
        environment_path="/venv",
        site_packages=("/venv/lib/python3.11/site-packages",),
        packages=packages,
        ambiguous_names=ambiguous_names,
        issues=issues,
        total_metadata_dirs=len(packages) + truncated_metadata_dirs,
        truncated_metadata_dirs=truncated_metadata_dirs,
    )


def _advisory(
    package: str,
    affected_range: str,
    *,
    normalized_package_name: str | None = None,
    ghsa_id: str = "GHSA-test-0001",
    cve_id: str | None = "CVE-2026-0001",
    state: str = "published",
    withdrawn_at: str | None = None,
    severity: AdvisorySeverity = AdvisorySeverity.HIGH,
    cvss_score: float | None = 8.0,
    fixed_version: str | None = "2.0",
) -> AdvisoryRecord:
    return AdvisoryRecord(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        state=state,
        withdrawn_at=withdrawn_at,
        summary=f"{package} advisory",
        severity=severity,
        cvss_score=cvss_score,
        source="github_api",
        updated_at="2026-08-30T00:00:00Z",
        package_name=package,
        normalized_package_name=normalized_package_name or package.lower(),
        version_range=affected_range,
        fixed_version=fixed_version,
    )


def _snapshot(
    *advisories: AdvisoryRecord,
    issues: tuple[AuditIssue, ...] = (),
    last_sync_at: str | None = "2026-08-31T12:00:00Z",
    last_sync_status: str | None = "ok",
) -> VulnerabilitySnapshot:
    return VulnerabilitySnapshot(
        metadata=DatabaseMetadata(
            path="/opt/vuln-database/vulnerabilities.db",
            size_bytes=1234,
            sources=("github_api",),
            last_sync_at=last_sync_at,
            last_sync_status=last_sync_status,
            last_sync_message="complete",
        ),
        advisories=advisories,
        issues=issues,
    )


def test_service_reports_confirmed_vulnerability_and_exact_report_shape() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(_advisory("demo", "< 2.0", severity=AdvisorySeverity.HIGH)),
        now=NOW,
    )

    assert report.report_type == "dependency_audit"
    assert report.schema_version == "0.1.0"
    assert report.generated_at == "2026-08-31T12:00:00+00:00"
    assert report.audit_status is AuditStatus.COMPLETED_WITH_FINDINGS
    assert report.target == {
        "environment_path": "/venv",
        "site_packages": ("/venv/lib/python3.11/site-packages",),
    }
    assert report.database.path == "/opt/vuln-database/vulnerabilities.db"
    assert report.actions_executed is False
    assert report.warnings == ()
    assert report.inventory_issues == ()
    assert report.findings[0].ghsa_id == "GHSA-test-0001"
    assert report.findings[0].package_name == "demo"
    assert report.summary == {
        "installed_packages": 1,
        "packages_with_findings": 1,
        "confirmed_findings": 1,
        "indeterminate_findings": 0,
        "inventory_issues": 0,
        "critical_findings": 0,
        "high_findings": 1,
        "medium_findings": 0,
        "low_findings": 0,
        "unknown_findings": 0,
        "withdrawn_advisories_excluded": 0,
        "truncated_details": 0,
    }


def test_service_does_not_report_unaffected_version() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "2.0")),
        _snapshot(_advisory("demo", "< 2.0")),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_CLEAN
    assert report.findings == ()
    assert report.indeterminate_findings == ()


def test_service_groups_ranges_by_logical_advisory_and_affected_wins() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.5")),
        _snapshot(
            _advisory("demo", ">= 1.0, < 2.0"),
            _advisory("demo", "< 0.8.3ubuntu7.5"),
            _advisory("demo", ">= 3.0, < 4.0"),
        ),
        now=NOW,
    )

    assert len(report.findings) == 1
    assert report.findings[0].affected_range == ">= 1.0, < 2.0"
    assert report.indeterminate_findings == ()
    assert report.audit_status is AuditStatus.COMPLETED_WITH_FINDINGS


def test_indeterminate_beats_not_affected_for_one_advisory() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "2.0")),
        _snapshot(
            _advisory("demo", ">= 3.0"),
            _advisory("demo", "< 0.8.3ubuntu7.5"),
        ),
        now=NOW,
    )

    assert report.findings == ()
    assert len(report.indeterminate_findings) == 1
    assert report.indeterminate_findings[0].reason_code == "unsupported_version_range"


def test_duplicate_ranges_produce_one_logical_finding() -> None:
    advisory = _advisory("demo", "< 2.0")
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(advisory, advisory),
        now=NOW,
    )

    assert report.summary["confirmed_findings"] == 1
    assert len(report.findings) == 1


def test_same_ghsa_with_different_cves_are_distinct_logical_results() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(
            _advisory("demo", "< 2", cve_id="CVE-2026-0001"),
            _advisory("demo", "< 2", cve_id="CVE-2026-0002"),
        ),
        now=NOW,
    )

    assert report.summary["confirmed_findings"] == 2
    assert [finding.cve_id for finding in report.findings] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]


def test_missing_and_empty_cve_values_remain_distinct_logical_keys() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(
            _advisory("demo", "< 2", cve_id=None),
            _advisory("demo", "< 2", cve_id=""),
        ),
        now=NOW,
    )

    assert report.summary["confirmed_findings"] == 2
    assert [finding.cve_id for finding in report.findings] == [None, ""]


def test_advisories_for_uninstalled_packages_are_ignored() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "3.0")),
        _snapshot(_advisory("other", "< 99")),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_CLEAN
    assert report.findings == ()
    assert report.summary["withdrawn_advisories_excluded"] == 0


@pytest.mark.parametrize("withdrawal_kind", ["state", "timestamp"])
def test_any_withdrawn_row_excludes_the_entire_mixed_group(withdrawal_kind: str) -> None:
    withdrawn = (
        _advisory("demo", ">= 9", state="withdrawn")
        if withdrawal_kind == "state"
        else _advisory("demo", ">= 9", withdrawn_at="2026-08-20")
    )
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(_advisory("demo", "< 2.0"), withdrawn),
        now=NOW,
    )

    assert report.summary["withdrawn_advisories_excluded"] == 1
    assert report.findings == ()
    assert report.audit_status is AuditStatus.COMPLETED_CLEAN


@pytest.mark.parametrize("withdrawn_at", [None, "", "   ", "\t"])
def test_empty_withdrawn_timestamp_does_not_exclude_group(
    withdrawn_at: str | None,
) -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(_advisory("demo", "< 2.0", withdrawn_at=withdrawn_at)),
        now=NOW,
    )

    assert report.summary["withdrawn_advisories_excluded"] == 0
    assert report.summary["confirmed_findings"] == 1


def test_invalid_matching_range_prevents_clean_result() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(_advisory("demo", "< 0.8.3ubuntu7.5")),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert report.summary["indeterminate_findings"] == 1
    assert report.indeterminate_findings[0].reason_code == "unsupported_version_range"


def test_ambiguous_installed_versions_are_indeterminate() -> None:
    inventory = _inventory(
        _package("demo", "2.0"),
        _package("demo", "1.0"),
        ambiguous_names=frozenset({"demo"}),
    )
    report = build_dependency_audit_report(
        inventory,
        _snapshot(_advisory("demo", "< 3.0")),
        now=NOW,
    )

    assert report.findings == ()
    assert report.indeterminate_findings[0].reason_code == "ambiguous_installed_versions"
    assert report.indeterminate_findings[0].installed_versions == ("1.0", "2.0")


def test_explicit_inventory_ambiguity_is_honored_with_one_retained_version() -> None:
    report = build_dependency_audit_report(
        _inventory(
            _package("demo", "1.0"),
            ambiguous_names=frozenset({"demo"}),
        ),
        _snapshot(_advisory("demo", "< 2.0")),
        now=NOW,
    )

    assert report.findings == ()
    assert report.indeterminate_findings[0].reason_code == (
        "ambiguous_installed_versions"
    )


def test_any_invalid_installed_version_makes_group_indeterminate() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "vendor", version_valid=False)),
        _snapshot(_advisory("demo", "< 3.0")),
        now=NOW,
    )

    assert report.findings == ()
    assert report.indeterminate_findings[0].reason_code == "invalid_installed_version"
    assert report.indeterminate_findings[0].installed_versions == ("vendor",)


@pytest.mark.parametrize(
    ("last_sync_at", "last_sync_status", "expected_warning"),
    [
        (None, "ok", "漏洞库最后同步时间缺失或无效。"),
        ("not-a-time", "ok", "漏洞库最后同步时间缺失或无效。"),
        ("2026-08-01T00:00:00Z", "ok", "漏洞库已超过 7 天未成功同步。"),
        (
            "2026-08-31T12:05:01Z",
            "ok",
            "漏洞库最后同步时间位于允许的未来偏差之外。",
        ),
        ("2026-08-31T12:00:00Z", "failed", "漏洞库最后同步状态异常。"),
    ],
)
def test_bad_database_freshness_prevents_clean_status(
    last_sync_at: str | None,
    last_sync_status: str,
    expected_warning: str,
) -> None:
    report = build_dependency_audit_report(
        _inventory(_package("demo", "3.0")),
        _snapshot(last_sync_at=last_sync_at, last_sync_status=last_sync_status),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert expected_warning in report.warnings


def test_sync_status_is_trimmed_and_case_insensitive_and_boundaries_are_allowed() -> None:
    report = build_dependency_audit_report(
        _inventory(),
        _snapshot(
            last_sync_at="2026-08-31T20:05:00+08:00",
            last_sync_status=" OK ",
        ),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_CLEAN
    assert report.generated_at == "2026-08-31T12:00:00+00:00"
    assert report.warnings == ()


@pytest.mark.parametrize("bad_max", [0, -1, True, False, 1.0, "1", None])
def test_max_details_must_be_a_positive_non_boolean_integer(bad_max: object) -> None:
    with pytest.raises(ValueError, match="max_details"):
        build_dependency_audit_report(
            _inventory(),
            _snapshot(),
            now=NOW,
            max_details=bad_max,  # type: ignore[arg-type]
        )


def test_naive_explicit_now_is_rejected() -> None:
    with pytest.raises(ValueError, match="now"):
        build_dependency_audit_report(
            _inventory(),
            _snapshot(),
            now=datetime(2026, 8, 31, 12, 0),
        )


def test_explicit_aware_now_is_converted_to_utc() -> None:
    report = build_dependency_audit_report(
        _inventory(),
        _snapshot(last_sync_at="2026-08-31T12:00:00Z"),
        now=datetime.fromisoformat("2026-08-31T20:00:00+08:00"),
    )

    assert report.generated_at == "2026-08-31T12:00:00+00:00"
    assert report.audit_status is AuditStatus.COMPLETED_CLEAN


@pytest.mark.parametrize(
    "last_sync_at",
    [
        "0001-01-01T00:00:00+14:00",
        "9999-12-31T23:59:59.999999-14:00",
    ],
)
def test_sync_timestamp_that_overflows_utc_conversion_is_a_gap(
    last_sync_at: str,
) -> None:
    report = build_dependency_audit_report(
        _inventory(),
        _snapshot(last_sync_at=last_sync_at),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert "漏洞库最后同步时间缺失或无效。" in report.warnings


@pytest.mark.parametrize("edge_now", [datetime.min, datetime.max])
def test_utc_datetime_edges_do_not_overflow_freshness_checks(
    edge_now: datetime,
) -> None:
    aware_now = edge_now.replace(tzinfo=timezone.utc)
    report = build_dependency_audit_report(
        _inventory(),
        _snapshot(last_sync_at=aware_now.isoformat()),
        now=aware_now,
    )

    assert report.audit_status is AuditStatus.COMPLETED_CLEAN
    assert report.generated_at == aware_now.isoformat()


def test_inventory_issues_and_truncation_are_gaps() -> None:
    issue = AuditIssue("invalid_metadata", "invalid_metadata", "/venv/METADATA")
    report = build_dependency_audit_report(
        _inventory(issues=(issue,), truncated_metadata_dirs=2),
        _snapshot(),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert report.inventory_issues == (issue,)
    assert report.summary["inventory_issues"] == 1


def test_relevant_repository_issue_does_not_suppress_confirmed_match() -> None:
    issue = AuditIssue("invalid_cvss", "公告 CVSS 不是有效数值。", "demo")
    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(
            _advisory("demo", "< 2.0", cvss_score=None),
            issues=(issue,),
        ),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS
    assert report.summary["confirmed_findings"] == 1
    assert report.findings[0].cvss_score is None
    assert report.inventory_issues == (issue,)


def test_unrelated_database_issue_does_not_make_clean_audit_incomplete() -> None:
    issue = AuditIssue("invalid_cvss", "公告 CVSS 不是有效数值。", "not-installed")
    report = build_dependency_audit_report(
        _inventory(_package("demo", "3.0")),
        _snapshot(issues=(issue,)),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_CLEAN
    assert report.inventory_issues == ()


def test_subjectless_database_issue_affects_every_audit() -> None:
    issue = AuditIssue("snapshot_quality", "数据库快照存在质量问题。")
    report = build_dependency_audit_report(
        _inventory(),
        _snapshot(issues=(issue,)),
        now=NOW,
    )

    assert report.audit_status is AuditStatus.COMPLETED_INCOMPLETE
    assert report.inventory_issues == (issue,)


def test_counts_are_exact_before_confirmed_first_shared_cap() -> None:
    report = build_dependency_audit_report(
        _inventory(_package("alpha", "1.0"), _package("beta", "1.0")),
        _snapshot(
            _advisory("alpha", "< 0.8.3ubuntu7.5", ghsa_id="GHSA-test-gap1"),
            _advisory(
                "beta",
                "< 2.0",
                ghsa_id="GHSA-test-hit1",
                severity=AdvisorySeverity.CRITICAL,
            ),
            _advisory(
                "beta",
                "< 2.0",
                ghsa_id="GHSA-test-hit2",
                severity=AdvisorySeverity.HIGH,
            ),
        ),
        now=NOW,
        max_details=2,
    )

    assert [item.ghsa_id for item in report.findings] == [
        "GHSA-test-hit1",
        "GHSA-test-hit2",
    ]
    assert report.indeterminate_findings == ()
    assert report.summary["confirmed_findings"] == 2
    assert report.summary["indeterminate_findings"] == 1
    assert report.summary["truncated_details"] == 1
    assert report.audit_status is AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS
    assert "审计报告明细已达到上限，部分结果未保留。" in report.warnings


def test_confirmed_and_indeterminate_results_have_stable_sort_order() -> None:
    report = build_dependency_audit_report(
        _inventory(
            _package("zeta", "1.0"),
            _package("alpha", "2.0"),
            _package("alpha", "1.0"),
            _package("beta", "1.0"),
        ),
        _snapshot(
            _advisory("zeta", "< 2", ghsa_id="GHSA-z", severity=AdvisorySeverity.LOW),
            _advisory("beta", "< 2", ghsa_id="GHSA-b", severity=AdvisorySeverity.CRITICAL),
            _advisory("alpha", "< 3", ghsa_id="GHSA-a2", severity=AdvisorySeverity.HIGH),
            _advisory("alpha", "< 3", ghsa_id="GHSA-a1", severity=AdvisorySeverity.HIGH),
            _advisory("zeta", "vendor", ghsa_id="GHSA-gap-z"),
            _advisory("beta", "vendor", ghsa_id="GHSA-gap-b"),
        ),
        now=NOW,
    )

    confirmed_order = [
        (item.severity, item.normalized_package_name, item.ghsa_id)
        for item in report.findings
    ]
    assert confirmed_order == [
        (AdvisorySeverity.CRITICAL, "beta", "GHSA-b"),
        (AdvisorySeverity.LOW, "zeta", "GHSA-z"),
    ]
    indeterminate_order = [
        (item.normalized_package_name, item.ghsa_id)
        for item in report.indeterminate_findings
    ]
    assert indeterminate_order == [
        ("alpha", "GHSA-a1"),
        ("alpha", "GHSA-a2"),
        ("beta", "GHSA-gap-b"),
        ("zeta", "GHSA-gap-z"),
    ]


def test_installed_group_is_precomputed_once_for_many_advisories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service._installed_group
    calls: list[str] = []

    def spy(
        packages: list[InstalledPackage],
        explicitly_ambiguous: bool,
    ) -> object:
        calls.append(packages[0].normalized_name)
        return original(packages, explicitly_ambiguous)

    monkeypatch.setattr(service, "_installed_group", spy)
    advisories = tuple(
        _advisory("demo", "< 2", ghsa_id=f"GHSA-load-{index:04d}")
        for index in range(250)
    )

    report = build_dependency_audit_report(
        _inventory(_package("demo", "1.0")),
        _snapshot(*advisories),
        now=NOW,
    )

    assert calls == ["demo"]
    assert report.summary["confirmed_findings"] == 250


def test_default_detail_limit_is_production_bound() -> None:
    assert MAX_REPORT_DETAILS == 10_000
