from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from svarog.dependency_audit.models import (
    AdvisorySeverity,
    AuditStatus,
    DatabaseMetadata,
    DependencyFinding,
    InstalledPackage,
)
from svarog.project_audit.models import (
    DifferenceStatus,
    LockedPackage,
    LockFinding,
    ProjectDependencyAuditReport,
    VersionDifference,
)
from svarog.project_audit.reporting import (
    render_project_html,
    render_project_json,
    write_project_html,
    write_project_json,
)


def _report() -> ProjectDependencyAuditReport:
    installed = InstalledPackage(
        name="演示包",
        normalized_name="demo",
        version="1.0",
        version_valid=True,
        metadata_path="C:/project/.venv/Lib/site-packages/demo.dist-info/METADATA",
    )
    locked = LockedPackage("演示包", "demo", "1.0", True, "registry")
    environment_finding = DependencyFinding(
        package_name="演示包",
        normalized_package_name="demo",
        installed_version="1.0",
        ghsa_id="GHSA-test-0001",
        cve_id="CVE-2026-0001",
        severity=AdvisorySeverity.HIGH,
        cvss_score=8.0,
        affected_range="< 2.0",
        fixed_version="2.0",
        summary="测试公告",
        source="github_api",
        advisory_updated_at="2026-09-02T02:00:00Z",
    )
    lock_finding = LockFinding(
        package_name="演示包",
        normalized_package_name="demo",
        locked_version="1.0",
        ghsa_id="GHSA-test-0001",
        cve_id="CVE-2026-0001",
        severity=AdvisorySeverity.HIGH,
        cvss_score=8.0,
        affected_range="< 2.0",
        fixed_version="2.0",
        summary="测试公告",
        source="github_api",
        advisory_updated_at="2026-09-02T02:00:00Z",
    )
    return ProjectDependencyAuditReport(
        report_type="project_dependency_audit",
        schema_version="0.1.0",
        generated_at="2026-09-02T03:00:00+00:00",
        audit_status=AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS,
        target={
            "environment_path": "C:/project/.venv",
            "site_packages": ("C:/project/.venv/Lib/site-packages",),
            "lock_file_path": "C:/project/uv.lock",
            "lock_format": "uv",
        },
        database=DatabaseMetadata(
            path="C:/data/vulnerabilities.db",
            size_bytes=1024,
            sources=("github_api",),
            last_sync_at="2026-09-02T03:00:00Z",
            last_sync_status="ok",
            last_sync_message="complete",
        ),
        lock_evaluation={
            "marker_policy": "ignored",
            "version_policy": "all_distinct_versions",
            "applicability": "unverified",
        },
        summary={
            "installed_packages": 1,
            "locked_packages": 1,
            "version_differences": 1,
            "matched": 1,
            "version_mismatch": 0,
            "missing": 0,
            "unexpected": 0,
            "ambiguous": 0,
            "indeterminate_differences": 0,
            "confirmed_environment_findings": 1,
            "environment_indeterminate_findings": 0,
            "potential_lock_findings": 1,
            "lock_indeterminate_findings": 0,
            "environment_withdrawn_advisories_excluded": 0,
            "lock_withdrawn_advisories_excluded": 0,
            "environment_issues": 0,
            "lock_issues": 0,
            "truncated_details": 0,
            "lock_match_evaluation_limit_reached": 0,
        },
        installed_packages=(installed,),
        locked_packages=(locked,),
        version_differences=(
            VersionDifference(
                name="演示包",
                normalized_name="demo",
                installed_versions=("1.0",),
                locked_versions=("1.0",),
                status=DifferenceStatus.MATCHED,
            ),
        ),
        environment_findings=(environment_finding,),
        environment_indeterminate_findings=(),
        lock_findings=(lock_finding,),
        lock_indeterminate_findings=(),
        warnings=("已忽略 marker。",),
    )


def test_project_json_is_the_stable_authoritative_schema() -> None:
    payload = json.loads(render_project_json(_report()))

    assert payload["report_type"] == "project_dependency_audit"
    assert payload["schema_version"] == "0.1.0"
    assert payload["audit_status"] == "completed_with_findings_and_gaps"
    assert payload["lock_evaluation"] == {
        "marker_policy": "ignored",
        "version_policy": "all_distinct_versions",
        "applicability": "unverified",
    }
    assert payload["environment_findings"][0]["installed_version"] == "1.0"
    assert payload["lock_findings"][0]["locked_version"] == "1.0"
    assert payload["lock_findings"][0]["applicability"] == "unverified"
    assert payload["version_differences"][0]["status"] == "matched"
    assert payload["actions_executed"] is False


def test_project_json_is_utf8_and_rejects_non_finite_numbers() -> None:
    assert "演示包" in render_project_json(_report())
    invalid_finding = replace(_report().lock_findings[0], cvss_score=float("nan"))
    invalid = replace(_report(), lock_findings=(invalid_finding,))

    with pytest.raises(ValueError, match="Out of range float values"):
        render_project_json(invalid)


def test_project_json_write_is_private_atomic_and_leaves_no_temporary_file(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "project.json"

    write_project_json(_report(), destination)

    assert destination.read_bytes() == render_project_json(_report()).encode("utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".project.json.*.tmp")) == []


def test_project_json_replace_failure_preserves_previous_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "project.json"
    destination.write_bytes(b"previous-good-report")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated output failure")

    monkeypatch.setattr("svarog.project_audit.reporting.os.replace", fail)

    with pytest.raises(OSError, match="simulated output failure"):
        write_project_json(_report(), destination)

    assert destination.read_bytes() == b"previous-good-report"
    assert list(tmp_path.glob(".project.json.*.tmp")) == []


@pytest.mark.parametrize("path", [Path("."), Path("..")])
def test_project_json_rejects_non_leaf_destination(path: Path) -> None:
    with pytest.raises(ValueError, match="output filename"):
        write_project_json(_report(), path)


def test_single_file_html_preserves_authoritative_json_status_and_counts() -> None:
    report = _report()
    payload = json.loads(render_project_json(report))

    document = render_project_html(report)

    assert '<meta name="svarog-audit-status" content="completed_with_findings_and_gaps">' in document
    assert '<meta name="svarog-confirmed-environment-findings" content="1">' in document
    assert '<meta name="svarog-potential-lock-findings" content="1">' in document
    assert payload["audit_status"] in document
    assert str(payload["summary"]["confirmed_environment_findings"]) in document
    assert str(payload["summary"]["potential_lock_findings"]) in document


def test_single_file_html_has_no_javascript_or_external_dependencies() -> None:
    document = render_project_html(_report()).lower()

    assert "<script" not in document
    assert "javascript:" not in document
    assert "<link" not in document
    assert " src=" not in document
    assert "default-src 'none'; style-src 'unsafe-inline'; img-src data:" in document
    assert document.count("<style>") == 1


def test_single_file_html_escapes_all_untrusted_report_text() -> None:
    hostile = '</style><script>alert("x")</script><img src=x onerror=alert(1)>'
    report = _report()
    installed = replace(report.installed_packages[0], name=hostile)
    locked = replace(report.locked_packages[0], name=hostile)
    environment_finding = replace(
        report.environment_findings[0],
        package_name=hostile,
        summary=hostile,
    )
    lock_finding = replace(
        report.lock_findings[0],
        package_name=hostile,
        summary=hostile,
    )
    hostile_report = replace(
        report,
        installed_packages=(installed,),
        locked_packages=(locked,),
        environment_findings=(environment_finding,),
        lock_findings=(lock_finding,),
        warnings=(hostile,),
    )

    document = render_project_html(hostile_report)

    assert hostile not in document
    assert "&lt;/style&gt;&lt;script&gt;" in document
    assert document.lower().count("<script") == 0
    assert document.lower().count("<style>") == 1


def test_project_html_uses_the_same_private_atomic_writer(tmp_path: Path) -> None:
    destination = tmp_path / "project.html"

    write_project_html(_report(), destination)

    assert destination.read_bytes() == render_project_html(_report()).encode("utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".project.html.*.tmp")) == []
