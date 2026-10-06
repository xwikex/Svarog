import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from svarog.dependency_audit.models import (
    AdvisorySeverity,
    AuditIssue,
    AuditStatus,
    DatabaseMetadata,
    DependencyAuditReport,
    DependencyFinding,
    IndeterminateFinding,
    InstalledPackage,
)
from svarog.dependency_audit.reporting import (
    render_dependency_json,
    render_dependency_terminal,
    write_dependency_json,
)


def _report() -> DependencyAuditReport:
    package = InstalledPackage(
        name="demo",
        normalized_name="demo",
        version="1.0",
        version_valid=True,
        metadata_path="/venv/lib/python3.11/site-packages/demo.dist-info/METADATA",
    )
    finding = DependencyFinding(
        package_name="demo",
        normalized_package_name="demo",
        installed_version="1.0",
        ghsa_id="GHSA-test-0001",
        cve_id="CVE-2026-0001",
        severity=AdvisorySeverity.HIGH,
        cvss_score=8.0,
        affected_range="< 2.0",
        fixed_version="2.0",
        summary="demo advisory",
        source="github_api",
        advisory_updated_at="2026-08-30T00:00:00Z",
    )
    uncertain = IndeterminateFinding(
        package_name="other",
        normalized_package_name="other",
        installed_versions=("vendor-1",),
        ghsa_id="GHSA-test-0002",
        cve_id=None,
        affected_range="< 0.8.3ubuntu7.5",
        fixed_version=None,
        reason_code="unsupported_version_range",
    )
    return DependencyAuditReport(
        report_type="dependency_audit",
        schema_version="0.1.0",
        generated_at="2026-08-31T12:00:00+00:00",
        audit_status=AuditStatus.COMPLETED_WITH_FINDINGS_AND_GAPS,
        target={
            "environment_path": "/venv",
            "site_packages": ("/venv/lib/python3.11/site-packages",),
        },
        database=DatabaseMetadata(
            path="/opt/vuln-database/vulnerabilities.db",
            size_bytes=1234,
            sources=("github_api",),
            last_sync_at="2026-08-31T11:00:00Z",
            last_sync_status="ok",
            last_sync_message="complete",
        ),
        summary={
            "installed_packages": 2,
            "packages_with_findings": 1,
            "confirmed_findings": 1,
            "indeterminate_findings": 1,
            "inventory_issues": 1,
            "critical_findings": 0,
            "high_findings": 1,
            "medium_findings": 0,
            "low_findings": 0,
            "unknown_findings": 0,
            "withdrawn_advisories_excluded": 0,
            "truncated_details": 0,
        },
        installed_packages=(package,),
        findings=(finding,),
        indeterminate_findings=(uncertain,),
        inventory_issues=(AuditIssue("test_issue", "test issue", "demo"),),
        warnings=("database warning",),
        actions_executed=False,
    )


def test_dependency_terminal_report_states_findings_gaps_and_no_actions() -> None:
    text = render_dependency_terminal(_report())

    assert "Svarog Python 依赖漏洞审计" in text
    assert "确认漏洞：1" in text
    assert "无法判断：1" in text
    assert "GHSA-test-0001" in text
    assert "未执行任何动作" in text


def test_dependency_terminal_report_escapes_untrusted_fields() -> None:
    report = _report()
    hostile = "demo\n伪造报告\x1b[31m\u202e"
    finding = DependencyFinding(
        package_name=hostile,
        normalized_package_name="demo",
        installed_version=hostile,
        ghsa_id=hostile,
        cve_id=hostile,
        severity=AdvisorySeverity.HIGH,
        cvss_score=8.0,
        affected_range=hostile,
        fixed_version=hostile,
        summary=hostile,
        source=hostile,
        advisory_updated_at=None,
    )
    uncertain = IndeterminateFinding(
        package_name=hostile,
        normalized_package_name="demo",
        installed_versions=("1.0",),
        ghsa_id=hostile,
        cve_id=None,
        affected_range=hostile,
        fixed_version=None,
        reason_code=hostile,
    )
    report = DependencyAuditReport(
        report_type=report.report_type,
        schema_version=report.schema_version,
        generated_at=report.generated_at,
        audit_status=report.audit_status,
        target=report.target,
        database=report.database,
        summary=report.summary,
        installed_packages=report.installed_packages,
        findings=(finding,),
        indeterminate_findings=(uncertain,),
        inventory_issues=report.inventory_issues,
        warnings=(hostile,),
    )

    text = render_dependency_terminal(report)

    assert "demo\\n伪造报告\\x1b[31m\\u202e" in text
    assert "\n伪造报告" not in text
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_dependency_json_has_stable_schema() -> None:
    payload = json.loads(render_dependency_json(_report()))

    assert payload["report_type"] == "dependency_audit"
    assert payload["schema_version"] == "0.1.0"
    assert payload["audit_status"] == "completed_with_findings_and_gaps"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["actions_executed"] is False


def test_dependency_json_rejects_non_finite_numbers() -> None:
    report = _report()
    finding = replace(report.findings[0], cvss_score=float("nan"))
    invalid_report = replace(report, findings=(finding,))

    with pytest.raises(ValueError, match="Out of range float values"):
        render_dependency_json(invalid_report)


def test_dependency_json_success_is_exact_utf8_and_private(tmp_path: Path) -> None:
    report = _report()
    target = tmp_path / "audit.json"

    write_dependency_json(report, target)

    assert target.read_bytes() == render_dependency_json(report).encode("utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".audit.json.*.tmp")) == []


def _raise_oserror(*_args: object, **_kwargs: object) -> None:
    raise OSError("simulated output failure")


def test_atomic_json_replace_failure_preserves_existing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "audit.json"
    target.write_bytes(b"previous-good-report")
    monkeypatch.setattr("svarog.dependency_audit.reporting.os.replace", _raise_oserror)

    with pytest.raises(OSError, match="simulated output failure"):
        write_dependency_json(_report(), target)

    assert target.read_bytes() == b"previous-good-report"
    assert list(tmp_path.glob(".audit.json.*.tmp")) == []


def test_atomic_json_file_fsync_failure_preserves_existing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "audit.json"
    target.write_bytes(b"previous-good-report")
    monkeypatch.setattr("svarog.dependency_audit.reporting.os.fsync", _raise_oserror)

    with pytest.raises(OSError, match="simulated output failure"):
        write_dependency_json(_report(), target)

    assert target.read_bytes() == b"previous-good-report"
    assert list(tmp_path.glob(".audit.json.*.tmp")) == []


def test_atomic_json_fsyncs_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        pytest.skip("directory fsync is not available on this platform")
    target = tmp_path / "audit.json"
    original_fsync = os.fsync
    directory_fsyncs = 0

    def record_fsync(descriptor: int) -> None:
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_fsyncs += 1
        original_fsync(descriptor)

    monkeypatch.setattr("svarog.dependency_audit.reporting.os.fsync", record_fsync)

    write_dependency_json(_report(), target)

    assert directory_fsyncs == 1


def test_directory_fsync_failure_reports_committed_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        pytest.skip("directory fsync is not available on this platform")
    target = tmp_path / "audit.json"
    target.write_bytes(b"previous-good-report")
    expected = render_dependency_json(_report()).encode("utf-8")
    original_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("simulated directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(
        "svarog.dependency_audit.reporting.os.fsync", fail_directory_fsync
    )

    with pytest.raises(OSError, match="simulated directory fsync failure"):
        write_dependency_json(_report(), target)

    assert target.read_bytes() == expected
    assert list(tmp_path.glob(".audit.json.*.tmp")) == []


def test_relative_destination_is_fixed_before_cwd_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = tmp_path / "initial"
    elsewhere = tmp_path / "elsewhere"
    initial.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(tmp_path)
    original_replace = os.replace

    def replace_after_chdir(source: Path, destination: Path) -> None:
        os.chdir(elsewhere)
        original_replace(source, destination)

    monkeypatch.setattr(
        "svarog.dependency_audit.reporting.os.replace", replace_after_chdir
    )

    write_dependency_json(_report(), Path("initial") / "audit.json")

    assert (initial / "audit.json").read_bytes() == render_dependency_json(
        _report()
    ).encode("utf-8")
    assert not (elsewhere / "initial" / "audit.json").exists()


def test_resolved_destination_ignores_parent_symlink_retargeting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("directory symlink replacement requires POSIX semantics")
    original = tmp_path / "original"
    redirected = tmp_path / "redirected"
    original.mkdir()
    redirected.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(original, target_is_directory=True)
    original_replace = os.replace

    def replace_after_retarget(source: Path, destination: Path) -> None:
        alias.unlink()
        alias.symlink_to(redirected, target_is_directory=True)
        original_replace(source, destination)

    monkeypatch.setattr(
        "svarog.dependency_audit.reporting.os.replace", replace_after_retarget
    )

    write_dependency_json(_report(), alias / "audit.json")

    assert (original / "audit.json").exists()
    assert not (redirected / "audit.json").exists()


@pytest.mark.parametrize("path", [Path("."), Path("..")])
def test_dependency_json_rejects_non_leaf_destination(path: Path) -> None:
    with pytest.raises(ValueError, match="output filename"):
        write_dependency_json(_report(), path)


def test_dependency_json_does_not_create_missing_parent(tmp_path: Path) -> None:
    missing_parent = tmp_path / "missing"

    with pytest.raises(FileNotFoundError):
        write_dependency_json(_report(), missing_parent / "audit.json")

    assert not missing_parent.exists()
