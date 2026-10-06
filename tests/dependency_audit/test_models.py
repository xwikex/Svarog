from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest

from svarog.dependency_audit.models import (
    AdvisorySeverity,
    AuditIssue,
    AuditStatus,
    DatabaseMetadata,
    DependencyAuditReport,
    MatchStatus,
)


def test_models_are_frozen_and_enum_values_are_strings():
    issue = AuditIssue("code", "message")
    with pytest.raises(FrozenInstanceError):
        issue.code = "changed"
    assert AdvisorySeverity.HIGH.value == "high"
    assert AuditStatus.COMPLETED_CLEAN.value == "completed_clean"
    assert MatchStatus.AFFECTED.value == "affected"


def test_report_copies_target_and_summary_as_immutable_mappings():
    target = {"environment": "env"}
    summary = {"packages": 1}
    report = DependencyAuditReport(
        report_type="dependency_audit",
        schema_version="1",
        generated_at="2026-01-01T00:00:00Z",
        audit_status=AuditStatus.COMPLETED_CLEAN,
        target=target,
        database=DatabaseMetadata("db", 1, ("source",)),
        summary=summary,
        installed_packages=(),
        findings=(),
        indeterminate_findings=(),
    )
    target["environment"] = "mutated"
    summary["packages"] = 99
    assert isinstance(report.target, MappingProxyType)
    assert isinstance(report.summary, MappingProxyType)
    assert report.target["environment"] == "env"
    assert report.summary["packages"] == 1
    with pytest.raises(TypeError):
        report.target["x"] = 1


def test_report_copies_target_string_sequences():
    target = {"environment_path": "/v", "site_packages": ["/v/lib"]}
    report = DependencyAuditReport("t", "1", "now", AuditStatus.COMPLETED_CLEAN, target,
                                  DatabaseMetadata("db", 1, ("s",)), {}, (), (), ())
    target["site_packages"].append("/v/other")
    assert report.target["site_packages"] == ("/v/lib",)


def test_report_rejects_unsupported_target_values():
    with pytest.raises(TypeError):
        DependencyAuditReport("t", "1", "now", AuditStatus.COMPLETED_CLEAN,
                              {"bad": {"nested": "value"}}, DatabaseMetadata("db", 1, ()), {}, (), (), ())
