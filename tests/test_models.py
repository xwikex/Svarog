from dataclasses import FrozenInstanceError

import pytest

from svarog.models import (
    AnalysisReport,
    Evidence,
    InputIssue,
    NormalizedEvent,
    ParseResult,
    Severity,
)


def test_domain_models_preserve_normalized_evidence() -> None:
    event = NormalizedEvent(
        line_number=1,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/search",
        query="q=test",
    )
    evidence = Evidence(
        rule_id="WEB-SQLI-001",
        category="sql_injection",
        severity=Severity.HIGH,
        description="检测到明显 SQL 注入模式",
        matched_field="query",
        matched_excerpt="union select",
        references=("CWE-89", "ATT&CK:T1190"),
    )

    assert event.method == "GET"
    assert event.status is None
    assert evidence.severity is Severity.HIGH
    assert evidence.references == ("CWE-89", "ATT&CK:T1190")


def test_analysis_report_summary_is_immutable() -> None:
    source_summary = {"total_events": 1}
    report = AnalysisReport(
        schema_version="0.1",
        generated_at="2026-08-03T12:00:00+08:00",
        analysis_status="completed",
        summary=source_summary,
        events=(),
    )

    source_summary["total_events"] = 2

    assert report.summary == {"total_events": 1}
    with pytest.raises(TypeError):
        report.summary["total_events"] = 0


def test_parse_result_defaults_total_issue_count_and_keeps_it_immutable() -> None:
    issue = InputIssue(line_number=1, code="invalid_event", message="invalid")
    result = ParseResult(events=(), issues=(issue,))

    assert result.total_issue_count == 1
    with pytest.raises(FrozenInstanceError):
        result.total_issue_count = 2


def test_parse_result_rejects_total_below_retained_issue_count() -> None:
    issue = InputIssue(line_number=1, code="invalid_event", message="invalid")

    with pytest.raises(ValueError, match="total_issue_count"):
        ParseResult(events=(), issues=(issue,), total_issue_count=0)
