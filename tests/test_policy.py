import pytest

from svarog import policy
from svarog.models import ConclusionStatus, Evidence, InputIssue, NormalizedEvent, Severity
from svarog.policy import analyze_event, build_report


def _event(query: str = "") -> NormalizedEvent:
    return NormalizedEvent(
        line_number=1,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/search",
        query=query,
    )


def test_policy_marks_strong_rule_evidence_as_highly_likely_not_confirmed() -> None:
    result = analyze_event(_event("id=1 UNION SELECT password FROM users"))

    assert result.local_severity is Severity.HIGH
    assert result.conclusion is ConclusionStatus.HIGHLY_LIKELY
    assert result.confidence == 0.85
    assert result.actions_executed is False


def test_policy_keeps_no_match_as_insufficient_evidence() -> None:
    result = analyze_event(_event("page=2"))

    assert result.local_severity is Severity.INFO
    assert result.conclusion is ConclusionStatus.INSUFFICIENT_EVIDENCE
    assert result.confidence == 0.2


def test_policy_uses_generic_recommendation_for_unknown_evidence_category(monkeypatch) -> None:
    evidence = Evidence(
        rule_id="WEB-UNKNOWN-001",
        category="unknown_category",
        severity=Severity.MEDIUM,
        description="未知类别规则命中",
        matched_field="query",
        matched_excerpt="probe=true",
    )
    monkeypatch.setattr(policy, "detect_event", lambda event: (evidence,))

    result = analyze_event(_event("probe=true"))

    assert result.conclusion is ConclusionStatus.HIGHLY_LIKELY
    assert result.confidence == 0.7
    assert result.recommendations == ("检查命中的规则证据，并结合更多日志进行人工复核。",)
    assert result.actions_executed is False


def test_report_never_claims_actions_were_executed() -> None:
    report = build_report((_event("id=1 UNION SELECT password FROM users"),), ())

    assert report.analysis_status == "completed_local"
    assert report.actions_executed is False
    assert report.summary["total_events"] == 1
    assert report.summary["severity_high"] == 1


def test_report_uses_explicit_total_input_issue_count() -> None:
    retained = (InputIssue(1, "invalid_event", "invalid"),)

    report = build_report((_event(),), retained, total_input_issues=1002)

    assert report.summary["input_issues"] == 1002
    assert report.input_issues == retained


def test_report_defaults_to_retained_input_issue_count() -> None:
    retained = (InputIssue(1, "invalid_event", "invalid"),)

    report = build_report((_event(),), retained)

    assert report.summary["input_issues"] == 1


def test_report_rejects_total_below_retained_input_issue_count() -> None:
    retained = (InputIssue(1, "invalid_event", "invalid"),)

    with pytest.raises(ValueError, match="total_input_issues"):
        build_report((_event(),), retained, total_input_issues=0)
