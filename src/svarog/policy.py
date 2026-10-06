from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from svarog.detectors.web import detect_event
from svarog.models import (
    AnalysisReport,
    ConclusionStatus,
    EventAnalysis,
    InputIssue,
    NormalizedEvent,
    Severity,
)

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_RECOMMENDATIONS = {
    "sql_injection": "检查参数化查询、WAF 记录和相关数据库审计日志。",
    "xss": "检查输出编码、CSP 与相同来源的后续请求。",
    "path_traversal": "检查路径规范化、文件访问日志和受影响目录权限。",
    "scanning": "继续观察同一来源的路径分布，必要时采用限流或挑战机制。",
}
_FALLBACK_RECOMMENDATION = "检查命中的规则证据，并结合更多日志进行人工复核。"


def analyze_event(event: NormalizedEvent) -> EventAnalysis:
    evidence = detect_event(event)
    if not evidence:
        return EventAnalysis(
            event=event,
            local_severity=Severity.INFO,
            conclusion=ConclusionStatus.INSUFFICIENT_EVIDENCE,
            confidence=0.2,
            evidence=(),
            attack_mappings=(),
            recommendations=("未发现明显规则命中；如仍有怀疑，请结合更多日志继续调查。",),
        )

    local_severity = max((item.severity for item in evidence), key=_SEVERITY_ORDER.__getitem__)
    confidence = 0.85 if _SEVERITY_ORDER[local_severity] >= _SEVERITY_ORDER[Severity.HIGH] else 0.7
    mappings = tuple(dict.fromkeys(
        reference.removeprefix("ATT&CK:")
        for item in evidence
        for reference in item.references
        if reference.startswith("ATT&CK:")
    ))
    categories = tuple(dict.fromkeys(item.category for item in evidence))
    recommendations = tuple(
        _RECOMMENDATIONS.get(category, _FALLBACK_RECOMMENDATION)
        for category in categories
    )
    return EventAnalysis(
        event=event,
        local_severity=local_severity,
        conclusion=ConclusionStatus.HIGHLY_LIKELY,
        confidence=confidence,
        evidence=evidence,
        attack_mappings=mappings,
        recommendations=recommendations,
    )


def build_report(
    events: tuple[NormalizedEvent, ...],
    input_issues: tuple[InputIssue, ...],
    *,
    total_input_issues: int | None = None,
    generated_at: str | None = None,
) -> AnalysisReport:
    input_issue_count = len(input_issues) if total_input_issues is None else total_input_issues
    if (
        isinstance(input_issue_count, bool)
        or not isinstance(input_issue_count, int)
        or input_issue_count < len(input_issues)
    ):
        raise ValueError("total_input_issues 必须是不小于已保留问题数的整数")
    analyses = tuple(analyze_event(event) for event in events)
    severity_counts = Counter(item.local_severity.value for item in analyses)
    summary = {
        "total_events": len(analyses),
        "suspicious_events": sum(bool(item.evidence) for item in analyses),
        "input_issues": input_issue_count,
        **{
            f"severity_{severity.value}": severity_counts.get(severity.value, 0)
            for severity in Severity
        },
    }
    warnings = ("部分输入行无效，详见 input_issues。",) if input_issue_count else ()
    return AnalysisReport(
        schema_version="0.1.0",
        generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
        analysis_status="completed_local",
        summary=summary,
        events=analyses,
        input_issues=input_issues,
        warnings=warnings,
    )
