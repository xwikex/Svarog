from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from svarog.models import AnalysisReport
from svarog.text_safety import terminal_safe


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    value = _jsonable(report)
    if not isinstance(value, dict):
        raise TypeError("报告必须转换为 JSON 对象")
    return value


def render_json(report: AnalysisReport) -> str:
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=2) + "\n"


def write_json_report(report: AnalysisReport, path: Path) -> None:
    payload = render_json(report).encode("utf-8")
    path.write_bytes(payload)


def render_terminal(report: AnalysisReport) -> str:
    lines = [
        "Svarog 本地分析报告",
        f"事件总数：{report.summary['total_events']}",
        f"可疑事件：{report.summary['suspicious_events']}",
        f"输入问题：{report.summary['input_issues']}",
        "",
    ]
    for analysis in report.events:
        lines.extend([
            f"第 {analysis.event.line_number} 行 | {analysis.local_severity.value.upper()} | "
            f"{terminal_safe(analysis.event.method)} {terminal_safe(analysis.event.path)}",
            f"来源：{terminal_safe(analysis.event.source_ip)}（仅表示网络来源，不代表真实身份）",
            f"结论：{analysis.conclusion.value}，置信度 {analysis.confidence:.0%}",
        ])
        if analysis.evidence:
            for item in analysis.evidence:
                lines.append(
                    f"  - [{terminal_safe(item.rule_id)}] {terminal_safe(item.description)}；"
                    f"字段={terminal_safe(item.matched_field)}；"
                    f"证据={terminal_safe(item.matched_excerpt)}"
                )
        else:
            lines.append("  - 未发现明显本地规则命中")
        for recommendation in analysis.recommendations:
            lines.append(f"  建议：{terminal_safe(recommendation)}")
        lines.append("")

    for warning in report.warnings:
        lines.append(f"[提醒] {terminal_safe(warning)}")
    lines.append("安全边界：本次分析未执行任何动作。")
    return "\n".join(lines) + "\n"


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value
