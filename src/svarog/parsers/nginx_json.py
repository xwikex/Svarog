from __future__ import annotations

import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from svarog.models import InputIssue, NormalizedEvent, ParseResult

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDED_ISSUES = 1000
_INVALID_SURROGATE_MESSAGE = "字符串字段包含无效 Unicode 代理字符"


class InputFileError(ValueError):
    pass


def parse_jsonl(path: Path) -> ParseResult:
    if not path.is_file():
        raise InputFileError(f"输入文件不存在或不是普通文件：{path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InputFileError("输入文件超过 10 MiB 限制")

    events: list[NormalizedEvent] = []
    issues: list[InputIssue] = []
    total_issue_count = 0
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            if len(raw_line) > MAX_LINE_BYTES:
                total_issue_count += 1
                if len(issues) < MAX_RECORDED_ISSUES:
                    issues.append(InputIssue(line_number, "line_too_large", "单行超过 1 MiB 限制"))
                continue
            try:
                text = raw_line.decode("utf-8")
                payload = json.loads(text)
                events.append(_normalize_event(payload, line_number))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
                total_issue_count += 1
                if len(issues) < MAX_RECORDED_ISSUES:
                    issues.append(InputIssue(line_number, "invalid_event", str(exc)))

    if not events:
        raise InputFileError("输入文件没有有效事件")
    omitted_issue_count = total_issue_count - len(issues)
    if omitted_issue_count:
        issues.append(InputIssue(
            0,
            "issues_truncated",
            f"另有 {omitted_issue_count} 个输入问题未逐条记录",
        ))
    return ParseResult(tuple(events), tuple(issues), total_issue_count)


def _normalize_event(payload: Any, line_number: int) -> NormalizedEvent:
    if not isinstance(payload, dict):
        raise ValueError("事件必须是 JSON 对象")

    timestamp = _required_string(payload, "timestamp", 64)
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp 必须是 ISO 8601 时间") from exc
    if "T" not in timestamp or parsed_timestamp.utcoffset() is None:
        raise ValueError("timestamp 必须包含时间和 UTC 偏移")

    source_ip = _required_string(payload, "source_ip", 64)
    try:
        ip_address(source_ip)
    except ValueError as exc:
        raise ValueError("source_ip 不是有效 IP 地址") from exc

    status = payload.get("status")
    if status is not None and (
        isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
    ):
        raise ValueError("status 必须是 100 到 599 的整数")

    return NormalizedEvent(
        line_number=line_number,
        timestamp=timestamp,
        source_ip=source_ip,
        method=_required_string(payload, "method", 16).upper(),
        host=_required_string(payload, "host", 255).lower(),
        path=_required_string(payload, "path", 4096),
        query=_optional_string(payload, "query", 8192),
        status=status,
        user_agent=_optional_string(payload, "user_agent", 1024),
        request_id=_optional_nullable_string(payload, "request_id", 256),
        body_excerpt=_optional_string(payload, "body_excerpt", 2048),
    )


def _required_string(payload: dict[str, Any], name: str, limit: int) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} 必须是非空字符串")
    _reject_surrogates(value)
    if len(value) > limit:
        raise ValueError(f"{name} 超过 {limit} 字符限制")
    return value.strip()


def _optional_string(payload: dict[str, Any], name: str, limit: int) -> str:
    value = payload.get(name, "")
    if not isinstance(value, str):
        raise ValueError(f"{name} 必须是字符串")
    _reject_surrogates(value)
    if len(value) > limit:
        raise ValueError(f"{name} 超过 {limit} 字符限制")
    return value


def _optional_nullable_string(payload: dict[str, Any], name: str, limit: int) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} 必须是最多 {limit} 字符的字符串")
    _reject_surrogates(value)
    if len(value) > limit:
        raise ValueError(f"{name} 必须是最多 {limit} 字符的字符串")
    return value


def _reject_surrogates(value: str) -> None:
    if any("\ud800" <= character <= "\udfff" for character in value):
        raise ValueError(_INVALID_SURROGATE_MESSAGE)
