from __future__ import annotations

import re
from urllib.parse import unquote_plus

from svarog.models import Evidence, NormalizedEvent, Severity

_SQLI = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|\binformation_schema\b)",
    re.IGNORECASE,
)
_XSS = re.compile(
    r"(?:<[ \t]{0,8}script\b|"
    r"<[A-Za-z][^>\r\n]{0,511}[ \t](?:href|src|action|formaction)"
    r"[ \t]{0,16}=[ \t]{0,16}(?:[\"'][ \t]{0,16})?"
    r"javascript[ \t]{0,8}:[^>\r\n]{0,512}>|"
    r"<(?:[A-Za-z][^>\r\n]{0,511}[ \t]|[A-Za-z][A-Za-z0-9:-]{0,511}/)"
    r"on(?:error|load|click)[ \t]{0,16}="
    r"[^>\r\n]{0,512}>)",
    re.IGNORECASE,
)
_TRAVERSAL = re.compile(r"(?:\.\./|\.\.\\)")
_SCAN_PATHS = ("/.env", "/.git", "/wp-admin", "/phpmyadmin", "/actuator", "/server-status")
_SCAN_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "ffuf")
_SCAN_AGENT = re.compile(
    rf"(?<![A-Za-z0-9_])(?:{'|'.join(_SCAN_AGENTS)})(?=$|[/\s;,\-])",
    re.IGNORECASE,
)


def detect_event(event: NormalizedEvent) -> tuple[Evidence, ...]:
    fields = {
        "path": _decode(event.path),
        "query": _decode(event.query),
        "body_excerpt": _decode(event.body_excerpt),
        "user_agent": event.user_agent,
    }
    evidence: list[Evidence] = []

    _append_regex_evidence(
        evidence, fields, _SQLI, "WEB-SQLI-001", "sql_injection", Severity.HIGH,
        "检测到明显 SQL 注入模式", ("CWE-89", "ATT&CK:T1190"),
    )
    _append_regex_evidence(
        evidence, fields, _XSS, "WEB-XSS-001", "xss", Severity.HIGH,
        "检测到明显跨站脚本模式", ("CWE-79", "ATT&CK:T1190"),
    )
    _append_regex_evidence(
        evidence, fields, _TRAVERSAL, "WEB-PATH-001", "path_traversal", Severity.HIGH,
        "检测到明显路径遍历模式", ("CWE-22", "ATT&CK:T1190"),
    )

    path_lower = fields["path"].lower()
    if any(path_lower == prefix or path_lower.startswith(f"{prefix}/") for prefix in _SCAN_PATHS):
        evidence.append(_evidence(
            "WEB-SCAN-001", "scanning", Severity.MEDIUM, "访问常见敏感探测路径",
            "path", fields["path"], ("ATT&CK:T1595",),
        ))
    if _SCAN_AGENT.search(event.user_agent):
        evidence.append(_evidence(
            "WEB-SCAN-002", "scanning", Severity.MEDIUM, "User-Agent 包含常见扫描工具标识",
            "user_agent", event.user_agent, ("ATT&CK:T1595",),
        ))
    return tuple(evidence)


def _decode(value: str) -> str:
    decoded = value
    for _ in range(2):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _append_regex_evidence(
    output: list[Evidence],
    fields: dict[str, str],
    pattern: re.Pattern[str],
    rule_id: str,
    category: str,
    severity: Severity,
    description: str,
    references: tuple[str, ...],
) -> None:
    for field_name in ("path", "query", "body_excerpt"):
        match = pattern.search(fields[field_name])
        if match:
            output.append(_evidence(
                rule_id, category, severity, description, field_name, match.group(0), references,
            ))
            return


def _evidence(
    rule_id: str,
    category: str,
    severity: Severity,
    description: str,
    field_name: str,
    excerpt: str,
    references: tuple[str, ...],
) -> Evidence:
    safe_excerpt = "".join(char if char.isprintable() else "?" for char in excerpt)[:160]
    return Evidence(
        rule_id=rule_id,
        category=category,
        severity=severity,
        description=description,
        matched_field=field_name,
        matched_excerpt=safe_excerpt,
        references=references,
    )
