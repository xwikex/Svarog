"""Authoritative JSON and derived single-file HTML project reports."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from html import escape
from pathlib import Path
from typing import Any

from svarog.text_safety import terminal_safe

from .models import ProjectDependencyAuditReport


def render_project_json(report: ProjectDependencyAuditReport) -> str:
    """Render the authoritative, deterministic project report document."""

    return json.dumps(
        _jsonable(report),
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    ) + "\n"


def write_project_json(report: ProjectDependencyAuditReport, path: Path) -> None:
    """Durably replace ``path`` with a private UTF-8 JSON report."""

    _write_private_atomic(path, render_project_json(report).encode("utf-8"))


def render_project_terminal(report: ProjectDependencyAuditReport) -> str:
    """Render a terminal-safe summary without merging the two evidence layers."""

    lines = [
        "Svarog Python 项目依赖审计",
        f"审计状态：{report.audit_status.value}",
        f"实际环境确认漏洞：{report.summary['confirmed_environment_findings']}",
        f"锁文件潜在漏洞：{report.summary['potential_lock_findings']}",
        f"版本差异：{report.summary['version_differences']}",
        "锁文件结论：适用性未经验证。",
    ]
    for warning in report.warnings:
        lines.append(f"[提醒] {terminal_safe(warning)}")
    lines.append("安全边界：仅执行只读审计，未安装、升级或修改任何依赖。")
    return "\n".join(lines) + "\n"


def render_project_html(report: ProjectDependencyAuditReport) -> str:
    """Render a self-contained, no-script view of the authoritative report."""

    status = escape(report.audit_status.value, quote=True)
    confirmed = int(report.summary["confirmed_environment_findings"])
    potential = int(report.summary["potential_lock_findings"])
    warnings = "".join(
        f'<li>{escape(str(warning), quote=True)}</li>' for warning in report.warnings
    ) or "<li>无额外提醒。</li>"
    summary_cards = "".join(
        (
            '<div class="metric">'
            f'<span>{escape(str(key), quote=True)}</span>'
            f'<strong>{int(value)}</strong>'
            "</div>"
        )
        for key, value in report.summary.items()
    )
    differences = "".join(
        "<tr>"
        f"<td>{escape(item.name, quote=True)}</td>"
        f"<td>{escape(', '.join(item.installed_versions) or '—', quote=True)}</td>"
        f"<td>{escape(', '.join(item.locked_versions) or '—', quote=True)}</td>"
        f"<td><code>{escape(item.status.value, quote=True)}</code></td>"
        "</tr>"
        for item in report.version_differences
    ) or '<tr><td colspan="4">没有版本对账记录。</td></tr>'
    environment_findings = "".join(
        "<tr>"
        f"<td>{escape(item.package_name, quote=True)}</td>"
        f"<td>{escape(item.installed_version, quote=True)}</td>"
        f"<td>{escape(item.severity.value, quote=True)}</td>"
        f"<td>{escape(item.ghsa_id, quote=True)}</td>"
        f"<td>{escape(item.summary, quote=True)}</td>"
        "</tr>"
        for item in report.environment_findings
    ) or '<tr><td colspan="5">没有确认的实际环境漏洞。</td></tr>'
    lock_findings = "".join(
        "<tr>"
        f"<td>{escape(item.package_name, quote=True)}</td>"
        f"<td>{escape(item.locked_version, quote=True)}</td>"
        f"<td>{escape(item.severity.value, quote=True)}</td>"
        f"<td>{escape(item.ghsa_id, quote=True)}</td>"
        f"<td>{escape(item.summary, quote=True)}</td>"
        "</tr>"
        for item in report.lock_findings
    ) or '<tr><td colspan="5">没有锁文件潜在漏洞。</td></tr>'
    indeterminate = "".join(
        "<tr>"
        f"<td>实际环境</td><td>{escape(item.package_name, quote=True)}</td>"
        f"<td>{escape(', '.join(item.installed_versions), quote=True)}</td>"
        f"<td>{escape(item.ghsa_id, quote=True)}</td>"
        f"<td>{escape(item.reason_code, quote=True)}</td>"
        "</tr>"
        for item in report.environment_indeterminate_findings
    ) + "".join(
        "<tr>"
        f"<td>锁文件</td><td>{escape(item.package_name, quote=True)}</td>"
        f"<td>{escape(item.locked_version, quote=True)}</td>"
        f"<td>{escape(item.ghsa_id, quote=True)}</td>"
        f"<td>{escape(item.reason_code, quote=True)}</td>"
        "</tr>"
        for item in report.lock_indeterminate_findings
    )
    if not indeterminate:
        indeterminate = '<tr><td colspan="5">没有无法判断的漏洞结果。</td></tr>'

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="svarog-audit-status" content="{status}">
<meta name="svarog-confirmed-environment-findings" content="{confirmed}">
<meta name="svarog-potential-lock-findings" content="{potential}">
<title>Svarog Python 项目依赖审计</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#64748b; --line:#dbe3ee; --panel:#fff; --bg:#f3f6fa; --accent:#2854c5; --warn:#8a4b08; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1180px; margin:0 auto; padding:32px 20px 64px; }}
header {{ padding:28px; border-radius:18px; color:#fff; background:linear-gradient(135deg,#172554,#2854c5); box-shadow:0 12px 30px #17255426; }}
h1 {{ margin:0 0 8px; font-size:28px; }} h2 {{ margin:0 0 14px; font-size:19px; }}
.status {{ display:inline-block; margin-top:12px; padding:5px 10px; border:1px solid #ffffff55; border-radius:999px; }}
.notice {{ margin:18px 0; padding:16px 18px; border-left:5px solid #d97706; border-radius:10px; background:#fff7ed; color:var(--warn); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; }}
.metric,.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; box-shadow:0 4px 14px #1720330a; }}
.metric {{ padding:14px; }} .metric span {{ display:block; color:var(--muted); font-size:12px; overflow-wrap:anywhere; }} .metric strong {{ display:block; margin-top:4px; font-size:24px; }}
.panel {{ margin-top:18px; padding:20px; overflow:hidden; }}
.table-wrap {{ overflow:auto; }} table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }} th {{ color:var(--muted); font-size:12px; }}
code {{ padding:2px 6px; border-radius:5px; background:#eef2ff; color:#3730a3; }}
footer {{ margin-top:24px; color:var(--muted); }}
</style>
</head>
<body><main>
<header><h1>Svarog Python 项目依赖审计</h1><div>生成时间：{escape(report.generated_at, quote=True)}</div><div class="status">{status}</div></header>
<section class="notice"><strong>锁文件适用性未经验证</strong><br>Svarog 未解释平台、Python 版本、extra 或依赖组标记；所有不同锁定版本均已纳入审计。<ul>{warnings}</ul></section>
<section class="grid">{summary_cards}</section>
<section class="panel"><h2>实际环境确认漏洞</h2><div class="table-wrap"><table><thead><tr><th>包</th><th>安装版本</th><th>严重度</th><th>公告</th><th>摘要</th></tr></thead><tbody>{environment_findings}</tbody></table></div></section>
<section class="panel"><h2>锁文件潜在漏洞（适用性未验证）</h2><div class="table-wrap"><table><thead><tr><th>包</th><th>锁定版本</th><th>严重度</th><th>公告</th><th>摘要</th></tr></thead><tbody>{lock_findings}</tbody></table></div></section>
<section class="panel"><h2>版本对账</h2><div class="table-wrap"><table><thead><tr><th>包</th><th>实际版本</th><th>锁定版本集合</th><th>状态</th></tr></thead><tbody>{differences}</tbody></table></div></section>
<section class="panel"><h2>无法判断</h2><div class="table-wrap"><table><thead><tr><th>层级</th><th>包</th><th>版本</th><th>公告</th><th>原因</th></tr></thead><tbody>{indeterminate}</tbody></table></div></section>
<footer>本报告由权威 JSON 报告对象直接渲染；HTML 层未重新计算漏洞或版本差异。未执行安装、升级或修复动作。</footer>
</main></body></html>
"""


def write_project_html(report: ProjectDependencyAuditReport, path: Path) -> None:
    """Durably replace ``path`` with a private, self-contained HTML report."""

    _write_private_atomic(path, render_project_html(report).encode("utf-8"))


def _write_private_atomic(path: Path, payload: bytes) -> None:
    filename = path.name
    if filename in {"", ".", ".."}:
        raise ValueError("output filename must be a single path leaf")
    directory = path.parent.resolve(strict=True)
    if not directory.is_dir():
        raise NotADirectoryError(str(directory))
    destination = directory / filename
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=f".{filename}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            os.chmod(temporary_path, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _jsonable(getattr(value, item.name)) for item in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, frozenset)):
        return [_jsonable(item) for item in value]
    return value
