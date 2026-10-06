"""Safe terminal and durable JSON output for dependency audit reports."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from svarog.dependency_audit.models import DependencyAuditReport
from svarog.text_safety import terminal_safe


def render_dependency_json(report: DependencyAuditReport) -> str:
    """Render a stable, UTF-8-ready JSON document."""

    return (
        json.dumps(_jsonable(report), ensure_ascii=False, indent=2, allow_nan=False)
        + "\n"
    )


def render_dependency_terminal(report: DependencyAuditReport) -> str:
    """Render a terminal-safe Chinese summary of the dependency audit."""

    lines = [
        "Svarog Python 依赖漏洞审计",
        f"审计状态：{report.audit_status.value}",
        f"已检查包：{report.summary['installed_packages']}",
        f"确认漏洞：{report.summary['confirmed_findings']}",
        f"无法判断：{report.summary['indeterminate_findings']}",
        f"明细截断：{report.summary['truncated_details']}",
        "",
    ]
    for finding in report.findings:
        lines.extend(
            [
                f"[{finding.severity.value.upper()}] "
                f"{terminal_safe(finding.package_name)} "
                f"{terminal_safe(finding.installed_version)}",
                f"  公告：{terminal_safe(finding.ghsa_id)} / "
                f"{terminal_safe(finding.cve_id or '无 CVE')}",
                f"  影响范围：{terminal_safe(finding.affected_range)}",
                f"  修复版本：{terminal_safe(finding.fixed_version or '未提供')}",
                f"  摘要：{terminal_safe(finding.summary)}",
            ]
        )
    for finding in report.indeterminate_findings:
        lines.extend(
            [
                f"[无法判断] {terminal_safe(finding.package_name)}",
                f"  公告：{terminal_safe(finding.ghsa_id)}",
                f"  原因：{terminal_safe(finding.reason_code)}",
            ]
        )
    for warning in report.warnings:
        lines.append(f"[提醒] {terminal_safe(warning)}")
    lines.append("安全边界：本次审计未执行任何动作。")
    return "\n".join(lines) + "\n"


def write_dependency_json(report: DependencyAuditReport, path: Path) -> None:
    """Durably replace ``path`` with a private JSON report in the same directory."""

    filename = path.name
    if filename in {"", ".", ".."}:
        raise ValueError("output filename must be a single path leaf")
    payload = render_dependency_json(report).encode("utf-8")
    directory = path.parent.resolve(strict=True)
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
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value
