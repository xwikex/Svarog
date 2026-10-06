from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path
from typing import Sequence, TextIO

from svarog.dependency_audit.inventory import (
    InventoryError,
    inventory_current_python_environment,
    inventory_python_environment,
)
from svarog.dependency_audit.models import AuditStatus
from svarog.dependency_audit.reporting import (
    render_dependency_terminal,
    write_dependency_json,
)
from svarog.dependency_audit.repository import (
    VulnerabilityDatabaseError,
    load_vulnerability_snapshot,
)
from svarog.dependency_audit.remote_repository import (
    RemoteVulnerabilityError,
    load_remote_vulnerability_snapshot,
)
from svarog.dependency_audit.service import build_dependency_audit_report
from svarog.doctor import (
    DoctorOverallStatus,
    render_doctor_terminal,
    run_doctor,
)
from svarog.parsers.nginx_json import InputFileError, parse_jsonl
from svarog.policy import build_report
from svarog.project_audit.lockfile import LockfileError, load_lock_snapshot
from svarog.project_audit.reporting import (
    render_project_terminal,
    write_project_html,
    write_project_json,
)
from svarog.project_audit.service import build_project_audit_report
from svarog.reporting import render_terminal, write_json_report


_AUDIT_OUTPUT_PATH_ERROR = (
    "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
)
_AUDIT_OUTPUT_ALIAS_ERROR = (
    "[错误] JSON 报告不能覆盖漏洞库或虚拟环境元数据。\n"
)
_REMOTE_ERROR_MESSAGES = {
    "invalid_configuration": "[错误] 漏洞知识库 API 地址或 Token 配置无效。\n",
    "authentication_failed": "[错误] 漏洞知识库 API 身份验证失败。\n",
    "rate_limited": "[错误] 漏洞知识库 API 请求受到限流。\n",
    "unavailable": "[错误] 漏洞知识库 API 不可访问或请求超时。\n",
    "invalid_response": "[错误] 漏洞知识库 API 响应无效或超出安全限制。\n",
    "unstable_snapshot": "[错误] 漏洞知识库在读取期间持续变化，请稍后重试。\n",
}


class _SvarogArgumentParser(argparse.ArgumentParser):
    def parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> argparse.Namespace:
        parsed = super().parse_args(args, namespace)
        if (
            getattr(parsed, "command", None) == "audit-project"
            and parsed.json_out is None
            and parsed.html_out is None
        ):
            self.error("audit-project 至少需要 --json-out 或 --html-out 之一")
        return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = _SvarogArgumentParser(
        prog="svarog",
        description="Svarog 本地 Web 安全告警分析器",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="分析 Nginx JSON Lines 日志")
    analyze.add_argument("input", type=Path, help="UTF-8 JSONL 输入文件")
    analyze.add_argument("--json-out", type=Path, help="写入机器可读 JSON 报告")
    analyze.set_defaults(handler=_run_analyze)

    audit_python = subparsers.add_parser(
        "audit-python",
        help="检查本机 Python 环境依赖漏洞",
    )
    audit_python.add_argument(
        "environment",
        nargs="?",
        type=Path,
        help="Python 环境目录；省略时检查当前环境",
    )
    vulnerability_source = audit_python.add_mutually_exclusive_group(
        required=True,
    )
    vulnerability_source.add_argument(
        "--vuln-db",
        type=Path,
        help="只读 SQLite 漏洞库",
    )
    vulnerability_source.add_argument(
        "--vuln-api",
        help="vuln-sync API 基础地址",
    )
    audit_python.add_argument(
        "--json-out",
        type=Path,
        help="原子写入 UTF-8 JSON 报告",
    )
    audit_python.set_defaults(handler=_run_audit_python)

    audit_project = subparsers.add_parser(
        "audit-project",
        help="按显式环境和锁文件审计 Python 项目",
    )
    audit_project.add_argument(
        "--environment",
        required=True,
        type=Path,
        help="明确指定的 Python 虚拟环境目录",
    )
    audit_project.add_argument(
        "--lock-file",
        required=True,
        type=Path,
        help="明确指定的 poetry.lock 或 uv.lock",
    )
    project_source = audit_project.add_mutually_exclusive_group(required=True)
    project_source.add_argument(
        "--vuln-db",
        type=Path,
        help="只读 SQLite 漏洞库",
    )
    project_source.add_argument(
        "--vuln-api",
        help="vuln-sync API 基础地址",
    )
    audit_project.add_argument(
        "--json-out",
        type=Path,
        help="原子写入 UTF-8 JSON 项目报告",
    )
    audit_project.add_argument(
        "--html-out",
        type=Path,
        help="原子写入无外部依赖的单文件 HTML 报告",
    )
    audit_project.set_defaults(handler=_run_audit_project)

    doctor = subparsers.add_parser(
        "doctor",
        help="运行范围锁定的三项项目审计就绪检查",
    )
    doctor.add_argument("--environment", required=True, type=Path)
    doctor.add_argument("--lock-file", required=True, type=Path)
    doctor_source = doctor.add_mutually_exclusive_group(required=True)
    doctor_source.add_argument("--vuln-db", type=Path)
    doctor_source.add_argument("--vuln-api")
    doctor.add_argument("--output-directory", required=True, type=Path)
    doctor.set_defaults(handler=_run_doctor)

    ui = subparsers.add_parser(
        "ui",
        help="启动仅限本机访问的 Svarog 可视化工作台",
    )
    ui.add_argument(
        "--host",
        default="127.0.0.1",
        choices=("127.0.0.1", "localhost", "::1"),
    )
    ui.add_argument("--port", default=8765, type=int)
    ui.add_argument("--workspace", required=True, type=Path)
    ui.add_argument("--case-db", type=Path)
    ui.add_argument("--open-browser", action="store_true")
    ui.set_defaults(handler=_run_ui)
    from svarog.sop.cli import register_sop_commands

    register_sop_commands(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


def _run_analyze(args: argparse.Namespace) -> int:
    if args.json_out is not None and _paths_may_refer_to_same_file(args.input, args.json_out):
        _write_stream(sys.stderr, "[错误] 输入文件和 JSON 报告不能指向同一文件。\n")
        return 1

    try:
        parsed = parse_jsonl(args.input)
        report = build_report(
            parsed.events,
            parsed.issues,
            total_input_issues=parsed.total_issue_count,
        )
    except (InputFileError, OSError):
        _write_stream(sys.stderr, "[错误] 无法读取或分析输入文件。\n")
        return 1

    try:
        _write_stream(sys.stdout, render_terminal(report))
    except (LookupError, OSError, UnicodeError):
        _write_stream(sys.stderr, "[错误] 无法输出终端报告。\n")
        return 1

    if args.json_out is not None:
        try:
            write_json_report(report, args.json_out)
        except (OSError, UnicodeError):
            _write_stream(sys.stderr, "[错误] 无法写入 JSON 报告。\n")
            return 1
    return 0


def _run_audit_python(args: argparse.Namespace) -> int:
    output_destination: Path | None = None
    if args.json_out is not None:
        output_destination = _fixed_output_destination(args.json_out)
        if output_destination is None or (
            args.vuln_db is not None
            and _paths_may_refer_to_same_file(
                args.vuln_db,
                output_destination,
            )
        ) or (
            args.environment is not None
            and _path_is_within(output_destination, args.environment)
        ):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_PATH_ERROR)
            return 1
        if _existing_output_has_multiple_links(output_destination):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_ALIAS_ERROR)
            return 1

    try:
        if args.environment is None:
            inventory = inventory_current_python_environment()
        else:
            inventory = inventory_python_environment(args.environment)
    except (InventoryError, OSError):
        _write_stream(
            sys.stderr,
            "[错误] Python 虚拟环境不可读取或结构无效。\n",
        )
        return 1
    if not inventory.packages:
        _write_stream(
            sys.stderr,
            "[错误] Python 虚拟环境中没有可审计的有效安装包。\n",
        )
        return 1

    if output_destination is not None:
        if not _output_parent_is_unchanged(args.json_out, output_destination):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_PATH_ERROR)
            return 1
        if _path_is_within(
            output_destination,
            Path(inventory.environment_path),
        ):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_PATH_ERROR)
            return 1
    if output_destination is not None and any(
        _paths_may_refer_to_same_file(
            Path(package.metadata_path), output_destination
        )
        for package in inventory.packages
    ):
        _write_stream(sys.stderr, _AUDIT_OUTPUT_ALIAS_ERROR)
        return 1

    local_snapshot_path: Path | None = None
    if args.vuln_db is not None:
        try:
            snapshot = load_vulnerability_snapshot(args.vuln_db)
        except (VulnerabilityDatabaseError, OSError):
            _write_stream(
                sys.stderr,
                "[错误] 漏洞数据库不可读取、损坏、锁定或结构不兼容。\n",
            )
            return 1
        local_snapshot_path = Path(snapshot.metadata.path)
    else:
        token = os.environ.get("SVAROG_VULN_API_TOKEN", "")
        if not token.strip():
            _write_stream(
                sys.stderr,
                _REMOTE_ERROR_MESSAGES["invalid_configuration"],
            )
            return 1
        try:
            snapshot = load_remote_vulnerability_snapshot(
                args.vuln_api,
                token,
            )
        except RemoteVulnerabilityError as exc:
            _write_stream(
                sys.stderr,
                _REMOTE_ERROR_MESSAGES.get(
                    exc.code,
                    _REMOTE_ERROR_MESSAGES["invalid_response"],
                ),
            )
            return 1

    if output_destination is not None:
        if not _output_parent_is_unchanged(
            args.json_out,
            output_destination,
        ) or (
            local_snapshot_path is not None
            and _paths_may_refer_to_same_file(
                local_snapshot_path,
                output_destination,
            )
        ):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_PATH_ERROR)
            return 1
    report = build_dependency_audit_report(inventory, snapshot)

    try:
        _write_stream(sys.stdout, render_dependency_terminal(report))
    except (LookupError, OSError, UnicodeError):
        _write_stream(
            sys.stderr,
            "[错误] 无法输出依赖审计终端报告。\n",
        )
        return 1

    if output_destination is not None:
        if not _output_parent_is_unchanged(
            args.json_out,
            output_destination,
        ) or _path_is_within(
            output_destination,
            Path(inventory.environment_path),
        ) or (
            local_snapshot_path is not None
            and _paths_may_refer_to_same_file(
                local_snapshot_path,
                output_destination,
            )
        ):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_PATH_ERROR)
            return 1
        if any(
            _paths_may_refer_to_same_file(
                Path(package.metadata_path),
                output_destination,
            )
            for package in inventory.packages
        ) or _existing_output_has_multiple_links(output_destination):
            _write_stream(sys.stderr, _AUDIT_OUTPUT_ALIAS_ERROR)
            return 1
        try:
            write_dependency_json(report, output_destination)
        except (OSError, UnicodeError, ValueError):
            _write_stream(
                sys.stderr,
                "[错误] 无法安全写入依赖审计 JSON 报告。\n",
            )
            return 1

    if report.summary["confirmed_findings"]:
        return 3
    if report.audit_status is AuditStatus.COMPLETED_INCOMPLETE:
        return 4
    return 0


def _run_audit_project(args: argparse.Namespace) -> int:
    if args.json_out is None and args.html_out is None:
        _write_stream(
            sys.stderr,
            "[错误] audit-project 至少需要 --json-out 或 --html-out 之一。\n",
        )
        return 2

    requested_outputs = tuple(
        path for path in (args.json_out, args.html_out) if path is not None
    )
    fixed_outputs: list[Path] = []
    for output in requested_outputs:
        destination = _fixed_output_destination(output)
        if destination is None or _path_is_within(destination, args.environment):
            _write_stream(sys.stderr, "[错误] 项目报告输出路径不安全。\n")
            return 1
        if _paths_may_refer_to_same_file(args.lock_file, destination) or (
            args.vuln_db is not None
            and _paths_may_refer_to_same_file(args.vuln_db, destination)
        ):
            _write_stream(
                sys.stderr,
                "[错误] 项目报告不能覆盖环境、锁文件或漏洞库。\n",
            )
            return 1
        if _existing_output_has_multiple_links(destination):
            _write_stream(sys.stderr, "[错误] 项目报告输出文件存在不安全别名。\n")
            return 1
        fixed_outputs.append(destination)
    if len(fixed_outputs) == 2 and _paths_may_refer_to_same_file(
        fixed_outputs[0], fixed_outputs[1]
    ):
        _write_stream(sys.stderr, "[错误] JSON 与 HTML 报告不能指向同一文件。\n")
        return 1

    try:
        inventory = inventory_python_environment(args.environment)
    except (InventoryError, OSError):
        _write_stream(sys.stderr, "[错误] Python 虚拟环境不可读取或结构无效。\n")
        return 1
    try:
        lock = load_lock_snapshot(args.lock_file)
    except (LockfileError, OSError):
        _write_stream(
            sys.stderr,
            "[错误] 锁文件不可读取、格式无效或超出安全限制。\n",
        )
        return 1

    local_snapshot_path: Path | None = None
    if args.vuln_db is not None:
        try:
            snapshot = load_vulnerability_snapshot(args.vuln_db)
        except (VulnerabilityDatabaseError, OSError):
            _write_stream(
                sys.stderr,
                "[错误] 漏洞数据库不可读取、损坏、锁定或结构不兼容。\n",
            )
            return 1
        local_snapshot_path = Path(snapshot.metadata.path)
    else:
        token = os.environ.get("SVAROG_VULN_API_TOKEN", "")
        if not token.strip():
            _write_stream(sys.stderr, _REMOTE_ERROR_MESSAGES["invalid_configuration"])
            return 1
        try:
            snapshot = load_remote_vulnerability_snapshot(args.vuln_api, token)
        except RemoteVulnerabilityError as exc:
            _write_stream(
                sys.stderr,
                _REMOTE_ERROR_MESSAGES.get(
                    exc.code,
                    _REMOTE_ERROR_MESSAGES["invalid_response"],
                ),
            )
            return 1

    protected_paths = [Path(lock.path)]
    if local_snapshot_path is not None:
        protected_paths.append(local_snapshot_path)
    protected_paths.extend(Path(package.metadata_path) for package in inventory.packages)
    for original, destination in zip(requested_outputs, fixed_outputs, strict=True):
        if (
            not _output_parent_is_unchanged(original, destination)
            or _path_is_within(destination, Path(inventory.environment_path))
            or any(
                _paths_may_refer_to_same_file(path, destination)
                for path in protected_paths
            )
            or _existing_output_has_multiple_links(destination)
        ):
            _write_stream(sys.stderr, "[错误] 项目报告输出路径或别名不安全。\n")
            return 1

    report = build_project_audit_report(inventory, lock, snapshot)
    try:
        _write_stream(sys.stdout, render_project_terminal(report))
    except (LookupError, OSError, UnicodeError):
        _write_stream(sys.stderr, "[错误] 无法输出项目审计终端报告。\n")
        return 1

    if args.json_out is not None:
        destination = fixed_outputs[requested_outputs.index(args.json_out)]
        try:
            write_project_json(report, destination)
        except (OSError, UnicodeError, ValueError):
            _write_stream(sys.stderr, "[错误] 无法安全写入项目审计 JSON 报告。\n")
            return 1
    if args.html_out is not None:
        destination = fixed_outputs[requested_outputs.index(args.html_out)]
        try:
            write_project_html(report, destination)
        except (OSError, UnicodeError, ValueError):
            _write_stream(sys.stderr, "[错误] 无法安全写入项目审计 HTML 报告。\n")
            return 1

    if report.summary["confirmed_environment_findings"]:
        return 3
    if report.audit_status is AuditStatus.COMPLETED_INCOMPLETE:
        return 4
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    report = run_doctor(
        environment=args.environment,
        lock_file=args.lock_file,
        output_directory=args.output_directory,
        vuln_db=args.vuln_db,
        vuln_api=args.vuln_api,
    )
    try:
        _write_stream(sys.stdout, render_doctor_terminal(report))
    except (LookupError, OSError, UnicodeError):
        _write_stream(sys.stderr, "[错误] 无法输出 Doctor 检查报告。\n")
        return 1
    return 1 if report.overall_status is DoctorOverallStatus.NOT_READY else 0


def _run_ui(args: argparse.Namespace) -> int:
    from svarog.webui import server
    from svarog.webui.config import UiConfig

    try:
        config = UiConfig.build(
            args.host,
            args.port,
            args.workspace,
            args.case_db,
        )
        server.serve(config, open_browser=args.open_browser)
    except (ValueError, OSError, sqlite3.Error):
        _write_stream(
            sys.stderr,
            "[错误] 无法启动本地工作台，请检查主机、端口和工作区设置。\n",
        )
        return 1
    return 0


def _paths_may_refer_to_same_file(input_path: Path, output_path: Path) -> bool:
    try:
        if input_path.resolve(strict=False) == output_path.resolve(strict=False):
            return True
    except (OSError, RuntimeError):
        return True

    try:
        return input_path.samefile(output_path)
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _resolved(path: Path) -> Path | None:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def _path_is_within(path: Path, directory: Path) -> bool:
    resolved_path = _resolved(path)
    resolved_directory = _resolved(directory)
    if resolved_path is None or resolved_directory is None:
        return True
    try:
        resolved_path.relative_to(resolved_directory)
    except ValueError:
        return False
    return True


def _fixed_output_destination(path: Path) -> Path | None:
    filename = path.name
    if filename in {"", ".", ".."}:
        return None
    try:
        directory = path.parent.resolve(strict=True)
        if not directory.is_dir():
            return None
    except (OSError, RuntimeError):
        return None
    return directory / filename


def _output_parent_is_unchanged(original: Path, fixed: Path) -> bool:
    current = _fixed_output_destination(original)
    return current == fixed


def _existing_output_has_multiple_links(path: Path) -> bool:
    try:
        return path.stat().st_nlink > 1
    except FileNotFoundError:
        return False
    except (OSError, RuntimeError):
        return True


def _write_stream(stream: TextIO, text: str) -> None:
    encoding = stream.encoding or "utf-8"
    safe_text = text.encode(encoding, errors="backslashreplace").decode(encoding)
    stream.write(safe_text)
