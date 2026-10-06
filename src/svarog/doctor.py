"""Three-check readiness doctor, intentionally frozen against scope expansion."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from svarog.dependency_audit.repository import (
    VulnerabilityDatabaseError,
    load_vulnerability_snapshot,
)


COMMAND_TIMEOUT_SECONDS = 2.0
TCP_TIMEOUT_SECONDS = 2.0


class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class DoctorOverallStatus(str, Enum):
    READY = "ready"
    READY_WITH_WARNINGS = "ready_with_warnings"
    NOT_READY = "not_ready"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    check_id: str
    title: str
    status: CheckStatus
    message: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    overall_status: DoctorOverallStatus
    checks: tuple[DoctorCheck, DoctorCheck, DoctorCheck]


class _Connection(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(self, *args: object) -> object: ...


CommandRunner = Callable[[tuple[str, ...]], bool]
DatabaseChecker = Callable[[Path], bool]
TcpConnector = Callable[[tuple[str, int], float], _Connection]


def _run_fixed_command(argv: tuple[str, ...]) -> bool:
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _check_database(path: Path) -> bool:
    try:
        load_vulnerability_snapshot(path)
    except (VulnerabilityDatabaseError, OSError):
        return False
    return True


def _environment_python(environment: Path) -> Path | None:
    candidates = (
        environment / "Scripts" / "python.exe",
        environment / "bin" / "python",
    )
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            return None
    return None


def _python_and_tool_check(
    environment: Path,
    lock_file: Path,
    command_runner: CommandRunner,
) -> DoctorCheck:
    executable = _environment_python(environment)
    python_ready = executable is not None and command_runner(
        (str(executable), "--version")
    )
    tool = {"uv.lock": "uv", "poetry.lock": "poetry"}.get(lock_file.name)
    tool_ready = tool is not None and command_runner((tool, "--version"))

    if not python_ready or tool is None:
        return DoctorCheck(
            "python_and_package_manager",
            "Python 环境与包管理工具",
            CheckStatus.FAIL,
            "指定 Python 环境不可用，或锁文件名不是 uv.lock/poetry.lock。",
        )
    if not tool_ready:
        return DoctorCheck(
            "python_and_package_manager",
            "Python 环境与包管理工具",
            CheckStatus.WARN,
            f"Python 环境可用，但 {tool} 命令不可用；解析锁文件不依赖该工具。",
        )
    return DoctorCheck(
        "python_and_package_manager",
        "Python 环境与包管理工具",
        CheckStatus.PASS,
        f"指定 Python 环境与 {tool} 命令均可用。",
    )


def _data_source_check(
    vuln_db: Path | None,
    vuln_api: str | None,
    database_checker: DatabaseChecker,
) -> DoctorCheck:
    if (vuln_db is None) == (vuln_api is None):
        return DoctorCheck(
            "core_data_source",
            "核心数据源",
            CheckStatus.FAIL,
            "必须且只能明确指定一个本地 SQLite 或远程 API。",
        )
    if vuln_db is not None:
        if database_checker(vuln_db):
            return DoctorCheck(
                "core_data_source",
                "核心数据源",
                CheckStatus.PASS,
                "本地 SQLite 漏洞数据库存在、可读且结构兼容。",
            )
        return DoctorCheck(
            "core_data_source",
            "核心数据源",
            CheckStatus.FAIL,
            "本地 SQLite 漏洞数据库不可读或结构不兼容。",
        )
    if vuln_api is not None:
        return DoctorCheck(
            "core_data_source",
            "核心数据源",
            CheckStatus.WARN,
            "远程模式无法观察 Linux 服务内部 SQLite，仅检查后续 TCP 可达性。",
        )
    return DoctorCheck(
        "core_data_source",
        "核心数据源",
        CheckStatus.FAIL,
        "没有明确指定本地 SQLite 或远程 API。",
    )


def _directories_ready(
    environment: Path,
    lock_file: Path,
    output_directory: Path,
) -> bool:
    temporary: Path | None = None
    try:
        if (
            not environment.is_dir()
            or not (environment / "pyvenv.cfg").is_file()
            or lock_file.is_symlink()
            or not lock_file.is_file()
        ):
            return False
        with lock_file.open("rb") as handle:
            handle.read(1)
        directory = output_directory.resolve(strict=True)
        if not directory.is_dir():
            return False
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=".svarog-doctor-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            handle.write(b"svarog")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.unlink()
        temporary = None
        return True
    except (OSError, RuntimeError):
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _explicit_remote_endpoint(vuln_api: str) -> tuple[str, int] | None:
    try:
        parsed = urlsplit(vuln_api)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or port is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return parsed.hostname, port


def _directory_and_network_check(
    environment: Path,
    lock_file: Path,
    output_directory: Path,
    vuln_api: str | None,
    tcp_connector: TcpConnector,
) -> DoctorCheck:
    if not _directories_ready(environment, lock_file, output_directory):
        return DoctorCheck(
            "directories_and_network",
            "核心目录与网络权限",
            CheckStatus.FAIL,
            "环境或锁文件不可读，或报告目录不可写。",
        )
    if vuln_api is None:
        return DoctorCheck(
            "directories_and_network",
            "核心目录与网络权限",
            CheckStatus.PASS,
            "环境和锁文件可读，报告目录可安全写入。",
        )

    endpoint = _explicit_remote_endpoint(vuln_api)
    if endpoint is None:
        return DoctorCheck(
            "directories_and_network",
            "核心目录与网络权限",
            CheckStatus.FAIL,
            "远程 API 必须明确指定合法主机和端口。",
        )
    try:
        with tcp_connector(endpoint, TCP_TIMEOUT_SECONDS):
            pass
    except (OSError, TimeoutError):
        return DoctorCheck(
            "directories_and_network",
            "核心目录与网络权限",
            CheckStatus.FAIL,
            "核心目录可用，但远程主机和端口无法建立 TCP 连接。",
        )
    return DoctorCheck(
        "directories_and_network",
        "核心目录与网络权限",
        CheckStatus.PASS,
        "核心目录可用，指定主机和端口可建立 TCP 连接；未验证 API、认证或内部数据库状态。",
    )


def run_doctor(
    *,
    environment: Path,
    lock_file: Path,
    output_directory: Path,
    vuln_db: Path | None = None,
    vuln_api: str | None = None,
    command_runner: CommandRunner = _run_fixed_command,
    database_checker: DatabaseChecker = _check_database,
    tcp_connector: TcpConnector = socket.create_connection,
) -> DoctorReport:
    """Run exactly three bounded readiness checks and no system inventory."""

    source_is_valid = (vuln_db is None) != (vuln_api is None)
    checks = (
        _python_and_tool_check(environment, lock_file, command_runner),
        _data_source_check(vuln_db, vuln_api, database_checker),
        _directory_and_network_check(
            environment,
            lock_file,
            output_directory,
            vuln_api if source_is_valid else None,
            tcp_connector,
        ),
    )
    if any(check.status is CheckStatus.FAIL for check in checks):
        overall = DoctorOverallStatus.NOT_READY
    elif any(check.status is CheckStatus.WARN for check in checks):
        overall = DoctorOverallStatus.READY_WITH_WARNINGS
    else:
        overall = DoctorOverallStatus.READY
    return DoctorReport(overall, checks)


def render_doctor_terminal(report: DoctorReport) -> str:
    labels = {
        CheckStatus.PASS: "通过",
        CheckStatus.WARN: "提醒",
        CheckStatus.FAIL: "失败",
    }
    lines = ["Svarog Doctor（三项熔断版）", f"总体状态：{report.overall_status.value}"]
    for check in report.checks:
        lines.append(f"[{labels[check.status]}] {check.title}：{check.message}")
    lines.append("范围已锁定：不收集 CPU、内存、完整 PATH 或网络测速信息。")
    return "\n".join(lines) + "\n"
