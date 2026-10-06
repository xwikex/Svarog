import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from svarog.cli import build_parser, main
from svarog.dependency_audit import repository as dependency_repository
from svarog.dependency_audit.inventory import inventory_python_environment
from svarog.dependency_audit.models import (
    AdvisoryRecord,
    AdvisorySeverity,
    DatabaseMetadata,
    VulnerabilitySnapshot,
)
from svarog.dependency_audit.remote_repository import RemoteVulnerabilityError
from svarog.parsers.nginx_json import MAX_RECORDED_ISSUES

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"


def _write_event(file_path: Path, **changes: object) -> None:
    event: dict[str, object] = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/search",
        "query": "id=1 UNION SELECT password FROM users",
    }
    event.update(changes)
    file_path.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")


def _subprocess_env(*, output_encoding: str) -> dict[str, str]:
    environment = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "PYTHONIOENCODING": output_encoding,
    }
    environment.pop("PYTHONUTF8", None)
    return environment


@pytest.fixture
def cli_writable_database_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep writable SQLite fixture orchestration separate from POSIX policy tests."""

    if os.name == "posix":
        monkeypatch.setattr(
            dependency_repository,
            "_validate_posix_database_access",
            lambda _path: None,
        )


def _linux_venv(
    tmp_path: Path,
    *,
    package: str | None,
    version: str = "1.0",
    environment_name: str = "environment",
) -> Path:
    environment = tmp_path / environment_name
    environment.mkdir()
    (environment / "pyvenv.cfg").write_text(
        "home = /usr/bin\n",
        encoding="utf-8",
    )
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    site_packages.mkdir(parents=True)
    if package is not None:
        metadata = site_packages / f"{package}-{version}.dist-info" / "METADATA"
        metadata.parent.mkdir()
        metadata.write_text(
            f"Name: {package}\nVersion: {version}\n",
            encoding="utf-8",
        )
    return environment


def _vulnerability_database(
    tmp_path: Path,
    *,
    package: str | None,
    affected_range: str | None,
    last_sync_at: str | None = None,
    last_sync_status: str = "ok",
    database_name: str = "vulnerabilities.db",
) -> Path:
    database = tmp_path / database_name
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE advisories (
            ghsa_id TEXT PRIMARY KEY, cve_id TEXT, state TEXT, summary TEXT,
            description TEXT, severity TEXT, cvss_score REAL, cvss_vector TEXT,
            published_at TEXT, updated_at TEXT, withdrawn_at TEXT, source TEXT,
            raw_json TEXT, first_seen_at TEXT, last_synced_at TEXT
        );
        CREATE TABLE affected_packages (
            id INTEGER PRIMARY KEY, ghsa_id TEXT, ecosystem TEXT,
            package_name TEXT, version_range TEXT, introduced TEXT,
            fixed_version TEXT
        );
        CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    if package is not None and affected_range is not None:
        connection.execute(
            """
            INSERT INTO advisories VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                "GHSA-test-0001",
                "CVE-2026-0001",
                "published",
                "demo advisory",
                "not loaded",
                "high",
                8.0,
                "vector",
                "2026-08-01",
                "2026-08-30",
                None,
                "github_api",
                "not loaded",
                "2026-08-01",
                "2026-08-31",
            ),
        )
        connection.execute(
            "INSERT INTO affected_packages VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                "GHSA-test-0001",
                "pip",
                package,
                affected_range,
                None,
                "2.0",
            ),
        )
    sync_time = last_sync_at or datetime.now(timezone.utc).isoformat()
    connection.executemany(
        "INSERT INTO sync_meta VALUES (?, ?)",
        (
            ("last_sync_at", sync_time),
            ("last_sync_status", last_sync_status),
            ("last_sync_message", "complete"),
        ),
    )
    connection.commit()
    connection.close()
    return database


def _remote_snapshot(
    *,
    package: str | None = None,
    affected_range: str = "< 2.0",
) -> VulnerabilitySnapshot:
    advisories = ()
    if package is not None:
        advisories = (
            AdvisoryRecord(
                ghsa_id="GHSA-test-0001",
                cve_id="CVE-2026-0001",
                state="published",
                withdrawn_at=None,
                summary="remote demo advisory",
                severity=AdvisorySeverity.HIGH,
                cvss_score=8.0,
                source="github_api",
                updated_at="2026-09-01T00:00:00Z",
                package_name=package,
                normalized_package_name=package.lower(),
                version_range=affected_range,
                fixed_version="2.0",
            ),
        )
    return VulnerabilitySnapshot(
        DatabaseMetadata(
            path="http://vm:8000",
            size_bytes=0,
            sources=("github_api",),
            last_sync_at=datetime.now(timezone.utc).isoformat(),
            last_sync_status="ok",
            last_sync_message="complete",
        ),
        advisories,
    )


def test_cli_exposes_analyze_command() -> None:
    args = build_parser().parse_args(["analyze", "events.jsonl"])

    assert args.command == "analyze"
    assert str(args.input) == "events.jsonl"


def test_cli_exposes_audit_python_command() -> None:
    args = build_parser().parse_args(
        [
            "audit-python",
            ".venv",
            "--vuln-db",
            "/var/lib/svarog/vulnerabilities.db",
        ]
    )

    assert args.command == "audit-python"
    assert str(args.environment) == ".venv"
    assert args.vuln_db == Path("/var/lib/svarog/vulnerabilities.db")


def test_cli_exposes_audit_project_with_explicit_inputs() -> None:
    args = build_parser().parse_args(
        [
            "audit-project",
            "--environment",
            r"C:\project\demo\.venv",
            "--lock-file",
            r"C:\project\demo\uv.lock",
            "--vuln-api",
            "http://vm:8000",
            "--json-out",
            "report.json",
            "--html-out",
            "report.html",
        ]
    )

    assert args.environment == Path(r"C:\project\demo\.venv")
    assert args.lock_file == Path(r"C:\project\demo\uv.lock")
    assert args.vuln_api == "http://vm:8000"
    assert args.vuln_db is None
    assert args.json_out == Path("report.json")
    assert args.html_out == Path("report.html")


def test_cli_exposes_fused_doctor_with_only_explicit_paths() -> None:
    args = build_parser().parse_args(
        [
            "doctor",
            "--environment",
            r"C:\project\demo\.venv",
            "--lock-file",
            r"C:\project\demo\uv.lock",
            "--vuln-api",
            "http://192.168.56.101:8000",
            "--output-directory",
            r"C:\project\demo\reports",
        ]
    )

    assert args.environment == Path(r"C:\project\demo\.venv")
    assert args.lock_file == Path(r"C:\project\demo\uv.lock")
    assert args.output_directory == Path(r"C:\project\demo\reports")
    assert args.vuln_api == "http://192.168.56.101:8000"


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "audit-project",
            "--lock-file",
            "uv.lock",
            "--vuln-db",
            "vulnerabilities.db",
            "--json-out",
            "report.json",
        ],
        [
            "audit-project",
            "--environment",
            ".venv",
            "--vuln-db",
            "vulnerabilities.db",
            "--json-out",
            "report.json",
        ],
        [
            "audit-project",
            "--environment",
            ".venv",
            "--lock-file",
            "uv.lock",
            "--json-out",
            "report.json",
        ],
        [
            "audit-project",
            "--environment",
            ".venv",
            "--lock-file",
            "uv.lock",
            "--vuln-db",
            "vulnerabilities.db",
            "--vuln-api",
            "http://vm:8000",
            "--json-out",
            "report.json",
        ],
    ],
)
def test_audit_project_requires_explicit_inputs(
    arguments: list[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(arguments)

    assert caught.value.code == 2


def _uv_lock(path: Path, *versions: str) -> Path:
    packages = "\n".join(
        (
            "[[package]]\n"
            'name = "demo"\n'
            f'version = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )
        for version in versions
    )
    path.write_text(
        "version = 1\nrevision = 1\n\n" + packages,
        encoding="utf-8",
    )
    return path


def test_audit_project_requires_at_least_one_report_output(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(
            [
                "audit-project",
                "--environment",
                str(tmp_path / ".venv"),
                "--lock-file",
                str(tmp_path / "uv.lock"),
                "--vuln-db",
                str(tmp_path / "vulnerabilities.db"),
            ]
        )

    assert caught.value.code == 2


def test_audit_project_json_hidden_mvp_runs_end_to_end(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    lock_file = _uv_lock(tmp_path / "uv.lock", "1.0")
    database = _vulnerability_database(
        tmp_path,
        package=None,
        affected_range=None,
    )
    output = tmp_path / "project.json"

    exit_code = main(
        [
            "audit-project",
            "--environment",
            str(environment),
            "--lock-file",
            str(lock_file),
            "--vuln-db",
            str(database),
            "--json-out",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["report_type"] == "project_dependency_audit"
    assert payload["summary"]["matched"] == 1
    assert payload["lock_evaluation"]["marker_policy"] == "ignored"
    assert payload["actions_executed"] is False
    assert "适用性未经验证" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("environment_version", "lock_versions", "expected_exit", "env_count", "lock_count"),
    [
        ("3.0", ("1.0", "3.0"), 4, 0, 1),
        ("1.0", ("1.0",), 3, 1, 1),
    ],
)
def test_audit_project_exit_codes_preserve_evidence_layers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
    environment_version: str,
    lock_versions: tuple[str, ...],
    expected_exit: int,
    env_count: int,
    lock_count: int,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version=environment_version)
    lock_file = _uv_lock(tmp_path / "uv.lock", *lock_versions)
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range="< 2.0",
    )
    output = tmp_path / "project.json"

    exit_code = main(
        [
            "audit-project",
            "--environment",
            str(environment),
            "--lock-file",
            str(lock_file),
            "--vuln-db",
            str(database),
            "--json-out",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == expected_exit
    assert payload["summary"]["confirmed_environment_findings"] == env_count
    assert payload["summary"]["potential_lock_findings"] == lock_count
    assert capsys.readouterr().err == ""


def test_audit_project_rejects_report_aliasing_the_lockfile(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    lock_file = _uv_lock(tmp_path / "uv.lock", "1.0")
    original = lock_file.read_bytes()
    database = _vulnerability_database(
        tmp_path,
        package=None,
        affected_range=None,
    )

    exit_code = main(
        [
            "audit-project",
            "--environment",
            str(environment),
            "--lock-file",
            str(lock_file),
            "--vuln-db",
            str(database),
            "--json-out",
            str(lock_file),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "不能覆盖" in captured.err
    assert lock_file.read_bytes() == original


def test_audit_project_writes_json_and_single_file_html_from_one_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    lock_file = _uv_lock(tmp_path / "uv.lock", "1.0")
    database = _vulnerability_database(
        tmp_path,
        package=None,
        affected_range=None,
    )
    json_output = tmp_path / "project.json"
    html_output = tmp_path / "project.html"

    exit_code = main(
        [
            "audit-project",
            "--environment",
            str(environment),
            "--lock-file",
            str(lock_file),
            "--vuln-db",
            str(database),
            "--json-out",
            str(json_output),
            "--html-out",
            str(html_output),
        ]
    )

    payload = json.loads(json_output.read_text(encoding="utf-8"))
    document = html_output.read_text(encoding="utf-8")
    assert exit_code == 0
    assert f'content="{payload["audit_status"]}"' in document
    assert "<script" not in document.lower()
    assert capsys.readouterr().err == ""


def test_audit_python_accepts_remote_api_without_environment() -> None:
    args = build_parser().parse_args(
        ["audit-python", "--vuln-api", "http://vm:8000"]
    )

    assert args.environment is None
    assert args.vuln_api == "http://vm:8000"
    assert args.vuln_db is None


@pytest.mark.parametrize(
    "arguments",
    [
        ["audit-python", "environment"],
        [
            "audit-python",
            "environment",
            "--vuln-db",
            "vulnerabilities.db",
            "--vuln-api",
            "http://vm:8000",
        ],
    ],
)
def test_audit_python_requires_exactly_one_vulnerability_source(
    arguments: list[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(arguments)

    assert caught.value.code == 2


def test_audit_python_rejects_missing_remote_token_before_request(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo")
    monkeypatch.delenv("SVAROG_VULN_API_TOKEN", raising=False)

    def unexpected_request(_url: str, _token: str):
        raise AssertionError("remote request must not run without a token")

    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        unexpected_request,
        raising=False,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-api",
            "http://vm:8000",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] 漏洞知识库 API 地址或 Token 配置无效。\n"
    )


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (
            "invalid_configuration",
            "[错误] 漏洞知识库 API 地址或 Token 配置无效。\n",
        ),
        (
            "authentication_failed",
            "[错误] 漏洞知识库 API 身份验证失败。\n",
        ),
        ("rate_limited", "[错误] 漏洞知识库 API 请求受到限流。\n"),
        (
            "unavailable",
            "[错误] 漏洞知识库 API 不可访问或请求超时。\n",
        ),
        (
            "invalid_response",
            "[错误] 漏洞知识库 API 响应无效或超出安全限制。\n",
        ),
        (
            "unstable_snapshot",
            "[错误] 漏洞知识库在读取期间持续变化，请稍后重试。\n",
        ),
    ],
)
def test_audit_python_maps_remote_errors_without_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    message: str,
) -> None:
    environment = _linux_venv(tmp_path, package="demo")
    secret = "never-print-this-token"
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", secret)

    def fail_remote(_url: str, _token: str):
        raise RemoteVulnerabilityError(code)

    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        fail_remote,
        raising=False,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-api",
            "http://vm:8000",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == message
    assert secret not in captured.err


def test_audit_python_remote_mode_writes_report_without_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    target = tmp_path / "remote-audit.json"
    secret = "never-write-this-token"
    calls: list[tuple[str, str]] = []
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", secret)

    def load_remote(url: str, token: str) -> VulnerabilitySnapshot:
        calls.append((url, token))
        return _remote_snapshot(package="demo")

    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        load_remote,
        raising=False,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-api",
            "http://vm:8000",
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert exit_code == 3
    assert calls == [("http://vm:8000", secret)]
    assert payload["audit_status"] == "completed_with_findings"
    assert payload["actions_executed"] is False
    assert secret not in captured.out
    assert secret not in captured.err
    assert secret not in target.read_text(encoding="utf-8")


def test_audit_python_remote_mode_uses_current_environment_when_omitted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="2.0")
    current_inventory = inventory_python_environment(environment)
    inventory_calls: list[None] = []
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", "test-token")

    def inventory_current():
        inventory_calls.append(None)
        return current_inventory

    monkeypatch.setattr(
        "svarog.cli.inventory_current_python_environment",
        inventory_current,
        raising=False,
    )
    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        lambda _url, _token: _remote_snapshot(),
        raising=False,
    )

    exit_code = main(
        ["audit-python", "--vuln-api", "http://vm:8000"]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert inventory_calls == [None]
    assert "审计状态" in captured.out
    assert captured.err == ""


def test_audit_python_remote_mode_rejects_output_inside_current_environment(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="2.0")
    current_inventory = inventory_python_environment(environment)
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", "test-token")
    monkeypatch.setattr(
        "svarog.cli.inventory_current_python_environment",
        lambda: current_inventory,
    )

    def unexpected_request(_url: str, _token: str):
        raise AssertionError("remote request must not run for unsafe output")

    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        unexpected_request,
    )

    exit_code = main(
        [
            "audit-python",
            "--vuln-api",
            "http://vm:8000",
            "--json-out",
            str(environment / "audit.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_maps_unknown_remote_error_to_invalid_response(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo")
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", "test-token")

    def fail_remote(_url: str, _token: str):
        raise RemoteVulnerabilityError("unexpected-code")

    monkeypatch.setattr(
        "svarog.cli.load_remote_vulnerability_snapshot",
        fail_remote,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-api",
            "http://vm:8000",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] 漏洞知识库 API 响应无效或超出安全限制。\n"
    )


def test_audit_python_returns_three_and_writes_report_for_confirmed_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range="< 2.0",
    )
    target = tmp_path / "audit.json"

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert exit_code == 3
    assert payload["summary"]["confirmed_findings"] == 1
    assert "未执行任何动作" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("affected_range", "sync_age_days", "expected_exit"),
    [
        (None, 0, 0),
        ("< 0.8.3ubuntu7.5", 0, 4),
        ("< 2.0", 8, 3),
    ],
)
def test_audit_python_result_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
    affected_range: str | None,
    sync_age_days: int,
    expected_exit: int,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    last_sync_at = (
        datetime.now(timezone.utc) - timedelta(days=sync_age_days)
    ).isoformat()
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=affected_range,
        last_sync_at=last_sync_at,
    )

    exit_code = main(
        ["audit-python", str(environment), "--vuln-db", str(database)]
    )

    captured = capsys.readouterr()
    assert exit_code == expected_exit
    assert captured.err == ""


def test_audit_python_returns_one_for_invalid_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = _vulnerability_database(
        tmp_path,
        package=None,
        affected_range=None,
    )

    exit_code = main(
        [
            "audit-python",
            str(tmp_path / "missing"),
            "--vuln-db",
            str(database),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] Python 虚拟环境不可读取或结构无效。\n"
    assert "Traceback" not in captured.err


def test_audit_python_rejects_empty_inventory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package=None)
    database = _vulnerability_database(
        tmp_path,
        package=None,
        affected_range=None,
    )

    exit_code = main(
        ["audit-python", str(environment), "--vuln-db", str(database)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] Python 虚拟环境中没有可审计的有效安装包。\n"


def test_audit_python_missing_database_argument_returns_two(tmp_path: Path) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    completed = subprocess.run(
        [sys.executable, "-m", "svarog", "audit-python", str(environment)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_subprocess_env(output_encoding="utf-8:strict"),
    )

    assert completed.returncode == 2
    assert "--vuln-db" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_audit_python_rejects_database_as_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range="< 2.0",
    )
    original = database.read_bytes()

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(database),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert database.read_bytes() == original
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_database_hardlink_as_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = tmp_path / "database-alias.json"
    try:
        os.link(database, target)
    except OSError as exc:
        pytest.skip(f"hard link unavailable: {exc}")
    original = database.read_bytes()

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert database.read_bytes() == original
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_output_inside_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = environment / "audit.json"

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert not target.exists()
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_output_symlinked_inside_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    alias = tmp_path / "environment-alias"
    try:
        alias.symlink_to(environment, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(alias / "audit.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert not (environment / "audit.json").exists()
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_metadata_hardlink_as_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range="< 2.0",
    )
    metadata = next(
        environment.glob("lib/python*/site-packages/*.dist-info/METADATA")
    )
    target = tmp_path / "outside-report.json"
    try:
        os.link(metadata, target)
    except OSError as exc:
        pytest.skip(f"hard link unavailable: {exc}")
    original = metadata.read_bytes()

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert metadata.read_bytes() == original
    assert captured.err == "[错误] JSON 报告不能覆盖漏洞库或虚拟环境元数据。\n"


def test_audit_python_fails_closed_when_output_resolution_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = tmp_path / "audit.json"

    def fail_resolve(self: Path, *, strict: bool = False) -> Path:
        raise OSError("sensitive path detail")

    monkeypatch.setattr(Path, "resolve", fail_resolve)

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )
    assert "sensitive" not in captured.err
    assert not target.exists()


def test_audit_python_hides_incompatible_database_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = tmp_path / "bad.db"
    sqlite3.connect(database).close()

    exit_code = main(
        ["audit-python", str(environment), "--vuln-db", str(database)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] 漏洞数据库不可读取、损坏、锁定或结构不兼容。\n"
    )
    assert "sqlite" not in captured.err.lower()
    assert "Traceback" not in captured.err


def test_audit_python_handles_json_write_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = tmp_path / "audit.json"

    def fail_write(report: object, path: Path) -> None:
        raise OSError("sensitive")

    monkeypatch.setattr("svarog.cli.write_dependency_json", fail_write)

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "[错误] 无法安全写入依赖审计 JSON 报告。\n"
    assert "sensitive" not in captured.err
    assert not target.exists()


def test_audit_python_handles_invalid_json_output_leaf(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            ".",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_missing_output_parent_before_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = tmp_path / "missing" / "audit.json"

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rejects_invalid_metadata_hardlink_as_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    invalid_metadata = site_packages / "invalid.dist-info" / "METADATA"
    invalid_metadata.parent.mkdir()
    invalid_metadata.write_text("invalid metadata\n", encoding="utf-8")
    target = tmp_path / "invalid-metadata-alias.json"
    try:
        os.link(invalid_metadata, target)
    except OSError as exc:
        pytest.skip(f"hard link unavailable: {exc}")
    original = invalid_metadata.read_bytes()
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert invalid_metadata.read_bytes() == original
    assert captured.err == "[错误] JSON 报告不能覆盖漏洞库或虚拟环境元数据。\n"


def test_audit_python_fails_closed_when_existing_output_stat_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    target = tmp_path / "audit.json"
    target.write_text("old report", encoding="utf-8")
    original_stat = Path.stat

    monkeypatch.setattr(
        "svarog.cli._paths_may_refer_to_same_file",
        lambda _left, _right: False,
    )
    monkeypatch.setattr(
        "svarog.cli._path_is_within",
        lambda _path, _directory: False,
    )

    def fail_target_stat(self: Path, *args: object, **kwargs: object):
        if self == target:
            raise OSError("sensitive stat failure")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_target_stat)

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(target),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] JSON 报告不能覆盖漏洞库或虚拟环境元数据。\n"
    assert "sensitive" not in captured.err
    assert target.read_text(encoding="utf-8") == "old report"


@pytest.mark.parametrize(
    "stage",
    ["inventory_python_environment", "load_vulnerability_snapshot", "render_dependency_terminal"],
)
def test_audit_python_detects_output_parent_retarget_during_long_operations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cli_writable_database_layer: None,
    stage: str,
) -> None:
    if os.name != "posix":
        pytest.skip("directory symlink replacement requires POSIX semantics")
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    metadata = next(
        environment.glob("lib/python*/site-packages/*.dist-info/METADATA")
    )
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )
    database_before = database.read_bytes()
    metadata_before = metadata.read_bytes()
    fixed_directory = tmp_path / "fixed-output"
    redirected_directory = tmp_path / "redirected-output"
    fixed_directory.mkdir()
    redirected_directory.mkdir()
    alias = tmp_path / "output-alias"
    alias.symlink_to(fixed_directory, target_is_directory=True)

    import svarog.cli as cli_module

    original = getattr(cli_module, stage)

    def retarget_then_call(*args: object, **kwargs: object):
        alias.unlink()
        alias.symlink_to(redirected_directory, target_is_directory=True)
        return original(*args, **kwargs)

    monkeypatch.setattr(cli_module, stage, retarget_then_call)

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(database),
            "--json-out",
            str(alias / "audit.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )
    assert not (fixed_directory / "audit.json").exists()
    assert not (redirected_directory / "audit.json").exists()
    assert database.read_bytes() == database_before
    assert metadata.read_bytes() == metadata_before


def test_audit_python_rechecks_actual_inventory_environment(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("directory symlink replacement requires POSIX semantics")
    first = _linux_venv(
        tmp_path,
        package="demo",
        version="1.0",
        environment_name="first-environment",
    )
    actual = _linux_venv(
        tmp_path,
        package="demo",
        version="1.0",
        environment_name="actual-environment",
    )
    alias = tmp_path / "environment-alias"
    alias.symlink_to(first, target_is_directory=True)
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )

    import svarog.cli as cli_module

    original_inventory = cli_module.inventory_python_environment

    def inventory_after_retarget(path: Path):
        alias.unlink()
        alias.symlink_to(actual, target_is_directory=True)
        return original_inventory(path)

    monkeypatch.setattr(
        cli_module,
        "inventory_python_environment",
        inventory_after_retarget,
    )

    exit_code = main(
        [
            "audit-python",
            str(alias),
            "--vuln-db",
            str(database),
            "--json-out",
            str(actual / "audit.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert not (actual / "audit.json").exists()
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_rechecks_actual_snapshot_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cli_writable_database_layer: None,
) -> None:
    if os.name != "posix":
        pytest.skip("file symlink replacement requires POSIX semantics")
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    first = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
        database_name="first.db",
    )
    actual = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
        database_name="actual.db",
    )
    actual_before = actual.read_bytes()
    alias = tmp_path / "database-alias.db"
    alias.symlink_to(first)

    import svarog.cli as cli_module

    original_load = cli_module.load_vulnerability_snapshot

    def load_after_retarget(path: Path):
        alias.unlink()
        alias.symlink_to(actual)
        return original_load(path)

    monkeypatch.setattr(
        cli_module,
        "load_vulnerability_snapshot",
        load_after_retarget,
    )

    exit_code = main(
        [
            "audit-python",
            str(environment),
            "--vuln-db",
            str(alias),
            "--json-out",
            str(actual),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert actual.read_bytes() == actual_before
    assert captured.err == (
        "[错误] JSON 报告不能覆盖漏洞库或写入虚拟环境内部。\n"
    )


def test_audit_python_handles_terminal_render_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    cli_writable_database_layer: None,
) -> None:
    environment = _linux_venv(tmp_path, package="demo", version="1.0")
    database = _vulnerability_database(
        tmp_path,
        package="demo",
        affected_range=None,
    )

    def fail_render(report: object) -> str:
        raise UnicodeError("sensitive")

    monkeypatch.setattr("svarog.cli.render_dependency_terminal", fail_render)
    exit_code = main(
        ["audit-python", str(environment), "--vuln-db", str(database)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] 无法输出依赖审计终端报告。\n"
    assert "sensitive" not in captured.err


def test_analyze_writes_json_report_and_returns_success(tmp_path: Path, capsys) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "report.json"
    _write_event(source)

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Svarog 本地分析报告" in captured.out
    assert captured.err == ""
    assert json.loads(target.read_text(encoding="utf-8"))["actions_executed"] is False


def test_analyze_reports_true_input_issue_total_when_details_are_truncated(
    tmp_path: Path, capsys,
) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "report.json"
    omitted = 2
    valid_event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/health",
    }
    source.write_text(
        "not json\n" * (MAX_RECORDED_ISSUES + omitted)
        + json.dumps(valid_event)
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "输入问题：1002" in captured.out
    assert payload["summary"]["input_issues"] == 1002
    assert len(payload["input_issues"]) == MAX_RECORDED_ISSUES + 1
    assert payload["input_issues"][-1]["code"] == "issues_truncated"
    assert payload["input_issues"][-1]["message"] == "另有 2 个输入问题未逐条记录"


def test_analyze_returns_one_for_invalid_input_without_traceback(
    tmp_path: Path, capsys,
) -> None:
    source = tmp_path / "invalid.jsonl"
    source.write_text("not json\n", encoding="utf-8")

    exit_code = main(["analyze", str(source)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.startswith("[错误] 无法读取或分析输入文件。")
    assert "Traceback" not in captured.err
    assert "not json" not in captured.err


def test_analyze_rejects_only_surrogate_event_without_creating_report(
    tmp_path: Path, capsys,
) -> None:
    source = tmp_path / "surrogate.jsonl"
    target = tmp_path / "report.json"
    event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/bad\ud800path",
    }
    source.write_text(json.dumps(event) + "\n", encoding="utf-8")

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert not target.exists()


def test_analyze_handles_json_unicode_encoding_failure_without_traceback(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "report.json"
    _write_event(source)

    def fail_encoding(report: object, path: Path) -> None:
        raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogate")

    monkeypatch.setattr("svarog.cli.write_json_report", fail_encoding)

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "surrogate" not in captured.err
    assert not target.exists()


@pytest.mark.parametrize("output_name", ["events.jsonl", "alias/../events.jsonl"])
def test_analyze_rejects_lexical_input_output_aliases_without_overwriting(
    tmp_path: Path, capsys, monkeypatch, output_name: str,
) -> None:
    source = tmp_path / "events.jsonl"
    _write_event(source)
    original = source.read_bytes()
    (tmp_path / "alias").mkdir()
    monkeypatch.chdir(tmp_path)

    exit_code = main(["analyze", "events.jsonl", "--json-out", output_name])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] 输入文件和 JSON 报告不能指向同一文件。\n"
    assert source.read_bytes() == original


def test_analyze_rejects_existing_hard_link_output_without_overwriting(
    tmp_path: Path, capsys,
) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "report.json"
    _write_event(source)
    original = source.read_bytes()
    try:
        os.link(source, target)
    except OSError as exc:
        pytest.skip(f"当前平台不能创建硬链接：{exc}")

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] 输入文件和 JSON 报告不能指向同一文件。\n"
    assert source.read_bytes() == original


def test_analyze_fails_closed_when_alias_resolution_raises_oserror(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "report.json"
    _write_event(source)
    original = source.read_bytes()

    def fail_resolve(self: Path, *, strict: bool = False) -> Path:
        raise OSError("sensitive path detail")

    monkeypatch.setattr(Path, "resolve", fail_resolve)

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] 输入文件和 JSON 报告不能指向同一文件。\n"
    assert "sensitive" not in captured.err
    assert source.read_bytes() == original


def test_analyze_fails_closed_when_samefile_raises_oserror(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "existing-report.json"
    _write_event(source)
    target.write_text("existing", encoding="utf-8")
    original = source.read_bytes()

    def fail_samefile(self: Path, other_path: object) -> bool:
        raise OSError("sensitive path detail")

    monkeypatch.setattr(Path, "samefile", fail_samefile)

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "[错误] 输入文件和 JSON 报告不能指向同一文件。\n"
    assert "sensitive" not in captured.err
    assert source.read_bytes() == original


def test_analyze_distinguishes_json_write_failure(tmp_path: Path, capsys) -> None:
    source = tmp_path / "events.jsonl"
    target = tmp_path / "missing" / "report.json"
    _write_event(source)

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Svarog 本地分析报告" in captured.out
    assert captured.err == "[错误] 无法写入 JSON 报告。\n"
    assert "Traceback" not in captured.err
    assert not target.exists()


def test_python_module_entrypoint_runs_analyzer(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    _write_event(source, query="page=2")

    completed = subprocess.run(
        [sys.executable, "-m", "svarog", "analyze", str(source)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_subprocess_env(output_encoding="utf-8:strict"),
    )

    assert completed.returncode == 0
    assert "Svarog 本地分析报告" in completed.stdout
    assert completed.stderr == ""


def test_module_entrypoint_degrades_unencodable_terminal_text_but_keeps_json_unicode(
    tmp_path: Path,
) -> None:
    source = tmp_path / "emoji.jsonl"
    target = tmp_path / "report.json"
    _write_event(source, path="/status/😀", query="page=2")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "svarog",
            "analyze",
            str(source),
            "--json-out",
            str(target),
        ],
        check=False,
        capture_output=True,
        env=_subprocess_env(output_encoding="cp936:strict"),
    )

    stdout = completed.stdout.decode("cp936", errors="strict")
    stderr = completed.stderr.decode("cp936", errors="strict")
    assert completed.returncode == 0
    assert r"\U0001f600" in stdout
    assert "Traceback" not in stderr
    assert stderr == ""
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["events"][0]["event"]["path"] == "/status/😀"


def test_attack_sample_covers_all_four_local_rule_categories(
    tmp_path: Path, capsys,
) -> None:
    target = tmp_path / "report.json"

    exit_code = main([
        "analyze",
        str(SAMPLES / "nginx-attacks.jsonl"),
        "--json-out",
        str(target),
    ])

    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    payload = json.loads(target.read_text(encoding="utf-8"))
    categories = {
        evidence["category"]
        for event in payload["events"]
        for evidence in event["evidence"]
    }
    assert payload["summary"]["suspicious_events"] == 4
    assert categories == {"sql_injection", "xss", "path_traversal", "scanning"}


def test_prompt_injection_sample_is_treated_only_as_log_data(
    tmp_path: Path, capsys,
) -> None:
    target = tmp_path / "report.json"

    exit_code = main([
        "analyze",
        str(SAMPLES / "nginx-prompt-injection.jsonl"),
        "--json-out",
        str(target),
    ])

    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["summary"]["suspicious_events"] == 0
    assert payload["actions_executed"] is False
    assert "未执行任何动作" in captured.out
    assert captured.err == ""


def test_dockerfile_uses_minimal_non_root_runtime_and_cli_entrypoint() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.startswith("FROM python:3.11-slim\n")
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile
    assert "PYTHONUNBUFFERED=1" in dockerfile
    assert "WORKDIR /app" in dockerfile
    assert "--uid 10001 svarog" in dockerfile
    assert "python -m pip install --no-cache-dir ." in dockerfile
    assert "USER svarog" in dockerfile
    assert 'ENTRYPOINT ["svarog"]' in dockerfile
    assert 'CMD ["--help"]' in dockerfile
    assert "COPY . " not in dockerfile
    assert [
        line for line in dockerfile.splitlines() if line.startswith("COPY ")
    ] == [
        "COPY pyproject.toml README.md ./",
        "COPY src ./src",
        "COPY samples ./samples",
    ]


def test_dockerignore_excludes_development_and_sensitive_files() -> None:
    ignored = {
        line.strip()
        for line in (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert {
        ".git",
        ".worktrees",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        "*.pyc",
        "*.doc",
        "docs",
        "tests",
        "report*.json",
        "svarog.toml",
        ".env",
    } <= ignored


def test_cli_ui_defaults_and_browser_opt_in(monkeypatch, tmp_path: Path) -> None:
    from svarog.webui import server

    calls = []
    monkeypatch.setattr(server, "serve", lambda config, open_browser=False: calls.append((config, open_browser)))
    assert main(["ui", "--workspace", str(tmp_path)]) == 0
    assert (calls[0][0].host, calls[0][0].port, calls[0][1]) == ("127.0.0.1", 8765, False)

    calls.clear()
    assert main(["ui", "--host", "localhost", "--port", "9001", "--workspace", str(tmp_path),
                 "--case-db", ".svarog/custom.sqlite3", "--open-browser"]) == 0
    assert calls[0][0].case_db == (tmp_path / ".svarog/custom.sqlite3").resolve()
    assert calls[0][1] is True


def test_cli_ui_redacts_socket_error(monkeypatch, tmp_path: Path, capsys) -> None:
    from svarog.webui import server

    secret = tmp_path / "private-socket"
    def fail(*_args, **_kwargs):
        raise OSError(str(secret))
    monkeypatch.setattr(server, "serve", fail)

    assert main(["ui", "--workspace", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "无法启动本地工作台" in captured.err
    assert str(secret) not in captured.err


def test_cli_ui_redacts_database_initialization_error(monkeypatch, tmp_path: Path, capsys) -> None:
    from svarog.webui import server

    class InvalidDatabase:
        def __init__(self, _path):
            raise sqlite3.DatabaseError("private database detail")

    monkeypatch.setattr(server, "CaseStore", InvalidDatabase, raising=False)
    assert main(["ui", "--workspace", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "无法启动本地工作台" in captured.err
    assert "private database detail" not in captured.err
