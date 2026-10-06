from __future__ import annotations

from pathlib import Path

import pytest

from svarog.doctor import (
    CheckStatus,
    DoctorOverallStatus,
    run_doctor,
)


def _explicit_project(tmp_path: Path, *, lock_name: str = "uv.lock") -> tuple[Path, Path, Path]:
    environment = tmp_path / ".venv"
    environment.mkdir()
    (environment / "pyvenv.cfg").write_text("home = test\n", encoding="utf-8")
    python = environment / "Scripts" / "python.exe"
    python.parent.mkdir()
    python.write_bytes(b"test executable placeholder")
    lock_file = tmp_path / lock_name
    lock_file.write_text("version = 1\nrevision = 1\npackage = []\n", encoding="utf-8")
    output = tmp_path / "reports"
    output.mkdir()
    return environment, lock_file, output


def test_doctor_has_exactly_three_fused_checks_in_local_mode(
    tmp_path: Path,
) -> None:
    environment, lock_file, output = _explicit_project(tmp_path)
    calls: list[tuple[str, ...]] = []

    def command_runner(argv: tuple[str, ...]) -> bool:
        calls.append(argv)
        return True

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_db=tmp_path / "vulnerabilities.db",
        command_runner=command_runner,
        database_checker=lambda _path: True,
    )

    assert [check.check_id for check in report.checks] == [
        "python_and_package_manager",
        "core_data_source",
        "directories_and_network",
    ]
    assert len(report.checks) == 3
    assert all(check.status is CheckStatus.PASS for check in report.checks)
    assert report.overall_status is DoctorOverallStatus.READY
    assert calls == [
        (str(environment / "Scripts" / "python.exe"), "--version"),
        ("uv", "--version"),
    ]


def test_missing_package_manager_is_only_a_warning(tmp_path: Path) -> None:
    environment, lock_file, output = _explicit_project(tmp_path, lock_name="poetry.lock")

    def command_runner(argv: tuple[str, ...]) -> bool:
        return argv[0] != "poetry"

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_db=tmp_path / "vulnerabilities.db",
        command_runner=command_runner,
        database_checker=lambda _path: True,
    )

    assert report.checks[0].status is CheckStatus.WARN
    assert report.overall_status is DoctorOverallStatus.READY_WITH_WARNINGS
    assert "解析锁文件不依赖" in report.checks[0].message


def test_python_unavailable_is_a_hard_failure(tmp_path: Path) -> None:
    environment, lock_file, output = _explicit_project(tmp_path)

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_db=tmp_path / "vulnerabilities.db",
        command_runner=lambda argv: argv[0] == "uv",
        database_checker=lambda _path: True,
    )

    assert report.checks[0].status is CheckStatus.FAIL
    assert report.overall_status is DoctorOverallStatus.NOT_READY


def test_remote_mode_only_connects_explicit_host_and_port_and_sends_no_data(
    tmp_path: Path,
) -> None:
    environment, lock_file, output = _explicit_project(tmp_path)
    connections: list[tuple[str, int, float]] = []

    class Connection:
        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def connector(address: tuple[str, int], timeout: float) -> Connection:
        connections.append((address[0], address[1], timeout))
        return Connection()

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_api="http://192.168.56.101:8000",
        command_runner=lambda _argv: True,
        tcp_connector=connector,
    )

    assert report.checks[1].status is CheckStatus.WARN
    assert "内部 SQLite" in report.checks[1].message
    assert report.checks[2].status is CheckStatus.PASS
    assert "未验证 API、认证或内部数据库状态" in report.checks[2].message
    assert connections == [("192.168.56.101", 8000, 2.0)]


def test_remote_mode_requires_an_explicit_port_and_does_not_connect_otherwise(
    tmp_path: Path,
) -> None:
    environment, lock_file, output = _explicit_project(tmp_path)
    calls: list[object] = []

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_api="http://vm.example",
        command_runner=lambda _argv: True,
        tcp_connector=lambda *_args, **_kwargs: calls.append(object()),
    )

    assert report.checks[2].status is CheckStatus.FAIL
    assert calls == []


@pytest.mark.parametrize(
    ("vuln_db", "vuln_api"),
    [(None, None), (Path("database.db"), "http://127.0.0.1:8000")],
)
def test_doctor_library_requires_exactly_one_data_source(
    tmp_path: Path,
    vuln_db: Path | None,
    vuln_api: str | None,
) -> None:
    environment, lock_file, output = _explicit_project(tmp_path)
    connections: list[object] = []

    report = run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output,
        vuln_db=vuln_db,
        vuln_api=vuln_api,
        command_runner=lambda _argv: True,
        database_checker=lambda _path: True,
        tcp_connector=lambda *_args, **_kwargs: connections.append(object()),
    )

    assert report.checks[1].status is CheckStatus.FAIL
    assert report.overall_status is DoctorOverallStatus.NOT_READY
    assert connections == []


def test_doctor_does_not_expand_into_system_information_collection() -> None:
    source = (Path(__file__).parents[1] / "src" / "svarog" / "doctor.py").read_text(
        encoding="utf-8"
    )

    forbidden = ("cpu_count", "virtual_memory", "environ.items", "/health", "latency")
    assert all(item not in source for item in forbidden)
