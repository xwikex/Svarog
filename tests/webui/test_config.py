from __future__ import annotations

import errno
import os
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from svarog.webui.config import UiConfig, resolve_workspace_path


def _symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except NotImplementedError as exc:
        pytest.skip(f"symbolic links are unavailable on this platform: {exc}")
    except OSError as exc:
        unavailable_errnos = {errno.EPERM, errno.EACCES}
        for name in ("ENOTSUP", "EOPNOTSUPP"):
            value = getattr(errno, name, None)
            if value is not None:
                unavailable_errnos.add(value)
        if exc.errno in unavailable_errnos or getattr(exc, "winerror", None) == 1314:
            pytest.skip(f"symbolic links are unavailable on this platform: {exc}")
        raise


def test_symlink_helper_propagates_unexpected_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_unexpected_error(
        self: Path, target: Path, target_is_directory: bool = False
    ) -> None:
        raise OSError(errno.EIO, "unexpected symlink failure")

    monkeypatch.setattr(Path, "symlink_to", raise_unexpected_error)

    with pytest.raises(OSError, match="unexpected symlink failure"):
        _symlink_or_skip(
            tmp_path / "link", tmp_path / "target", target_is_directory=False
        )


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_build_accepts_only_supported_loopback_hosts(tmp_path: Path, host: str) -> None:
    config = UiConfig.build(host, 8080, tmp_path, None)

    assert config.host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "LOCALHOST"])
def test_build_rejects_non_loopback_hosts(tmp_path: Path, host: str) -> None:
    with pytest.raises(ValueError, match="回环"):
        UiConfig.build(host, 8080, tmp_path, None)


@pytest.mark.parametrize("port", [True, False, 0, -1, 65536, "8080", 8080.0])
def test_build_rejects_bool_non_integer_and_out_of_range_ports(
    tmp_path: Path, port: object
) -> None:
    with pytest.raises(ValueError):
        UiConfig.build("127.0.0.1", port, tmp_path, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("port", [1, 65535])
def test_build_accepts_port_boundaries(tmp_path: Path, port: int) -> None:
    config = UiConfig.build("127.0.0.1", port, tmp_path, None)

    assert config.port == port


@pytest.mark.parametrize(
    ("host", "port"),
    [("0.0.0.0", 8000), ("localhost", True)],
)
def test_direct_construction_rejects_invalid_host_or_port(
    tmp_path: Path, host: str, port: object
) -> None:
    workspace = tmp_path.resolve(strict=True)
    case_db = (workspace / ".svarog" / "cases.sqlite3").resolve(strict=False)

    with pytest.raises(ValueError):
        UiConfig(  # type: ignore[arg-type]
            host=host, port=port, workspace=workspace, case_db=case_db
        )


def test_direct_construction_rejects_case_database_outside_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path.resolve(strict=True)
    outside_case_db = (workspace.parent / "outside.sqlite3").resolve(strict=False)

    with pytest.raises(ValueError):
        UiConfig(
            host="localhost",
            port=8000,
            workspace=workspace,
            case_db=outside_case_db,
        )


def test_direct_construction_accepts_valid_canonical_fields(tmp_path: Path) -> None:
    workspace = tmp_path.resolve(strict=True)
    case_db = (workspace / ".svarog" / "cases.sqlite3").resolve(strict=False)

    config = UiConfig(
        host="localhost", port=8000, workspace=workspace, case_db=case_db
    )

    assert config.workspace == workspace
    assert config.case_db == case_db
    assert config.max_request_bytes == 14 * 1024 * 1024


@pytest.mark.parametrize("max_request_bytes", [True, False, 0, -1, 1.5, "1024"])
def test_direct_construction_rejects_invalid_max_request_bytes(
    tmp_path: Path, max_request_bytes: object
) -> None:
    workspace = tmp_path.resolve(strict=True)
    case_db = (workspace / ".svarog" / "cases.sqlite3").resolve(strict=False)

    with pytest.raises(ValueError):
        UiConfig(  # type: ignore[arg-type]
            host="localhost",
            port=8000,
            workspace=workspace,
            case_db=case_db,
            max_request_bytes=max_request_bytes,
        )


def test_build_rejects_missing_or_non_directory_workspace(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    regular_file = tmp_path / "workspace.txt"
    regular_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError):
        UiConfig.build("localhost", 8000, missing, None)
    with pytest.raises(ValueError):
        UiConfig.build("localhost", 8000, regular_file, None)


def test_build_uses_resolved_default_case_database_and_is_immutable(
    tmp_path: Path,
) -> None:
    config = UiConfig.build("localhost", 8000, tmp_path, None)

    assert config.workspace == tmp_path.resolve(strict=True)
    assert config.case_db == tmp_path.resolve(strict=True) / ".svarog" / "database" / "cases.sqlite3"
    assert config.max_request_bytes == 14 * 1024 * 1024
    assert not hasattr(config, "__dict__")
    with pytest.raises(FrozenInstanceError):
        config.port = 9000  # type: ignore[misc]


def test_build_accepts_case_database_inside_workspace(tmp_path: Path) -> None:
    config = UiConfig.build(
        "::1", 443, tmp_path, tmp_path / "state" / "cases.sqlite3"
    )

    assert config.case_db == tmp_path.resolve(strict=True) / "state" / "cases.sqlite3"


def test_build_rejects_case_database_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ValueError):
        UiConfig.build("localhost", 8000, workspace, workspace / ".." / "cases.sqlite3")


@pytest.mark.parametrize("directory_name", [".", "existing"])
def test_build_rejects_workspace_or_existing_directory_as_case_database(
    tmp_path: Path, directory_name: str
) -> None:
    candidate = tmp_path if directory_name == "." else tmp_path / directory_name
    candidate.mkdir(exist_ok=True)

    with pytest.raises(ValueError):
        UiConfig.build("localhost", 8000, tmp_path, candidate)


@pytest.mark.parametrize(
    "filename",
    [
        "cases.sqlite3-wal",
        "cases.sqlite3-shm",
        "cases.sqlite3-journal",
        "cases.sqlite3-WAL",
        "cases.sqlite3-ShM",
        "cases.sqlite3-JoUrNaL",
    ],
)
def test_build_rejects_sqlite_sidecar_names(tmp_path: Path, filename: str) -> None:
    with pytest.raises(ValueError):
        UiConfig.build("localhost", 8000, tmp_path, tmp_path / filename)


def test_build_rejects_case_database_through_escaping_parent_symlink(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    _symlink_or_skip(workspace / "linked-parent", outside, target_is_directory=True)

    with pytest.raises(ValueError):
        UiConfig.build(
            "localhost", 8000, workspace, workspace / "linked-parent" / "cases.sqlite3"
        )


def test_resolve_workspace_path_accepts_internal_file_and_directory(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "reports"
    directory.mkdir()
    file_path = directory / "report.json"
    file_path.write_text("{}", encoding="utf-8")

    assert resolve_workspace_path(tmp_path, "reports/report.json", kind="file") == (
        file_path.resolve(strict=True)
    )
    assert resolve_workspace_path(tmp_path, Path("reports"), kind="directory") == (
        directory.resolve(strict=True)
    )


@pytest.mark.parametrize("raw_path", ["", "."])
def test_resolve_workspace_path_rejects_invalid_relative_paths(
    tmp_path: Path, raw_path: str
) -> None:
    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, raw_path, kind="file")


def test_resolve_workspace_path_rejects_existing_parent_traversal(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret", encoding="utf-8")

    with pytest.raises(ValueError):
        resolve_workspace_path(workspace, "../outside.txt", kind="file")


def test_resolve_workspace_path_rejects_absolute_path(tmp_path: Path) -> None:
    file_path = tmp_path / "report.json"
    file_path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, file_path.resolve(), kind="file")


@pytest.mark.skipif(os.name != "nt", reason="requires WindowsPath root semantics")
def test_resolve_workspace_path_rejects_windows_root_relative_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="相对路径"):
        resolve_workspace_path(tmp_path, Path(r"\definitely-missing"), kind="file")


def test_resolve_workspace_path_rejects_missing_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, "missing.txt", kind="file")


def test_resolve_workspace_path_enforces_requested_kind(tmp_path: Path) -> None:
    directory = tmp_path / "reports"
    directory.mkdir()
    file_path = tmp_path / "report.json"
    file_path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, directory.name, kind="file")
    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, file_path.name, kind="directory")
    with pytest.raises(ValueError):
        resolve_workspace_path(tmp_path, file_path.name, kind="socket")


def test_resolve_workspace_path_rejects_escaping_symlink(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret", encoding="utf-8")
    _symlink_or_skip(workspace / "outside-link", outside_file, target_is_directory=False)

    with pytest.raises(ValueError):
        resolve_workspace_path(workspace, "outside-link", kind="file")
