from pathlib import Path
import os
import stat
import sys
import sysconfig
import threading
from types import SimpleNamespace

import pytest

from svarog.dependency_audit import inventory
from svarog.dependency_audit.inventory import (
    MAX_METADATA_BYTES,
    MAX_METADATA_DIRS,
    MAX_NAME_CHARS,
    MAX_VERSION_CHARS,
    InventoryError,
    inventory_python_environment,
)


def make_environment(tmp_path: Path, site_roots: tuple[str, ...] = ("lib/python3.13/site-packages",)) -> tuple[Path, tuple[Path, ...]]:
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    roots = tuple(environment / relative for relative in site_roots)
    for root in roots:
        root.mkdir(parents=True)
    return environment, roots


def write_metadata(root: Path, directory: str, contents: bytes) -> Path:
    metadata = root / directory / "METADATA"
    metadata.parent.mkdir()
    metadata.write_bytes(contents)
    return metadata


def issue_codes(result) -> set[str]:
    return {issue.code for issue in result.issues}


def test_inventory_reads_linux_layout_and_canonicalizes_name(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    metadata = write_metadata(site_packages, "Example_Pkg-1.2.dist-info", b"Name: Example_Pkg\nVersion: 1.2\n")

    result = inventory_python_environment(environment)

    assert result.environment_path == str(environment.resolve())
    assert result.site_packages == (str(site_packages.resolve()),)
    assert result.packages[0].name == "Example_Pkg"
    assert result.packages[0].normalized_name == "example-pkg"
    assert result.packages[0].version == "1.2"
    assert result.packages[0].version_valid is True
    assert result.packages[0].metadata_path == str(metadata.resolve())
    assert result.total_metadata_dirs == 1
    assert result.truncated_metadata_dirs == 0


def test_inventory_reads_windows_virtual_environment(tmp_path: Path) -> None:
    environment, (site_packages,) = make_environment(
        tmp_path,
        ("Lib/site-packages",),
    )
    metadata = write_metadata(
        site_packages,
        "Demo_Pkg-1.2.3.dist-info",
        b"Name: Demo_Pkg\nVersion: 1.2.3\n",
    )

    result = inventory_python_environment(environment)

    assert result.environment_path == str(environment.resolve())
    assert result.site_packages == (str(site_packages.resolve()),)
    assert result.packages[0].normalized_name == "demo-pkg"
    assert result.packages[0].metadata_path == str(metadata.resolve())


def test_inventory_rejects_more_than_two_cross_platform_roots(
    tmp_path: Path,
) -> None:
    environment, _ = make_environment(
        tmp_path,
        (
            "lib/python3.12/site-packages",
            "lib64/python3.13/site-packages",
            "Lib/site-packages",
        ),
    )

    with pytest.raises(InventoryError, match="invalid_site_packages_count"):
        inventory_python_environment(environment)


def test_inventory_current_environment_uses_bounded_sysconfig_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "current-python"
    site_packages = prefix / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    metadata = write_metadata(
        site_packages,
        "Current-2.0.dist-info",
        b"Name: Current\nVersion: 2.0\n",
    )
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(
        sysconfig,
        "get_paths",
        lambda: {
            "purelib": str(site_packages),
            "platlib": str(site_packages),
        },
    )

    result = inventory.inventory_current_python_environment()

    assert result.environment_path == str(prefix.resolve())
    assert result.site_packages == (str(site_packages.resolve()),)
    assert result.packages[0].name == "Current"
    assert result.packages[0].metadata_path == str(metadata.resolve())


def test_inventory_current_environment_rejects_root_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "current-python"
    prefix.mkdir()
    outside = tmp_path / "outside-site-packages"
    outside.mkdir()
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(
        sysconfig,
        "get_paths",
        lambda: {"purelib": str(outside), "platlib": str(outside)},
    )

    with pytest.raises(InventoryError, match="site_packages_escape"):
        inventory.inventory_current_python_environment()


def test_inventory_current_environment_rejects_missing_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "current-python"
    prefix.mkdir()
    missing = prefix / "Lib" / "site-packages"
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(
        sysconfig,
        "get_paths",
        lambda: {"purelib": str(missing), "platlib": str(missing)},
    )

    with pytest.raises(InventoryError, match="invalid_site_packages_count"):
        inventory.inventory_current_python_environment()


@pytest.mark.parametrize("setup", ["missing", "no_config", "no_site_packages", "too_many_roots"])
def test_inventory_rejects_invalid_environment_shapes(tmp_path, setup):
    if setup == "missing":
        environment = tmp_path / "missing"
    elif setup == "no_config":
        environment = tmp_path / "environment"
        environment.mkdir()
    elif setup == "no_site_packages":
        environment, _ = make_environment(tmp_path, ())
    else:
        environment, _ = make_environment(
            tmp_path,
            ("lib/python3.11/site-packages", "lib/python3.12/site-packages", "lib64/python3.13/site-packages"),
        )

    with pytest.raises(InventoryError) as caught:
        inventory_python_environment(environment)

    assert str(caught.value) in {"invalid_environment", "invalid_site_packages_count"}
    assert str(environment) not in str(caught.value)


@pytest.mark.parametrize("target", ["pyvenv.cfg", "lib/python3.13/site-packages"])
def test_inventory_rejects_environment_symlink_escapes(tmp_path, target):
    environment, (site_packages,) = make_environment(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if target == "pyvenv.cfg":
        (environment / "pyvenv.cfg").unlink()
        (outside / "pyvenv.cfg").write_text("home = elsewhere\n", encoding="utf-8")
        link = environment / "pyvenv.cfg"
        expected = "environment_configuration_escape"
    else:
        site_packages.rmdir()
        (outside / "site-packages").mkdir()
        link = site_packages
        expected = "site_packages_escape"
    try:
        link.symlink_to(outside / link.name, target_is_directory=target != "pyvenv.cfg")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(InventoryError, match=expected):
        inventory_python_environment(environment)


def test_inventory_deduplicates_same_inode_lib_and_lib64_and_sorts_roots(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path, ("lib/python3.13/site-packages",))
    lib64_root = environment / "lib64/python3.13/site-packages"
    lib64_root.parent.mkdir(parents=True)
    try:
        lib64_root.symlink_to(site_packages, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    result = inventory_python_environment(environment)

    assert result.site_packages == (str(site_packages.resolve()),)


def test_inventory_sorts_multiple_valid_site_packages(tmp_path):
    environment, roots = make_environment(tmp_path, ("lib64/python3.13/site-packages", "lib/python3.12/site-packages"))

    result = inventory_python_environment(environment)

    assert result.site_packages == tuple(sorted(str(root.resolve()) for root in roots))


def test_inventory_streams_many_site_package_candidates_and_stops_at_third_unique_root(tmp_path, monkeypatch):
    environment, roots = make_environment(
        tmp_path,
        ("lib/python3.11/site-packages", "lib/python3.12/site-packages", "lib/python3.13/site-packages"),
    )

    def candidates_after_limit(path, pattern):
        if path == environment and pattern == "lib/python*/site-packages":
            for _ in range(100):
                yield roots[0]
            yield from roots[1:]
            raise AssertionError("candidate iterator was consumed after the third unique root")
        return
        yield  # pragma: no cover

    monkeypatch.setattr(Path, "glob", candidates_after_limit)

    with pytest.raises(InventoryError, match="invalid_site_packages_count"):
        inventory_python_environment(environment)


def test_inventory_rejects_oversized_metadata_without_reading(tmp_path, monkeypatch):
    environment, (site_packages,) = make_environment(tmp_path)
    metadata = write_metadata(site_packages, "huge-1.dist-info", b"Name: huge\nVersion: 1\n")
    monkeypatch.setattr("svarog.dependency_audit.inventory.MAX_METADATA_BYTES", 1)

    result = inventory_python_environment(environment)

    assert result.packages == ()
    assert "metadata_too_large" in issue_codes(result)
    assert result.issues[0].subject == str(metadata.resolve())


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        (b"Version: 1.0\n", "missing_package_identity"),
        (b"Name: example\n", "missing_package_identity"),
        (b"Name: bad\x01name\nVersion: 1.0\n", "invalid_metadata"),
        (b"Name: example\nVersion: version\x7f\n", "invalid_metadata"),
    ],
)
def test_inventory_reports_invalid_package_identity(tmp_path, contents, expected):
    environment, (site_packages,) = make_environment(tmp_path)
    write_metadata(site_packages, "bad-1.dist-info", contents)

    result = inventory_python_environment(environment)

    assert result.packages == ()
    assert expected in issue_codes(result)


def test_inventory_reports_missing_and_unparseable_metadata(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    missing = site_packages / "missing-1.dist-info"
    missing.mkdir()
    invalid = write_metadata(site_packages, "invalid-1.dist-info", b"\x80\x80\x80")

    result = inventory_python_environment(environment)

    assert result.packages == ()
    assert "metadata_missing" in issue_codes(result)
    assert "missing_package_identity" in issue_codes(result)
    assert str(invalid.resolve()) in {issue.subject for issue in result.issues}


def test_inventory_reports_metadata_symlink_escape(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    directory = site_packages / "escape-1.dist-info"
    directory.mkdir()
    outside = tmp_path / "outside-metadata"
    outside.write_bytes(b"Name: escaped\nVersion: 1\n")
    try:
        (directory / "METADATA").symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    result = inventory_python_environment(environment)

    assert result.packages == ()
    assert "metadata_escape" in issue_codes(result)


def test_metadata_reader_limits_read_after_file_grows(tmp_path, monkeypatch):
    _, (site_packages,) = make_environment(tmp_path)
    metadata = write_metadata(site_packages, "grow-1.dist-info", b"x")
    monkeypatch.setattr(inventory, "MAX_METADATA_BYTES", 3)
    read_sizes: list[int] = []

    def grown_file_read(_fd, size):
        read_sizes.append(size)
        return b"x" * size

    monkeypatch.setattr(inventory.os, "read", grown_file_read)

    contents, error = inventory._read_metadata_file(metadata.parent, site_packages)

    assert contents is None
    assert error == "metadata_too_large"
    assert read_sizes == [4]


def test_posix_metadata_open_includes_nonblocking_flag(tmp_path, monkeypatch):
    _, (site_packages,) = make_environment(tmp_path)
    metadata = write_metadata(site_packages, "flags-1.dist-info", b"x")
    opened: list[tuple[object, int]] = []
    nonblocking = 0x4000

    def fake_open(path, flags, *args, **kwargs):
        opened.append((path, flags))
        return len(opened)

    monkeypatch.setattr(inventory.os, "O_NONBLOCK", nonblocking, raising=False)
    monkeypatch.setattr(inventory.os, "open", fake_open)
    monkeypatch.setattr(inventory.os, "close", lambda _fd: None)
    monkeypatch.setattr(inventory.os, "fstat", lambda _fd: SimpleNamespace(st_mode=stat.S_IFREG, st_size=0))
    monkeypatch.setattr(inventory.os, "read", lambda _fd, _size: b"")

    contents, error = inventory._read_metadata_file_posix(metadata.parent, site_packages)

    assert contents == b""
    assert error is None
    assert next(flags for path, flags in opened if path == "METADATA") & nonblocking


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_inventory_refuses_fifo_metadata_without_blocking(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    metadata_directory = site_packages / "fifo-1.dist-info"
    metadata_directory.mkdir()
    os.mkfifo(metadata_directory / "METADATA")
    result: dict[str, object] = {}

    def inventory_in_background():
        result["value"] = inventory_python_environment(environment)

    worker = threading.Thread(target=inventory_in_background, daemon=True)
    worker.start()
    worker.join(timeout=2)

    assert not worker.is_alive(), "inventory must not block while opening a FIFO"
    inventory_result = result["value"]
    assert inventory_result.packages == ()
    assert "metadata_not_regular_file" in issue_codes(inventory_result)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX O_NOFOLLOW semantics")
def test_inventory_refuses_metadata_replaced_by_external_symlink_after_validation(tmp_path, monkeypatch):
    environment, (site_packages,) = make_environment(tmp_path)
    metadata = write_metadata(site_packages, "race-1.dist-info", b"Name: internal\nVersion: 1\n")
    outside = tmp_path / "external-metadata"
    outside.write_bytes(b"Name: escaped\nVersion: 1\n")
    original_resolve = Path.resolve
    replaced = False

    def replace_after_resolve(path, *args, **kwargs):
        nonlocal replaced
        resolved = original_resolve(path, *args, **kwargs)
        if path == metadata and not replaced:
            replaced = True
            metadata.unlink()
            metadata.symlink_to(outside)
        return resolved

    monkeypatch.setattr(Path, "resolve", replace_after_resolve)

    result = inventory_python_environment(environment)

    assert result.packages == ()
    assert {"metadata_unreadable", "metadata_escape"} & issue_codes(result)


def test_inventory_keeps_invalid_version_for_downstream_indeterminate_results(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    write_metadata(site_packages, "example-vendor.dist-info", b"Name: example\nVersion: vendor-build\n")

    result = inventory_python_environment(environment)

    assert result.packages[0].version == "vendor-build"
    assert result.packages[0].version_valid is False


def test_inventory_deduplicates_same_name_and_version(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    write_metadata(site_packages, "first.dist-info", b"Name: Example_Pkg\nVersion: 1.0\n")
    write_metadata(site_packages, "second.dist-info", b"Name: example-pkg\nVersion: 1.0\n")

    result = inventory_python_environment(environment)

    assert len(result.packages) == 1
    assert "duplicate_metadata" in issue_codes(result)
    assert result.ambiguous_names == frozenset()


def test_inventory_retains_ambiguous_versions(tmp_path):
    environment, (site_packages,) = make_environment(tmp_path)
    write_metadata(site_packages, "one.dist-info", b"Name: example\nVersion: 1.0\n")
    write_metadata(site_packages, "two.dist-info", b"Name: Example\nVersion: 2.0\n")

    result = inventory_python_environment(environment)

    assert [package.version for package in result.packages] == ["1.0", "2.0"]
    assert result.ambiguous_names == frozenset({"example"})
    assert "ambiguous_versions" in issue_codes(result)


def test_inventory_truncates_metadata_reads_but_counts_all_directories(tmp_path, monkeypatch):
    environment, (site_packages,) = make_environment(tmp_path)
    for index in range(3):
        write_metadata(site_packages, f"example-{index}.dist-info", f"Name: example{index}\nVersion: 1\n".encode())
    monkeypatch.setattr("svarog.dependency_audit.inventory.MAX_METADATA_DIRS", 2)

    result = inventory_python_environment(environment)

    assert result.total_metadata_dirs == 3
    assert result.truncated_metadata_dirs == 1
    assert len(result.packages) == 2


def test_metadata_selection_uses_bounded_stable_top_k(tmp_path):
    _, (site_packages,) = make_environment(tmp_path)
    for name in ("z-last.dist-info", "a-first.dist-info", "b-second.dist-info"):
        (site_packages / name).mkdir()

    selected, total = inventory._select_metadata_directories((site_packages,), [], limit=2)

    assert total == 3
    assert [directory.name for _, directory in selected] == ["a-first.dist-info", "b-second.dist-info"]


def test_inventory_exports_exact_production_limits():
    assert MAX_METADATA_BYTES == 1024 * 1024
    assert MAX_METADATA_DIRS == 10_000
    assert MAX_NAME_CHARS == 256
    assert MAX_VERSION_CHARS == 128


def test_inventory_module_does_not_use_process_execution():
    module = Path(__file__).parents[2] / "src/svarog/dependency_audit/inventory.py"
    source = module.read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "pip" not in source
