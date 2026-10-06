from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from svarog.project_audit.lockfile import load_lock_snapshot


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles" / "real"


def test_real_lockfile_provenance_is_frozen_and_offline() -> None:
    provenance = json.loads(
        (FIXTURES / "PROVENANCE.json").read_text(encoding="utf-8")
    )

    assert provenance["runtime_network_required"] is False
    assert len(provenance["fixtures"]) == 3
    for item in provenance["fixtures"]:
        fixture = FIXTURES / item["file"]
        payload = fixture.read_bytes()
        assert len(payload) == item["size_bytes"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        assert item["commit"] in item["source"]
        assert item["source"].startswith(
            "https://raw.githubusercontent.com/"
        )


@pytest.mark.parametrize(
    ("filename", "lock_format", "package_count", "issue_count"),
    [
        ("cleo/poetry.lock", "poetry", 53, 0),
        ("uv-docker-example/uv.lock", "uv", 42, 0),
        ("fastapi-cli/uv.lock", "uv", 56, 1),
    ],
)
def test_real_lockfiles_parse_without_network_or_project_execution(
    filename: str,
    lock_format: str,
    package_count: int,
    issue_count: int,
) -> None:
    snapshot = load_lock_snapshot(FIXTURES / filename)

    assert snapshot.lock_format == lock_format
    assert len(snapshot.packages) == package_count
    assert len(snapshot.issues) == issue_count
    assert snapshot.marker_policy == "ignored"
    assert snapshot.version_policy == "all_distinct_versions"
    assert snapshot.applicability == "unverified"
    assert all(isinstance(package.dependencies, tuple) for package in snapshot.packages)
    assert any(package.dependencies for package in snapshot.packages)
    for package in snapshot.packages:
        identity = package.source_identity
        if identity is None:
            continue
        assert "@" not in identity
        assert not identity.startswith(("/", "\\\\"))
        assert not (
            len(identity) >= 3
            and identity[0].isalpha()
            and identity[1] == ":"
            and identity[2] in "/\\"
        )
        assert not any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            for character in identity
        )


def test_uv_lock_keeps_all_versions_and_ignores_markers(tmp_path: Path) -> None:
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(
        """
version = 1
resolution-markers = ["sys_platform == 'win32'", "sys_platform == 'linux'"]

[[package]]
name = "Demo_Pkg"
version = "1.0"
marker = "sys_platform == 'win32'"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "demo-pkg"
version = "2.0"
marker = "sys_platform == 'linux'"
source = { registry = "https://pypi.org/simple" }
""".strip(),
        encoding="utf-8",
    )

    snapshot = load_lock_snapshot(lock_file)

    assert [
        (package.normalized_name, package.version)
        for package in snapshot.packages
    ] == [("demo-pkg", "1.0"), ("demo-pkg", "2.0")]
    assert snapshot.warnings == (
        "Svarog 未解释锁文件中的平台、Python 版本、extra 或依赖组标记。"
        "报告已审计锁文件中出现的所有不同版本，因此部分结果可能不适用于当前环境。",
    )
