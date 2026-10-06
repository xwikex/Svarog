from __future__ import annotations

from pathlib import Path

import pytest

from svarog.project_audit import models
from svarog.project_audit import lockfile
from svarog.project_audit.lockfile import LockfileError, load_lock_snapshot


def _write_lock(tmp_path: Path, body: str, *, name: str = "uv.lock") -> Path:
    path = tmp_path / name
    path.write_text(body.strip(), encoding="utf-8")
    return path


def test_locked_package_freezes_dependency_sequences() -> None:
    dependency = models.LockedDependency(
        name="child",
        normalized_name="child",
        version=None,
        source_kind=None,
    )

    package = models.LockedPackage(
        name="parent",
        normalized_name="parent",
        version="1.0",
        version_valid=True,
        source_kind="registry",
        dependencies=[dependency],
    )

    assert package.dependencies == (dependency,)
    assert isinstance(package.dependencies, tuple)


@pytest.mark.parametrize("name", ["requirements.txt", "pyproject.toml", "lock.toml"])
def test_lockfile_rejects_unsupported_filename(tmp_path: Path, name: str) -> None:
    path = _write_lock(tmp_path, "package = []", name=name)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == "unsupported_lockfile"
    assert str(path) not in str(caught.value)


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"\xff", "invalid_encoding"),
        (b"[[package]\n", "invalid_toml"),
        (b"version = 1\n", "invalid_structure"),
        (b"package = {}\n", "invalid_structure"),
    ],
)
def test_lockfile_rejects_invalid_content(
    tmp_path: Path,
    payload: bytes,
    code: str,
) -> None:
    path = tmp_path / "uv.lock"
    path.write_bytes(payload)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == code


def test_lockfile_enforces_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_lock(tmp_path, "package = []\n" + ("x" * 128))
    monkeypatch.setattr(lockfile, "MAX_LOCKFILE_BYTES", 32, raising=False)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == "lockfile_too_large"


def test_lockfile_enforces_package_entry_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "one"
version = "1.0"
[[package]]
name = "two"
version = "2.0"
""",
    )
    monkeypatch.setattr(lockfile, "MAX_LOCK_PACKAGE_ENTRIES", 1, raising=False)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == "too_many_lock_packages"


def test_lockfile_keeps_invalid_version_as_indeterminate_issue(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "Demo_Pkg"
version = "not a version"
source = { git = "https://example.invalid/private.git" }
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert len(snapshot.packages) == 1
    package = snapshot.packages[0]
    assert package.name == "Demo_Pkg"
    assert package.normalized_name == "demo-pkg"
    assert package.version == "not a version"
    assert package.version_valid is False
    assert package.source_kind == "git"
    assert [issue.code for issue in snapshot.issues] == ["invalid_lock_version"]


def test_lockfile_skips_virtual_record_without_version_and_bounds_issues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "project-one"
source = { virtual = "." }
[[package]]
name = "project-two"
source = { editable = "." }
""",
    )
    monkeypatch.setattr(lockfile, "MAX_LOCK_ISSUES", 1, raising=False)

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages == ()
    assert len(snapshot.issues) == 1
    assert snapshot.total_issue_count == 2
    assert snapshot.truncated_issue_count == 1
    assert snapshot.issues[0].code == "lock_package_missing_version"


def test_lockfile_deduplicates_exact_candidates_but_keeps_sources_and_versions(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "Demo_Pkg"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "demo-pkg"
version = "1.0"
source = { registry = "https://mirror.invalid/simple" }
[[package]]
name = "demo.pkg"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "demo-pkg"
version = "1.0"
source = { git = "https://example.invalid/demo.git" }
""",
    )

    snapshot = load_lock_snapshot(path)

    assert [
        (item.normalized_name, item.version, item.source_kind, item.source_identity)
        for item in snapshot.packages
    ] == [
        ("demo-pkg", "1.0", "git", "https://example.invalid/demo.git"),
        ("demo-pkg", "1.0", "registry", "https://mirror.invalid/simple"),
        ("demo-pkg", "1.0", "registry", "https://pypi.org/simple"),
        ("demo-pkg", "2.0", "registry", "https://pypi.org/simple"),
    ]
    assert snapshot.total_package_entries == 4


def test_uv_dependency_is_retained_without_marker_evaluation(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "Child_Pkg", version = "2.0", marker = "sys_platform == 'linux'" },
]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].dependencies == (
        models.LockedDependency("Child_Pkg", "child-pkg", "2.0", None),
    )
    assert snapshot.marker_policy == "ignored"


def test_poetry_dependency_string_table_and_list_forms(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"

[package.dependencies]
string-child = ">=1,<3"
table-child = { version = "^2.0", optional = true, markers = "python_version >= '3.11'" }
list-child = [
  { version = "1.0", python = "<3.12" },
  { version = "2.0", platform = "linux" },
]
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert [
        (item.normalized_name, item.version, item.source_kind)
        for item in snapshot.packages[0].dependencies
    ] == [
        ("list-child", "1.0", None),
        ("list-child", "2.0", None),
        ("string-child", ">=1,<3", None),
        ("table-child", "^2.0", None),
    ]


def test_dependency_version_and_source_kind_are_optional(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"
dependencies = [
  { name = "unconstrained" },
  { name = "git-child", source = { git = "https://example.test/repo.git" } },
]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert [
        (item.normalized_name, item.version, item.source_kind)
        for item in snapshot.packages[0].dependencies
    ] == [
        ("git-child", None, "git"),
        ("unconstrained", None, None),
    ]


def test_dependency_and_package_candidates_sort_and_deduplicate_deterministically(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://one.example/simple" }
dependencies = [{ name = "zeta" }, { name = "Alpha" }, { name = "alpha" }]

[[package]]
name = "Demo"
version = "1.0"
source = { registry = "https://one.example/simple" }
dependencies = [{ name = "alpha" }, { name = "zeta" }]

[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://two.example/simple" }
dependencies = [{ name = "alpha" }, { name = "zeta" }]

[[package]]
name = "demo"
version = "1.0"
source = { registry = "https://one.example/simple" }
dependencies = [{ name = "alpha", version = "2" }, { name = "zeta" }]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert len(snapshot.packages) == 2
    assert [item.source_identity for item in snapshot.packages] == [
        "https://one.example/simple",
        "https://two.example/simple",
    ]
    assert [
        tuple((dep.normalized_name, dep.version) for dep in item.dependencies)
        for item in snapshot.packages
    ] == [
        (("alpha", None), ("alpha", "2"), ("zeta", None)),
        (("alpha", None), ("zeta", None)),
    ]


def test_invalid_dependency_fields_are_skipped_but_known_source_kind_is_retained(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"
source = { registry = "https://example.test/\u0085private" }
dependencies = [
  { name = "valid" },
  { name = "bad name" },
  { name = "bad-version", version = "1\u0085secret" },
  { name = "bad-source", source = { url = "https://example.test/\u0085secret" } },
]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity is None
    assert [item.normalized_name for item in snapshot.packages[0].dependencies] == [
        "bad-source",
        "valid",
    ]
    assert [issue.code for issue in snapshot.issues] == [
        "invalid_lock_source",
        "invalid_lock_dependency_name",
        "invalid_lock_dependency_version",
        "invalid_lock_dependency_source",
    ]
    assert "secret" not in repr(snapshot)


def test_source_url_credentials_query_and_fragment_are_not_retained(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "demo-package"
version = "1.0"
source = { registry = "https://alice:password@example.test/simple?token=secret#private" }
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity == "https://example.test/simple"
    serialized = repr(snapshot)
    for secret in ("alice", "password", "token", "secret", "private"):
        assert secret not in serialized
    assert [issue.code for issue in snapshot.issues] == [
        "lock_source_credentials_removed"
    ]


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "https://exa mple.test/simple",
        "https://alice%3Apassword%40example.test/simple",
        "https://alice%3Apassword@example.test/simple",
        "https://alice:password@other@example.test/simple",
        "https://example%0A.test/simple",
        "https://example.test/%0Asecret",
    ],
)
def test_source_urls_reject_malformed_or_encoded_credential_authorities(
    tmp_path: Path,
    unsafe_url: str,
) -> None:
    path = _write_lock(
        tmp_path,
        f"""
[[package]]
name = "demo-package"
version = "1.0"
source = {{ registry = "{unsafe_url}" }}
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity is None
    assert [issue.code for issue in snapshot.issues] == ["invalid_lock_source"]
    serialized = repr(snapshot)
    for secret in ("alice", "password", "%0A", "secret"):
        assert secret not in serialized


def test_source_urls_preserve_valid_dns_ipv4_and_ipv6_hosts(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "dns-package"
version = "1.0"
source = { registry = "https://example.test/simple" }

[[package]]
name = "ipv4-package"
version = "1.0"
source = { registry = "http://192.0.2.1/simple" }

[[package]]
name = "ipv6-package"
version = "1.0"
source = { registry = "https://[2001:db8::1]/simple" }
""",
    )

    snapshot = load_lock_snapshot(path)

    assert {
        package.normalized_name: package.source_identity
        for package in snapshot.packages
    } == {
        "dns-package": "https://example.test/simple",
        "ipv4-package": "http://192.0.2.1/simple",
        "ipv6-package": "https://[2001:db8::1]/simple",
    }
    assert snapshot.issues == ()


def test_safe_git_revision_and_artifact_hash_take_precedence(tmp_path: Path) -> None:
    digest = "a" * 64
    revision = "b" * 40
    path = _write_lock(
        tmp_path,
        f"""
[[package]]
name = "git-package"
version = "1.0"
source = {{ type = "git", url = "https://example.test/repo.git", resolved_reference = "{revision}" }}

[[package]]
name = "artifact-package"
version = "1.0"
source = {{ url = "https://example.test/archive.whl", hash = "sha256:{digest}" }}
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert {
        item.normalized_name: item.source_identity for item in snapshot.packages
    } == {
        "artifact-package": f"sha256:{digest}",
        "git-package": revision,
    }


def test_relative_source_paths_are_normalized_to_posix(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        r"""
[[package]]
name = "local-package"
version = "1.0"
source = { editable = '.\vendor\..\packages\demo' }
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity == "packages/demo"
    assert snapshot.issues == ()


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "https://alice:password@example.test/private?token=secret",
        "vendor/archive.whl:secret",
        "vendor/NUL.txt",
        "vendor/NUL .txt",
    ],
)
def test_relative_source_paths_reject_uri_ads_and_device_forms_without_leakage(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    path = _write_lock(
        tmp_path,
        f"""
[[package]]
name = "local-package"
version = "1.0"
source = {{ path = "{unsafe_path}" }}
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity is None
    assert [issue.code for issue in snapshot.issues] == ["unsafe_lock_source_path"]
    serialized = repr(snapshot)
    for secret in ("alice", "password", "token", "secret"):
        assert secret not in serialized


def test_poetry_unsafe_editable_dependency_is_retained_without_identity(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        r"""
[[package]]
name = "parent"
version = "1.0"

[package.dependencies]
local-child = { version = "^2", path = 'C:\Users\alice\secret', develop = true }
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].dependencies == (
        models.LockedDependency("local-child", "local-child", "^2", "editable"),
    )
    assert [issue.code for issue in snapshot.issues] == [
        "unsafe_lock_dependency_source"
    ]
    assert "alice" not in repr(snapshot)
    assert "secret" not in repr(snapshot)


def test_uv_dependency_with_nested_unsafe_source_is_retained(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"
dependencies = [
  { name = "local-child", version = "2", source = { path = "../private" } },
]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].dependencies == (
        models.LockedDependency("local-child", "local-child", "2", "path"),
    )
    assert [issue.code for issue in snapshot.issues] == [
        "unsafe_lock_dependency_source"
    ]


def test_duplicate_package_candidates_merge_dependency_union(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "Demo_Pkg"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "zeta" }, { name = "shared" }]

[[package]]
name = "demo-pkg"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "alpha" }, { name = "shared" }]
""",
    )

    snapshot = load_lock_snapshot(path)

    assert len(snapshot.packages) == 1
    assert [item.normalized_name for item in snapshot.packages[0].dependencies] == [
        "alpha",
        "shared",
        "zeta",
    ]


def test_abbreviated_git_revisions_fall_back_to_sanitized_url_or_none(
    tmp_path: Path,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "structured"
version = "1.0"
source = { type = "git", url = "https://example.test/repo.git", resolved_reference = "abc123" }

[[package]]
name = "fragment"
version = "1.0"
source = { git = "https://example.test/other.git#def456" }

[[package]]
name = "non-public"
version = "1.0"
source = { type = "git", url = "ssh://git@example.test/private.git", resolved_reference = "fedcba" }
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert {
        package.normalized_name: package.source_identity
        for package in snapshot.packages
    } == {
        "fragment": "https://example.test/other.git",
        "non-public": None,
        "structured": "https://example.test/repo.git",
    }
    assert [issue.code for issue in snapshot.issues] == ["invalid_lock_source"]


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/home/alice/project",
        "C:/Users/alice/project",
        "C:\\Users\\alice\\project",
        "//server/share/project",
        "\\\\server\\share\\project",
        "\\\\?\\C:\\private\\project",
        "file:///home/alice/project",
        "~/private/project",
        "../outside/project",
    ],
)
def test_absolute_or_escaping_local_source_paths_are_omitted(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    escaped = unsafe_path.replace("\\", "\\\\").replace('"', '\\"')
    path = _write_lock(
        tmp_path,
        f"""
[[package]]
name = "local-package"
version = "1.0"
source = {{ path = "{escaped}" }}
""",
        name="poetry.lock",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages[0].source_identity is None
    assert [issue.code for issue in snapshot.issues] == ["unsafe_lock_source_path"]
    assert unsafe_path not in repr(snapshot)


@pytest.mark.parametrize(
    ("limit_name", "limit", "expected_code"),
    [
        ("MAX_LOCK_DEPENDENCIES_PER_PACKAGE", 1, "too_many_lock_dependencies"),
        ("MAX_LOCK_DEPENDENCIES_TOTAL", 1, "too_many_lock_dependencies"),
    ],
)
def test_lockfile_rejects_dependency_count_bombs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    expected_code: str,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "parent"
version = "1.0"
dependencies = [{ name = "one" }, { name = "two" }]
""",
    )
    monkeypatch.setattr(lockfile, limit_name, limit, raising=False)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == expected_code


def test_duplicate_package_dependency_union_enforces_per_package_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_lock(
        tmp_path,
        """
[[package]]
name = "demo"
version = "1.0"
dependencies = [{ name = "one" }, { name = "two" }]

[[package]]
name = "Demo"
version = "1.0"
dependencies = [{ name = "three" }, { name = "four" }]
""",
    )
    monkeypatch.setattr(lockfile, "MAX_LOCK_DEPENDENCIES_PER_PACKAGE", 2)
    monkeypatch.setattr(lockfile, "MAX_LOCK_DEPENDENCIES_TOTAL", 4)

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(path)

    assert caught.value.code == "too_many_lock_dependencies"


def test_lockfile_rejects_overlong_fields(tmp_path: Path) -> None:
    path = _write_lock(
        tmp_path,
        f"""
[[package]]
name = "{'n' * 257}"
version = "1.0"
[[package]]
name = "valid"
version = "{'1' * 129}"
""",
    )

    snapshot = load_lock_snapshot(path)

    assert snapshot.packages == ()
    assert [issue.code for issue in snapshot.issues] == [
        "invalid_lock_name",
        "invalid_lock_version",
    ]


def test_lockfile_rejects_symlink(tmp_path: Path) -> None:
    target = _write_lock(tmp_path, "package = []", name="target.toml")
    link = tmp_path / "uv.lock"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(LockfileError) as caught:
        load_lock_snapshot(link)

    assert caught.value.code == "unsafe_lockfile"
