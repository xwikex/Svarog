import json
import os
import shutil
import sqlite3
import stat
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import svarog.runtime_layout as runtime_layout_module

from svarog.runtime_layout import (
    ProjectIdentity,
    RuntimeLayout,
    RuntimeLayoutError,
    RuntimeMigrationError,
    RuntimeSettings,
    create_project_identity,
    load_project_identity,
    load_settings,
    migrate_legacy_cases_db,
    save_settings,
)


def _layout(tmp_path: Path) -> RuntimeLayout:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return RuntimeLayout.build(workspace)


def test_runtime_layout_has_exact_slots_and_paths(tmp_path):
    layout = _layout(tmp_path)

    assert [field.name for field in fields(RuntimeLayout)] == [
        "workspace",
        "root",
        "config_dir",
        "database_dir",
        "backup_dir",
        "reports_dir",
        "cache_dir",
        "logs_dir",
        "temp_dir",
        "project_file",
        "settings_file",
        "history_db",
        "case_db",
    ]
    assert not hasattr(layout, "__dict__")
    root = layout.workspace / ".svarog"
    assert layout.root == root
    assert layout.config_dir == root / "config"
    assert layout.database_dir == root / "database"
    assert layout.backup_dir == root / "database" / "backups"
    assert layout.reports_dir == root / "reports"
    assert layout.cache_dir == root / "cache"
    assert layout.logs_dir == root / "logs"
    assert layout.temp_dir == root / "temp"
    assert layout.project_file == root / "config" / "project.json"
    assert layout.settings_file == root / "config" / "settings.json"
    assert layout.history_db == root / "database" / "audit-history.sqlite3"
    assert layout.case_db == root / "database" / "cases.sqlite3"

    with pytest.raises(FrozenInstanceError):
        layout.root = tmp_path


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_runtime_layout_rejects_invalid_workspace_with_path_free_error(tmp_path, kind):
    workspace = tmp_path / "private-workspace"
    if kind == "file":
        workspace.write_text("not a directory", encoding="utf-8")

    with pytest.raises(RuntimeLayoutError) as raised:
        RuntimeLayout.build(workspace)

    assert str(raised.value) == "invalid_workspace"
    assert str(workspace) not in str(raised.value)


def test_ensure_directories_creates_exact_managed_tree(tmp_path):
    layout = _layout(tmp_path)

    layout.ensure_directories()

    expected = {
        layout.root,
        layout.config_dir,
        layout.database_dir,
        layout.backup_dir,
        layout.reports_dir,
        layout.reports_dir / "audits",
        layout.reports_dir / "differences",
        layout.reports_dir / "sbom",
        layout.reports_dir / "cases",
        layout.cache_dir,
        layout.logs_dir,
        layout.temp_dir,
    }
    assert {path for path in layout.root.rglob("*") if path.is_dir()} | {layout.root} == expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_new_runtime_directories_are_private_where_permissions_are_portable(tmp_path):
    layout = _layout(tmp_path)

    layout.ensure_directories()

    for directory in (layout.root, layout.config_dir, layout.backup_dir, layout.temp_dir):
        assert stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0


def _symlink_directory_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are not available: {exc}")


def test_link_detection_uses_lstat_symlink_mode(monkeypatch):
    monkeypatch.setattr(
        runtime_layout_module.os,
        "lstat",
        lambda path: SimpleNamespace(st_mode=stat.S_IFLNK, st_reparse_tag=0),
    )

    assert runtime_layout_module._is_link(Path("symlink")) is True


def test_link_detection_recognizes_windows_mount_point_reparse_tag(monkeypatch):
    mount_point_tag = 0xA0000003
    monkeypatch.setattr(
        runtime_layout_module.stat,
        "IO_REPARSE_TAG_MOUNT_POINT",
        mount_point_tag,
        raising=False,
    )
    monkeypatch.setattr(
        runtime_layout_module.os,
        "lstat",
        lambda path: SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_reparse_tag=mount_point_tag,
        ),
    )

    assert runtime_layout_module._is_link(Path("junction")) is True


@pytest.mark.parametrize("relative", [Path("."), Path("database"), Path("reports/audits")])
def test_ensure_directories_rejects_symlinked_managed_ancestor_or_descendant(
    tmp_path, relative
):
    layout = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = layout.root if relative == Path(".") else layout.root / relative
    link.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _symlink_directory_or_skip(link, outside)

    with pytest.raises(RuntimeLayoutError) as raised:
        layout.ensure_directories()

    assert str(raised.value) == "unsafe_runtime_symlink"
    assert str(layout.workspace) not in str(raised.value)


def test_ensure_directories_rejects_workspace_ancestor_replaced_by_symlink(tmp_path):
    layout = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    layout.workspace.rmdir()
    _symlink_directory_or_skip(layout.workspace, outside)

    with pytest.raises(RuntimeLayoutError) as raised:
        layout.ensure_directories()

    assert str(raised.value) == "unsafe_runtime_symlink"
    assert not (outside / ".svarog").exists()


def test_ensure_directories_validates_workspace_ancestor_before_creation(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    monkeypatch.setattr(
        "svarog.runtime_layout._is_link",
        lambda path: path == layout.workspace,
    )

    with pytest.raises(RuntimeLayoutError) as raised:
        layout.ensure_directories()

    assert str(raised.value) == "unsafe_runtime_symlink"
    assert not layout.root.exists()


def test_ensure_directories_rejects_managed_directory_replaced_during_use(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    replacement = tmp_path / "replacement-directory"
    replacement.mkdir()
    displaced = tmp_path / "displaced-managed-directory"
    real_lstat = os.lstat
    swapped = False

    def swap_after_lstat(path, *args, **kwargs):
        nonlocal swapped
        metadata = real_lstat(path, *args, **kwargs)
        if Path(path) == layout.temp_dir and not swapped:
            swapped = True
            os.replace(layout.temp_dir, displaced)
            os.replace(replacement, layout.temp_dir)
        return metadata

    monkeypatch.setattr(runtime_layout_module.os, "lstat", swap_after_lstat)

    with pytest.raises(RuntimeLayoutError) as raised:
        layout.ensure_directories()

    assert str(raised.value) == "runtime_path_changed"
    assert str(layout.workspace) not in str(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows no-delete-share handle test")
def test_windows_directory_guard_blocks_ancestor_replacement(tmp_path):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    displaced = tmp_path / "displaced-runtime-root"

    with runtime_layout_module._SafeDirectory(layout, layout.root):
        with pytest.raises(OSError):
            os.replace(layout.root, displaced)

    os.replace(layout.root, displaced)
    os.replace(displaced, layout.root)
    assert layout.root.is_dir()
    assert not displaced.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows native handle fail-closed test")
def test_windows_directory_guard_fails_closed_when_createfile_is_unavailable(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    monkeypatch.setattr(runtime_layout_module, "_CREATE_FILE", None)

    with pytest.raises(RuntimeLayoutError) as raised:
        layout.ensure_directories()

    assert str(raised.value) == "runtime_metadata_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.root.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction race test")
def test_windows_directory_creation_race_cannot_write_through_swapped_junction(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    displaced = tmp_path / "displaced-runtime-root"
    real_mkdir = os.mkdir
    attempted = False
    replacement_blocked = False

    def swapping_mkdir(path, *args, **kwargs):
        nonlocal attempted, replacement_blocked
        if Path(path) == layout.config_dir and not attempted:
            attempted = True
            try:
                os.replace(layout.root, displaced)
            except OSError:
                replacement_blocked = True
            else:
                result = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(layout.root), str(outside)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert result.returncode == 0
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "mkdir", swapping_mkdir)
    raised = None
    try:
        layout.ensure_directories()
    except RuntimeLayoutError as error:
        raised = error
    outside_was_modified = (outside / "config").exists()

    if os.path.lexists(layout.root) and displaced.exists():
        os.rmdir(layout.root)
        os.replace(displaced, layout.root)

    assert raised is None
    assert attempted is True
    assert replacement_blocked is True
    assert outside_was_modified is False


@pytest.mark.skipif(os.name != "nt", reason="Windows junction integration test")
def test_ensure_directories_rejects_windows_junction_without_symlink_privilege(tmp_path):
    layout = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(layout.root), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("Windows junction creation is unavailable")
    try:
        with pytest.raises(RuntimeLayoutError) as raised:
            layout.ensure_directories()
        assert str(raised.value) == "unsafe_runtime_symlink"
    finally:
        if os.path.lexists(layout.root):
            os.rmdir(layout.root)


def test_project_identity_public_create_and_load_use_exact_stable_schema(tmp_path):
    layout = _layout(tmp_path)

    created = create_project_identity(layout, "  Example project  ")
    loaded = load_project_identity(layout)

    assert [field.name for field in fields(ProjectIdentity)] == [
        "schema_version",
        "project_id",
        "display_name",
        "created_at",
    ]
    assert not hasattr(created, "__dict__")
    assert created == loaded
    assert created.schema_version == 1
    assert created.display_name == "Example project"
    assert created.project_id == f"proj_{UUID(created.project_id[5:]).hex}"
    parsed_created_at = datetime.fromisoformat(created.created_at.replace("Z", "+00:00"))
    assert parsed_created_at.utcoffset().total_seconds() == 0
    with pytest.raises(FrozenInstanceError):
        created.display_name = "changed"

    payload = json.loads(layout.project_file.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": 1,
        "project_id": created.project_id,
        "display_name": "Example project",
        "created_at": created.created_at,
    }


def test_concurrent_project_identity_creators_all_return_persisted_winner(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    creator_count = 8
    creation_barrier = threading.Barrier(creator_count)
    synchronized_threads: set[int] = set()
    synchronization_lock = threading.Lock()
    real_child_metadata = runtime_layout_module._SafeDirectory.child_metadata

    def synchronized_missing_project(self, name):
        metadata = real_child_metadata(self, name)
        thread_id = threading.get_ident()
        if name == layout.project_file.name and metadata is None:
            with synchronization_lock:
                first_check = thread_id not in synchronized_threads
                synchronized_threads.add(thread_id)
            if first_check:
                creation_barrier.wait(timeout=5)
        return metadata

    monkeypatch.setattr(
        runtime_layout_module._SafeDirectory,
        "child_metadata",
        synchronized_missing_project,
    )

    with ThreadPoolExecutor(max_workers=creator_count) as executor:
        identities = list(
            executor.map(
                lambda _: create_project_identity(layout, "Concurrent project"),
                range(creator_count),
            )
        )

    persisted = load_project_identity(layout)
    assert identities == [persisted] * creator_count


def test_project_identity_preserves_id_and_created_at_across_copy_and_name_change(tmp_path):
    source_layout = _layout(tmp_path)
    original = create_project_identity(source_layout, "Original")
    copied_workspace = tmp_path / "copied"
    copied_workspace.mkdir()
    copied_layout = RuntimeLayout.build(copied_workspace)
    copied_layout.ensure_directories()
    shutil.copy2(source_layout.project_file, copied_layout.project_file)

    copied = ProjectIdentity.load_or_create(copied_layout, display_name="Renamed")

    assert copied.project_id == original.project_id
    assert copied.created_at == original.created_at
    assert copied.display_name == "Renamed"
    assert load_project_identity(copied_layout) == copied


def test_project_json_is_stable_and_contains_no_ambient_sensitive_data(tmp_path):
    workspace = tmp_path / "private-user-token" / "workspace"
    workspace.mkdir(parents=True)
    layout = RuntimeLayout.build(workspace)
    identity = create_project_identity(layout, "Safe display name")

    raw = layout.project_file.read_text(encoding="utf-8")

    assert raw == json.dumps(
        {
            "schema_version": 1,
            "project_id": identity.project_id,
            "display_name": identity.display_name,
            "created_at": identity.created_at,
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    assert str(workspace.resolve()) not in raw
    assert str(workspace.parent.resolve()) not in raw
    assert set(json.loads(raw)) == {"schema_version", "project_id", "display_name", "created_at"}


@pytest.mark.parametrize(
    "payload",
    [
        "{not-json",
        "[]",
        '{"schema_version":1,"project_id":"invalid","display_name":"name","created_at":"2026-01-01T00:00:00Z"}',
        '{"schema_version":2,"project_id":"proj_a8098c1a8f4c4ae5a5f9ef7d85cdbbef","display_name":"name","created_at":"2026-01-01T00:00:00Z"}',
        '{"schema_version":1,"project_id":"proj_a8098c1a8f4c4ae5a5f9ef7d85cdbbef","display_name":"name","created_at":"not-a-date"}',
        '{"schema_version":1,"project_id":"proj_a8098c1a8f4c4ae5a5f9ef7d85cdbbef","display_name":"name","created_at":"2026-01-01T00:00:00Z","extra":1}',
    ],
)
def test_load_project_identity_rejects_invalid_json_without_replacing_it(tmp_path, payload):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    layout.project_file.write_text(payload, encoding="utf-8")

    with pytest.raises(RuntimeLayoutError) as raised:
        load_project_identity(layout)

    assert str(raised.value).startswith("invalid_project_")
    assert str(layout.workspace) not in str(raised.value)
    assert layout.project_file.read_text(encoding="utf-8") == payload


def test_load_project_identity_rejects_source_replaced_after_validation(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    create_project_identity(layout, "Original")
    replacement = layout.config_dir / ".replacement-project.json"
    replacement.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": "proj_a8098c1a8f4c4ae5a5f9ef7d85cdbbef",
                "display_name": "Replacement",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    real_lstat = os.lstat
    swapped = False

    def swap_after_lstat(path, *args, **kwargs):
        nonlocal swapped
        metadata = real_lstat(path, *args, **kwargs)
        if Path(path) == layout.project_file and not swapped:
            swapped = True
            os.replace(replacement, layout.project_file)
        return metadata

    monkeypatch.setattr(runtime_layout_module.os, "lstat", swap_after_lstat)

    with pytest.raises(RuntimeLayoutError) as raised:
        load_project_identity(layout)

    assert str(raised.value) == "runtime_path_changed"
    assert str(layout.workspace) not in str(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows JSON source guard test")
def test_windows_json_read_blocks_source_replacement_before_path_open(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    expected = create_project_identity(layout, "Guarded read")
    real_open = os.open
    source_reopened = False

    def reject_source_reopen(path, flags, *args, **kwargs):
        nonlocal source_reopened
        if Path(path) == layout.project_file:
            source_reopened = True
            raise AssertionError("verified JSON source was reopened by path")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "open", reject_source_reopen)

    assert load_project_identity(layout) == expected
    assert source_reopened is False


@pytest.mark.parametrize(
    "display_name",
    ["", "   ", "bad\x00name", "bad\nname", "x" * 129, "C:\\Users\\secret", "/home/secret"],
)
def test_create_project_identity_rejects_invalid_display_name(tmp_path, display_name):
    layout = _layout(tmp_path)

    with pytest.raises(RuntimeLayoutError) as raised:
        create_project_identity(layout, display_name)

    assert str(raised.value) == "invalid_display_name"
    assert not layout.project_file.exists()


def test_load_or_create_does_not_treat_explicit_empty_display_name_as_default(tmp_path):
    layout = _layout(tmp_path)

    with pytest.raises(RuntimeLayoutError) as raised:
        ProjectIdentity.load_or_create(layout, display_name="")

    assert str(raised.value) == "invalid_display_name"
    assert not layout.project_file.exists()


def test_project_atomic_write_failure_is_path_free_and_leaves_no_partial_file(tmp_path, monkeypatch):
    layout = _layout(tmp_path)

    def fail_link(source, destination, *args, **kwargs):
        raise OSError("raw path-bearing operating-system error")

    monkeypatch.setattr("svarog.runtime_layout.os.link", fail_link)

    with pytest.raises(RuntimeLayoutError) as raised:
        create_project_identity(layout, "Project")

    assert str(raised.value) == "atomic_write_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.project_file.exists()
    assert list(layout.config_dir.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows JSON parent guard test")
def test_windows_json_publication_blocks_parent_replacement(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    displaced = layout.root / ".displaced-config"
    real_link = os.link
    replacement_blocked = False

    def swapping_link(source, destination, *args, **kwargs):
        nonlocal replacement_blocked
        if Path(destination) == layout.project_file:
            try:
                os.replace(layout.config_dir, displaced)
            except OSError:
                replacement_blocked = True
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "link", swapping_link)
    created = create_project_identity(layout, "Guarded project")

    assert replacement_blocked is True
    assert not displaced.exists()
    assert load_project_identity(layout) == created


def test_runtime_settings_exact_slots_default_schema_and_public_load(tmp_path):
    layout = _layout(tmp_path)

    settings = load_settings(layout)

    assert [field.name for field in fields(RuntimeSettings)] == [
        "schema_version",
        "audit_retention_days",
    ]
    assert not hasattr(settings, "__dict__")
    assert settings == RuntimeSettings(schema_version=1, audit_retention_days=180)
    assert json.loads(layout.settings_file.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "audit_retention_days": 180,
    }
    with pytest.raises(FrozenInstanceError):
        settings.audit_retention_days = 30


@pytest.mark.parametrize("days", [3, 30, 365])
def test_save_settings_accepts_inclusive_retention_bounds(tmp_path, days):
    layout = _layout(tmp_path)

    saved = save_settings(layout, {"audit_retention_days": days})

    assert saved == RuntimeSettings(schema_version=1, audit_retention_days=days)
    assert load_settings(layout) == saved


@pytest.mark.parametrize("days", [2, 366, True, 3.5, "30"])
def test_invalid_retention_uses_stable_runtime_layout_error(tmp_path, days):
    layout = _layout(tmp_path)

    with pytest.raises(RuntimeLayoutError) as raised:
        save_settings(layout, {"audit_retention_days": days})

    assert str(raised.value) == "invalid_retention_days"
    assert str(layout.workspace) not in str(raised.value)


def test_runtime_settings_immutable_update_persists_new_value(tmp_path):
    layout = _layout(tmp_path)
    original = load_settings(layout)

    updated = original.update(layout, audit_retention_days=45)

    assert original.audit_retention_days == 180
    assert updated.audit_retention_days == 45
    assert load_settings(layout) == updated


@pytest.mark.parametrize(
    "payload",
    [
        "{bad-json",
        "[]",
        '{"schema_version":2,"audit_retention_days":30}',
        '{"schema_version":1,"audit_retention_days":2}',
        '{"schema_version":1,"audit_retention_days":30,"extra":true}',
    ],
)
def test_load_settings_rejects_invalid_existing_json_without_replacing_it(tmp_path, payload):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    layout.settings_file.write_text(payload, encoding="utf-8")

    with pytest.raises(RuntimeLayoutError):
        load_settings(layout)

    assert layout.settings_file.read_text(encoding="utf-8") == payload


def test_settings_atomic_failure_preserves_existing_destination(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    load_settings(layout)
    original_payload = layout.settings_file.read_bytes()

    def fail_replace(source, destination):
        raise OSError("raw operating-system error")

    monkeypatch.setattr("svarog.runtime_layout.os.replace", fail_replace)

    with pytest.raises(RuntimeLayoutError) as raised:
        save_settings(layout, {"audit_retention_days": 30})

    assert str(raised.value) == "atomic_write_failed"
    assert layout.settings_file.read_bytes() == original_payload
    assert list(layout.config_dir.glob("*.tmp")) == []


def _create_legacy_cases_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE cases (case_id TEXT PRIMARY KEY, title TEXT NOT NULL)")
        connection.execute("INSERT INTO cases VALUES ('case-1', 'Original case')")
        connection.commit()
    finally:
        connection.close()


def test_legacy_case_database_migration_uses_case_db_and_preserves_source(tmp_path):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    source_bytes = source.read_bytes()

    assert migrate_legacy_cases_db(layout) is True

    assert source.read_bytes() == source_bytes
    with sqlite3.connect(layout.case_db) as connection:
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT * FROM cases").fetchall() == [
            ("case-1", "Original case")
        ]


def test_migration_only_uses_in_memory_sqlite_connections(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    real_connect = sqlite3.connect
    connection_targets: list[str] = []

    def memory_only_connect(database, *args, **kwargs):
        target = os.fspath(database)
        connection_targets.append(target)
        assert target == ":memory:"
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", memory_only_connect)

    assert migrate_legacy_cases_db(layout) is True
    assert connection_targets == [":memory:", ":memory:"]


def test_source_swap_and_restore_during_sqlite_connect_cannot_redirect_migration(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    source_bytes = source.read_bytes()
    replacement = layout.root / ".replacement-cases.sqlite3"
    _create_legacy_cases_database(replacement)
    connection = sqlite3.connect(replacement)
    try:
        connection.execute("UPDATE cases SET title = 'Replacement case'")
        connection.commit()
    finally:
        connection.close()
    replacement_bytes = replacement.read_bytes()
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(database, *args, **kwargs):
        nonlocal swapped
        assert os.fspath(database) == ":memory:"
        if not swapped:
            swapped = True
            source.write_bytes(replacement_bytes)
            try:
                return real_connect(database, *args, **kwargs)
            finally:
                source.write_bytes(source_bytes)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", swapping_connect)

    assert migrate_legacy_cases_db(layout) is True
    assert swapped is True
    assert source.read_bytes() == source_bytes
    with real_connect(layout.case_db) as connection:
        assert connection.execute("SELECT title FROM cases").fetchone() == (
            "Original case",
        )


def test_temp_replacement_attempt_never_becomes_a_sqlite_path_binding(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    real_connect = sqlite3.connect
    real_write = runtime_layout_module._write_all_to_descriptor
    connection_count = 0
    replacement_blocked = False
    replacement_restored = False
    temporary_creations = 0
    temporary_reopens = 0
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        nonlocal temporary_creations, temporary_reopens
        name = Path(path).name
        if name.startswith(".cases.sqlite3.") and name.endswith(".sqlite3.tmp"):
            if flags & os.O_CREAT:
                temporary_creations += 1
            else:
                temporary_reopens += 1
        return real_open(path, flags, *args, **kwargs)

    def memory_connect(database, *args, **kwargs):
        nonlocal connection_count
        assert os.fspath(database) == ":memory:"
        connection_count += 1
        assert list(layout.database_dir.glob(".cases.sqlite3.*.sqlite3.tmp")) == []
        return real_connect(database, *args, **kwargs)

    def replacing_write(descriptor, payload):
        nonlocal replacement_blocked, replacement_restored
        temporary = next(layout.database_dir.glob(".cases.sqlite3.*.sqlite3.tmp"))
        displaced = layout.database_dir / ".displaced-owned-temp"
        try:
            os.replace(temporary, displaced)
        except OSError:
            replacement_blocked = True
            return real_write(descriptor, payload)
        temporary.write_bytes(b"substituted temp path")
        try:
            return real_write(descriptor, payload)
        finally:
            temporary.unlink()
            os.replace(displaced, temporary)
            replacement_restored = True

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", memory_connect)
    monkeypatch.setattr(
        runtime_layout_module,
        "_write_all_to_descriptor",
        replacing_write,
    )
    monkeypatch.setattr(runtime_layout_module.os, "open", tracking_open)

    assert migrate_legacy_cases_db(layout) is True
    assert connection_count == 2
    assert replacement_blocked or replacement_restored
    assert temporary_creations == 1
    assert temporary_reopens == 0
    with real_connect(layout.case_db) as connection:
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT title FROM cases").fetchone() == (
            "Original case",
        )


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_migration_rejects_legacy_database_sidecars(tmp_path, suffix):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    sidecar = source.with_name(source.name + suffix)
    sidecar.write_bytes(b"active sidecar")

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.case_db.exists()
    assert sidecar.read_bytes() == b"active sidecar"


def test_migration_fails_closed_without_sqlite_serialization_support(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    monkeypatch.setattr(
        runtime_layout_module,
        "_SQLITE_SERIALIZATION_SUPPORTED",
        False,
    )

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.case_db.exists()


def test_legacy_case_database_migration_is_idempotent_and_handles_missing_source(tmp_path):
    layout = _layout(tmp_path)
    assert migrate_legacy_cases_db(layout) is False
    assert not layout.case_db.exists()

    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    assert migrate_legacy_cases_db(layout) is True
    destination_bytes = layout.case_db.read_bytes()
    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO cases VALUES ('case-2', 'Later source case')")

    assert migrate_legacy_cases_db(layout) is False
    assert layout.case_db.read_bytes() == destination_bytes


def test_concurrent_legacy_migrations_only_publish_a_complete_winner(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    first_connected = threading.Event()
    release_first = threading.Event()
    first_thread_id: list[int] = []
    real_write = runtime_layout_module._write_all_to_descriptor

    def delayed_first_writer(descriptor, payload):
        if (
            first_thread_id
            and threading.get_ident() == first_thread_id[0]
        ):
            first_connected.set()
            assert release_first.wait(timeout=5)
        return real_write(descriptor, payload)

    monkeypatch.setattr(
        runtime_layout_module,
        "_write_all_to_descriptor",
        delayed_first_writer,
    )

    def first_migration():
        first_thread_id.append(threading.get_ident())
        return migrate_legacy_cases_db(layout)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(first_migration)
        assert first_connected.wait(timeout=5)
        second_result = executor.submit(migrate_legacy_cases_db, layout)
        try:
            assert second_result.result(timeout=5) is True
            with sqlite3.connect(layout.case_db) as connection:
                assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                assert connection.execute("SELECT * FROM cases").fetchall() == [
                    ("case-1", "Original case")
                ]
        finally:
            release_first.set()
        assert first_result.result(timeout=5) is False

    assert sorted(path.name for path in layout.database_dir.iterdir()) == [
        "backups",
        "cases.sqlite3",
    ]


def _mock_lstat_for_path(monkeypatch, target: Path, metadata) -> None:
    original_lstat = os.lstat

    def selective_lstat(path, *args, **kwargs):
        if Path(path) == target:
            return metadata
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "lstat", selective_lstat)


def test_migration_rejects_linked_source_before_opening_it(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    _mock_lstat_for_path(
        monkeypatch,
        source,
        SimpleNamespace(st_mode=stat.S_IFLNK, st_reparse_tag=0),
    )

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "unsafe_legacy_case_source"
    assert not layout.case_db.exists()


def test_migration_requires_source_to_be_regular_via_nonfollowing_metadata(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    _mock_lstat_for_path(
        monkeypatch,
        source,
        SimpleNamespace(st_mode=stat.S_IFDIR, st_reparse_tag=0),
    )

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "unsafe_legacy_case_source"
    assert not layout.case_db.exists()


def test_migration_rejects_source_replaced_after_nonfollowing_validation(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    replacement = layout.root / ".replacement-cases.sqlite3"
    _create_legacy_cases_database(replacement)
    connection = sqlite3.connect(replacement)
    try:
        connection.execute("UPDATE cases SET title = 'Replacement case'")
        connection.commit()
    finally:
        connection.close()
    displaced = layout.root / ".original-cases.sqlite3"
    real_connect = sqlite3.connect
    swapped = False

    def swap_before_connect(database, *args, **kwargs):
        nonlocal swapped
        if os.fspath(database) == ":memory:" and not swapped:
            swapped = True
            os.replace(source, displaced)
            os.replace(replacement, source)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", swap_before_connect)

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.case_db.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows no-delete-share source test")
def test_windows_migration_source_handle_blocks_swap_before_sqlite_open(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    replacement = layout.root / ".replacement-cases.sqlite3"
    _create_legacy_cases_database(replacement)
    connection = sqlite3.connect(replacement)
    try:
        connection.execute("UPDATE cases SET title = 'Replacement case'")
        connection.commit()
    finally:
        connection.close()
    displaced = layout.root / ".original-cases.sqlite3"

    real_open = os.open
    source_reopened = False

    def reject_source_reopen(path, flags, *args, **kwargs):
        nonlocal source_reopened
        if Path(path) == source:
            source_reopened = True
            raise AssertionError("verified SQLite source was reopened by path")
        return real_open(path, flags, *args, **kwargs)

    real_connect = sqlite3.connect
    replacement_blocked = False
    attempted = False

    def swapping_connect(database, *args, **kwargs):
        nonlocal attempted, replacement_blocked
        if os.fspath(database) == ":memory:" and not attempted:
            attempted = True
            try:
                os.replace(source, displaced)
            except OSError:
                replacement_blocked = True
            else:
                os.replace(replacement, source)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "open", reject_source_reopen)
    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", swapping_connect)
    migration_result = None
    raised = None
    try:
        migration_result = migrate_legacy_cases_db(layout)
    except RuntimeMigrationError as error:
        raised = error
    finally:
        if displaced.exists():
            source.unlink(missing_ok=True)
            os.replace(displaced, source)

    assert raised is None
    assert migration_result is True
    assert source_reopened is False
    assert replacement_blocked is True
    with sqlite3.connect(layout.case_db) as connection:
        assert connection.execute("SELECT title FROM cases").fetchone() == (
            "Original case",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows destination parent guard test")
def test_windows_migration_temp_parent_is_guarded_during_sqlite_open(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    displaced = layout.root / ".displaced-database"
    real_connect = sqlite3.connect
    replacement_blocked = False
    connection_count = 0

    def swapping_connect(database, *args, **kwargs):
        nonlocal connection_count, replacement_blocked
        connection_count += 1
        if connection_count == 2:
            try:
                os.replace(layout.database_dir, displaced)
            except OSError:
                replacement_blocked = True
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", swapping_connect)

    assert migrate_legacy_cases_db(layout) is True
    assert replacement_blocked is True
    assert not displaced.exists()
    with sqlite3.connect(layout.case_db) as connection:
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]


@pytest.mark.parametrize(
    ("destination_exists", "metadata"),
    [
        (True, SimpleNamespace(st_mode=stat.S_IFLNK, st_reparse_tag=0)),
        (
            False,
            SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_reparse_tag=0xA0000003,
            ),
        ),
    ],
)
def test_migration_rejects_linked_or_dangling_reparse_destination(
    tmp_path, monkeypatch, destination_exists, metadata
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    if destination_exists:
        layout.case_db.write_bytes(b"linked destination placeholder")
    _mock_lstat_for_path(monkeypatch, layout.case_db, metadata)

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "unsafe_legacy_case_destination"
    assert str(layout.workspace) not in str(raised.value)
    if destination_exists:
        assert layout.case_db.read_bytes() == b"linked destination placeholder"


def test_migration_rejects_destination_reparse_inserted_between_checks(
    tmp_path, monkeypatch
):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    real_lstat = os.lstat
    destination_checks = 0
    reparse_metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR,
        st_reparse_tag=0xA0000003,
    )

    def destination_changes_after_first_check(path, *args, **kwargs):
        nonlocal destination_checks
        if Path(path) == layout.case_db:
            destination_checks += 1
            if destination_checks == 1:
                return None
            return reparse_metadata
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(
        runtime_layout_module.os,
        "lstat",
        destination_changes_after_first_check,
    )

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "unsafe_legacy_case_destination"
    assert str(layout.workspace) not in str(raised.value)
    assert not layout.case_db.exists()


def test_migration_failure_cleans_destination_and_hides_paths_and_sqlite_details(tmp_path):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    source.write_bytes(b"not a sqlite database")

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_failed"
    assert str(layout.workspace) not in str(raised.value)
    assert source.read_bytes() == b"not a sqlite database"
    assert not layout.case_db.exists()
    assert sorted(path.name for path in layout.database_dir.iterdir()) == ["backups"]


def test_migration_translates_expected_unicode_path_failure(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)

    def fail_open(path, *args, **kwargs):
        raise UnicodeError("sensitive unicode detail")

    monkeypatch.setattr(runtime_layout_module.sqlite3, "connect", fail_open)

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_failed"


@pytest.mark.parametrize(
    "cleanup_error",
    [OSError("sensitive cleanup detail"), UnicodeError("sensitive unicode detail")],
)
def test_migration_cleanup_failure_has_safe_explicit_error(tmp_path, monkeypatch, cleanup_error):
    layout = _layout(tmp_path)
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    _create_legacy_cases_database(source)
    original_unlink = os.unlink

    def fail_temp_write(descriptor, payload):
        raise OSError("sensitive write detail")

    def fail_destination_cleanup(path, *args, **kwargs):
        candidate = Path(path)
        if (
            candidate.parent == layout.database_dir
            and candidate.name.startswith(".cases.sqlite3.")
        ):
            raise cleanup_error
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(runtime_layout_module.os, "unlink", fail_destination_cleanup)
    monkeypatch.setattr(
        runtime_layout_module,
        "_write_all_to_descriptor",
        fail_temp_write,
    )

    with pytest.raises(RuntimeMigrationError) as raised:
        migrate_legacy_cases_db(layout)

    assert str(raised.value) == "legacy_case_migration_cleanup_failed"
    assert str(layout.workspace) not in str(raised.value)
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
