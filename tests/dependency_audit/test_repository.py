from __future__ import annotations

import os
import signal
import sqlite3
import stat
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

import pytest

from svarog.dependency_audit import repository
from svarog.dependency_audit.models import AdvisorySeverity, AuditIssue
from svarog.dependency_audit.repository import (
    VulnerabilityDatabaseError,
    _cvss,
    _severity,
    load_vulnerability_snapshot,
)


@pytest.fixture
def real_posix_preflight() -> None:
    """Declare that a test intentionally exercises the production POSIX policy."""


@pytest.fixture(autouse=True)
def repository_preflight_policy(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if "real_posix_preflight" not in request.fixturenames:
        monkeypatch.setattr(repository, "_validate_posix_database_access", lambda _: None)


def _database(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
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
        INSERT INTO advisories VALUES (
            'GHSA-test-0001', 'CVE-2026-0001', 'published', 'demo issue',
            'must not be loaded', 'high', 8.1, 'vector',
            '2026-08-01', '2026-08-30', NULL, 'github_api',
            'must not be loaded', '2026-08-01', '2026-08-31'
        );
        INSERT INTO affected_packages VALUES (
            1, 'GHSA-test-0001', 'pip', 'Demo_Pkg', '< 2.0', NULL, '2.0'
        );
        INSERT INTO sync_meta VALUES ('last_sync_at', '2026-08-31T11:48:22Z');
        INSERT INTO sync_meta VALUES ('last_sync_status', 'ok');
        INSERT INTO sync_meta VALUES ('last_sync_message', 'completed');
        INSERT INTO sync_meta VALUES ('unrelated_secret', 'must not be loaded');
        """
    )
    connection.commit()
    connection.close()
    return path


def _update(path: Path, sql: str, parameters: tuple[object, ...]) -> None:
    connection = sqlite3.connect(path)
    connection.execute(sql, parameters)
    connection.commit()
    connection.close()


def _require_posix() -> None:
    if os.name != "posix":
        pytest.skip("requires real POSIX permission semantics")


@contextmanager
def _deadline(seconds: int = 20) -> Iterator[None]:
    def expired(_: int, __: object) -> None:
        raise TimeoutError("POSIX repository acceptance test timed out")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@contextmanager
def _readonly_permissions(directory: Path, files: tuple[Path, ...]) -> Iterator[None]:
    original_directory_mode = stat.S_IMODE(directory.stat().st_mode)
    original_file_modes = {
        path: stat.S_IMODE(path.stat().st_mode)
        for path in files
    }
    try:
        for path, mode in original_file_modes.items():
            path.chmod(mode & ~0o222)
        directory.chmod(original_directory_mode & ~0o222)
        protected = (directory,) + files
        if any(repository._effective_access(path, os.W_OK) for path in protected):
            pytest.skip("effective POSIX identity can still write read-only fixtures")
        if any(not repository._effective_access(path, os.R_OK) for path in files):
            pytest.skip("effective POSIX identity cannot read fixture files")
        yield
    finally:
        directory.chmod(original_directory_mode)
        for path, mode in original_file_modes.items():
            if path.exists():
                path.chmod(mode)


def _filesystem_state(
    directory: Path, files: tuple[Path, ...],
) -> tuple[tuple[str, ...], tuple[tuple[str, int, int, int, bytes], ...]]:
    entries = tuple(sorted(path.name for path in directory.iterdir()))
    states = tuple(
        (
            path.name,
            stat.S_IMODE(path.stat().st_mode),
            path.stat().st_size,
            path.stat().st_mtime_ns,
            path.read_bytes(),
        )
        for path in files
    )
    return entries, states


@pytest.fixture
def posix_readonly_wal_database(
    tmp_path: Path,
) -> Iterator[tuple[Path, sqlite3.Connection, tuple[Path, ...]]]:
    _require_posix()
    path = _database(tmp_path / "vulnerabilities.db")
    writer = sqlite3.connect(path, timeout=5.0)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO advisories SELECT ?, cve_id, state, summary, description, severity, "
            "cvss_score, cvss_vector, published_at, updated_at, withdrawn_at, source, raw_json, "
            "first_seen_at, last_synced_at FROM advisories WHERE ghsa_id = ?",
            ("GHSA-test-0002", "GHSA-test-0001"),
        )
        writer.execute(
            "INSERT INTO affected_packages VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (2, "GHSA-test-0002", "pip", "second", "< 2.0", "2.0"),
        )
        tracked = (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        assert all(item.is_file() for item in tracked)
        with _readonly_permissions(tmp_path, tracked):
            yield path, writer, tracked
    finally:
        if writer.in_transaction:
            writer.rollback()
        writer.close()


def test_repository_loads_only_pip_fields_from_read_only_snapshot(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    before = path.read_bytes()

    snapshot = load_vulnerability_snapshot(path)

    assert path.read_bytes() == before
    assert snapshot.metadata.last_sync_status == "ok"
    assert snapshot.advisories[0].normalized_package_name == "demo-pkg"
    assert snapshot.advisories[0].cvss_score == 8.1
    assert snapshot.advisories[0].summary == "demo issue"


def test_repository_never_reads_description_or_raw_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    real_connect = sqlite3.connect

    def guarded_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)

        def authorize(action: int, arg1: str | None, arg2: str | None, *_: object) -> int:
            if action == sqlite3.SQLITE_READ and arg2 in {"description", "raw_json"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize)
        return connection

    monkeypatch.setattr("svarog.dependency_audit.repository.sqlite3.connect", guarded_connect)

    snapshot = load_vulnerability_snapshot(path)

    assert len(snapshot.advisories) == 1


@pytest.mark.parametrize("table", ["advisories", "affected_packages", "sync_meta"])
def test_repository_rejects_missing_required_schema_column(tmp_path: Path, table: str) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    connection = sqlite3.connect(path)
    connection.execute(f"ALTER TABLE {table} RENAME TO old_{table}")
    connection.execute(f"CREATE TABLE {table} (placeholder TEXT)")
    connection.commit()
    connection.close()

    with pytest.raises(VulnerabilityDatabaseError, match="^incompatible_schema$"):
        load_vulnerability_snapshot(path)

    path.unlink()


def test_repository_uses_bound_ecosystem_parameter(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    _update(
        path,
        "INSERT INTO affected_packages VALUES (2, ?, ?, ?, ?, NULL, ?)",
        ("GHSA-test-0001", "npm", "ignored", "< 99", "99"),
    )

    snapshot = load_vulnerability_snapshot(path)

    assert [item.package_name for item in snapshot.advisories] == ["Demo_Pkg"]


def test_repository_bounds_untrusted_text_and_marks_invalid_score(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    _update(
        path,
        "UPDATE advisories SET cvss_score = ?, severity = ?, summary = ? WHERE ghsa_id = ?",
        ("not-a-score", "unexpected", "line\n" + "x" * 700, "GHSA-test-0001"),
    )

    snapshot = load_vulnerability_snapshot(path)
    affected = snapshot.advisories[0]

    assert affected.cvss_score is None
    assert affected.severity is AdvisorySeverity.UNKNOWN
    assert len(affected.summary) == 500
    assert snapshot.issues == (
        AuditIssue("invalid_cvss", "公告 CVSS 不是有效数值。", "demo-pkg"),
        AuditIssue("invalid_severity", "公告严重度不是支持的枚举值。", "demo-pkg"),
    )


@pytest.mark.parametrize("value", [True, False, "8.1", float("inf"), float("-inf"), 10.1, -0.1])
def test_cvss_rejects_non_numeric_non_finite_and_out_of_range_values(value: object) -> None:
    score, issue = _cvss(value)

    assert score is None
    assert issue is not None
    assert issue.code == "invalid_cvss"


def test_cvss_accepts_absent_and_boundary_values() -> None:
    assert _cvss(None) == (None, None)
    assert _cvss(0) == (0.0, None)
    assert _cvss(10.0) == (10.0, None)


def test_literal_unknown_severity_is_valid() -> None:
    assert _severity("unknown") == (AdvisorySeverity.UNKNOWN, None)


@pytest.mark.parametrize("value", [None, "", "   ", 0, b""])
def test_missing_or_empty_severity_is_invalid(value: object) -> None:
    severity, issue = _severity(value)

    assert severity is AdvisorySeverity.UNKNOWN
    assert issue == AuditIssue("invalid_severity", "公告严重度不是支持的枚举值。")


def test_literal_unknown_severity_allows_whitespace_and_case() -> None:
    assert _severity("  UNKNOWN ") == (AdvisorySeverity.UNKNOWN, None)


def test_repository_does_not_coerce_blob_unknown_into_valid_severity(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    _update(
        path,
        "UPDATE advisories SET severity=? WHERE ghsa_id='GHSA-test-0001'",
        (sqlite3.Binary(b"unknown"),),
    )

    snapshot = load_vulnerability_snapshot(path)

    assert snapshot.advisories[0].severity is AdvisorySeverity.UNKNOWN
    assert snapshot.issues == (
        AuditIssue("invalid_severity", "公告严重度不是支持的枚举值。", "demo-pkg"),
    )


def test_repository_retains_withdrawn_record_for_service_exclusion(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    _update(
        path,
        "UPDATE advisories SET state = ?, withdrawn_at = ? WHERE ghsa_id = ?",
        ("withdrawn", "2026-08-30T00:00:00Z", "GHSA-test-0001"),
    )

    snapshot = load_vulnerability_snapshot(path)

    assert snapshot.advisories[0].state == "withdrawn"
    assert snapshot.advisories[0].withdrawn_at == "2026-08-30T00:00:00Z"


def test_repository_bounds_all_loaded_text_and_metadata(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    long = "x" * 800
    connection = sqlite3.connect(path)
    connection.execute(
        """UPDATE advisories SET ghsa_id=?, cve_id=?, state=?, summary=?, source=?,
           updated_at=?, withdrawn_at=? WHERE ghsa_id='GHSA-test-0001'""",
        (long, long, long, long, long, long, long),
    )
    connection.execute(
        "UPDATE affected_packages SET ghsa_id=?, package_name=?, version_range=?, fixed_version=?",
        (long, long, long, long),
    )
    connection.execute("UPDATE sync_meta SET value=?", (long,))
    connection.commit()
    connection.close()

    snapshot = load_vulnerability_snapshot(path)
    advisory = snapshot.advisories[0]

    assert len(advisory.ghsa_id) == 64
    assert len(advisory.cve_id or "") == 64
    assert len(advisory.state) == 32
    assert len(advisory.summary) == 500
    assert len(advisory.source) == 64
    assert len(advisory.updated_at or "") == 64
    assert len(advisory.withdrawn_at or "") == 64
    assert len(advisory.package_name) == 256
    assert len(advisory.version_range) == 512
    assert len(advisory.fixed_version or "") == 128
    assert len(snapshot.metadata.last_sync_at or "") == 64
    assert len(snapshot.metadata.last_sync_status or "") == 32
    assert len(snapshot.metadata.last_sync_message or "") == 500


def test_repository_returns_stably_sorted_records_sources_and_issues(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO advisories VALUES (?, NULL, 'published', 'second', '', 'odd', ?, '', '', '', NULL, ?, '', '', '')",
        ("GHSA-test-0002", "bad", "alpha_source"),
    )
    connection.execute(
        "INSERT INTO affected_packages VALUES (2, ?, 'pip', ?, '<3', NULL, '3')",
        ("GHSA-test-0002", "Alpha.Pkg"),
    )
    connection.commit()
    connection.close()

    snapshot = load_vulnerability_snapshot(path)

    assert [item.package_name for item in snapshot.advisories] == ["Alpha.Pkg", "Demo_Pkg"]
    assert snapshot.metadata.sources == ("alpha_source", "github_api")
    assert [issue.subject for issue in snapshot.issues] == ["alpha-pkg", "alpha-pkg"]


def test_repository_uses_all_record_fields_for_deterministic_sorting(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    connection = sqlite3.connect(path)
    connection.executemany(
        "INSERT INTO affected_packages VALUES (?, ?, 'pip', 'same', '<4', NULL, ?)",
        (
            (2, "GHSA-test-0001", "9"),
            (3, "GHSA-test-0001", "3"),
        ),
    )
    connection.commit()
    connection.close()

    snapshot = load_vulnerability_snapshot(path)

    assert [
        item.fixed_version
        for item in snapshot.advisories
        if item.package_name == "same"
    ] == ["3", "9"]


def test_repository_rejects_more_than_the_bounded_advisory_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    _update(
        path,
        "INSERT INTO affected_packages VALUES (2, ?, 'pip', 'second', '<2', NULL, '2')",
        ("GHSA-test-0001",),
    )
    monkeypatch.setattr(repository, "MAX_PIP_ADVISORY_ROWS", 1)

    with pytest.raises(VulnerabilityDatabaseError, match="^advisory_limit_exceeded$"):
        load_vulnerability_snapshot(path)


def test_repository_bounds_large_text_and_blob_inside_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    huge_text = "x" * (2 * 1024 * 1024)
    huge_blob = sqlite3.Binary(b"y" * (2 * 1024 * 1024))
    _update(
        path,
        """UPDATE advisories SET summary=?, cve_id=?, cvss_score=?, severity=?
           WHERE ghsa_id='GHSA-test-0001'""",
        (huge_text, huge_blob, huge_blob, huge_blob),
    )
    _update(
        path,
        "UPDATE sync_meta SET value=? WHERE key='last_sync_message'",
        (huge_text,),
    )
    observed_lengths: list[int] = []
    original_bounded = repository._bounded

    def observed_bounded(value: object, limit: int) -> str | None:
        if isinstance(value, (str, bytes)):
            observed_lengths.append(len(value))
        return original_bounded(value, limit)

    monkeypatch.setattr(repository, "_bounded", observed_bounded)

    snapshot = load_vulnerability_snapshot(path)

    assert len(snapshot.advisories[0].summary) == 500
    assert max(observed_lengths) <= 512
    assert snapshot.advisories[0].cvss_score is None
    assert snapshot.advisories[0].severity is AdvisorySeverity.UNKNOWN
    assert len(snapshot.metadata.last_sync_message or "") == 500


def test_repository_rejects_duplicate_sync_metadata(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        DROP TABLE sync_meta;
        CREATE TABLE sync_meta (key TEXT, value TEXT);
        INSERT INTO sync_meta VALUES ('last_sync_status', 'ok');
        INSERT INTO sync_meta VALUES ('last_sync_status', 'duplicate');
        """
    )
    connection.commit()
    connection.close()

    with pytest.raises(VulnerabilityDatabaseError, match="^invalid_sync_metadata$"):
        load_vulnerability_snapshot(path)


def test_repository_reads_consistent_wal_snapshot_while_writer_is_active(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO advisories SELECT ?, cve_id, state, summary, description, severity, "
        "cvss_score, cvss_vector, published_at, updated_at, withdrawn_at, source, raw_json, "
        "first_seen_at, last_synced_at FROM advisories WHERE ghsa_id = ?",
        ("GHSA-test-0002", "GHSA-test-0001"),
    )
    writer.execute(
        "INSERT INTO affected_packages VALUES (?, ?, ?, ?, ?, NULL, ?)",
        (2, "GHSA-test-0002", "pip", "second", "< 2.0", "2.0"),
    )

    before_commit = load_vulnerability_snapshot(path)
    assert [item.ghsa_id for item in before_commit.advisories] == ["GHSA-test-0001"]

    writer.commit()
    writer.close()
    after_commit = load_vulnerability_snapshot(path)
    assert {item.ghsa_id for item in after_commit.advisories} == {
        "GHSA-test-0001",
        "GHSA-test-0002",
    }


def test_repository_does_not_change_database_or_wal_sidecars(tmp_path: Path) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "UPDATE sync_meta SET value='working' WHERE key='last_sync_status'"
    )
    tracked = (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
    assert all(item.exists() for item in tracked)

    def state() -> tuple[tuple[str, ...], tuple[tuple[int, int], ...], tuple[bytes, ...]]:
        entries = tuple(sorted(item.name for item in tmp_path.iterdir()))
        stats = tuple(
            (item.stat().st_size, item.stat().st_mtime_ns)
            for item in tracked
        )
        contents = tuple(item.read_bytes() for item in tracked[:2])
        return entries, stats, contents

    before = state()
    load_vulnerability_snapshot(path)
    after = state()

    writer.rollback()
    writer.close()
    assert after == before


def test_posix_preflight_rejects_missing_wal_sidecars(
    tmp_path: Path, real_posix_preflight: None,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    assert not Path(f"{path}-wal").exists()

    with pytest.raises(VulnerabilityDatabaseError, match="^database_sidecar_unavailable$"):
        repository._validate_posix_database_access(path)


@pytest.mark.parametrize("unsafe_target", ["directory", "database", "wal", "shm"])
def test_posix_preflight_rejects_effectively_writable_database_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_target: str,
    real_posix_preflight: None,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    wal.write_bytes(b"wal")
    shm.write_bytes(b"shm")
    targets = {"directory": path.parent, "database": path, "wal": wal, "shm": shm}

    def effective_access(candidate: Path, mode: int) -> bool:
        if mode == os.W_OK:
            return candidate == targets[unsafe_target]
        return True

    monkeypatch.setattr(repository, "_effective_access", effective_access)

    with pytest.raises(VulnerabilityDatabaseError, match="^database_permissions_unsafe$"):
        repository._validate_posix_database_access(path)


@pytest.mark.parametrize("sidecar_name", ["wal", "shm"])
def test_posix_preflight_rejects_unreadable_wal_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sidecar_name: str,
    real_posix_preflight: None,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    wal.write_bytes(b"wal")
    shm.write_bytes(b"shm")
    unreadable = {"wal": wal, "shm": shm}[sidecar_name]

    def effective_access(candidate: Path, mode: int) -> bool:
        if mode == os.W_OK:
            return False
        return candidate != unreadable

    monkeypatch.setattr(repository, "_effective_access", effective_access)

    with pytest.raises(VulnerabilityDatabaseError, match="^database_unavailable$"):
        repository._validate_posix_database_access(path)


def test_public_repository_reads_real_posix_readonly_wal_without_mutation(
    posix_readonly_wal_database: tuple[Path, sqlite3.Connection, tuple[Path, ...]],
    real_posix_preflight: None,
) -> None:
    path, writer, tracked = posix_readonly_wal_database

    before_uncommitted_read = _filesystem_state(path.parent, tracked)
    with _deadline():
        before_commit = load_vulnerability_snapshot(path)
    after_uncommitted_read = _filesystem_state(path.parent, tracked)

    assert [item.ghsa_id for item in before_commit.advisories] == ["GHSA-test-0001"]
    assert after_uncommitted_read == before_uncommitted_read

    with _deadline():
        writer.commit()
    before_committed_read = _filesystem_state(path.parent, tracked)
    with _deadline():
        after_commit = load_vulnerability_snapshot(path)
    after_committed_read = _filesystem_state(path.parent, tracked)

    assert {item.ghsa_id for item in after_commit.advisories} == {
        "GHSA-test-0001",
        "GHSA-test-0002",
    }
    assert after_committed_read == before_committed_read


@pytest.mark.parametrize("writable_target", ["directory", "database", "wal", "shm"])
def test_public_repository_fails_closed_when_any_posix_target_is_writable(
    posix_readonly_wal_database: tuple[Path, sqlite3.Connection, tuple[Path, ...]],
    writable_target: str,
    real_posix_preflight: None,
) -> None:
    path, _, tracked = posix_readonly_wal_database
    targets = {
        "directory": path.parent,
        "database": tracked[0],
        "wal": tracked[1],
        "shm": tracked[2],
    }
    target = targets[writable_target]
    target.chmod(stat.S_IMODE(target.stat().st_mode) | stat.S_IWUSR)
    if not repository._effective_access(target, os.W_OK):
        pytest.skip("fixture cannot grant effective write permission")

    with _deadline(), pytest.raises(
        VulnerabilityDatabaseError, match="^database_permissions_unsafe$"
    ):
        load_vulnerability_snapshot(path)


def test_public_repository_fails_closed_when_posix_wal_sidecar_is_missing(
    tmp_path: Path,
    real_posix_preflight: None,
) -> None:
    _require_posix()
    path = _database(tmp_path / "vulnerabilities.db")
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    wal.unlink(missing_ok=True)
    shm.unlink(missing_ok=True)

    with _readonly_permissions(tmp_path, (path,)):
        before = _filesystem_state(tmp_path, (path,))
        with _deadline(), pytest.raises(
            VulnerabilityDatabaseError, match="^database_sidecar_unavailable$"
        ):
            load_vulnerability_snapshot(path)
        after = _filesystem_state(tmp_path, (path,))

    assert after == before


def test_public_repository_reads_real_posix_readonly_non_wal_database(
    tmp_path: Path,
    real_posix_preflight: None,
) -> None:
    _require_posix()
    path = _database(tmp_path / "vulnerabilities.db")
    connection = sqlite3.connect(path)
    journal_mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
    connection.close()
    assert journal_mode == ("delete",)

    with _readonly_permissions(tmp_path, (path,)):
        before = _filesystem_state(tmp_path, (path,))
        with _deadline():
            snapshot = load_vulnerability_snapshot(path)
        after = _filesystem_state(tmp_path, (path,))

    assert [item.ghsa_id for item in snapshot.advisories] == ["GHSA-test-0001"]
    assert after == before


def test_repository_retries_lock_exactly_three_times(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    calls = 0

    def locked(_: Path) -> None:
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr("svarog.dependency_audit.repository._load_once", locked)
    monkeypatch.setattr("svarog.dependency_audit.repository._is_lock_error", lambda _: True)

    with pytest.raises(VulnerabilityDatabaseError, match="^database_locked$"):
        load_vulnerability_snapshot(path)

    assert calls == 3


def test_repository_does_not_retry_non_lock_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database(tmp_path / "vulnerabilities.db")
    calls = 0

    def failed(_: Path) -> None:
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("sensitive details")

    monkeypatch.setattr("svarog.dependency_audit.repository._load_once", failed)
    monkeypatch.setattr("svarog.dependency_audit.repository._is_lock_error", lambda _: False)

    with pytest.raises(VulnerabilityDatabaseError, match="^database_read_failed$") as raised:
        load_vulnerability_snapshot(path)

    assert calls == 1
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize("kind", ["missing", "directory", "broken_symlink"])
def test_repository_rejects_unavailable_non_file_paths(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "database"
    if kind == "directory":
        path.mkdir()
    elif kind == "broken_symlink":
        try:
            path.symlink_to(tmp_path / "absent")
        except OSError:
            pytest.skip("symlink creation is unavailable")

    with pytest.raises(VulnerabilityDatabaseError, match="^database_unavailable$"):
        load_vulnerability_snapshot(path)


def test_repository_rejects_corrupt_database_with_fixed_error(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"this is not sqlite")

    with pytest.raises(VulnerabilityDatabaseError, match="^database_read_failed$") as raised:
        load_vulnerability_snapshot(path)

    assert str(path) not in str(raised.value)
    path.unlink()
