"""Scoped persistent audit history over the local Web API."""

import io
import json
from pathlib import Path

import pytest

from svarog.audit_history.database import DatabaseManager
from svarog.audit_diff.service import DiffService
from svarog.audit_history.repository import HistoryRepository, PackageRow, SnapshotInput
from svarog.runtime_layout import ProjectIdentity, RuntimeLayout
from svarog.webui.application import WorkbenchApplication
from svarog.webui.config import UiConfig


HOST = "127.0.0.1:8765"
SCHEMA = "svarog-project-audit/1"
RUN = "00000000-0000-4000-8000-000000000001"


def _request(app, method, target, body=None):
    raw = json.dumps(body or {}).encode()
    headers = {"Host": HOST}
    if method == "POST":
        headers.update({"Origin": f"http://{HOST}", "X-Svarog-CSRF": "token",
                        "Content-Type": "application/json", "Content-Length": str(len(raw))})
    response = app.handle(method, target, headers, io.BytesIO(raw))
    return response, json.loads(response.body) if "json" in response.content_type else None


@pytest.fixture
def history_app(tmp_path: Path):
    layout = RuntimeLayout.build(tmp_path)
    identity = ProjectIdentity.load_or_create(layout)
    with DatabaseManager.open(layout.history_db) as database:
        repository = HistoryRepository(database.connection)
        package = PackageRow("lock", "demo", "demo", "1.0", True, "registry", None,
                             "lock:demo:1.0", None, "unverified")
        saved = repository.save_run(SnapshotInput(
            project_id=identity.project_id, display_name=identity.display_name,
            audit_kind="python_project", started_at="2026-09-28T00:00:00Z",
            completed_at="2026-09-28T00:00:01Z", python_version="3.12.7",
            environment_hash="1" * 64, semantic_lock_hash="2" * 64,
            knowledge_content_hash="3" * 64, knowledge_metadata_hash="4" * 64,
            evaluation_context_hash="5" * 64, policy_hash="6" * 64,
            analysis_contract_version="analysis/1", composite_hash="7" * 64,
            audit_status="completed_clean", result_schema_version=SCHEMA,
            result={"schema_version": SCHEMA, "audit_status": "completed_clean",
                    "locked_packages": [{"name": "demo", "normalized_name": "demo",
                                         "version": "1.0", "version_valid": True,
                                         "source_kind": "registry", "source_identity": None,
                                         "dependencies": []}]},
            lock_package_count=1, packages=(package,),
        ), run_id=RUN)
        DiffService(repository).compare_run(RUN)
    config = UiConfig.build("127.0.0.1", 8765, tmp_path)
    return WorkbenchApplication(config, "token"), identity.project_id, saved.snapshot_id


def test_history_list_and_snapshot_detail_are_scoped_and_bounded(history_app):
    app, project_id, snapshot_id = history_app
    response, data = _request(app, "GET", "/api/audit-history?limit=20&offset=0")
    assert response.status == 200, data
    assert data["data"]["project_id"] == project_id
    assert data["data"]["total_count"] == 1
    assert data["data"]["items"][0]["snapshot_id"] == snapshot_id
    assert data["data"]["items"][0]["classification"] == "initial_snapshot"
    detail, detail_data = _request(app, "GET", f"/api/audit-history/snapshots/{snapshot_id}")
    assert detail.status == 200
    assert detail_data["data"]["summary"]["snapshot_id"] == snapshot_id
    assert detail_data["data"]["packages"]["items"][0]["normalized_name"] == "demo"
    assert "result_json_zlib" not in detail.body.decode()
    for target in ("/api/audit-history?limit=101", "/api/audit-history?limit=2&limit=3"):
        assert _request(app, "GET", target)[0].status == 400
    assert _request(app, "GET", "/api/audit-history/snapshots/not-a-number")[0].status == 400
    assert _request(app, "GET", "/api/audit-history/snapshots/999999")[0].status == 404


def test_history_routes_enforce_methods_and_identity(tmp_path, history_app):
    app, _, _ = history_app
    assert _request(app, "POST", "/api/audit-history")[0].status == 405
    blank_dir = tmp_path / "blank"
    blank_dir.mkdir()
    blank = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, blank_dir), "token")
    assert _request(blank, "GET", "/api/audit-history")[0].status in (404, 409)


def test_history_filters_status_time_and_reuse(history_app):
    app, _, _ = history_app
    matching, data = _request(app, "GET", "/api/audit-history?run_status=completed_computed&reused=0&completed_from=2026-09-28T00%3A00%3A00Z&completed_to=2026-09-28T23%3A59%3A59Z")
    assert matching.status == 200
    assert data["data"]["total_count"] == 1
    nonmatching, data = _request(app, "GET", "/api/audit-history?run_status=failed")
    assert nonmatching.status == 200
    assert data["data"]["total_count"] == 0
    for query in ("run_status=invalid", "reused=yes", "completed_from=2026-09-28",
                  "completed_from=2026-09-29T00%3A00%3A00Z&completed_to=2026-09-28T00%3A00%3A00Z"):
        assert _request(app, "GET", "/api/audit-history?" + query)[0].status == 400


def test_audit_failure_returns_stable_code_without_internal_detail(history_app, tmp_path, monkeypatch):
    from svarog.audit_history.service import HistoryServiceError
    from svarog.webui import application

    app, _, _ = history_app
    (tmp_path / "env").mkdir()
    (tmp_path / "vulns.db").write_bytes(b"db")
    def fail(*args, **kwargs):
        raise HistoryServiceError("history_hash_failed")
    monkeypatch.setattr(application, "audit_with_persistent_history", fail)
    response, data = _request(app, "POST", "/api/audit-python", {
        "environment": "env", "vuln_db": "vulns.db", "vuln_api": None,
    })
    assert response.status == 500
    assert data["error"]["code"] == "history_hash_failed"
    assert str(tmp_path).encode() not in response.body


def test_project_audit_uses_server_derived_history_store(history_app, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from svarog.webui import application
    from test_application import _valid_result

    app, project_id, _ = history_app
    (tmp_path / "env").mkdir()
    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "vulns.db").write_bytes(b"db")
    calls = []

    def audit(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(
            result=_valid_result("project_audit"),
            run_id="history-run", snapshot_id=22, reused=False,
            baseline_run_id=None,
            change_summary=SimpleNamespace(classification="initial_snapshot"),
            cleanup=SimpleNamespace(warning=False),
        )

    monkeypatch.setattr(application, "audit_with_persistent_history", audit, raising=False)
    response, data = _request(app, "POST", "/api/audit-project", {
        "environment": "env", "lock_file": "uv.lock",
        "vuln_db": "vulns.db", "vuln_api": None,
    })
    assert response.status == 200, data
    assert data["data"]["history"]["snapshot_id"] == 22
    assert data["data"]["history"]["classification"] == "initial_snapshot"
    assert calls[0][1]["project_id"] == project_id
    assert calls[0][1]["history_db"] == RuntimeLayout.build(tmp_path).history_db
