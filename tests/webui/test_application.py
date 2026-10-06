from __future__ import annotations

import base64
import io
import json
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from svarog.sop.storage import CaseStore
from svarog.runtime_layout import ProjectIdentity, RuntimeLayout
from svarog.webui import application
from svarog.webui.application import WorkbenchApplication
from svarog.webui.config import UiConfig
from svarog.webui.history import RunCache


HOST = "127.0.0.1:8765"
JSON_MIME = "application/json; charset=utf-8"


def _valid_result(kind: str) -> dict:
    reports = {
        "web_analysis": {"analysis_status": "completed_local",
                         "summary": {"total_events": 0, "suspicious_events": 0, "input_issues": 0}, "events": [],
                         "warnings": [], "actions_executed": False},
        "dependency_audit": {"audit_status": "completed_clean",
                             "summary": {"installed_packages": 0, "confirmed_findings": 0,
                                         "indeterminate_findings": 0},
                             "installed_packages": [], "findings": [],
                             "indeterminate_findings": [], "warnings": [],
                             "actions_executed": False},
        "project_audit": {"audit_status": "completed_clean",
                          "summary": {"installed_packages": 0, "locked_packages": 0,
                                      "confirmed_environment_findings": 0,
                                      "potential_lock_findings": 0, "version_differences": 0},
                          "installed_packages": [], "locked_packages": [],
                          "version_differences": [], "environment_findings": [],
                          "environment_indeterminate_findings": [], "lock_findings": [],
                          "lock_indeterminate_findings": [], "warnings": [],
                          "actions_executed": False},
        "doctor": {"overall_status": "ready", "checks": [], "warnings": []},
    }
    return {"kind": kind, "report": reports[kind]}


def _case() -> dict:
    return {
        "case_id": "case-1", "created_at": "2026-09-09T00:00:00+00:00",
        "status": "awaiting_review", "review": None, "actions_executed": False,
        "alert": {"alert_id": "alert-1", "title": "Demo", "severity": "high"},
        "steps": [
            {"number": index, "name": name,
             "status": "awaiting_review" if index == 7 else "completed"}
            for index, name in enumerate([
                "告警接入", "Agent 初步分析", "查询日志", "IOC 提取",
                "ATT&CK 映射", "生成处置建议", "人工确认",
            ], start=1)
        ],
        "agent": {"mode": "rules", "summary": "未发现匹配日志", "query_plan": {}},
        "query": {"matched": 0, "retained": 0, "invalid_lines": 0, "truncated": False},
        "evidence": [], "iocs": [],
        "attack_mappings": [], "recommendations": [], "warnings": [],
    }


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "env").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "vulns.db").write_bytes(b"db")
    (tmp_path / "agent.toml").write_text("agent", encoding="utf-8")
    cfg = UiConfig.build("127.0.0.1", 8765, tmp_path)
    ProjectIdentity.load_or_create(RuntimeLayout.build(tmp_path))
    calls: list[tuple] = []

    def result(name):
        def run(*args, **kwargs):
            calls.append((name, args, kwargs, [p.exists() for p in args if isinstance(p, Path)]))
            value = _valid_result(name)
            value["report"]["warnings"] = ["<secret>"]
            return value
        return run

    monkeypatch.setattr(application, "analyze_web_log", result("web_analysis"))
    monkeypatch.setattr(application, "audit_python", result("dependency_audit"))
    monkeypatch.setattr(application, "audit_project", result("project_audit"))
    def persistent_audit(environment, *, lock_file, vuln_db, vuln_api, **_kwargs):
        adapter = application.audit_project if lock_file is not None else application.audit_python
        args = (environment, lock_file) if lock_file is not None else (environment,)
        report = adapter(*args, vuln_db=vuln_db, vuln_api=vuln_api)
        return SimpleNamespace(result=report, run_id="history-run", snapshot_id=1,
            reused=False, baseline_run_id=None,
            change_summary=SimpleNamespace(classification="initial_snapshot"))
    monkeypatch.setattr(application, "audit_with_persistent_history", persistent_audit)
    monkeypatch.setattr(application, "run_doctor_check", result("doctor"))

    def sop(alert, logs, *, case_db, **kwargs):
        calls.append(("sop", (alert, logs), kwargs, [alert.exists(), logs.exists()]))
        return {"kind": "sop_case", "report": _case()}

    monkeypatch.setattr(application, "run_sop_case", sop)
    assets = {"index.html": b"<h1>Svarog</h1>", "app.css": b"body{}", "app.js": b"const x=1;"}
    app = WorkbenchApplication(cfg, "csrf-secret", asset_loader=assets.__getitem__)

    class Client:
        def request(self, method, target, payload=None, headers=None, raw_body=None):
            raw = raw_body if raw_body is not None else json.dumps(payload or {}, ensure_ascii=False).encode()
            base = {"Host": HOST}
            if method == "POST":
                base.update({"Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf-secret",
                             "Content-Type": "application/json", "Content-Length": str(len(raw))})
            if headers:
                base.update(headers)
            return app.handle(method, target, base, io.BytesIO(raw))

    return Client(), cfg, calls


def payload(response):
    return json.loads(response.body)


def upload(name: str, data: bytes) -> dict:
    return {"name": name, "data": base64.b64encode(data).decode("ascii")}


def test_shell_assets_headers_and_host(harness):
    client, _, _ = harness
    for path, mime in (("/", "text/html; charset=utf-8"), ("/app.css", "text/css; charset=utf-8"),
                       ("/app.js", "text/javascript; charset=utf-8")):
        response = client.request("GET", path)
        assert response.status == 200 and response.content_type == mime
        assert response.headers["Content-Length"] == str(len(response.body))
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert client.request("GET", "/", headers={"Host": "evil.test"}).status == 400


def test_nested_v02_scripts_have_fixed_self_hosted_routes(tmp_path):
    app = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf")
    for path in ("/components/table.js", "/pages/history.js", "/pages/diff.js",
                 "/pages/sbom.js", "/pages/settings.js"):
        response = app.handle("GET", path, {"Host": HOST}, io.BytesIO())
        assert response.status == 200
        assert response.content_type == "text/javascript; charset=utf-8"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert app.handle("GET", "/pages/../../secret", {"Host": HOST}, io.BytesIO()).status == 400


def test_shell_injects_escaped_csrf_and_missing_assets_are_safe(tmp_path: Path):
    cfg = UiConfig.build("localhost", 8765, tmp_path)
    app = WorkbenchApplication(
        cfg, 'csrf\"<&', asset_loader=lambda name: b'<meta content="__SVAROG_CSRF_TOKEN__">'
    )
    response = app.handle("GET", "/", {"Host": "[::1]:8765"}, io.BytesIO())
    assert b'csrf&amp;quot;' not in response.body
    assert b'csrf&quot;&lt;&amp;' in response.body

    default_assets = WorkbenchApplication(cfg, "csrf")
    assert default_assets.handle("GET", "/", {"Host": "localhost:8765"}, io.BytesIO()).status == 200

    def missing_loader(_name: str) -> bytes:
        raise FileNotFoundError

    missing = WorkbenchApplication(cfg, "csrf", asset_loader=missing_loader)
    assert missing.handle("GET", "/", {"Host": "localhost:8765"}, io.BytesIO()).status == 404


def test_all_operation_routes_and_downloads(harness):
    client, _, calls = harness
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    requests = [
        ("/api/analyze", {"logs": upload("events.jsonl", b"{}\n")}),
        ("/api/audit-python", common),
        ("/api/audit-project", {**common, "lock_file": "uv.lock"}),
        ("/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"}),
    ]
    for route, body in requests:
        response = client.request("POST", route, body)
        data = payload(response)["data"]
        assert response.status == 200 and data["run_id"]
        download = client.request("GET", data["downloads"]["json"])
        assert download.status == 200 and download.content_type == JSON_MIME
        assert "attachment; filename=\"svarog-" in download.headers["Content-Disposition"]
    project = payload(client.request("POST", "/api/audit-project", {**common, "lock_file": "uv.lock"}))["data"]
    html = client.request("GET", project["downloads"]["html"])
    assert html.status == 200 and html.content_type == "text/html; charset=utf-8"
    assert b"&lt;secret&gt;" in html.body and b"<script" not in html.body
    assert calls


def test_sop_case_list_overview_get_and_review_conflict(harness):
    client, _, _ = harness
    created = payload(client.request("POST", "/api/sop", {
        "alert": upload("alert.json", b"{}"), "logs": upload("logs.jsonl", b"{}\n"),
        "log_format": "jsonl", "log_host": None, "window_minutes": 15,
        "limit": 20, "agent_config": None,
    }))["data"]
    assert created["case_id"] == "case-1"
    assert payload(client.request("GET", "/api/cases?status=awaiting_review&query=&limit=20&offset=0"))["data"]["total"] == 1
    assert payload(client.request("GET", "/api/cases/case-1"))["data"]["case_id"] == "case-1"
    overview = payload(client.request("GET", "/api/overview"))["data"]
    assert overview["total"] == 1 and overview["awaiting_review"] == 1
    review = {"decision": "approve", "reviewer": "analyst", "note": "checked"}
    assert payload(client.request("POST", "/api/cases/case-1/review", review))["data"]["status"] == "approved"
    assert client.request("POST", "/api/cases/case-1/review", review).status == 409


@pytest.mark.parametrize("target", ["/api//overview", "/api/%2e%2e/overview", "/api/overview#x", "/api/over\\view", "/api/%ZZ"])
def test_malformed_targets_are_rejected(harness, target):
    client, _, _ = harness
    assert client.request("GET", target).status == 400


@pytest.mark.parametrize("target", ["/api/cases?limit=1&limit=2", "/api/cases?unknown=x", "/api/cases?status[]=approved"])
def test_bad_queries_are_rejected(harness, target):
    client, _, _ = harness
    assert client.request("GET", target).status == 400


def test_post_security_and_json_validation_precede_adapter(harness):
    client, cfg, calls = harness
    before = len(calls)
    assert client.request("POST", "/api/analyze", {"logs": upload("x", b"x")}, headers={"Origin": "http://evil.test"}).status == 403
    assert client.request("POST", "/api/analyze", raw_body=b"{bad").status == 400
    duplicate = b'{"logs":{},"logs":{}}'
    assert client.request("POST", "/api/analyze", raw_body=duplicate).status == 400
    response = client.request("POST", "/api/analyze", raw_body=b"", headers={"Content-Length": str(cfg.max_request_bytes + 1)})
    assert response.status == 413 and len(calls) == before


def test_missing_csrf_and_invalid_api_urls_are_rejected(harness):
    client, _, _ = harness
    assert client.request("POST", "/api/doctor", {}, headers={"X-Svarog-CSRF": None}).status == 403
    base = {"environment": "env", "vuln_db": None}
    for value in ("javascript:alert(1)", "https://user:pass@example.test", "https://example.test/#"):
        assert client.request("POST", "/api/audit-python", {**base, "vuln_api": value}).status == 400


@pytest.mark.parametrize("route,body", [
    ("/api/analyze", {"logs": upload("x", b"x"), "extra": 1}),
    ("/api/audit-python", {"environment": "../env", "vuln_db": "vulns.db", "vuln_api": None}),
    ("/api/audit-project", {"environment": "env", "lock_file": "C:/x", "vuln_db": "vulns.db", "vuln_api": None}),
])
def test_unknown_fields_and_unsafe_paths_are_rejected(harness, route, body):
    client, _, _ = harness
    assert client.request("POST", route, body).status == 400


def test_bad_ids_stale_download_unknown_route_and_method(harness):
    client, _, _ = harness
    assert client.request("GET", "/api/cases/bad.id").status == 400
    missing = client.request("GET", "/api/cases/missing")
    assert missing.status == 404
    assert payload(missing)["error"]["code"] == "case_not_found"
    assert client.request("GET", "/api/runs/missing/download/json").status == 404
    assert client.request("GET", "/missing").status == 404
    assert client.request("DELETE", "/api/cases/case-1").status == 405


def test_adapter_exception_is_redacted(harness, monkeypatch):
    client, cfg, _ = harness
    secret = f"TOKEN {cfg.workspace}"
    monkeypatch.setattr(application, "audit_python", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(secret)))
    response = client.request("POST", "/api/audit-python", {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None})
    assert response.status == 500
    assert secret.encode() not in response.body and str(cfg.workspace).encode() not in response.body


def test_analyze_rejects_svarog_symlink_without_creating_outside_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    cfg = UiConfig.build("127.0.0.1", 8765, workspace)
    try:
        (workspace / ".svarog").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"当前环境不可创建目录符号链接: {exc}")

    called = False

    def adapter(path: Path) -> dict:
        nonlocal called
        called = True
        return {"kind": "web_analysis", "report": {}}

    monkeypatch.setattr(application, "analyze_web_log", adapter)
    app = WorkbenchApplication(cfg, "csrf", asset_loader=lambda name: b"")
    raw = json.dumps({"logs": upload("events.jsonl", b"{}\n")}).encode()
    response = app.handle("POST", "/api/analyze", {
        "Host": HOST, "Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
        "Content-Type": "application/json", "Content-Length": str(len(raw)),
    }, io.BytesIO(raw))

    assert response.status == 500
    assert not (outside / "tmp").exists()
    assert called is False


@pytest.mark.parametrize("kind", ["x\r\nInjected: y", "项目审计"])
def test_download_filename_uses_only_fixed_ascii_kind_slugs(tmp_path: Path, kind: str):
    cache = RunCache()
    run_id = cache.put(kind, {}, {"json": (JSON_MIME, b"{}")})
    cfg = UiConfig.build("127.0.0.1", 8765, tmp_path)
    app = WorkbenchApplication(cfg, "csrf", cache=cache, asset_loader=lambda name: b"")

    response = app.handle(
        "GET", f"/api/runs/{run_id}/download/json", {"Host": HOST}, io.BytesIO()
    )

    disposition = response.headers["Content-Disposition"]
    assert response.status == 200
    assert disposition.isascii()
    assert "\r" not in disposition and "\n" not in disposition
    assert "svarog-report-" in disposition


@pytest.mark.parametrize("character", ["\r", "\n", "\t", " ", "\u00a0", "\u200b"])
def test_target_rejects_unicode_controls_and_whitespace_before_urlsplit(harness, character):
    client, _, _ = harness
    response = client.request("GET", f"/api/over{character}view")
    assert response.status == 400
    assert payload(response)["error"]["code"] == "invalid_target"


def test_corrupt_existing_case_is_internal_error_not_not_found(tmp_path: Path):
    cfg = UiConfig.build("127.0.0.1", 8765, tmp_path)
    with CaseStore(cfg.case_db) as store:
        store.save(_case())
    with sqlite3.connect(cfg.case_db) as connection:
        connection.execute(
            "UPDATE cases SET result_json=? WHERE case_id=?", ("{broken", "case-1")
        )
    app = WorkbenchApplication(cfg, "csrf", asset_loader=lambda name: b"")

    response = app.handle("GET", "/api/cases/case-1", {"Host": HOST}, io.BytesIO())

    assert response.status == 500
    assert payload(response)["error"]["code"] == "operation_failed"


def test_incompatible_case_store_is_500_and_does_not_leak_details(tmp_path: Path):
    cfg = UiConfig.build("127.0.0.1", 8765, tmp_path)
    cfg.case_db.parent.mkdir(parents=True)
    with sqlite3.connect(cfg.case_db) as connection:
        connection.execute("CREATE TABLE unrelated(secret TEXT)")
    app = WorkbenchApplication(cfg, "csrf", asset_loader=lambda name: b"")

    response = app.handle("GET", "/api/overview", {"Host": HOST}, io.BytesIO())

    assert response.status == 500
    assert str(cfg.case_db).encode() not in response.body
    assert "不兼容".encode() not in response.body


def test_successful_adapter_cache_capacity_failure_is_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "env").mkdir()
    (tmp_path / "vulns.db").write_bytes(b"db")
    cfg = UiConfig.build("127.0.0.1", 8765, tmp_path)
    ProjectIdentity.load_or_create(RuntimeLayout.build(tmp_path))
    monkeypatch.setattr(
        application, "audit_python",
        lambda *args, **kwargs: _valid_result("dependency_audit"),
    )
    monkeypatch.setattr(application, "audit_with_persistent_history", lambda environment, **kwargs: SimpleNamespace(
        result=application.audit_python(environment, vuln_db=kwargs["vuln_db"], vuln_api=kwargs["vuln_api"]),
        run_id="history-run", snapshot_id=1, reused=False, baseline_run_id=None,
        change_summary=SimpleNamespace(classification="initial_snapshot")))
    app = WorkbenchApplication(
        cfg, "csrf", cache=RunCache(max_item_bytes=1), asset_loader=lambda name: b""
    )
    raw = json.dumps({
        "environment": "env", "vuln_db": "vulns.db", "vuln_api": None,
    }).encode()

    response = app.handle("POST", "/api/audit-python", {
        "Host": HOST, "Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
        "Content-Type": "application/json", "Content-Length": str(len(raw)),
    }, io.BytesIO(raw))

    assert response.status == 500
    assert payload(response)["error"]["code"] == "operation_failed"


def test_temporary_leaf_is_revalidated_before_upload_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    cfg = UiConfig.build("127.0.0.1", 8765, workspace)
    called = False

    def adapter(path: Path) -> dict:
        nonlocal called
        called = True
        return {"kind": "web_analysis", "report": {}}

    monkeypatch.setattr(application, "analyze_web_log", adapter)
    monkeypatch.setattr(
        application.tempfile, "TemporaryDirectory",
        lambda **kwargs: nullcontext(str(outside)),
    )
    app = WorkbenchApplication(cfg, "csrf", asset_loader=lambda name: b"")
    raw = json.dumps({"logs": upload("events.jsonl", b"{}\n")}).encode()

    response = app.handle("POST", "/api/analyze", {
        "Host": HOST, "Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
        "Content-Type": "application/json", "Content-Length": str(len(raw)),
    }, io.BytesIO(raw))

    assert response.status == 500
    assert called is False
    assert list(outside.iterdir()) == []
