from __future__ import annotations

import base64
import copy
import io
import json
import shutil
import sqlite3
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from svarog.sop.storage import CaseStore
from svarog.dependency_audit.models import DatabaseMetadata, VulnerabilitySnapshot
from svarog.runtime_layout import ProjectIdentity, RuntimeLayout
from svarog.webui import adapters, application
from svarog.webui.application import WorkbenchApplication
from svarog.webui.config import UiConfig


HOST = "127.0.0.1:8765"
NODE = shutil.which("node")


def _upload(name: str, payload: bytes) -> dict:
    return {"name": name, "data": base64.b64encode(payload).decode("ascii")}


def _case() -> dict:
    evidence = [{"id": "log:1", "line_number": 1, "event": {
        "timestamp": "2026-09-09T00:01:00Z", "source_ip": "192.0.2.8",
        "method": "GET", "path": "/.env"}, "rules": [{"category": "exposure"}]}]
    return {
        "case_id": "case-8", "created_at": "2026-09-09T00:00:00+00:00",
        "status": "awaiting_review", "review": None, "actions_executed": False,
        "alert": {"alert_id": "alert-8", "title": "Sensitive path", "severity": "high"},
        "steps": [
            {"number": index, "name": name, "status": "awaiting_review" if index == 7 else "completed"}
            for index, name in enumerate(
                ["告警接入", "Agent 初步分析", "查询日志", "IOC 提取", "ATT&CK 映射", "生成处置建议", "人工确认"],
                start=1,
            )
        ],
        "agent": {"mode": "local_rules", "summary": "需人工核对", "query_plan": "只读查询"},
        "query": {"matched": 1, "retained": 1, "invalid_lines": 0, "truncated": False},
        "warnings": ["结果需要人工确认"], "evidence": evidence,
        "iocs": [{"type": "ipv4", "value": "192.0.2.8", "role": "source",
                  "status": "unverified", "evidence_ids": ["log:1"]}],
        "attack_mappings": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application",
                             "status": "candidate", "rationale": "rule match", "evidence_ids": ["log:1"]}],
        "recommendations": [{"id": "REC-1", "text": "核对来源", "precondition": "人工确认",
                             "impact": "无自动处置", "evidence_ids": ["log:1"]}],
    }


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("env", "out"):
        (tmp_path / name).mkdir()
    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "vulns.db").write_bytes(b"db")
    calls: list[str] = []

    reports = {
        "web_analysis": {"schema_version": "0.1.0", "analysis_status": "completed_local",
            "summary": {"total_events": 1, "suspicious_events": 1, "input_issues": 0,
                        "severity_high": 1},
            "events": [{"event": {"timestamp": "2026-09-09T00:01:00Z",
                        "source_ip": "192.0.2.8", "method": "GET", "path": "/.env"},
                        "local_severity": "high", "conclusion": "suspicious",
                        "evidence": [{"rule_id": "WEB-1", "description": "sensitive path"}],
                        "recommendations": ["review source"]}],
            "warnings": ["review"], "actions_executed": False},
        "dependency_audit": {"schema_version": "0.1.0", "audit_status": "completed_with_findings",
            "summary": {"installed_packages": 2, "confirmed_findings": 1, "indeterminate_findings": 0},
            "installed_packages": [{"name": "demo", "version": "1", "version_valid": True}],
            "findings": [{"package_name": "demo", "installed_version": "1", "severity": "high",
                          "ghsa_id": "GHSA-demo", "fixed_version": "2", "summary": "demo"}],
            "indeterminate_findings": [], "warnings": [], "actions_executed": False},
        "project_audit": {"schema_version": "0.1.0", "audit_status": "completed_with_findings",
            "summary": {"installed_packages": 2, "locked_packages": 2,
                        "confirmed_environment_findings": 1, "potential_lock_findings": 1,
            "version_differences": 1},
            "installed_packages": [{"name": "demo", "version": "1", "version_valid": True}],
            "locked_packages": [{"name": "demo", "version": "2", "source_kind": "registry"}],
            "environment_findings": [], "environment_indeterminate_findings": [],
            "lock_findings": [], "lock_indeterminate_findings": [],
            "version_differences": [{"name": "demo", "installed_versions": ["1"],
                                      "locked_versions": ["2"], "status": "version_mismatch"}],
            "warnings": [], "actions_executed": False},
        "doctor": {"overall_status": "ready_with_warnings", "checks": [
            {"check_id": "python_tools", "title": "Python 与包管理工具", "status": "pass", "message": "ok"}]},
    }

    def adapter(kind):
        def run(*_args, **_kwargs):
            calls.append(kind)
            return {"kind": kind, "report": reports[kind]}
        return run

    monkeypatch.setattr(application, "analyze_web_log", adapter("web_analysis"))
    monkeypatch.setattr(application, "audit_python", adapter("dependency_audit"))
    monkeypatch.setattr(application, "audit_project", adapter("project_audit"))
    ProjectIdentity.load_or_create(RuntimeLayout.build(tmp_path))
    def persistent_audit(environment, *, lock_file, vuln_db, vuln_api, **_kwargs):
        current = application.audit_project if lock_file is not None else application.audit_python
        args = (environment, lock_file) if lock_file is not None else (environment,)
        return SimpleNamespace(result=current(*args, vuln_db=vuln_db, vuln_api=vuln_api),
            run_id="history-run", snapshot_id=1, reused=False, baseline_run_id=None,
            change_summary=SimpleNamespace(classification="initial_snapshot"))
    monkeypatch.setattr(application, "audit_with_persistent_history", persistent_audit)
    monkeypatch.setattr(application, "run_doctor_check", adapter("doctor"))

    def sop(_alert, _logs, *, case_db, **_kwargs):
        calls.append("sop_case")
        return {"kind": "sop_case", "report": _case()}

    monkeypatch.setattr(application, "run_sop_case", sop)
    app = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf")

    def request(method: str, target: str, data: dict | None = None):
        raw = json.dumps(data or {}).encode()
        headers = {"Host": HOST}
        if method == "POST":
            headers.update({"Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
                            "Content-Type": "application/json", "Content-Length": str(len(raw))})
        response = app.handle(method, target, headers, io.BytesIO(raw))
        if response.content_type.startswith("application/json"):
            return response, json.loads(response.body)
        return response, response.body

    request.app = app
    return request, calls


def test_sop_create_list_review_reopen_and_download(client):
    request, _ = client
    created = request("POST", "/api/sop", {"alert": _upload("alert.json", b"{}"),
        "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl", "log_host": None,
        "window_minutes": 15, "limit": 20, "agent_config": None})[1]["data"]
    assert created["kind"] == "sop_case" and created["actions_executed"] is False
    assert created["case"]["status"] == "awaiting_review"
    evidence_table = next(table for table in created["tables"] if table["id"] == "evidence")
    assert evidence_table["columns"][0]["type"] == "evidence_target"
    assert {table["id"] for table in created["tables"]} >= {
        "steps", "agent", "query", "evidence", "iocs", "attack", "recommendations"
    }
    assert {card["key"] for card in created["summary_cards"]} >= {"severity", "evidence", "iocs", "attack"}
    attack = next(table for table in created["tables"] if table["id"] == "attack")
    assert attack["rows"][0]["url"] == "https://attack.mitre.org/techniques/T1190/"
    assert request("GET", "/api/cases?status=awaiting_review&query=&limit=20&offset=0")[1]["data"]["total"] == 1
    reviewed = request("POST", "/api/cases/case-8/review", {
        "decision": "needs_investigation", "reviewer": "analyst", "note": "补充日志"})[1]["data"]
    assert reviewed["status"] == "needs_investigation" and reviewed["actions_executed"] is False
    reopened = request("GET", "/api/cases/case-8")[1]["data"]
    assert reopened["status"] == "needs_investigation" and reopened["downloads"]["json"]
    assert reopened["case"]["review"]["reviewer"] == "analyst"
    assert any(table["id"] == "review" for table in reopened["tables"])
    download = request("GET", reopened["downloads"]["json"])
    assert download[0].status == 200
    assert download[1]["actions_executed"] is False
    html = request("GET", reopened["downloads"]["html"])
    assert html[0].status == 200 and html[0].content_type.startswith("text/html")
    assert b"<script" not in html[0].body and b"<link" not in html[0].body and b" src=" not in html[0].body


def test_all_non_sop_workflows_have_fixed_schema_downloads_and_fail_safely(client, monkeypatch):
    request, calls = client
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    operations = [
        ("/api/analyze", {"logs": _upload("logs.jsonl", b"{}\n")}, "web_analysis"),
        ("/api/audit-python", common, "dependency_audit"),
        ("/api/audit-project", {**common, "lock_file": "uv.lock"}, "project_audit"),
        ("/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"}, "doctor"),
    ]
    for route, body, kind in operations:
        response, payload = request("POST", route, body)
        data = payload["data"]
        assert response.status == 200
        assert data["kind"] == kind and data["title"] and data["status"]
        assert isinstance(data["report"], dict)
        assert isinstance(data["summary_cards"], list) and isinstance(data["tables"], list)
        assert isinstance(data["warnings"], list) and data["actions_executed"] is False
        assert request("GET", data["downloads"]["json"])[0].status == 200

    table_ids = {
        item[2]: {table["id"] for table in request("POST", item[0], item[1])[1]["data"]["tables"]}
        for item in operations
    }
    assert table_ids["web_analysis"] >= {"events", "recommendations"}
    assert table_ids["dependency_audit"] >= {"installed_packages", "findings", "indeterminate_findings"}
    assert table_ids["project_audit"] >= {
        "installed_packages", "locked_packages", "version_differences",
        "environment_findings", "environment_indeterminate_findings",
        "lock_findings", "lock_indeterminate_findings",
    }

    before = len(calls)
    response, payload = request("POST", "/api/doctor", {**operations[-1][1], "command": "calc.exe"})
    assert response.status == 400 and len(calls) == before

    monkeypatch.setattr(application, "audit_python", lambda *_a, **_k: {"kind": "unknown", "report": {}})
    response, payload = request("POST", "/api/audit-python", common)
    assert response.status == 500 and payload["error"]["code"] == "invalid_result_schema"

    monkeypatch.setattr(application, "run_doctor_check", lambda *_a, **_k: {"kind": "doctor", "report": {}})
    response, payload = request("POST", "/api/doctor", operations[-1][1])
    assert response.status == 500 and payload["error"]["code"] == "invalid_result_schema"


def test_opening_cases_does_not_evict_non_sop_download(client):
    request, _ = client
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    audit = request("POST", "/api/audit-python", common)[1]["data"]
    request("POST", "/api/sop", {"alert": _upload("alert.json", b"{}"),
        "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl", "log_host": None,
        "window_minutes": 15, "limit": 20, "agent_config": None})
    for _ in range(25):
        assert request("GET", "/api/cases/case-8")[0].status == 200
    assert request("GET", audit["downloads"]["json"])[0].status == 200


def test_overview_exposes_case_summaries_recent_runs_and_volatile_notice(client):
    request, _ = client
    initial = request("GET", "/api/overview")[1]["data"]
    assert initial["doctor_status"] == "not_run" and "尚未" in initial["doctor_notice"]
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    request("POST", "/api/audit-python", common)
    request("POST", "/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"})
    data = request("GET", "/api/overview")[1]["data"]
    assert data["recent_runs"][0]["kind"] == "doctor"
    assert data["recent_runs"][1]["summary_cards"]
    assert data["doctor_status"] == "ready_with_warnings"
    assert data["run_history_volatile"] is True
    assert "重启" in data["run_history_notice"]


@pytest.mark.parametrize(("adapter", "route", "body"), [
    ("analyze_web_log", "/api/analyze", {"logs": _upload("x.jsonl", b"{}\n")}),
    ("audit_python", "/api/audit-python", {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}),
    ("audit_project", "/api/audit-project", {"environment": "env", "lock_file": "uv.lock", "vuln_db": "vulns.db", "vuln_api": None}),
    ("run_doctor_check", "/api/doctor", {"environment": "env", "lock_file": "uv.lock", "output_directory": "out", "vuln_db": "vulns.db", "vuln_api": None}),
])
def test_operation_failures_are_redacted(client, monkeypatch, adapter, route, body):
    request, _ = client
    monkeypatch.setattr(application, adapter, lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("secret-command")))
    response, payload = request("POST", route, body)
    assert response.status == 500 and payload["ok"] is False
    assert b"secret-command" not in response.body


def test_non_finite_adapter_result_is_schema_error(client, monkeypatch):
    request, _ = client
    result = {"kind": "dependency_audit", "report": {
        "audit_status": "completed_clean", "summary": {"installed_packages": float("nan"),
        "confirmed_findings": 0, "indeterminate_findings": 0}, "installed_packages": [],
        "findings": [], "indeterminate_findings": [], "warnings": [], "actions_executed": False}}
    monkeypatch.setattr(application, "audit_python", lambda *_a, **_k: result)
    response, payload = request("POST", "/api/audit-python", {
        "environment": "env", "vuln_db": "vulns.db", "vuln_api": None})
    assert response.status == 500 and payload["error"]["code"] == "invalid_result_schema"


def test_invalid_evidence_graph_is_rejected_before_case_persistence(client, monkeypatch):
    request, _ = client
    case = _case()
    case["evidence"].append({**case["evidence"][0]})
    case["iocs"][0]["evidence_ids"] = ["log:missing"]
    monkeypatch.setattr(application, "run_sop_case", lambda *_a, **_k: {
        "kind": "sop_case", "report": case})
    response, payload = request("POST", "/api/sop", {"alert": _upload("alert.json", b"{}"),
        "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl", "log_host": None,
        "window_minutes": 15, "limit": 20, "agent_config": None})
    assert response.status == 500 and payload["error"]["code"] == "invalid_result_schema"
    assert request("GET", "/api/cases?limit=20&offset=0")[1]["data"]["total"] == 0


@pytest.mark.parametrize("defect", ["empty_steps", "bad_created_at", "bad_step_number"])
def test_unreviewable_sop_case_is_rejected_before_persistence(client, monkeypatch, defect):
    request, _ = client
    case = copy.deepcopy(_case())
    if defect == "empty_steps":
        case["steps"] = []
    elif defect == "bad_created_at":
        case["created_at"] = "not-a-time"
    else:
        case["steps"][0]["number"] = "one"
    monkeypatch.setattr(application, "run_sop_case", lambda *_a, **_k: {
        "kind": "sop_case", "report": case})
    response, payload = request("POST", "/api/sop", {"alert": _upload("alert.json", b"{}"),
        "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl", "log_host": None,
        "window_minutes": 15, "limit": 20, "agent_config": None})
    assert response.status == 500 and payload["error"]["code"] == "invalid_result_schema"
    assert request("GET", "/api/cases?limit=20&offset=0")[1]["data"]["total"] == 0


def test_browser_uses_only_fixed_safe_renderers():
    root = Path(__file__).parents[2] / "src" / "svarog" / "webui" / "assets"
    js = (root / "app.js").read_text(encoding="utf-8")
    html = (root / "index.html").read_text(encoding="utf-8")
    assert "const RESULT_RENDERERS" in js and "unsupported_result_schema" in js
    assert "JSON.stringify(data.report || data" not in js
    assert "evidence_target" in js and 'rel", "noopener noreferrer"' in js
    assert "attack.mitre.org" in js and "data-recent-runs" in html
    assert 'section.setAttribute("data-technical-details", "")' in js
    assert 'target.closest("details")' in js
    assert 'event.preventDefault();' in js
    assert "if (!renderPresentation(body, data))" in js
    assert "if (!renderPresentation(body, data)) { selectedCaseId = null" in js
    assert 'showView("cases")' in js and "await openCase(data.case_id)" in js
    assert 'form.querySelectorAll(\'input[type="file"]\')' in js
    assert 'fields: {[input.name]' in js
    for line in js.splitlines():
        if "sessionStorage.setItem" in line:
            assert all(word not in line.lower() for word in ("upload", "token", "raw", "result", "model"))


def _browser_schema_results(cases: list[dict]) -> list[bool]:
    app_js = (Path(__file__).parents[2] / "src" / "svarog" / "webui" / "assets" / "app.js").read_text(
        encoding="utf-8"
    )
    encoded = base64.b64encode(json.dumps(cases, ensure_ascii=False).encode()).decode()
    harness = r'''
const inert = () => ({
  content: "csrf", value: "", checked: false, hidden: false, disabled: false,
  dataset: {}, classList: {contains: () => false, toggle: () => {}},
  setAttribute: () => {}, removeAttribute: () => {}, getAttribute: () => "",
  addEventListener: () => {}, append: () => {}, replaceChildren: () => {},
  focus: () => {}, scrollIntoView: () => {}, querySelector: () => inert(),
  querySelectorAll: () => [], elements: {namedItem: () => null},
});
globalThis.document = {body: inert(), querySelector: () => inert(), querySelectorAll: () => [],
  getElementById: () => inert(), createElement: () => inert(), createTextNode: () => inert()};
globalThis.window = {matchMedia: () => ({matches: false, addEventListener: () => {}}), addEventListener: () => {}};
globalThis.location = {hash: "", origin: "http://127.0.0.1:8765"};
globalThis.CSS = {escape: (value) => value};
globalThis.sessionStorage = {getItem: () => null, setItem: () => {}};
globalThis.fetch = () => new Promise(() => {});
globalThis.FileReader = function FileReader() {};
globalThis.btoa = () => "";
'''
    probe = (
        harness + app_js
        + f'\nconst schemaCases = JSON.parse(Buffer.from("{encoded}", "base64").toString("utf8"));'
        + '\nprocess.stdout.write(JSON.stringify(schemaCases.map(validatePresentationSchema)));'
    )
    completed = subprocess.run(
        [NODE], input=probe, check=True, capture_output=True, encoding="utf-8", timeout=10
    )
    return json.loads(completed.stdout)


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser behavior checks")
def test_browser_rejects_missing_or_forged_result_schema():
    valid = {
        "schema": "svarog.workbench.result.v1", "kind": "doctor",
        "title": "Doctor", "status": "ready", "actions_executed": False,
        "summary_cards": [
            {"key": "pass", "label": "通过", "value": 1},
            {"key": "warn", "label": "警告", "value": 0},
            {"key": "fail", "label": "失败", "value": 0},
        ],
        "warnings": [], "downloads": {"json": "/api/runs/run-1/download/json"},
        "tables": [{"id": "checks", "title": "检查项", "columns": [
            {"key": "title", "label": "检查", "type": "text"},
            {"key": "status", "label": "状态", "type": "text"},
            {"key": "message", "label": "说明", "type": "text"},
        ], "rows": [{"title": "Python", "status": "pass", "message": "ok"}]}],
    }
    cases = [
        valid,
        {key: value for key, value in valid.items() if key != "title"},
        {**valid, "tables": []},
        {**valid, "tables": [{**valid["tables"][0], "columns": [
            {"key": "title", "label": "检查", "type": "attack_link"},
            *valid["tables"][0]["columns"][1:],
        ]}]},
        {**valid, "actions_executed": True},
        {**valid, "summary_cards": []},
        {**valid, "summary_cards": [{"key": "forged", "label": "伪造", "value": 1}]},
        {**valid, "downloads": {**valid["downloads"], "html": "/api/runs/run-1/download/html"}},
    ]
    assert _browser_schema_results(cases) == [True, False, False, False, False, False, False, False]


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser behavior checks")
def test_all_workbench_results_pass_the_browser_schema(client):
    request, _ = client
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    calls = [
        ("/api/analyze", {"logs": _upload("events.jsonl", b"{}\n")}),
        ("/api/audit-python", common),
        ("/api/audit-project", {**common, "lock_file": "uv.lock"}),
        ("/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"}),
        ("/api/sop", {"alert": _upload("alert.json", b"{}"),
                      "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl",
                      "log_host": None, "window_minutes": 15, "limit": 20,
                      "agent_config": None}),
    ]
    results = [request("POST", route, body)[1]["data"] for route, body in calls]
    assert _browser_schema_results(results) == [True, True, True, True, True]


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser behavior checks")
def test_browser_rejects_sop_without_case_identity_or_review_state(client):
    request, _ = client
    response = request("POST", "/api/sop", {"alert": _upload("alert.json", b"{}"),
        "logs": _upload("logs.jsonl", b"{}\n"), "log_format": "jsonl", "log_host": None,
        "window_minutes": 15, "limit": 20, "agent_config": None})[1]["data"]
    without_id = {key: value for key, value in response.items() if key != "case_id"}
    without_review = {key: value for key, value in response.items() if key != "review"}
    assert _browser_schema_results([response, without_id, without_review]) == [True, False, False]


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser behavior checks")
def test_failed_upload_is_cleared_and_error_is_bound_to_the_field():
    app_js = (Path(__file__).parents[2] / "src" / "svarog" / "webui" / "assets" / "app.js").read_text(
        encoding="utf-8"
    )
    prefix = r'''
const inert = () => ({content: "csrf", value: "", checked: false, hidden: false, disabled: false,
  dataset: {}, classList: {contains: () => false, toggle: () => {}}, setAttribute: () => {},
  removeAttribute: () => {}, getAttribute: () => "", addEventListener: () => {}, append: () => {},
  replaceChildren: () => {}, focus: () => {}, scrollIntoView: () => {}, querySelector: () => inert(),
  querySelectorAll: () => [], elements: {namedItem: () => null}});
globalThis.document = {body: inert(), querySelector: () => inert(), querySelectorAll: () => [],
  getElementById: () => inert(), createElement: () => inert(), createTextNode: () => inert()};
globalThis.window = {matchMedia: () => ({matches: false, addEventListener: () => {}}), addEventListener: () => {}};
globalThis.location = {hash: "", origin: "http://127.0.0.1:8765"};
globalThis.CSS = {escape: (value) => value};
globalThis.sessionStorage = {getItem: () => null, setItem: () => {}};
globalThis.fetch = () => new Promise(() => {});
globalThis.FileReader = function FileReader() {};
globalThis.btoa = () => "";
'''
    probe = r'''
const state = {focused: false, invalid: false};
const upload = {name: "logs", value: "selected.jsonl",
  setAttribute: (name) => { if (name === "aria-invalid") state.invalid = true; },
  removeAttribute: () => {}, getAttribute: () => "logs-help logs-error",
  focus: () => { state.focused = true; }};
const secondUpload = {value: "alert.json", setAttribute: () => {}, removeAttribute: () => {}};
const button = {disabled: false}; const status = {textContent: ""}; const fieldError = {textContent: ""};
const form = {
  elements: {namedItem: () => upload},
  querySelector: (selector) => selector.includes("button") ? button
    : selector === ".form-status" ? status : fieldError,
  querySelectorAll: (selector) => selector === 'input[type="file"]' ? [upload, secondUpload]
    : selector === ".field-error" ? [fieldError] : [],
};
submitBusy(form, () => Promise.reject(new ApiError({message: "bad", fields: {logs: "文件错误"}})))
  .catch(() => process.stdout.write(JSON.stringify({first: upload.value, second: secondUpload.value,
    invalid: state.invalid, focused: state.focused, message: fieldError.textContent})));
'''
    completed = subprocess.run(
        [NODE], input=prefix + app_js + probe, check=True, capture_output=True,
        encoding="utf-8", timeout=10
    )
    assert json.loads(completed.stdout) == {
        "first": "", "second": "", "invalid": True, "focused": True, "message": "文件错误"
    }


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser behavior checks")
def test_duplicate_form_submit_sends_one_request_and_restores_button():
    app_js = (Path(__file__).parents[2] / "src" / "svarog" / "webui" / "assets" / "app.js").read_text(encoding="utf-8")
    harness = r'''
const inert = () => ({content: "csrf", value: "", checked: false, hidden: false, disabled: false,
  dataset: {}, classList: {contains: () => false, toggle: () => {}}, setAttribute: () => {},
  removeAttribute: () => {}, getAttribute: () => "", addEventListener: () => {},
  append: () => {}, replaceChildren: () => {}, focus: () => {}, scrollIntoView: () => {},
  querySelector: () => inert(), querySelectorAll: () => [], elements: {namedItem: () => null}});
globalThis.document = {body: inert(), querySelector: () => inert(), querySelectorAll: () => [],
  getElementById: () => inert(), createElement: () => inert(), createTextNode: () => inert()};
globalThis.window = {matchMedia: () => ({matches: false, addEventListener: () => {}}), addEventListener: () => {}};
globalThis.location = {hash: "", origin: "http://127.0.0.1:8765"};
globalThis.CSS = {escape: (value) => value};
globalThis.sessionStorage = {getItem: () => null, setItem: () => {}};
globalThis.fetch = () => new Promise(() => {});
globalThis.FileReader = function FileReader() {};
globalThis.btoa = () => "";
'''
    probe = r'''
const button = {disabled: false};
const status = {textContent: ""};
const form = {querySelector: (selector) => selector.includes("button") ? button : status,
  querySelectorAll: () => []};
let sends = 0, finish;
const work = () => { sends += 1; return new Promise((resolve) => { finish = resolve; }); };
const first = submitBusy(form, work);
const second = submitBusy(form, work);
finish("done");
Promise.all([first, second]).then((values) => process.stdout.write(JSON.stringify({
  sends, values, disabled: button.disabled, status: status.textContent,
})));
'''
    completed = subprocess.run([NODE], input=harness + app_js + probe, check=True,
                               capture_output=True, encoding="utf-8", timeout=10)
    assert json.loads(completed.stdout) == {
        "sends": 1, "values": ["done", "done"], "disabled": False, "status": "操作完成。",
    }


def test_real_workbench_routes_execute_only_doctor_fixed_version_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    environment = tmp_path / "env"
    metadata = environment / "Lib" / "site-packages" / "demo-1.0.dist-info"
    metadata.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("home = test\n", encoding="utf-8")
    (metadata / "METADATA").write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")
    (environment / "Scripts").mkdir()
    (environment / "Scripts" / "python.exe").write_bytes(b"")
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "demo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    (tmp_path / "out").mkdir()
    snapshot = VulnerabilitySnapshot(
        metadata=DatabaseMetadata(path="injected", size_bytes=0, sources=("test",),
                                  last_sync_at="2026-09-09T00:00:00+00:00", last_sync_status="ok"),
        advisories=(),
    )
    monkeypatch.setattr(adapters, "_remote_snapshot_loader", lambda _url, _token: snapshot)
    monkeypatch.setattr(adapters, "_doctor_tcp_connector", lambda _endpoint, _timeout: nullcontext())
    monkeypatch.setattr(application, "analyze_web_log", adapters.analyze_web_log)
    monkeypatch.setattr(application, "audit_python", adapters.audit_python)
    monkeypatch.setattr(application, "audit_project", adapters.audit_project)
    monkeypatch.setattr(application, "run_doctor_check", adapters.run_doctor_check)
    monkeypatch.setattr(application, "run_sop_case", adapters.run_sop_case)
    ProjectIdentity.load_or_create(RuntimeLayout.build(tmp_path))
    command_calls = []

    def capture_command(argv, **kwargs):
        command_calls.append((tuple(argv), kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("svarog.doctor.subprocess.run", capture_command)
    app = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf")

    def post(route: str, body: dict):
        raw = json.dumps(body).encode()
        return app.handle("POST", route, {"Host": HOST, "Origin": f"http://{HOST}",
            "X-Svarog-CSRF": "csrf", "Content-Type": "application/json",
            "Content-Length": str(len(raw))}, io.BytesIO(raw))

    common = {"environment": "env", "vuln_db": None, "vuln_api": "https://api.test:443"}
    web_event = {"timestamp": "2026-09-09T00:01:00Z", "source_ip": "192.0.2.1",
                 "method": "GET", "host": "demo.test", "path": "/", "status": 200}
    assert post("/api/analyze", {"logs": _upload(
        "events.jsonl", (json.dumps(web_event) + "\n").encode()
    )}).status == 200
    assert post("/api/audit-python", common).status == 200
    assert post("/api/audit-project", {**common, "lock_file": "uv.lock"}).status == 200
    with sqlite3.connect(RuntimeLayout.build(tmp_path).history_db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM run_diffs").fetchone()[0] == 2
    alert = {"alert_id": "a-1", "title": "demo", "timestamp": "2026-09-09T00:00:00Z",
             "source_ip": "192.0.2.1", "host": "demo.test"}
    log = {"timestamp": "2026-09-09T00:01:00Z", "source_ip": "192.0.2.1",
           "method": "GET", "host": "demo.test", "path": "/.env", "status": 403}
    assert post("/api/sop", {"alert": _upload("alert.json", json.dumps(alert).encode()),
        "logs": _upload("logs.jsonl", (json.dumps(log) + "\n").encode()), "log_format": "jsonl",
        "log_host": None, "window_minutes": 15, "limit": 20, "agent_config": None}).status == 200
    assert command_calls == []
    assert post("/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"}).status == 200
    assert [call[0] for call in command_calls] == [
        (str(environment / "Scripts" / "python.exe"), "--version"), ("uv", "--version")
    ]
    assert all(call[1]["shell"] is False for call in command_calls)


def test_doctor_status_survives_recent_run_cache_eviction(client):
    request, _ = client
    common = {"environment": "env", "vuln_db": "vulns.db", "vuln_api": None}
    request("POST", "/api/doctor", {**common, "lock_file": "uv.lock", "output_directory": "out"})
    for _ in range(10):
        request("POST", "/api/audit-python", common)
    overview = request("GET", "/api/overview")[1]["data"]
    assert len(overview["recent_runs"]) == 10
    assert overview["doctor_status"] == "ready_with_warnings"


def test_real_web_report_matches_workbench_schema(tmp_path: Path):
    sample = Path(__file__).parents[2] / "samples" / "nginx-attacks.jsonl"
    app = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf")
    body = {"logs": _upload("nginx-attacks.jsonl", sample.read_bytes())}
    raw = json.dumps(body).encode()
    response = app.handle("POST", "/api/analyze", {
        "Host": HOST, "Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
        "Content-Type": "application/json", "Content-Length": str(len(raw)),
    }, io.BytesIO(raw))
    payload = json.loads(response.body)["data"]
    assert response.status == 200 and payload["kind"] == "web_analysis"
    events = next(table for table in payload["tables"] if table["id"] == "events")
    assert events["rows"] and events["rows"][0]["rules"]
