# Svarog Local Workbench UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a light, localhost-only Web workbench that exposes all current Svarog analysis, audit, Doctor, SOP history, report download, and human-review workflows without changing their security conclusions or executing remediation.

**Architecture:** A new `svarog.webui` package uses Python's standard `http.server` and packaged HTML/CSS/JavaScript, with a narrow adapter layer over existing services. The browser sends bounded JSON requests; uploaded files are base64-decoded into a workspace-contained temporary directory, while Python environments, lock files, and vulnerability databases are resolved through a workspace path guard. SOP cases persist in the dedicated SQLite store; other run results live in a bounded in-memory cache.

**Tech Stack:** Python 3.11+ standard library, existing Svarog services and SQLite, semantic HTML, CSS custom properties, vanilla JavaScript, pytest.

---

## File map

- Create `src/svarog/webui/__init__.py`: package marker and public `serve` export.
- Create `src/svarog/webui/config.py`: loopback-only configuration and workspace path policy.
- Create `src/svarog/webui/security.py`: request limits, host/origin/CSRF checks, upload decoding, response headers, and safe errors.
- Create `src/svarog/webui/adapters.py`: calls existing analyzer, dependency audit, project audit, Doctor, and SOP functions.
- Create `src/svarog/webui/history.py`: bounded in-memory run cache and SOP case-list DTOs.
- Create `src/svarog/webui/application.py`: fixed route table and JSON/download request handling.
- Create `src/svarog/webui/server.py`: `ThreadingHTTPServer` lifecycle and optional browser opening.
- Create `src/svarog/webui/assets/index.html`: accessible shell, navigation, forms, status regions, and result containers.
- Create `src/svarog/webui/assets/app.css`: light Svarog design system and responsive layout.
- Create `src/svarog/webui/assets/app.js`: navigation, safe DOM rendering, requests, filters, downloads, and review UI.
- Modify `src/svarog/sop/storage.py`: schema v2 migration plus paginated case summaries.
- Modify `src/svarog/cli.py`: register and run `svarog ui`.
- Modify `pyproject.toml`: include Web assets in wheels.
- Create `tests/webui/`: isolated tests for each module and HTTP-level integration tests.
- Create `docs/UI使用说明.md`: Windows VM installation, startup, each feature test, and stop procedure.
- Modify `README.md`: short UI entry point and link to the full guide.

### Task 1: Loopback configuration and workspace path guard

**Files:**
- Create: `src/svarog/webui/__init__.py`
- Create: `src/svarog/webui/config.py`
- Test: `tests/webui/test_config.py`

- [ ] **Step 1: Write failing configuration tests**

```python
from pathlib import Path
import pytest

from svarog.webui.config import UiConfig, resolve_workspace_path


def test_config_accepts_only_loopback(tmp_path):
    config = UiConfig.build("127.0.0.1", 8765, tmp_path, None)
    assert config.workspace == tmp_path.resolve()
    assert config.case_db == tmp_path.resolve() / ".svarog" / "cases.sqlite3"
    for host in ("0.0.0.0", "192.168.1.2", "example.com"):
        with pytest.raises(ValueError, match="回环"):
            UiConfig.build(host, 8765, tmp_path, None)


def test_workspace_path_cannot_escape(tmp_path):
    inside = tmp_path / "project" / "uv.lock"
    inside.parent.mkdir()
    inside.write_text("version = 1", encoding="utf-8")
    assert resolve_workspace_path(tmp_path, "project/uv.lock", kind="file") == inside.resolve()
    with pytest.raises(ValueError, match="工作区"):
        resolve_workspace_path(tmp_path, "../secret.txt", kind="file")
    with pytest.raises(ValueError, match="相对路径"):
        resolve_workspace_path(tmp_path, str(inside.resolve()), kind="file")
```

- [ ] **Step 2: Run the tests and verify the missing-module failure**

Run: `python -m pytest tests/webui/test_config.py -v -p no:cacheprovider`

Expected: collection fails with `ModuleNotFoundError: No module named 'svarog.webui'`.

- [ ] **Step 3: Implement immutable configuration and fail-closed path resolution**

```python
@dataclass(frozen=True, slots=True)
class UiConfig:
    host: str
    port: int
    workspace: Path
    case_db: Path
    max_request_bytes: int = 14 * 1024 * 1024

    @classmethod
    def build(cls, host, port, workspace, case_db):
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("UI 第一版只允许绑定回环地址")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port 必须为 1..65535")
        root = Path(workspace).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace 必须是目录")
        database = Path(case_db).resolve(strict=False) if case_db else root / ".svarog" / "cases.sqlite3"
        if database != root and root not in database.parents:
            raise ValueError("案件库必须位于工作区内")
        return cls(host, port, root, database)


def resolve_workspace_path(root: Path, value: str, *, kind: str) -> Path:
    relative = Path(value)
    if relative.is_absolute():
        raise ValueError("网页路径必须是相对于工作区的相对路径")
    candidate = (root / relative).resolve(strict=True)
    if candidate != root and root not in candidate.parents:
        raise ValueError("路径超出工作区")
    if kind == "file" and not candidate.is_file():
        raise ValueError("目标不是普通文件")
    if kind == "directory" and not candidate.is_dir():
        raise ValueError("目标不是目录")
    return candidate
```

Also reject a `case_db` that aliases the workspace directory, resolves through a symlink outside the workspace, or has a name ending in `-wal`, `-shm`, or `-journal`.

- [ ] **Step 4: Add Windows/Linux symlink and case-database boundary tests, then run the module tests**

Run: `python -m pytest tests/webui/test_config.py -v -p no:cacheprovider`

Expected: all configuration tests pass; symlink tests may skip only when the host cannot create symlinks.

- [ ] **Step 5: Commit this task**

```powershell
git add src/svarog/webui/__init__.py src/svarog/webui/config.py tests/webui/test_config.py
git commit -m "feat: add local UI workspace policy"
```

### Task 2: HTTP security primitives and bounded uploads

**Files:**
- Create: `src/svarog/webui/security.py`
- Test: `tests/webui/test_security.py`

- [ ] **Step 1: Write failing tests for Host, Origin, CSRF, body limits, and upload decoding**

```python
import base64
import pytest

from svarog.webui.security import RequestRejected, decode_upload, validate_mutation


def test_mutation_requires_same_origin_and_token():
    validate_mutation(
        host="127.0.0.1:8765",
        origin="http://127.0.0.1:8765",
        csrf_header="abc123",
        expected_csrf="abc123",
        allowed_hosts={"127.0.0.1:8765", "localhost:8765"},
    )
    with pytest.raises(RequestRejected):
        validate_mutation("evil.test", "http://evil.test", "abc123", "abc123", {"127.0.0.1:8765"})
    with pytest.raises(RequestRejected):
        validate_mutation("127.0.0.1:8765", "http://127.0.0.1:8765", "wrong", "abc123", {"127.0.0.1:8765"})


def test_upload_uses_generated_name_and_enforces_decoded_limit(tmp_path):
    encoded = base64.b64encode(b"safe data").decode("ascii")
    path = decode_upload(tmp_path, {"name": "../../escape.json", "data": encoded}, 64, ".json")
    assert path.parent == tmp_path
    assert path.name != "escape.json"
    assert path.read_bytes() == b"safe data"
    with pytest.raises(RequestRejected, match="过大"):
        decode_upload(tmp_path, {"name": "x.json", "data": base64.b64encode(b"x" * 65).decode()}, 64, ".json")
```

- [ ] **Step 2: Run the tests and verify they fail because the module is absent**

Run: `python -m pytest tests/webui/test_security.py -v -p no:cacheprovider`

Expected: import or symbol failure for `svarog.webui.security`.

- [ ] **Step 3: Implement the security contract**

Implement:

```python
class RequestRejected(ValueError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}
```

`read_json_body()` must require `application/json`, require a numeric `Content-Length`, reject negative/chunked/oversize bodies before reading, read exactly the declared count, reject trailing/short data, decode UTF-8, reject duplicate JSON keys and non-finite numbers, and require a JSON object. `decode_upload()` must validate the original display name as text only, require strict Base64, estimate decoded size before allocation, write with mode `0o600` to a caller-owned temporary directory, and use a generated UUID filename with a server-selected suffix.

- [ ] **Step 4: Add header-injection, duplicate-key, malformed Base64, exact-limit, short-read, control-character, and cleanup tests**

Run: `python -m pytest tests/webui/test_security.py -v -p no:cacheprovider`

Expected: all security tests pass without network access.

- [ ] **Step 5: Commit this task**

```powershell
git add src/svarog/webui/security.py tests/webui/test_security.py
git commit -m "feat: enforce local UI request boundaries"
```

### Task 3: SOP database v2 migration and paginated history

**Files:**
- Modify: `src/svarog/sop/storage.py`
- Create: `tests/webui/test_history.py`

- [ ] **Step 1: Write a v1-to-v2 migration test before changing the schema**

```python
def test_v1_store_migrates_and_lists_without_losing_review(tmp_path, sample_case):
    db = tmp_path / "cases.sqlite3"
    create_v1_database(db, sample_case, decision="approve")
    with CaseStore(db) as store:
        page = store.list_cases(status="approved", query="demo", limit=20, offset=0)
        loaded = store.get(sample_case["case_id"])
    assert page["total"] == 1
    assert page["items"][0]["case_id"] == sample_case["case_id"]
    assert loaded["review"]["decision"] == "approve"
    assert read_user_version(db) == 2
```

The fixture must construct the exact current v1 `cases` and `reviews` DDL and application ID, not call the new initializer.

- [ ] **Step 2: Run the migration test and confirm v1 is rejected by the current implementation**

Run: `python -m pytest tests/webui/test_history.py::test_v1_store_migrates_and_lists_without_losing_review -v -p no:cacheprovider`

Expected: FAIL because current `SCHEMA_VERSION` is 1 and no `list_cases` method exists.

- [ ] **Step 3: Implement schema version 2 and transactional migration**

Schema v2 adds `alert_id TEXT NOT NULL`, `title TEXT NOT NULL`, `severity TEXT NOT NULL` to `cases`, backfills each row from bounded `result_json`, and creates:

```sql
CREATE INDEX cases_created_at_idx ON cases(created_at DESC, case_id);
CREATE INDEX cases_alert_id_idx ON cases(alert_id);
```

Migration must run under `BEGIN IMMEDIATE`, leave `PRAGMA application_id` unchanged, set `user_version=2` only after all rows backfill, roll back on invalid/oversize JSON, and remain safe on close/reopen. Fresh databases are created directly as v2. `save()` writes summary columns and JSON in one statement.

- [ ] **Step 4: Add a fixed-query paginated listing API**

```python
def list_cases(self, *, status: str | None, query: str, limit: int, offset: int) -> dict:
    """Return bounded summaries only; never deserialize result_json for list views."""
```

Allowed statuses are `awaiting_review`, `approved`, `rejected`, and `needs_investigation`. Search uses an escaped literal `LIKE` match over `case_id`, `alert_id`, and `title`; limit is 1..100 and offset is 0..100000. The SQL uses fixed ordering `created_at DESC, case_id ASC`, parameters only, a `LEFT JOIN reviews`, and maps review decisions to display status.

- [ ] **Step 5: Test rollback, fresh v2, paging, literal `%/_`, status filters, concurrent open, and existing SOP behavior**

Run: `python -m pytest tests/webui/test_history.py tests/sop -v -p no:cacheprovider`

Expected: all tests pass; current SOP save/get/review behavior remains unchanged.

- [ ] **Step 6: Commit this task**

```powershell
git add src/svarog/sop/storage.py tests/webui/test_history.py
git commit -m "feat: add paginated SOP case history"
```

### Task 4: Business adapters and bounded run cache

**Files:**
- Create: `src/svarog/webui/adapters.py`
- Create: `src/svarog/webui/history.py`
- Test: `tests/webui/test_adapters.py`
- Test: `tests/webui/test_run_cache.py`

- [ ] **Step 1: Write failing adapter tests using real fixtures and injected repositories**

```python
def test_web_analysis_adapter_returns_json_shape(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text('{"timestamp":"2026-09-08T10:00:00Z","source_ip":"192.0.2.1","method":"GET","host":"demo.example","path":"/.env"}\n', encoding="utf-8")
    result = analyze_web_log(source)
    assert result["kind"] == "web_analysis"
    assert result["report"]["summary"]["suspicious_events"] == 1
    assert result["report"]["actions_executed"] is False


def test_dependency_adapter_requires_exactly_one_source(environment_fixture, snapshot_fixture):
    with pytest.raises(ValueError, match="一个漏洞来源"):
        audit_python(environment_fixture, vuln_db=None, vuln_api=None)
```

Add analogous tests for `audit_project`, `run_doctor_check`, and `run_sop_case`. Remote repository loaders and command/network probes must be injectable so tests never use the network or launch arbitrary processes.

- [ ] **Step 2: Run the adapter tests and confirm missing symbols**

Run: `python -m pytest tests/webui/test_adapters.py tests/webui/test_run_cache.py -v -p no:cacheprovider`

Expected: failures for missing adapters and `RunCache`.

- [ ] **Step 3: Implement adapters as orchestration only**

Define five public functions with these exact signatures and return a JSON-compatible dictionary from each:

- `analyze_web_log(path: Path) -> dict`
- `audit_python(environment: Path, *, vuln_db: Path | None, vuln_api: str | None, token: str | None = None) -> dict`
- `audit_project(environment: Path, lock_file: Path, *, vuln_db: Path | None, vuln_api: str | None, token: str | None = None) -> dict`
- `run_doctor_check(environment: Path, lock_file: Path, output_directory: Path, *, vuln_db: Path | None, vuln_api: str | None) -> dict`
- `run_sop_case(alert: Path, logs: Path, *, case_db: Path, log_format: str, log_host: str | None, window_minutes: int, limit: int, agent_config: Path | None) -> dict`

Serialize existing immutable reports by calling their authoritative JSON renderers and `json.loads`; do not reconstruct vulnerability conclusions. For the Doctor dataclasses, add one local dataclass/enum serializer. Remote vulnerability tokens default to `SVAROG_VULN_API_TOKEN`; model keys remain inside `load_advisor` and never enter result objects.

- [ ] **Step 4: Implement a bounded run cache**

`RunCache` has constructor `RunCache(max_items: int = 20, max_item_bytes: int = 16 * 1024 * 1024)`, method `put(kind: str, result: dict, downloads: dict[str, tuple[str, bytes]]) -> str`, and method `get(run_id: str) -> RunRecord`. `RunRecord` is a frozen dataclass containing `run_id`, `kind`, `created_at`, `result`, and the fixed download mapping.

Use an `OrderedDict` and lock; IDs are random, oldest entries are evicted, payload sizes are checked before insertion, and downloads use fixed logical names (`json`, `html`) with fixed MIME types. Do not cache uploaded source bytes.

- [ ] **Step 5: Run adapter, run-cache, and existing domain tests**

Run: `python -m pytest tests/webui/test_adapters.py tests/webui/test_run_cache.py tests/dependency_audit tests/project_audit tests/sop -v -p no:cacheprovider`

Expected: all tests pass or retain only documented platform skips.

- [ ] **Step 6: Commit this task**

```powershell
git add src/svarog/webui/adapters.py src/svarog/webui/history.py tests/webui/test_adapters.py tests/webui/test_run_cache.py
git commit -m "feat: adapt Svarog services for the workbench"
```

### Task 5: Fixed-route Web application

**Files:**
- Create: `src/svarog/webui/application.py`
- Test: `tests/webui/test_application.py`

- [ ] **Step 1: Write HTTP-level failing tests with an in-memory request harness**

```python
def test_shell_and_assets_have_security_headers(app_client):
    response = app_client.get("/")
    assert response.status == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert b"Svarog" in response.body


def test_post_rejects_cross_origin_and_missing_csrf(app_client):
    response = app_client.post_json("/api/doctor", {}, origin="http://evil.test", csrf=None)
    assert response.status == 403
    assert response.json == {"ok": False, "error": {"code": "request_rejected", "message": "请求来源校验失败。"}}
```

Add fixed-route tests for `/api/overview`, `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/review`, `/api/analyze`, `/api/audit-python`, `/api/audit-project`, `/api/doctor`, `/api/sop`, and `/api/runs/<id>/download/<json|html>`.

- [ ] **Step 2: Run the route tests and verify application symbols are absent**

Run: `python -m pytest tests/webui/test_application.py -v -p no:cacheprovider`

Expected: collection fails on missing `WorkbenchApplication`.

- [ ] **Step 3: Implement a fixed route dispatcher and response envelope**

```python
@dataclass(frozen=True, slots=True)
class Response:
    status: int
    content_type: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class WorkbenchApplication:
    """Dispatch fixed local-workbench routes to existing Svarog services."""
```

Add a `handle(self, method: str, raw_target: str, headers: Mapping[str, str], body: BinaryIO) -> Response` method. It validates the request before selecting one of the fixed route handlers and returns a `Response`; it catches only the documented validation/domain exceptions and converts them to the safe error envelope.

Reject paths containing decoded `..`, NUL, backslash, duplicate slashes in API routing, unsupported methods, query arrays, unknown fields, and route IDs outside `[A-Za-z0-9_-]{1,128}`. Parse query strings with bounded field counts. Use a single JSON envelope: success `{"ok":true,"data":{"status":"ready"}}` and error `{"ok":false,"error":{"code":"invalid_input","message":"请检查输入字段。","fields":{"logs":"请选择日志文件。"}}}`. Never include exception text in the browser response.

- [ ] **Step 4: Implement upload-backed and path-backed operations**

SOP and Web analysis requests include Base64 uploads. Decode them inside `TemporaryDirectory(dir=workspace / ".svarog" / "tmp")`; invoke adapters before leaving the context. Python/project/Doctor requests include workspace-relative paths only and call `resolve_workspace_path`. API URL and log-host fields use explicit text/length validation. Each successful non-SOP operation enters `RunCache`; SOP saves to `CaseStore` and returns its case ID.

- [ ] **Step 5: Implement safe downloads and case review**

Downloads set fixed filenames with RFC 5987-safe ASCII fallbacks, `Content-Disposition: attachment`, correct MIME type, `nosniff`, and `Content-Length`. Review accepts only the three current decisions, then re-reads and returns the case. A second review returns HTTP 409. There is no delete or remediation route.

- [ ] **Step 6: Add tests for oversized requests, traversal, unknown fields, malformed JSON, stale run IDs, report filenames, review conflict, and redacted errors**

Run: `python -m pytest tests/webui/test_application.py -v -p no:cacheprovider`

Expected: all application tests pass without binding a socket.

- [ ] **Step 7: Commit this task**

```powershell
git add src/svarog/webui/application.py tests/webui/test_application.py
git commit -m "feat: add secure workbench routes"
```

### Task 6: Accessible light workbench assets

**Files:**
- Create: `src/svarog/webui/assets/index.html`
- Create: `src/svarog/webui/assets/app.css`
- Create: `src/svarog/webui/assets/app.js`
- Test: `tests/webui/test_assets.py`

- [ ] **Step 1: Write failing asset-contract tests**

```python
def test_shell_is_local_accessible_and_complete(asset_text):
    html = asset_text("index.html")
    css = asset_text("app.css")
    js = asset_text("app.js")
    assert '<a class="skip-link" href="#main-content">' in html
    assert 'aria-live="polite"' in html
    assert 'aria-live="assertive"' in html
    for view in ("overview", "sop-new", "cases", "web-analysis", "python-audit", "project-audit", "doctor"):
        assert f'data-view="{view}"' in html
    assert "https://" not in html + css + js
    assert "http://" not in html + css + js
    assert "innerHTML" not in js
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
```

- [ ] **Step 2: Run the asset tests and verify files are missing**

Run: `python -m pytest tests/webui/test_assets.py -v -p no:cacheprovider`

Expected: file-not-found failures for the three assets.

- [ ] **Step 3: Build the semantic HTML shell**

Use a skip link, `<aside>` navigation, `<header>` safety/status strip, and `<main id="main-content">`. Each form has visible `<label>`, helper text, a field-level error element, and a submit status region. The seven views are present but only the active view is unhidden. Use inline SVG symbols with `aria-hidden="true"` plus visible labels; every icon-only control has an `aria-label`.

The exact primary navigation is:

```text
概览
新建调查
案件历史
Web 日志分析
Python 环境审计
项目审计
Doctor
```

The persistent safety strip reads `本地只读分析 · 未执行处置`.

A top-bar “界面偏好” button opens a session-only settings drawer containing case-list page size, the default SOP time window, the SOP result limit, and whether technical details start expanded. It never contains a server path, Token, model key, or external endpoint, and it resets when the browser closes.

- [ ] **Step 4: Implement the approved light design system**

Define CSS tokens:

```css
:root {
  color-scheme: light;
  --bg: #f3f6f8;
  --surface: #ffffff;
  --surface-muted: #eaf0f3;
  --ink: #172a3a;
  --muted: #586b78;
  --line: #ced9df;
  --primary: #0b7669;
  --primary-strong: #075d54;
  --warning: #9a5a08;
  --danger: #b42318;
  --focus: #1769aa;
  --radius: 12px;
}
```

Use system fonts only, 16px base text, at least 44px controls, visible 3px focus rings, non-color status labels, responsive tables, a two-column desktop grid that becomes one column below 760px, and a compact navigation drawer below 900px. No gradients, glassmorphism, bouncing controls, decorative animation, or external fonts. Motion is 150–250ms and disabled under `prefers-reduced-motion`.

- [ ] **Step 5: Implement JavaScript with safe DOM APIs**

Use `textContent`, `createElement`, `append`, and explicit attribute setters. Never use `innerHTML`, `insertAdjacentHTML`, `eval`, dynamic imports, or inline event handlers. Implement:

```javascript
async function api(path, options = {}) {
  const headers = Object.assign({"Accept": "application/json"}, options.headers || {});
  if (options.method && options.method !== "GET") headers["X-Svarog-CSRF"] = csrfToken;
  const requestOptions = Object.assign({}, options, {headers});
  const response = await fetch(path, requestOptions);
  const payload = await response.json();
  if (!response.ok || !payload.ok) throw new ApiError(payload.error);
  return payload.data;
}
```

Read selected files with `FileReader.readAsArrayBuffer`, convert to Base64 in bounded chunks, and reject oversize files before reading. Disable submit buttons while a request is active, restore them in `finally`, focus the first invalid field, and announce success/errors through ARIA live regions. Render all result values as text. Downloads use regular same-origin links returned by the API, not Blob URLs containing report data.

- [ ] **Step 6: Add static checks and DOM-independent JavaScript behavior tests**

Test navigation labels, settings-drawer fields, form field names matching API contracts, absence of unsafe sinks/external URLs, all status text alternatives, responsive breakpoints, loading button state functions, and source-file size constants matching the server.

Run: `python -m pytest tests/webui/test_assets.py -v -p no:cacheprovider`

Expected: all asset tests pass.

- [ ] **Step 7: Commit this task**

```powershell
git add src/svarog/webui/assets tests/webui/test_assets.py
git commit -m "feat: add light Svarog workbench interface"
```

### Task 7: Server lifecycle and CLI command

**Files:**
- Create: `src/svarog/webui/server.py`
- Modify: `src/svarog/cli.py`
- Test: `tests/webui/test_server.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing server and CLI tests**

```python
def test_ui_command_defaults_to_no_browser(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr("svarog.webui.server.serve", lambda config, open_browser=False: calls.append((config, open_browser)))
    assert main(["ui", "--workspace", str(tmp_path)]) == 0
    assert calls[0][0].host == "127.0.0.1"
    assert calls[0][0].port == 8765
    assert calls[0][1] is False


def test_open_browser_is_explicit(monkeypatch, ui_config):
    opened = []
    serve(ui_config, open_browser=True, browser_opener=opened.append, server_factory=one_request_server)
    assert opened == ["http://127.0.0.1:8765/"]
```

- [ ] **Step 2: Run the tests and verify the command is unknown**

Run: `python -m pytest tests/webui/test_server.py tests/test_cli.py -k "ui" -v -p no:cacheprovider`

Expected: argparse rejects `ui` or import fails for `svarog.webui.server`.

- [ ] **Step 3: Implement the HTTP handler and lifecycle**

Create a handler subclass that forwards method, target, headers, and bounded body stream to `WorkbenchApplication`, writes exactly one response, suppresses default request logging, and logs only method/path/status without query strings or headers. Use `ThreadingHTTPServer`, `daemon_threads=True`, `allow_reuse_address=False`, and a per-server app reference. On Ctrl+C, close cleanly and print a short Chinese stop message.

`serve()` prints the local URL before `serve_forever()`. It calls `webbrowser.open()` only when `open_browser=True`; browser opener is injectable for tests. Never open a browser during automated tests.

- [ ] **Step 4: Register the CLI parser**

Add:

```python
ui = subparsers.add_parser("ui", help="启动仅限本机访问的 Svarog 可视化工作台")
ui.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost", "::1"))
ui.add_argument("--port", default=8765, type=int)
ui.add_argument("--workspace", required=True, type=Path)
ui.add_argument("--case-db", type=Path)
ui.add_argument("--open-browser", action="store_true")
ui.set_defaults(handler=_run_ui)
```

`_run_ui` builds `UiConfig`, calls `serve`, returns 0 after normal shutdown, and maps invalid configuration/socket errors to a concise message and exit code 1 without printing traceback or absolute sensitive paths.

- [ ] **Step 5: Test real loopback HTTP with an ephemeral port, without launching a browser**

Start a server in a test thread on port 0, request `/`, `/assets/app.css`, and `/api/overview`, then shut it down in `finally`. Assert response security headers, content types, bounded lengths, and that non-loopback/invalid Host headers are rejected.

Run: `python -m pytest tests/webui/test_server.py tests/test_cli.py -k "ui or existing_parser_case" -v -p no:cacheprovider`

Expected: all selected tests pass.

- [ ] **Step 6: Commit this task**

```powershell
git add src/svarog/webui/server.py src/svarog/cli.py tests/webui/test_server.py tests/test_cli.py
git commit -m "feat: add Svarog UI command"
```

### Task 8: End-to-end workbench workflows

**Files:**
- Create: `tests/webui/test_workflows.py`
- Modify: `src/svarog/webui/application.py`
- Modify: `src/svarog/webui/assets/app.js`
- Modify: `src/svarog/webui/assets/index.html`

- [ ] **Step 1: Write end-to-end HTTP workflow tests**

Use current fixtures to cover:

```python
def test_sop_create_list_review_reopen_and_download(http_client, sop_uploads):
    created = http_client.post_json("/api/sop", sop_uploads).json["data"]
    case_id = created["case_id"]
    assert created["case"]["status"] == "awaiting_review"
    assert created["case"]["actions_executed"] is False
    assert http_client.get("/api/cases?status=awaiting_review").json["data"]["total"] == 1
    reviewed = http_client.post_json(f"/api/cases/{case_id}/review", {
        "decision": "needs_investigation", "reviewer": "analyst", "note": "补充后端日志"
    }).json["data"]
    assert reviewed["status"] == "needs_investigation"
    reopened = http_client.get(f"/api/cases/{case_id}").json["data"]
    assert reopened["review"]["reviewer"] == "analyst"
    assert reopened["actions_executed"] is False
    assert http_client.get(f"/api/cases/{case_id}/download/json").status == 200
```

Add complete success/failure flows for Web analysis, Python audit, project audit, and Doctor with injected local fixtures. Assert no request can trigger a shell command except Doctor's existing fixed `python --version` and fixed package-manager version checks.

- [ ] **Step 2: Run the workflow tests and confirm missing integration behavior**

Run: `python -m pytest tests/webui/test_workflows.py -v -p no:cacheprovider`

Expected: at least one route/response mismatch fails before integration fixes.

- [ ] **Step 3: Complete result renderers and cross-links**

Ensure each result contains a stable `kind`, title, status, summary cards, warning list, table sections, and download links. The browser renderer uses a fixed schema per kind and treats unknown/missing fields as an explicit display error. SOP evidence IDs create keyboard-focusable links and targets; ATT&CK links use only server-provided fixed MITRE URLs and open with `rel="noopener noreferrer"`.

- [ ] **Step 4: Complete overview state and error recovery**

Overview fetches case summary plus in-memory recent runs. A service restart labels non-SOP recent runs as unavailable rather than pretending they persist. Forms retain only non-sensitive path/option inputs after errors; uploaded `File` objects, tokens, model keys, and raw result JSON are never stored in browser storage.

- [ ] **Step 5: Run all Web UI and existing domain tests**

Run: `python -m pytest tests/webui tests/sop tests/dependency_audit tests/project_audit tests/test_doctor.py tests/test_cli.py -v -p no:cacheprovider`

Expected: all new tests pass; only known platform-specific existing tests may skip.

- [ ] **Step 6: Commit this task**

```powershell
git add src/svarog/webui tests/webui
git commit -m "feat: connect complete Svarog workbench flows"
```

### Task 9: Package assets and write Windows VM instructions

**Files:**
- Modify: `pyproject.toml`
- Create: `docs/UI使用说明.md`
- Modify: `README.md`
- Test: `tests/webui/test_packaging.py`

- [ ] **Step 1: Write a failing installed-package asset test**

```python
def test_assets_are_package_resources():
    root = resources.files("svarog.webui").joinpath("assets")
    assert (root / "index.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert ":root" in (root / "app.css").read_text(encoding="utf-8")
    assert "function" in (root / "app.js").read_text(encoding="utf-8")
```

- [ ] **Step 2: Run the test and confirm package-data is not configured**

Run: `python -m pytest tests/webui/test_packaging.py -v -p no:cacheprovider`

Expected: resource lookup or installed-wheel smoke check fails.

- [ ] **Step 3: Configure package data**

Add:

```toml
[tool.setuptools.package-data]
"svarog.webui" = ["assets/*.html", "assets/*.css", "assets/*.js"]
```

Load assets with `resources.files("svarog.webui").joinpath("assets", filename)` so the assets directory does not need to become an importable Python package.

- [ ] **Step 4: Write the Windows VM guide**

Document exact commands from copying the folder onward:

```powershell
cd C:\Users\Administrator\Desktop\Svarog
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m svarog ui --workspace . --case-db .\.svarog\cases.sqlite3
```

Tell the user to manually open the printed `http://127.0.0.1:8765/`, verify every page with included samples, stop with Ctrl+C, and use a separate terminal for the UI service. Include troubleshooting for wrong Python, stale editable installs, occupied port (`--port 8766`), missing files, invalid workspace-relative paths, API Token environment variable, and firewall expectations. Explicitly state that the service must not be exposed through port forwarding or `0.0.0.0`.

- [ ] **Step 5: Update README with a short entry point and run documentation checks**

Run: `rg -n "svarog ui|127\.0\.0\.1|未执行处置|Windows" README.md docs/UI使用说明.md`

Expected: all four topics are present, and README links to the full guide.

- [ ] **Step 6: Commit this task**

```powershell
git add pyproject.toml docs/UI使用说明.md README.md tests/webui/test_packaging.py
git commit -m "docs: package and explain the local workbench"
```

### Task 10: Final security, regression, and wheel verification

**Files:**
- Modify only files implicated by failures from this task.
- Create: `docs/UI验收记录.md`

- [ ] **Step 1: Read the UI pre-delivery rules and audit the final assets**

Read `C:\Users\18201\.codex\skills\ui-ux-pro-max\references\pro-rules.md`. Check keyboard focus, labels, contrast, 44px targets, 375/768/1024/1440 layouts, non-color status text, reduced motion, table overflow, loading/error feedback, and icon labels. Record each result in `docs/UI验收记录.md`.

- [ ] **Step 2: Run targeted security and workbench tests**

Run: `python -m pytest tests/webui tests/sop -v -p no:cacheprovider`

Expected: every new test passes with zero skips unless a test explicitly exercises unavailable symlink behavior.

- [ ] **Step 3: Run the complete regression suite**

Run: `python -m pytest -p no:cacheprovider -o addopts='' -q -rs`

Expected: zero failures. Record exact pass/skip counts and every skip category; do not describe skipped tests as passed.

- [ ] **Step 4: Perform static safety checks**

Run: `rg -n "innerHTML|insertAdjacentHTML|eval\(|exec\(|shell=True|0\.0\.0\.0|https?://" src/svarog/webui`

Expected: no unsafe JavaScript sinks, no dynamic code execution, no shell execution, no non-loopback bind, and no external asset URL. The only acceptable URL-like strings are fixed local-origin handling and the already-approved ATT&CK links passed through trusted report data; inspect each hit manually.

Run: `git diff --check`

Expected: no whitespace errors or conflict markers.

- [ ] **Step 5: Build and inspect a wheel without starting the UI**

Run: `python -m pip wheel --no-deps --no-build-isolation . --wheel-dir build-check`

Expected: one `svarog_security-0.1.0-py3-none-any.whl` is built.

Run: `python -m zipfile -l build-check/svarog_security-0.1.0-py3-none-any.whl`

Expected: wheel contains every `src/svarog/webui/*.py` module and the three UI assets.

Install the wheel into an isolated target and import `svarog.webui.server`; invoke only `build_parser().parse_args(["ui", "--workspace", "."])`. Do not call `serve`, bind a port, open a browser, or use `--open-browser` on the physical machine.

- [ ] **Step 6: Write the acceptance record**

Record commands, exact results, known platform skips, absence of physical-machine browser/server launch, and the remaining Windows VM manual visual checklist in `docs/UI验收记录.md`. Do not claim real-model compatibility unless a real configured service was tested by the user.

- [ ] **Step 7: Request focused code review and fix actionable findings**

Review scope: `src/svarog/webui`, the `ui` CLI addition, SOP schema migration, Web UI tests, packaging, and UI docs. Ask specifically for Host/Origin bypass, path escape, request-size bypass, report injection, SQLite migration loss, secret leakage, and misleading security conclusions. Reproduce every accepted finding with a failing test before fixing it.

- [ ] **Step 8: Re-run final verification after review fixes**

Run: `python -m pytest -p no:cacheprovider -o addopts='' -q -rs`

Expected: zero failures and exact counts added to the acceptance record.

- [ ] **Step 9: Commit final verification artifacts**

```powershell
git add docs/UI验收记录.md
git commit -m "test: record Svarog workbench verification"
```

Do not start or open the Web UI on the physical machine. The user performs visual and interaction acceptance in the Windows VM using `docs/UI使用说明.md`.
