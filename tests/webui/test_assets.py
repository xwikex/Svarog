from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "src" / "svarog" / "webui" / "assets"
ASSET_NAMES = ("index.html", "app.css", "app.js")
NODE = shutil.which("node")


def asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


class _MarkupAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.label_targets: set[str] = set()
        self.controls: list[tuple[str, dict[str, str | None]]] = []
        self.inline_events: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "label" and values.get("for"):
            self.label_targets.add(values["for"])
        if tag in {"input", "select", "textarea"}:
            self.controls.append((tag, values))
        self.inline_events.extend(name for name, _ in attrs if name.startswith("on"))
        if "style" in values:
            self.inline_styles += 1
        if tag == "script" and "src" not in values:
            self.inline_scripts += 1
        if tag == "style":
            self.inline_styles += 1


def form_block(html: str, form_id: str) -> str:
    match = re.search(
        rf'<form\b[^>]*\bid="{re.escape(form_id)}"[^>]*>(.*?)</form>',
        html,
        flags=re.DOTALL,
    )
    assert match, f"missing form {form_id}"
    return match.group(1)


def field_names(block: str) -> set[str]:
    return set(re.findall(r'\bname="([^"]+)"', block))


def test_three_utf8_assets_exist() -> None:
    for name in ASSET_NAMES:
        path = ASSETS / name
        assert path.is_file(), f"missing asset: {name}"
        assert path.read_text(encoding="utf-8").strip()


def test_shell_has_exact_navigation_views_and_security_landmarks() -> None:
    html = asset("index.html")
    css = asset("app.css")
    js = asset("app.js")
    links = re.findall(r'<a\b[^>]*data-nav-view="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL)
    assert [view for view, _ in links] == [
        "overview", "sop-new", "cases", "web-analysis", "python-audit",
        "project-audit", "audit-history", "audit-diff", "sbom", "doctor", "settings",
    ]
    assert [re.sub(r"<[^>]+>", "", label).strip() for _, label in links] == [
        "概览", "新建调查", "案件历史", "Web 日志分析", "Python 环境审计", "项目审计",
        "审计历史", "差异对比", "SBOM", "Doctor", "设置",
    ]
    assert set(re.findall(r'\bdata-view="([^"]+)"', html)) == {
        "overview", "sop-new", "cases", "web-analysis", "python-audit",
        "project-audit", "audit-history", "audit-diff", "sbom", "doctor", "settings",
    }
    assert 'href="#main-content"' in html
    assert "<aside" in html and "<header" in html and '<main id="main-content"' in html
    assert "核心工作流只读 · 未自动处置" not in html
    assert "告警 → Agent 分析 → 日志查询 → IOC → ATT&amp;CK → 建议 → 人工确认。" not in html
    assert "safety-strip" not in html
    assert ".safety-strip" not in css
    assert 'aria-controls="primary-navigation"' in html
    assert 'aria-expanded="false"' in html
    assert 'id="feature-navigation"' in html
    assert 'id="feature-views"' in html
    assert "扩展功能" in html
    assert "可信模块与工作台进程拥有相同权限" in js


def test_v02_pages_are_concise_modular_and_self_hosted() -> None:
    html = asset("index.html")
    for view in ("audit-history", "audit-diff", "sbom", "settings"):
        assert f'data-view="{view}"' in html
    for filename in ("components/table.js", "pages/history.js", "pages/diff.js",
                     "pages/sbom.js", "pages/settings.js"):
        assert f'src="/{filename}"' in html
        assert (ASSETS / filename).is_file()
    assert html.index('src="/components/table.js"') < html.index('src="/app.js"')
    assert all(value not in html for value in ("http://", "https://", "<iframe", "<script type=\"module\""))
    assert "核心工作流只读 · 未自动处置" not in html
    assert "告警 → Agent 分析" not in html
    for filename in ("components/table.js", "pages/history.js", "pages/diff.js",
                     "pages/sbom.js", "pages/settings.js"):
        script = asset(filename)
        assert "innerHTML" not in script
        assert "eval(" not in script


def test_shared_table_uses_text_nodes_for_untrusted_values() -> None:
    if NODE is None:
        return
    script = asset("components/table.js")
    probe = r'''
const nodes = [];
globalThis.window = {};
globalThis.document = {createElement(tag) {
  const node = {tag, children: [], append(...values) { this.children.push(...values); }};
  Object.defineProperty(node, "innerHTML", {set() { throw new Error("HTML insertion"); }});
  nodes.push(node);
  return node;
}};
'''
    probe += script + r'''
const rendered = window.SvarogUI.table([{label: "名称", value: (row) => row.name}],
  [{name: "<img src=x onerror=alert(1)>"}]);
const cell = rendered.children[0].children[1].children[0].children[0];
process.stdout.write(JSON.stringify({tag: cell.tag, text: cell.textContent}));
'''
    result = subprocess.run([NODE], input=probe, capture_output=True, text=True, check=True, timeout=10)
    assert result.stdout == '{"tag":"td","text":"<img src=x onerror=alert(1)>"}'


def test_history_detail_and_diff_do_not_hide_additional_rows() -> None:
    html = asset("index.html")
    history = asset("pages/history.js")
    diff = asset("pages/diff.js")
    assert 'id="history-detail" tabindex="-1"' in html
    assert "row.raw_name" in history
    assert "detail.focus()" in history
    assert "detailOffset" in history and "detail-next" in history
    assert "完整差异 JSON" in diff and "slice(0, 200)" in diff


def test_forms_match_application_contract_and_explain_every_field() -> None:
    html = asset("index.html")
    expected = {
        "sop-form": {"alert", "logs", "log_format", "log_host", "window_minutes", "limit", "agent_config"},
        "analyze-form": {"logs"},
        "python-audit-form": {"environment", "vuln_source", "vuln_db", "vuln_api"},
        "project-audit-form": {"environment", "lock_file", "vuln_source", "vuln_db", "vuln_api"},
        "doctor-form": {"environment", "lock_file", "output_directory", "vuln_source", "vuln_db", "vuln_api"},
        "review-form": {"decision", "reviewer", "note"},
    }
    for form_id, names in expected.items():
        block = form_block(html, form_id)
        assert field_names(block) == names
        assert "field-error" in block
        assert 'aria-live="polite"' in block
    assert "批准仅记录复核意见，不执行处置" in html
    assert "Nginx" in html and 'data-nginx-host' in html

    audit = _MarkupAudit()
    audit.feed(html)
    assert audit.controls
    for _, attrs in audit.controls:
        control_id = attrs.get("id")
        if attrs.get("type") == "hidden":
            continue
        assert control_id and control_id in audit.label_targets
        described_by = (attrs.get("aria-describedby") or "").split()
        assert described_by and all(item in audit.ids for item in described_by)


def test_accessibility_live_regions_and_no_inline_content() -> None:
    html = asset("index.html")
    audit = _MarkupAudit()
    audit.feed(html)
    assert not audit.inline_events
    assert audit.inline_scripts == 0
    assert audit.inline_styles == 0
    assert 'aria-live="polite"' in html
    assert 'aria-live="assertive"' in html
    assert 'id="global-notice"' in html
    assert 'aria-hidden="true"' in html
    assert '<script src="/app.js" defer></script>' in html
    assert '<link rel="stylesheet" href="/app.css">' in html


def test_settings_are_only_non_sensitive_session_preferences() -> None:
    html = asset("index.html")
    block = re.search(r'<section\b[^>]*id="preferences-drawer"[^>]*>(.*?)</section>', html, re.DOTALL)
    assert block
    assert field_names(block.group(1)) == {
        "cases_page_size", "default_sop_window", "sop_result_limit", "technical_details_open",
    }
    assert "界面偏好" in block.group(1)

    js = asset("app.js")
    storage_lines = "\n".join(line for line in js.splitlines() if "sessionStorage" in line)
    assert "sessionStorage.getItem" in storage_lines
    assert "sessionStorage.setItem" in storage_lines
    for forbidden in ("path", "token", "model", "endpoint", "api", "environment", "lock_file"):
        assert forbidden not in storage_lines.casefold()


def test_css_implements_light_tokens_responsive_layout_and_motion_rules() -> None:
    css = asset("app.css")
    for declaration in (
        "--bg: #f3f6f8", "--surface: #fff", "--surface-muted: #eaf0f3",
        "--ink: #172a3a", "--muted: #586b78", "--line: #ced9df",
        "--primary: #0b7669", "--primary-strong: #075d54", "--warning: #9a5a08",
        "--danger: #b42318", "--focus: #1769aa", "--radius: 12px",
        "color-scheme: light",
    ):
        assert declaration in css
    assert re.search(r":focus-visible\s*\{[^}]*3px", css, re.DOTALL)
    assert "min-height: 44px" in css
    assert "@media (max-width: 899px)" in css
    assert "visibility: hidden" in css and "visibility: visible" in css
    assert "@media (max-width: 759px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "overflow-x: hidden" in css
    for forbidden in ("gradient", "backdrop-filter", "bounce"):
        assert forbidden not in css.casefold()


def test_javascript_uses_safe_rendering_upload_limits_and_api_routes() -> None:
    js = asset("app.js")
    for forbidden in (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function",
        "Function(", "document.write", "import(", ".srcdoc",
    ):
        assert forbidden not in js
    assert "textContent" in js and "createElement" in js and ".append(" in js
    assert "setAttribute" in js
    assert "class ApiError" in js
    assert "fetch(" in js and 'X-Svarog-CSRF' in js
    assert "__SVAROG_CSRF_TOKEN__" in asset("index.html")
    assert "FileReader" in js and "readAsArrayBuffer" in js
    assert "64 * 1024" in js
    assert "10 * 1024 * 1024" in js
    for route in (
        "/api/overview", "/api/cases", "/api/analyze", "/api/audit-python",
        "/api/audit-project", "/api/doctor", "/api/sop", "/review",
        "/api/features",
    ):
        assert route in js
    assert "finally" in js and ".disabled" in js
    assert "aria-invalid" in js and ".focus()" in js
    assert "URLSearchParams" in js and "limit" in js and "offset" in js
    assert "location.origin" in js
    assert 'getAttribute("aria-describedby")' in js
    assert "navigation.inert" in js
    assert 'typeof parsed === "object"' in js
    assert 'data-technical-details' in js
    assert 'element("caption", definition.title)' in js
    assert 'headerCell.setAttribute("scope", "col")' in js
    assert "createObjectURL" not in js and "Blob(" not in js
    assert "function validateFeatureCatalog" in js
    assert "function installFeatures" in js
    assert "function validateFeatureResultSchema" in js
    assert "svarog.workbench.feature-result.v1" in js
    assert "hash-file" not in js
    assert 'if (control.value === "") return;' in js


def test_assets_have_no_external_urls() -> None:
    for name in ASSET_NAMES:
        content = asset(name).casefold()
        assert "http://" not in content
        assert "https://" not in content
