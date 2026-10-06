"""Fixed, in-memory request dispatcher for the local Svarog workbench."""

from __future__ import annotations

import html
import importlib.resources
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import unicodedata
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import BinaryIO
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

from svarog.features.contracts import FeatureContext
from svarog.features.registry import FeatureRegistry
from svarog.features.runtime import (
    FeatureInputError,
    FeatureResultError,
    present_feature_result,
    validate_feature_input,
)
from svarog.sop.storage import CaseStore
from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.repository import HistoryRepository
from svarog.audit_history.service import HistoryServiceError
from svarog.runtime_layout import (
    RuntimeLayout, RuntimeLayoutError, load_project_identity, load_settings,
)

from .adapters import (
    analyze_web_log,
    audit_project,
    audit_python,
    audit_with_persistent_history,
    run_doctor_check,
    run_sop_case,
)
from .config import UiConfig, resolve_workspace_path
from .history import RunCache
from .history_api import get_snapshot as api_get_snapshot, list_history as api_list_history
from .diff_api import compare_snapshots as api_compare_snapshots
from .sbom_api import SBOM_MIME, download_sbom as api_download_sbom
from .settings_api import (
    SettingsApiInputError,
    get_project as api_get_project,
    get_settings as api_get_settings,
    update_project as api_update_project,
    update_settings as api_update_settings,
)
from .security import (
    SECURITY_HEADERS,
    RequestRejected,
    decode_upload,
    read_json_body,
    validate_mutation,
)


JSON_MIME = "application/json; charset=utf-8"
HTML_MIME = "text/html; charset=utf-8"
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_HEX = frozenset("0123456789abcdefABCDEF")
_ASSETS = {
    "/": ("index.html", HTML_MIME),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/components/table.js": ("components/table.js", "text/javascript; charset=utf-8"),
    "/pages/history.js": ("pages/history.js", "text/javascript; charset=utf-8"),
    "/pages/diff.js": ("pages/diff.js", "text/javascript; charset=utf-8"),
    "/pages/sbom.js": ("pages/sbom.js", "text/javascript; charset=utf-8"),
    "/pages/settings.js": ("pages/settings.js", "text/javascript; charset=utf-8"),
}
_CASE = re.compile(r"/api/cases/([A-Za-z0-9_-]{1,128})\Z")
_CASE_DOWNLOAD = re.compile(
    r"/api/cases/([A-Za-z0-9_-]{1,128})/download/(json|html)\Z"
)
_REVIEW = re.compile(r"/api/cases/([A-Za-z0-9_-]{1,128})/review\Z")
_DOWNLOAD = re.compile(
    r"/api/runs/([A-Za-z0-9_-]{1,128})/download/(json|html)\Z"
)
_FEATURE_RUN = re.compile(r"/api/features/([a-z][a-z0-9-]{0,63})/run\Z")
_HISTORY_SNAPSHOT = re.compile(r"/api/audit-history/snapshots/([0-9]+)\Z")
_HISTORY_SBOM = re.compile(r"/api/audit-history/snapshots/([0-9]+)/sbom\Z")
_DOWNLOAD_KIND_SLUGS = {
    "analyze": "analyze",
    "audit-python": "audit-python",
    "audit-project": "audit-project",
    "doctor": "doctor",
    "web_analysis": "web-analysis",
    "dependency_audit": "dependency-audit",
    "project_audit": "project-audit",
    "sop_case": "sop-case",
}

_TITLES = {
    "web_analysis": "Web 日志分析",
    "dependency_audit": "Python 环境审计",
    "project_audit": "项目依赖审计",
    "doctor": "Doctor 就绪检查",
    "sop_case": "告警调查案件",
}
_SUMMARY_LABELS = {
    "total_events": "事件总数", "suspicious_events": "可疑事件", "input_issues": "输入问题",
    "severity_critical": "严重", "severity_high": "高危", "severity_medium": "中危",
    "severity_low": "低危", "severity_info": "提示",
    "installed_packages": "已检查包", "confirmed_findings": "确认漏洞",
    "indeterminate_findings": "无法判断", "locked_packages": "锁定包",
    "confirmed_environment_findings": "环境确认漏洞", "potential_lock_findings": "锁文件潜在漏洞",
    "version_differences": "版本差异",
}
_ATTACK_ID = re.compile(r"T([0-9]{4})(?:\.([0-9]{3}))?\Z")
_RESULT_STATUSES = {
    "web_analysis": frozenset({"completed_local"}),
    "dependency_audit": frozenset({
        "completed_clean", "completed_with_findings", "completed_incomplete",
        "completed_with_findings_and_gaps",
    }),
    "project_audit": frozenset({
        "completed_clean", "completed_with_findings", "completed_incomplete",
        "completed_with_findings_and_gaps",
    }),
    "doctor": frozenset({"ready", "ready_with_warnings", "not_ready"}),
}
_REQUIRED_SUMMARY_KEYS = {
    "web_analysis": frozenset({"total_events", "suspicious_events", "input_issues"}),
    "dependency_audit": frozenset({"installed_packages", "confirmed_findings", "indeterminate_findings"}),
    "project_audit": frozenset({
        "installed_packages", "locked_packages", "confirmed_environment_findings",
        "potential_lock_findings", "version_differences",
    }),
}
_SOP_STEP_NAMES = (
    "告警接入", "Agent 初步分析", "查询日志", "IOC 提取",
    "ATT&CK 映射", "生成处置建议", "人工确认",
)


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    content_type: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class _InputError(ValueError):
    def __init__(self, fields: Mapping[str, str] | None = None):
        super().__init__("invalid input")
        self.fields = dict(fields or {})


class _SchemaError(ValueError):
    pass


class _FeatureExecutionError(RuntimeError):
    pass


def _default_asset_loader(name: str) -> bytes:
    return importlib.resources.files("svarog.webui").joinpath("assets", name).read_bytes()


def _header_values(headers: object, wanted: str) -> list[object]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(wanted)
        return [] if values is None else list(values) if isinstance(values, (list, tuple)) else [values]
    if not isinstance(headers, Mapping):
        return []
    return [value for key, value in headers.items()
            if isinstance(key, str) and key.casefold() == wanted.casefold()]


def _single_header(headers: object, name: str) -> str:
    values = _header_values(headers, name)
    return values[0] if len(values) == 1 and isinstance(values[0], str) else ""


def _response(status: int, content_type: str, body: bytes,
              extra: Mapping[str, str] | None = None) -> Response:
    headers = dict(SECURITY_HEADERS)
    headers.update(extra or {})
    headers["Content-Type"] = content_type
    headers["Content-Length"] = str(len(body))
    return Response(status, content_type, body, MappingProxyType(headers))


def _json_response(status: int, value: object,
                   extra: Mapping[str, str] | None = None) -> Response:
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return _response(status, JSON_MIME, body, extra)


def _success(data: object, status: int = 200) -> Response:
    return _json_response(status, {"ok": True, "data": data})


def _error(status: int, code: str, message: str,
           fields: Mapping[str, str] | None = None,
           extra: Mapping[str, str] | None = None) -> Response:
    error: dict[str, object] = {"code": code, "message": message}
    if fields:
        error["fields"] = dict(fields)
    return _json_response(status, {"ok": False, "error": error}, extra)


def _strict_unquote(value: str) -> str:
    index = 0
    while index < len(value):
        if value[index] == "%":
            if index + 2 >= len(value) or value[index + 1] not in _HEX or value[index + 2] not in _HEX:
                raise RequestRejected(400, "invalid_target", "请求地址无效")
            index += 3
        else:
            index += 1
    try:
        return unquote_to_bytes(value).decode("utf-8", "strict")
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise RequestRejected(400, "invalid_target", "请求地址无效") from exc


def _target(raw_target: object) -> tuple[str, str]:
    if (
        not isinstance(raw_target, str)
        or not raw_target
        or "\\" in raw_target
        or "#" in raw_target
        or any(
            character.isspace()
            or unicodedata.category(character).startswith("C")
            for character in raw_target
        )
    ):
        raise RequestRejected(400, "invalid_target", "请求地址无效")
    try:
        parsed = urlsplit(raw_target)
    except ValueError as exc:
        raise RequestRejected(400, "invalid_target", "请求地址无效") from exc
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise RequestRejected(400, "invalid_target", "请求地址无效")
    path = _strict_unquote(parsed.path)
    _strict_unquote(parsed.query)
    if "\x00" in path or "\\" in path or ".." in path.split("/"):
        raise RequestRejected(400, "invalid_target", "请求地址无效")
    if path.startswith("/api/") and "//" in path:
        raise RequestRejected(400, "invalid_target", "请求地址无效")
    return path, parsed.query


def _query(raw: str, allowed: set[str]) -> dict[str, str]:
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=False,
                          max_num_fields=20, encoding="utf-8", errors="strict")
    except (ValueError, UnicodeError) as exc:
        raise _InputError() from exc
    result: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in result or key.endswith("[]"):
            raise _InputError()
        result[key] = value
    return result


def _keys(data: dict[str, object], allowed: set[str], required: set[str]) -> None:
    bad = set(data) - allowed
    missing = required - set(data)
    if bad or missing:
        fields = {key: "不支持的字段。" for key in sorted(bad)}
        fields.update({key: "此字段必填。" for key in sorted(missing)})
        raise _InputError(fields)


def _safe_text(value: object, name: str, maximum: int, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise _InputError({name: "请输入有效文本。"})
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise _InputError({name: "请输入有效文本。"})
    return value.strip()


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _InputError({name: f"请输入 {minimum}..{maximum} 的整数。"})
    return value


def _query_integer(value: str, name: str, minimum: int, maximum: int) -> int:
    if not value.isascii() or not value.isdecimal():
        raise _InputError({name: "请输入有效整数。"})
    return _integer(int(value), name, minimum, maximum)


def _upload(value: object, name: str) -> dict:
    if type(value) is not dict or set(value) != {"name", "data"}:
        raise _InputError({name: "请选择有效文件。"})
    return value


def _api_url(value: object) -> str | None:
    if value is None:
        return None
    text = _safe_text(value, "vuln_api", 2048)
    assert text is not None
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise _InputError({"vuln_api": "请输入有效的 HTTP 或 HTTPS 地址。"}) from exc
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or "#" in text or any(char.isspace() for char in text)):
        raise _InputError({"vuln_api": "请输入有效的 HTTP 或 HTTPS 地址。"})
    del port
    return text


class WorkbenchApplication:
    """Dispatch a deliberately small set of local-workbench routes."""

    def __init__(self, config: UiConfig, csrf_token: str, cache: RunCache | None = None,
                 *, asset_loader: Callable[[str], bytes] | None = None,
                 feature_registry: FeatureRegistry | None = None) -> None:
        if not isinstance(config, UiConfig):
            raise TypeError("config 必须是 UiConfig")
        if not isinstance(csrf_token, str) or not csrf_token or not csrf_token.isascii():
            raise ValueError("csrf_token 必须是非空 ASCII 文本")
        self.config = config
        self.csrf_token = csrf_token
        self.cache = cache or RunCache()
        self.asset_loader = asset_loader or _default_asset_loader
        self.feature_registry = feature_registry or FeatureRegistry.discover()
        self._recent_runs: deque[dict[str, object]] = deque(maxlen=10)
        self._recent_runs_lock = RLock()
        self._doctor_status = "not_run"
        self.allowed_hosts = frozenset({
            f"127.0.0.1:{config.port}", f"localhost:{config.port}", f"[::1]:{config.port}",
        })

    def handle(self, method: str, raw_target: str, headers: Mapping[str, str],
               body: BinaryIO | bytes) -> Response:
        try:
            if method not in {"GET", "POST"}:
                return _error(405, "method_not_allowed", "不支持此请求方法。", extra={"Allow": "GET, POST"})
            host = _single_header(headers, "Host")
            if method == "POST":
                validate_mutation(host, _single_header(headers, "Origin"),
                                  _single_header(headers, "X-Svarog-CSRF"),
                                  self.csrf_token, self.allowed_hosts)
            elif host not in self.allowed_hosts:
                raise RequestRejected(400, "invalid_host", "请求主机无效")
            path, query = _target(raw_target)
            return self._dispatch(method, path, query, headers, body)
        except RequestRejected as exc:
            return _error(exc.status, exc.code, exc.message)
        except _InputError as exc:
            return _error(400, "invalid_input", "请检查输入字段。", exc.fields)
        except SettingsApiInputError as exc:
            return _error(400, "invalid_input", "请检查输入字段。", exc.fields)
        except FeatureInputError as exc:
            return _error(400, "invalid_feature_input", "请检查功能输入字段。", exc.fields)
        except FeatureResultError:
            return _error(500, "invalid_feature_result_schema", "功能返回了不支持的结果结构。")
        except _FeatureExecutionError:
            return _error(500, "feature_failed", "功能未能完成，请稍后重试。")
        except _SchemaError:
            return _error(500, "invalid_result_schema", "操作返回了不支持或缺失的结果结构。")
        except HistoryServiceError as exc:
            known_codes = {"invalid_audit_clock", "audit_already_completed", "history_hash_failed",
                           "history_persistence_failed", "history_result_failed", "audit_report_failed"}
            code = exc.code if exc.code in known_codes else "history_failed"
            return _error(500, code, "审计未能完成，请检查输入与历史库状态。")
        except HistoryDatabaseError as exc:
            if exc.code in {"snapshot_not_found", "run_not_found"}:
                return _error(404, exc.code, "审计记录不存在。")
            if exc.code.startswith("invalid_"):
                return _error(400, "invalid_input", "请检查输入字段。")
            return _error(500, "history_unavailable", "审计历史暂时不可用。")
        except RuntimeLayoutError as exc:
            if str(exc) == "project_identity_not_found":
                return _error(409, "project_not_initialized", "项目尚未初始化。")
            return _error(500, "runtime_unavailable", "项目数据暂时不可用。")
        except sqlite3.Error:
            return _error(500, "storage_error", "案件数据暂时不可用。")
        except (json.JSONDecodeError, OSError):
            return _error(500, "operation_failed", "操作未能完成，请稍后重试。")
        except ValueError:
            return _error(400, "invalid_input", "请检查输入字段。")
        except Exception:
            return _error(500, "internal_error", "服务暂时不可用，请稍后重试。")

    def _dispatch(self, method: str, path: str, query: str, headers: object,
                  body: BinaryIO | bytes) -> Response:
        if path in _ASSETS:
            if method != "GET" or query:
                return self._route_error(method)
            name, mime = _ASSETS[path]
            try:
                payload = self.asset_loader(name)
                if type(payload) is not bytes:
                    raise OSError("invalid asset")
            except (FileNotFoundError, ModuleNotFoundError, OSError, KeyError):
                return _error(404, "not_found", "请求的资源不存在。")
            if name == "index.html":
                token = html.escape(self.csrf_token, quote=True).encode("ascii")
                payload = payload.replace(b"__SVAROG_CSRF_TOKEN__", token)
            return _response(200, mime, payload)

        if path in {"/api/settings", "/api/project"}:
            self._no_query(query)
            layout = RuntimeLayout.build(self.config.workspace)
            if method == "GET":
                return _success(
                    api_get_settings(layout) if path == "/api/settings"
                    else api_get_project(layout)
                )
            if method == "POST":
                stream = io.BytesIO(body) if isinstance(body, bytes) else body
                data = read_json_body(stream, headers, self.config.max_request_bytes)
                return _success(
                    api_update_settings(layout, data) if path == "/api/settings"
                    else api_update_project(layout, data)
                )
            return self._route_error(method)

        if path == "/api/audit-history":
            if method != "GET":
                return self._route_error(method)
            values = _query(query, {"audit_kind", "run_status", "reused", "completed_from", "completed_to", "limit", "offset"})
            kind = values.get("audit_kind") or None
            if kind not in (None, "python_project", "python_environment"):
                raise _InputError({"audit_kind": "请选择有效审计类型。"})
            status = values.get("run_status") or None
            if status not in (None, "started", "completed_computed", "completed_reused", "failed", "interrupted"):
                raise _InputError({"run_status": "请选择有效运行状态。"})
            raw_reused = values.get("reused")
            if raw_reused not in (None, "0", "1"):
                raise _InputError({"reused": "请选择有效复用状态。"})
            reused = None if raw_reused is None else raw_reused == "1"
            limit = _query_integer(values.get("limit", "20"), "limit", 1, 100)
            offset = _query_integer(values.get("offset", "0"), "offset", 0, 100000)
            with self._history_store() as (repository, project_id):
                return _success(api_list_history(repository, project_id, audit_kind=kind,
                                                 run_status=status, reused=reused,
                                                 completed_from=values.get("completed_from"),
                                                 completed_to=values.get("completed_to"),
                                                 limit=limit, offset=offset))

        match = _HISTORY_SBOM.fullmatch(path)
        if match:
            if method != "GET":
                return self._route_error(method)
            self._no_query(query)
            snapshot_id = _query_integer(match.group(1), "snapshot_id", 1, 2**63 - 1)
            with self._history_store() as (repository, project_id):
                payload, digest = api_download_sbom(repository, project_id, snapshot_id)
            return _response(200, SBOM_MIME, payload, {
                "Content-Disposition": 'attachment; filename="svarog-sbom.json"',
                "X-Content-SHA256": digest,
            })

        match = _HISTORY_SNAPSHOT.fullmatch(path)
        if match:
            if method != "GET":
                return self._route_error(method)
            snapshot_id = _query_integer(match.group(1), "snapshot_id", 1, 2**63 - 1)
            values = _query(query, {"limit", "offset"})
            limit = _query_integer(values.get("limit", "50"), "limit", 1, 100)
            offset = _query_integer(values.get("offset", "0"), "offset", 0, 100000)
            with self._history_store() as (repository, project_id):
                return _success(api_get_snapshot(repository, project_id, snapshot_id,
                                                 limit=limit, offset=offset))

        if path == "/api/audit-history/compare":
            if method != "POST":
                return self._route_error(method)
            self._no_query(query)
            stream = io.BytesIO(body) if isinstance(body, bytes) else body
            data = read_json_body(stream, headers, self.config.max_request_bytes)
            _keys(data, {"baseline_snapshot_id", "target_snapshot_id"}, {"target_snapshot_id"})
            target_id = _integer(data["target_snapshot_id"], "target_snapshot_id", 1, 2**63 - 1)
            baseline_value = data.get("baseline_snapshot_id")
            baseline_id = None if baseline_value is None else _integer(
                baseline_value, "baseline_snapshot_id", 1, 2**63 - 1)
            with self._history_store() as (repository, project_id):
                return _success(api_compare_snapshots(
                    repository, project_id, baseline_snapshot_id=baseline_id,
                    target_snapshot_id=target_id,
                ))
        if path.startswith("/api/audit-history/snapshots/"):
            raise RequestRejected(400, "invalid_route_id", "快照编号无效")

        if method == "GET" and path == "/api/overview":
            self._no_query(query)
            return _success(self._overview())
        if method == "GET" and path == "/api/features":
            self._no_query(query)
            return _success(self.feature_registry.catalog())
        if method == "GET" and path == "/api/cases":
            return _success(self._list_cases(query))
        match = _CASE_DOWNLOAD.fullmatch(path)
        if match:
            if method != "GET":
                return self._route_error(method)
            self._no_query(query)
            return self._download_case(match.group(1), match.group(2))
        match = _CASE.fullmatch(path)
        if method == "GET" and match:
            self._no_query(query)
            return _success(self._get_case(match.group(1)))
        match = _DOWNLOAD.fullmatch(path)
        if method == "GET" and match:
            self._no_query(query)
            return self._download(match.group(1), match.group(2))

        feature = _FEATURE_RUN.fullmatch(path)
        if feature:
            if method != "POST":
                return self._route_error(method)
            self._no_query(query)
            stream = io.BytesIO(body) if isinstance(body, bytes) else body
            data = read_json_body(stream, headers, self.config.max_request_bytes)
            return _success(self._run_feature(feature.group(1), data))

        review = _REVIEW.fullmatch(path)
        posts = {"/api/analyze", "/api/audit-python", "/api/audit-project",
                 "/api/doctor", "/api/sop"}
        if method == "POST" and (review or path in posts):
            self._no_query(query)
            stream = io.BytesIO(body) if isinstance(body, bytes) else body
            data = read_json_body(stream, headers, self.config.max_request_bytes)
            if review:
                return _success(self._review(review.group(1), data))
            return _success(self._operation(path, data))

        known_wrong_method = (path in _ASSETS or path in posts
                              or path in {"/api/overview", "/api/cases", "/api/features"}
                              or _CASE.fullmatch(path) or _REVIEW.fullmatch(path) or _DOWNLOAD.fullmatch(path))
        if known_wrong_method:
            return self._route_error(method)
        if path.startswith("/api/cases/") or path.startswith("/api/runs/"):
            pieces = path.split("/")
            candidate = pieces[3] if len(pieces) > 3 else ""
            if candidate and _ID.fullmatch(candidate) is None:
                raise RequestRejected(400, "invalid_route_id", "路由标识无效")
        return _error(404, "not_found", "请求的资源不存在。")

    def _run_feature(self, feature_id: str, data: dict[str, object]) -> dict[str, object]:
        registered = self.feature_registry.get(feature_id)
        if registered is None:
            raise RequestRejected(404, "feature_not_found", "功能不存在或未启用")
        values = validate_feature_input(registered.manifest, data, self.config.workspace)
        context = FeatureContext(
            workspace=self.config.workspace,
            resolve_workspace_path=resolve_workspace_path,
        )
        try:
            result = registered.handler(context, values)
        except Exception as exc:
            raise _FeatureExecutionError("trusted feature failed") from exc
        presented = present_feature_result(registered.manifest, result)
        encoded = json.dumps(
            presented, ensure_ascii=False, indent=2, allow_nan=False
        ).encode("utf-8") + b"\n"
        downloads = {"json": (JSON_MIME, encoded)}
        try:
            run_id = self.cache.put(f"feature:{feature_id}", presented, downloads)
        except ValueError as exc:
            raise FeatureResultError("功能结果无法缓存") from exc
        data_out = dict(presented)
        data_out["run_id"] = run_id
        data_out["downloads"] = {"json": f"/api/runs/{run_id}/download/json"}
        with self._recent_runs_lock:
            self._recent_runs.append({
                "run_id": run_id, "kind": "trusted_feature", "feature_id": feature_id,
                "title": presented["title"], "status": presented["status"],
                "summary_cards": [dict(card) for card in presented["summary_cards"]],
            })
        return data_out

    @staticmethod
    def _route_error(method: str) -> Response:
        return _error(405 if method in {"GET", "POST"} else 405,
                      "method_not_allowed", "不支持此请求方法。",
                      extra={"Allow": "GET, POST"})

    @staticmethod
    def _no_query(query: str) -> None:
        if query:
            _query(query, set())

    def _store(self):
        try:
            return CaseStore(self.config.case_db, create=True)
        except ValueError as exc:
            raise OSError("case store unavailable") from exc

    @contextmanager
    def _history_store(self):
        layout = RuntimeLayout.build(self.config.workspace)
        identity = load_project_identity(layout)
        with DatabaseManager.open(layout.history_db) as database:
            yield HistoryRepository(database.connection), identity.project_id

    def _persistent_audit(
        self, environment: Path, lock_file: Path | None,
        vuln_db: Path | None, vuln_api: str | None,
    ) -> dict[str, object]:
        layout = RuntimeLayout.build(self.config.workspace)
        identity = load_project_identity(layout)
        settings = load_settings(layout)
        outcome = audit_with_persistent_history(
            environment,
            lock_file=lock_file,
            vuln_db=vuln_db,
            vuln_api=vuln_api,
            history_db=layout.history_db,
            project_id=identity.project_id,
            display_name=identity.display_name,
            retention_days=settings.audit_retention_days,
        )
        result = self._cache_result(
            "audit-project" if lock_file is not None else "audit-python",
            outcome.result, html_download=lock_file is not None,
        )
        result["history"] = {
            "run_id": outcome.run_id,
            "snapshot_id": outcome.snapshot_id,
            "reused": outcome.reused,
            "baseline_run_id": outcome.baseline_run_id,
            "classification": outcome.change_summary.classification,
        }
        return result

    @staticmethod
    def _case_exists(store: CaseStore, case_id: str) -> bool:
        return store.connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? LIMIT 1", (case_id,)
        ).fetchone() is not None

    @staticmethod
    def _review_exists(store: CaseStore, case_id: str) -> bool:
        return store.connection.execute(
            "SELECT 1 FROM reviews WHERE case_id=? LIMIT 1", (case_id,)
        ).fetchone() is not None

    def _overview(self) -> dict:
        with self._store() as store:
            recent = store.list_cases(status=None, query="", limit=5, offset=0)
            awaiting = store.list_cases(status="awaiting_review", query="", limit=1, offset=0)
        runs = self._recent_run_snapshot()
        with self._recent_runs_lock:
            doctor_status = self._doctor_status
        return {"total": recent["total"], "awaiting_review": awaiting["total"],
                "recent": recent["items"],
                "token_configured": os.environ.get("SVAROG_VULN_API_TOKEN") is not None,
                "recent_runs": runs,
                "doctor_status": doctor_status,
                "doctor_notice": ("Doctor 尚未检查。" if doctor_status == "not_run"
                                  else "Doctor 最近一次状态已记录。"),
                "run_history_volatile": True,
                "run_history_notice": "非 SOP 运行记录仅保存在内存中，服务重启后会清空。"}

    def _list_cases(self, query: str) -> dict:
        values = _query(query, {"status", "query", "limit", "offset"})
        status = values.get("status") or None
        if status not in {None, "awaiting_review", "approved", "rejected", "needs_investigation"}:
            raise _InputError({"status": "请选择有效状态。"})
        search = values.get("query", "")
        if len(search) > 256 or any(unicodedata.category(c).startswith("C") for c in search):
            raise _InputError({"query": "搜索文本无效。"})
        limit = _query_integer(values.get("limit", "20"), "limit", 1, 100)
        offset = _query_integer(values.get("offset", "0"), "offset", 0, 100000)
        with self._store() as store:
            return store.list_cases(status=status, query=search, limit=limit, offset=offset)

    def _get_case(self, case_id: str) -> dict:
        with self._store() as store:
            if not self._case_exists(store, case_id):
                raise RequestRejected(404, "case_not_found", "案件不存在")
            try:
                return self._case_response(store.get(case_id))
            except ValueError as exc:
                raise OSError("case payload unavailable") from exc

    def _review(self, case_id: str, data: dict[str, object]) -> dict:
        _keys(data, {"decision", "reviewer", "note"}, {"decision", "reviewer", "note"})
        decision = data["decision"]
        if decision not in {"approve", "reject", "needs_investigation"}:
            raise _InputError({"decision": "请选择有效决定。"})
        reviewer = _safe_text(data["reviewer"], "reviewer", 128)
        note = _safe_text(data["note"], "note", 2000)
        with self._store() as store:
            if not self._case_exists(store, case_id):
                raise RequestRejected(404, "case_not_found", "案件不存在")
            try:
                store.review(case_id, decision, reviewer, note)  # type: ignore[arg-type]
            except ValueError as exc:
                if self._review_exists(store, case_id):
                    raise RequestRejected(
                        409, "review_conflict", "案件已经复核，不能覆盖。"
                    ) from None
                raise OSError("case review unavailable") from exc
            try:
                return self._case_response(store.get(case_id))
            except ValueError as exc:
                raise OSError("case payload unavailable") from exc

    def _operation(self, route: str, data: dict[str, object]) -> dict:
        if route == "/api/analyze":
            _keys(data, {"logs"}, {"logs"})
            with self._temporary_directory() as directory:
                logs = decode_upload(directory, _upload(data["logs"], "logs"), 10 * 1024 * 1024, ".jsonl")
                result = analyze_web_log(logs)
            return self._cache_result("analyze", result, html_download=False)

        common_allowed = {"environment", "vuln_db", "vuln_api"}
        required = {"environment"}
        if route == "/api/audit-python":
            _keys(data, common_allowed, required)
            env, db, api = self._audit_inputs(data)
            return self._persistent_audit(env, None, db, api)
        if route == "/api/audit-project":
            _keys(data, common_allowed | {"lock_file"}, required | {"lock_file"})
            env, db, api = self._audit_inputs(data)
            lock = self._path(data["lock_file"], "lock_file", "file")
            return self._persistent_audit(env, lock, db, api)
        if route == "/api/doctor":
            allowed = common_allowed | {"lock_file", "output_directory"}
            _keys(data, allowed, required | {"lock_file", "output_directory"})
            env, db, api = self._audit_inputs(data)
            lock = self._path(data["lock_file"], "lock_file", "file")
            output = self._path(data["output_directory"], "output_directory", "directory")
            result = run_doctor_check(env, lock, output, vuln_db=db, vuln_api=api)
            return self._cache_result("doctor", result, html_download=False)

        allowed = {"alert", "logs", "log_format", "log_host", "window_minutes",
                   "limit", "agent_config"}
        required = {"alert", "logs", "log_format", "window_minutes", "limit"}
        _keys(data, allowed, required)
        log_format = data["log_format"]
        if log_format not in {"jsonl", "nginx-combined"}:
            raise _InputError({"log_format": "请选择有效日志格式。"})
        log_host = _safe_text(data.get("log_host"), "log_host", 253, nullable=True)
        window = _integer(data["window_minutes"], "window_minutes", 1, 1440)
        limit = _integer(data["limit"], "limit", 1, 1000)
        agent = None if data.get("agent_config") is None else self._path(data["agent_config"], "agent_config", "file")
        with self._temporary_directory() as directory:
            alert = decode_upload(directory, _upload(data["alert"], "alert"), 64 * 1024, ".json")
            suffix = ".jsonl" if log_format == "jsonl" else ".log"
            logs = decode_upload(directory, _upload(data["logs"], "logs"), 10 * 1024 * 1024, suffix)
            result = run_sop_case(alert, logs, case_db=self.config.case_db,
                                  log_format=log_format, log_host=log_host,
                                  window_minutes=window, limit=limit, agent_config=agent,
                                  persist=False)
        if not isinstance(result, dict) or result.get("kind") != "sop_case":
            raise _SchemaError()
        case = result.get("report")
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str):
            raise OSError("invalid adapter result")
        self._present_case(case)
        with self._store() as store:
            try:
                store.save(case)
                saved_case = store.get(case["case_id"])
            except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
                raise _SchemaError() from exc
        return self._case_response(saved_case)

    def _audit_inputs(self, data: dict[str, object]) -> tuple[Path, Path | None, str | None]:
        environment = self._path(data["environment"], "environment", "directory")
        raw_db, raw_api = data.get("vuln_db"), data.get("vuln_api")
        if (raw_db is None) == (raw_api is None):
            raise _InputError({"vuln_db": "漏洞来源必须且只能选择一个。",
                               "vuln_api": "漏洞来源必须且只能选择一个。"})
        database = None if raw_db is None else self._path(raw_db, "vuln_db", "file")
        return environment, database, _api_url(raw_api)

    def _path(self, value: object, name: str, kind: str) -> Path:
        if not isinstance(value, str):
            raise _InputError({name: "请输入工作区相对路径。"})
        try:
            return resolve_workspace_path(self.config.workspace, value, kind=kind)
        except ValueError:
            raise _InputError({name: "请输入工作区内有效的相对路径。"}) from None

    def _temporary_root(self) -> Path:
        root = self.config.workspace.resolve(strict=True)
        try:
            svarog_root = self._verified_local_directory(root / ".svarog", root)
            return self._verified_local_directory(svarog_root / "tmp", root)
        except (OSError, ValueError, RuntimeError) as exc:
            raise OSError("temporary directory unavailable") from exc

    @contextmanager
    def _temporary_directory(self):
        workspace = self.config.workspace.resolve(strict=True)
        temp_root = self._temporary_root()
        with tempfile.TemporaryDirectory(dir=temp_root) as raw_leaf:
            leaf = Path(raw_leaf)
            try:
                if leaf.is_symlink():
                    raise OSError("linked temporary directory forbidden")
                details = leaf.lstat()
                if not stat.S_ISDIR(details.st_mode):
                    raise OSError("temporary directory required")
                resolved = leaf.resolve(strict=True)
                resolved.relative_to(workspace)
                if leaf.parent.resolve(strict=True) != temp_root:
                    raise OSError("temporary parent changed")
                if resolved.parent != temp_root or not resolved.is_dir():
                    raise OSError("temporary directory escaped")
            except (OSError, ValueError, RuntimeError) as exc:
                raise OSError("temporary directory unavailable") from exc
            yield resolved

    @staticmethod
    def _verified_local_directory(candidate: Path, workspace: Path) -> Path:
        # Inspect each level before creating descendants so a link can never cause
        # mkdir to materialize the next component outside the workspace.
        if candidate.is_symlink():
            raise OSError("linked directory forbidden")
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            candidate.mkdir()
        else:
            if not stat.S_ISDIR(details.st_mode):
                raise OSError("directory required")
        if candidate.is_symlink():
            raise OSError("linked directory forbidden")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(workspace)
        if not resolved.is_dir():
            raise OSError("directory required")
        return resolved

    def _cache_result(self, kind: str, result: object, *, html_download: bool) -> dict:
        if type(result) is not dict:
            raise _SchemaError()
        presentation = self._present_result(kind, result)
        try:
            encoded = json.dumps(result, ensure_ascii=False, indent=2,
                                 allow_nan=False).encode("utf-8") + b"\n"
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
            raise _SchemaError() from exc
        downloads = {"json": (JSON_MIME, encoded)}
        if html_download:
            downloads["html"] = (HTML_MIME, self._single_file_html("Svarog 项目审计", result))
        try:
            run_id = self.cache.put(kind, result, downloads)
        except ValueError as exc:
            raise OSError("run cache unavailable") from exc
        data = dict(result)
        data.update(presentation)
        data["run_id"] = run_id
        data["downloads"] = {name: f"/api/runs/{run_id}/download/{name}" for name in downloads}
        with self._recent_runs_lock:
            self._recent_runs.append({"run_id": run_id, "kind": data["kind"],
                                      "title": data["title"], "status": data["status"],
                                      "summary_cards": [dict(card) for card in data["summary_cards"]]})
            if data["kind"] == "doctor":
                self._doctor_status = data["status"]
        return data

    def _recent_run_snapshot(self) -> list[dict[str, object]]:
        with self._recent_runs_lock:
            return [dict(item) for item in reversed(self._recent_runs)]

    def _case_response(self, case: dict) -> dict:
        presentation = self._present_case(case)
        data = dict(case)
        data.update(presentation)
        data["case"] = dict(case)
        case_id = case["case_id"]
        data["downloads"] = {
            name: f"/api/cases/{case_id}/download/{name}" for name in ("json", "html")
        }
        return data

    @staticmethod
    def _single_file_html(title: str, value: object) -> bytes:
        pretty = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        document = ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
                    "style-src 'unsafe-inline'\"><title>" + html.escape(title, quote=True)
                    + "</title></head><body><main><h1>" + html.escape(title, quote=True)
                    + "</h1><pre>" + html.escape(pretty, quote=True)
                    + "</pre></main></body></html>")
        return document.encode("utf-8")

    @staticmethod
    def _cards(summary: object) -> list[dict[str, object]]:
        if not isinstance(summary, dict):
            return []
        return [{"key": key, "label": label, "value": summary[key]}
                for key, label in _SUMMARY_LABELS.items()
                if key in summary and type(summary[key]) in {int, float, str}]

    @staticmethod
    def _table(table_id: str, title: str, columns: list[tuple[str, str, str]],
               rows: object) -> dict:
        source = rows if isinstance(rows, list) else []
        fixed_rows = []
        for row in source:
            if not isinstance(row, dict):
                continue
            fixed_rows.append({key: row.get(key, "") for key, _label, _kind in columns})
        return {"id": table_id, "title": title,
                "columns": [{"key": key, "label": label, "type": kind}
                            for key, label, kind in columns], "rows": fixed_rows}

    @staticmethod
    def _required_dict_rows(
        report: dict, name: str, required: frozenset[str] = frozenset()
    ) -> list[dict]:
        value = report.get(name)
        if (type(value) is not list or any(
                type(item) is not dict or not required.issubset(item)
                for item in value)):
            raise _SchemaError()
        return value

    @staticmethod
    def _required_warnings(report: dict) -> list[str]:
        value = report.get("warnings")
        if type(value) is not list or any(type(item) is not str for item in value):
            raise _SchemaError()
        return list(value)

    def _present_result(self, expected_kind: str, result: dict) -> dict:
        expected_kind = {"analyze": "web_analysis", "audit-python": "dependency_audit",
                         "audit-project": "project_audit"}.get(expected_kind, expected_kind)
        kind = result.get("kind")
        report = result.get("report")
        if kind != expected_kind or kind not in _TITLES or type(report) is not dict:
            raise _SchemaError()
        if kind != "doctor" and report.get("actions_executed") is not False:
            raise _SchemaError()
        if kind == "doctor" and report.get("actions_executed", False) is not False:
            raise _SchemaError()
        status_key = "overall_status" if kind == "doctor" else (
            "analysis_status" if kind == "web_analysis" else "audit_status")
        status = report.get(status_key)
        if status not in _RESULT_STATUSES[kind]:
            raise _SchemaError()
        warnings = ([] if kind == "doctor" and "warnings" not in report
                    else self._required_warnings(report))
        tables: list[dict] = []
        if kind == "dependency_audit":
            if (type(report.get("summary")) is not dict
                    or not _REQUIRED_SUMMARY_KEYS[kind].issubset(report["summary"])
                    or any(type(report["summary"][key]) is not int
                           for key in _REQUIRED_SUMMARY_KEYS[kind])):
                raise _SchemaError()
            columns = [("package_name", "包", "text"), ("installed_version", "安装版本", "text"),
                       ("severity", "严重度", "text"), ("ghsa_id", "公告", "text"),
                       ("fixed_version", "修复版本", "text"), ("summary", "摘要", "text")]
            tables.extend([
                self._table("installed_packages", "已安装包", [
                    ("name", "包", "text"), ("version", "版本", "text"),
                    ("version_valid", "版本有效", "text")],
                    self._required_dict_rows(report, "installed_packages",
                                             frozenset({"name", "version", "version_valid"}))),
                self._table("findings", "确认漏洞", columns,
                            self._required_dict_rows(report, "findings", frozenset({
                                "package_name", "installed_version", "severity", "ghsa_id",
                                "fixed_version", "summary"}))),
                self._table("indeterminate_findings", "无法判断", [
                    ("package_name", "包", "text"), ("installed_versions", "安装版本", "text"),
                    ("ghsa_id", "公告", "text"), ("affected_range", "影响范围", "text"),
                    ("fixed_version", "修复版本", "text"), ("reason_code", "原因", "text")],
                    self._required_dict_rows(report, "indeterminate_findings", frozenset({
                        "package_name", "installed_versions", "ghsa_id", "affected_range",
                        "fixed_version", "reason_code"}))),
            ])
        elif kind == "project_audit":
            if (type(report.get("summary")) is not dict
                    or not _REQUIRED_SUMMARY_KEYS[kind].issubset(report["summary"])
                    or any(type(report["summary"][key]) is not int
                           for key in _REQUIRED_SUMMARY_KEYS[kind])):
                raise _SchemaError()
            tables.extend([
                self._table("installed_packages", "环境包", [
                    ("name", "包", "text"), ("version", "版本", "text"),
                    ("version_valid", "版本有效", "text")],
                    self._required_dict_rows(report, "installed_packages",
                                             frozenset({"name", "version", "version_valid"}))),
                self._table("locked_packages", "锁文件包", [
                    ("name", "包", "text"), ("version", "版本", "text"),
                    ("source_kind", "来源", "text")],
                    self._required_dict_rows(report, "locked_packages",
                                             frozenset({"name", "version", "source_kind"}))),
                self._table("version_differences", "版本差异", [
                    ("name", "包", "text"), ("installed_versions", "环境版本", "text"),
                    ("locked_versions", "锁定版本", "text"), ("status", "状态", "text")],
                    self._required_dict_rows(report, "version_differences", frozenset({
                        "name", "installed_versions", "locked_versions", "status"}))),
                self._table("environment_findings", "环境确认漏洞", [
                    ("package_name", "包", "text"), ("installed_version", "环境版本", "text"),
                    ("severity", "严重度", "text"), ("ghsa_id", "公告", "text"),
                    ("fixed_version", "修复版本", "text"), ("summary", "摘要", "text")],
                    self._required_dict_rows(report, "environment_findings", frozenset({
                        "package_name", "installed_version", "severity", "ghsa_id",
                        "fixed_version", "summary"}))),
                self._table("environment_indeterminate_findings", "环境无法判断", [
                    ("package_name", "包", "text"), ("installed_versions", "环境版本", "text"),
                    ("ghsa_id", "公告", "text"), ("reason_code", "原因", "text")],
                    self._required_dict_rows(report, "environment_indeterminate_findings", frozenset({
                        "package_name", "installed_versions", "ghsa_id", "reason_code"}))),
                self._table("lock_findings", "锁文件潜在漏洞", [
                    ("package_name", "包", "text"), ("locked_version", "锁定版本", "text"),
                    ("severity", "严重度", "text"), ("ghsa_id", "公告", "text"),
                    ("fixed_version", "修复版本", "text"), ("summary", "摘要", "text")],
                    self._required_dict_rows(report, "lock_findings", frozenset({
                        "package_name", "locked_version", "severity", "ghsa_id",
                        "fixed_version", "summary"}))),
                self._table("lock_indeterminate_findings", "锁文件无法判断", [
                    ("package_name", "包", "text"), ("locked_version", "锁定版本", "text"),
                    ("ghsa_id", "公告", "text"), ("reason_code", "原因", "text")],
                    self._required_dict_rows(report, "lock_indeterminate_findings", frozenset({
                        "package_name", "locked_version", "ghsa_id", "reason_code"}))),
            ])
        elif kind == "doctor":
            checks = self._required_dict_rows(
                report, "checks", frozenset({"title", "status", "message"})
            )
            if any(check["status"] not in {"pass", "warn", "fail"} for check in checks):
                raise _SchemaError()
            tables.append(self._table("checks", "检查项", [
                ("title", "检查", "text"), ("status", "状态", "text"),
                ("message", "说明", "text")], checks))
        elif kind == "web_analysis":
            if (type(report.get("summary")) is not dict
                    or not _REQUIRED_SUMMARY_KEYS[kind].issubset(report["summary"])
                    or any(type(report["summary"][key]) is not int
                           for key in _REQUIRED_SUMMARY_KEYS[kind])):
                raise _SchemaError()
            events = self._required_dict_rows(report, "events", frozenset({
                "event", "local_severity", "conclusion", "evidence", "recommendations"}))
            rows = []
            recommendations = []
            for item in events:
                event = item.get("event")
                evidence = item.get("evidence")
                advice = item.get("recommendations")
                if (type(event) is not dict or type(evidence) is not list
                        or any(type(rule) is not dict for rule in evidence)
                        or type(advice) is not list or any(type(value) is not str for value in advice)):
                    raise _SchemaError()
                rules = [f'{rule.get("rule_id", "")}: {rule.get("description", "")}'.strip(": ")
                         for rule in evidence]
                request = f'{event.get("method", "")} {event.get("path", "")}'.strip()
                rows.append({"timestamp": event.get("timestamp", ""), "source_ip": event.get("source_ip", ""),
                             "request": request, "severity": item.get("local_severity", ""),
                             "conclusion": item.get("conclusion", ""), "rules": rules})
                recommendations.extend({"request": request, "recommendation": value}
                                       for value in advice)
            tables.append(self._table("events", "事件分析", [
                ("timestamp", "时间", "text"), ("source_ip", "来源", "text"),
                ("request", "请求", "text"), ("severity", "严重度", "text"),
                ("conclusion", "结论", "text"), ("rules", "规则证据", "text")], rows))
            tables.append(self._table("recommendations", "处置建议", [
                ("request", "请求", "text"), ("recommendation", "建议", "text")], recommendations))
        cards = self._cards(report.get("summary"))
        if kind == "doctor":
            counts = {"pass": 0, "warn": 0, "fail": 0}
            for check in self._required_dict_rows(report, "checks"):
                value = check.get("status")
                if value in counts:
                    counts[value] += 1
            cards = [{"key": key, "label": label, "value": counts[key]}
                     for key, label in (("pass", "通过"), ("warn", "警告"), ("fail", "失败"))]
        return {"schema": "svarog.workbench.result.v1", "kind": kind,
                "title": _TITLES[kind], "status": status,
                "summary_cards": cards,
                "warnings": warnings, "tables": tables, "actions_executed": False}

    def _present_case(self, case: dict) -> dict:
        if (type(case) is not dict or not isinstance(case.get("case_id"), str)
                or _ID.fullmatch(case["case_id"]) is None
                or case.get("status") not in {
                    "awaiting_review", "approved", "rejected", "needs_investigation"
                }
                or case.get("actions_executed") is not False):
            raise _SchemaError()
        created_at = case.get("created_at")
        if type(created_at) is not str:
            raise _SchemaError()
        try:
            parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise _SchemaError() from exc
        if parsed_created_at.tzinfo is None:
            raise _SchemaError()
        required_lists = ("steps", "evidence", "iocs", "attack_mappings", "recommendations")
        if any(type(case.get(name)) is not list or any(type(item) is not dict for item in case[name])
               for name in required_lists):
            raise _SchemaError()
        if (type(case.get("alert")) is not dict or type(case.get("agent")) is not dict
                or type(case.get("query")) is not dict
                or type(case.get("warnings")) is not list
                or any(type(item) is not str for item in case["warnings"])
                or (case.get("review") is not None and type(case.get("review")) is not dict)):
            raise _SchemaError()
        alert = case["alert"]
        if not isinstance(alert.get("title"), str) or not isinstance(alert.get("severity"), str):
            raise _SchemaError()
        if len(case["steps"]) != len(_SOP_STEP_NAMES):
            raise _SchemaError()
        for index, (step, expected_name) in enumerate(zip(case["steps"], _SOP_STEP_NAMES), start=1):
            if (type(step.get("number")) is not int or step["number"] != index
                    or step.get("name") != expected_name or type(step.get("status")) is not str
                    or ("detail" in step and type(step["detail"]) is not str)):
                raise _SchemaError()
            allowed_statuses = ({"completed", "partial", "no_evidence"} if index == 3
                                else ({case["status"]} if index == 7 else {"completed"}))
            if step["status"] not in allowed_statuses:
                raise _SchemaError()
        if not {"mode", "summary", "query_plan"}.issubset(case["agent"]):
            raise _SchemaError()
        if not {"matched", "retained", "invalid_lines", "truncated"}.issubset(case["query"]):
            raise _SchemaError()
        evidence = case["evidence"]
        evidence_ids = []
        for item in evidence:
            if not {"id", "event"}.issubset(item) or type(item["id"]) is not str:
                raise _SchemaError()
            if re.fullmatch(r"log:[1-9][0-9]*", item["id"]) is None or type(item["event"]) is not dict:
                raise _SchemaError()
            evidence_ids.append(item["id"])
        if len(evidence_ids) != len(set(evidence_ids)):
            raise _SchemaError()
        valid_evidence = frozenset(evidence_ids)
        reference_groups = (
            (case["iocs"], frozenset({"type", "value", "role", "status", "evidence_ids"})),
            (case["attack_mappings"], frozenset({
                "technique_id", "name", "status", "rationale", "evidence_ids"})),
            (case["recommendations"], frozenset({
                "id", "text", "precondition", "impact", "evidence_ids"})),
        )
        for rows, required in reference_groups:
            for row in rows:
                refs = row.get("evidence_ids")
                if (not required.issubset(row) or type(refs) is not list
                        or any(type(ref) is not str or ref not in valid_evidence for ref in refs)):
                    raise _SchemaError()
        if case["review"] is not None and not {
                "decision", "reviewer", "note", "reviewed_at"}.issubset(case["review"]):
            raise _SchemaError()
        evidence_rows = []
        for item in evidence:
            event = item.get("event") if isinstance(item.get("event"), dict) else {}
            evidence_rows.append({"id": item.get("id", ""), "timestamp": event.get("timestamp", ""),
                                  "source_ip": event.get("source_ip", ""),
                                  "request": f'{event.get("method", "")} {event.get("path", "")}'.strip()})
        attacks = []
        for item in case["attack_mappings"]:
            match = _ATTACK_ID.fullmatch(str(item.get("technique_id", "")))
            row = {key: item.get(key, "") for key in ("technique_id", "name", "status", "rationale", "evidence_ids")}
            row["url"] = (f"https://attack.mitre.org/techniques/T{match.group(1)}/"
                          + (f"{match.group(2)}/" if match and match.group(2) else "")) if match else ""
            attacks.append(row)
        columns = [("id", "证据", "evidence_target"), ("timestamp", "时间", "text"),
                   ("source_ip", "来源", "text"), ("request", "请求", "text")]
        tables = [self._table("steps", "SOP 进度", [
                      ("number", "步骤", "text"), ("name", "名称", "text"),
                      ("status", "状态", "text"), ("detail", "说明", "text")], case["steps"]),
                  self._table("agent", "Agent 分析", [
                      ("mode", "模式", "text"), ("summary", "摘要", "text"),
                      ("query_plan", "查询计划", "text")], [case["agent"]]),
                  self._table("query", "日志查询覆盖", [
                      ("matched", "匹配", "text"), ("retained", "保留", "text"),
                      ("invalid_lines", "无效行", "text"), ("truncated", "是否截断", "text")],
                      [case["query"]]),
                  self._table("evidence", "证据", columns, evidence_rows),
                  self._table("iocs", "IOC 候选", [
                      ("type", "类型", "text"), ("value", "值", "text"),
                      ("role", "角色", "text"), ("status", "状态", "text"),
                      ("evidence_ids", "证据", "evidence_links")], case.get("iocs")),
                  self._table("attack", "ATT&CK 候选映射", [
                      ("technique_id", "技术", "attack_link"), ("name", "名称", "text"),
                      ("status", "状态", "text"), ("rationale", "依据", "text"),
                      ("evidence_ids", "证据", "evidence_links"), ("url", "链接", "hidden")], attacks),
                  self._table("recommendations", "处置建议（待人工确认）", [
                      ("id", "编号", "text"), ("text", "建议", "text"),
                      ("precondition", "前提", "text"), ("impact", "影响", "text"),
                      ("evidence_ids", "证据", "evidence_links")], case["recommendations"])]
        if case["review"] is not None:
            tables.append(self._table("review", "人工复核记录", [
                ("decision", "决定", "text"), ("reviewer", "复核人", "text"),
                ("note", "说明", "text"), ("reviewed_at", "复核时间", "text")], [case["review"]]))
        severity = alert.get("severity") if isinstance(alert.get("severity"), str) else "未知"
        return {"schema": "svarog.workbench.result.v1", "kind": "sop_case",
                "title": str(alert.get("title") or _TITLES["sop_case"]),
                "status": case["status"],
                "case_id": case["case_id"], "review": case.get("review"),
                "summary_cards": [{"key": "severity", "label": "告警严重度", "value": severity},
                                  {"key": "steps", "label": "SOP 步骤", "value": len(case["steps"])},
                                  {"key": "evidence", "label": "证据", "value": len(evidence)},
                                  {"key": "iocs", "label": "IOC", "value": len(case["iocs"])},
                                  {"key": "attack", "label": "ATT&CK", "value": len(attacks)}],
                "warnings": list(case["warnings"]),
                "tables": tables, "actions_executed": False}

    def _download_case(self, case_id: str, name: str) -> Response:
        with self._store() as store:
            if not self._case_exists(store, case_id):
                return _error(404, "case_not_found", "案件不存在。")
            try:
                case = store.get(case_id)
            except ValueError as exc:
                raise OSError("case payload unavailable") from exc
        if name == "json":
            payload = json.dumps(case, ensure_ascii=False, indent=2,
                                 allow_nan=False).encode("utf-8") + b"\n"
            mime = JSON_MIME
        else:
            payload = self._single_file_html("Svarog 告警调查案件", case)
            mime = HTML_MIME
        filename = f"svarog-case-{case_id}.{name}"
        disposition = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{filename}'
        return _response(200, mime, payload, {"Content-Disposition": disposition})

    def _download(self, run_id: str, name: str) -> Response:
        try:
            record = self.cache.get(run_id)
            mime, payload = record.downloads[name]
        except (ValueError, KeyError):
            return _error(404, "run_not_found", "运行记录或下载不存在。")
        slug = _DOWNLOAD_KIND_SLUGS.get(record.kind, "report")
        filename = f"svarog-{slug}-{record.run_id}.{name}"
        disposition = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{filename}'
        return _response(200, mime, payload, {"Content-Disposition": disposition})


__all__ = ["Response", "WorkbenchApplication"]
