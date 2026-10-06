from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from svarog.features.contracts import FeatureField, FeatureManifest
from svarog.features.registry import FeatureRegistry
from svarog.webui.application import WorkbenchApplication
from svarog.webui.config import UiConfig


HOST = "127.0.0.1:8765"


def _manifest() -> FeatureManifest:
    return FeatureManifest(
        feature_id="hash-file", title="文件哈希", description="计算工作区文件摘要", order=30,
        fields=(FeatureField(
            "target", "目标文件", "workspace_file", True, "只能选择工作区内文件"
        ),), permissions=frozenset({"workspace_read"}),
    )


def _result() -> dict:
    return {
        "status": "completed",
        "summary": [{"key": "files", "label": "文件", "value": 1}],
        "warnings": [],
        "tables": [{"id": "results", "title": "结果", "columns": [
            {"key": "digest", "label": "SHA-256", "type": "text"}],
            "rows": [{"digest": "abc"}]}],
        "actions_executed": False,
    }


@pytest.fixture
def feature_client(tmp_path: Path):
    target = tmp_path / "input.txt"
    target.write_text("demo", encoding="utf-8")
    calls = []

    def handler(context, values):
        calls.append((context, values))
        return _result()

    registry = FeatureRegistry.from_entries(((_manifest(), handler),))
    app = WorkbenchApplication(
        UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf", feature_registry=registry
    )

    def request(method: str, path: str, payload: dict | None = None):
        raw = json.dumps(payload or {}).encode()
        headers = {"Host": HOST}
        if method == "POST":
            headers.update({"Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
                            "Content-Type": "application/json", "Content-Length": str(len(raw))})
        response = app.handle(method, path, headers, io.BytesIO(raw))
        return response, json.loads(response.body)

    return request, calls, target


def test_feature_catalog_and_run_need_no_core_registration(feature_client) -> None:
    request, calls, target = feature_client
    response, catalog = request("GET", "/api/features")
    assert response.status == 200
    assert catalog["data"]["features"][0]["feature_id"] == "hash-file"

    response, payload = request("POST", "/api/features/hash-file/run", {"target": "input.txt"})
    assert response.status == 200
    data = payload["data"]
    assert data["schema"] == "svarog.workbench.feature-result.v1"
    assert data["feature_id"] == "hash-file" and data["actions_executed"] is False
    assert calls[0][0].workspace == target.parent.resolve()
    assert calls[0][1] == {"target": target.resolve()}
    download, _ = request("GET", data["downloads"]["json"])
    assert download.status == 200
    source = (Path(__file__).parents[2] / "src" / "svarog" / "webui" / "assets" / "app.js").read_text(
        encoding="utf-8"
    )
    assert "hash-file" not in source
    assert 'api(`/api/features/${encodeURIComponent(feature.feature_id)}/run`' in source


def test_feature_route_rejects_unknown_fields_and_unknown_features(feature_client) -> None:
    request, calls, _ = feature_client
    response, payload = request("POST", "/api/features/hash-file/run", {
        "target": "input.txt", "command": "calc.exe",
    })
    assert response.status == 400
    assert payload["error"]["code"] == "invalid_feature_input"
    assert payload["error"]["fields"] == {"command": "不支持此字段。"}
    assert calls == []

    response, payload = request("POST", "/api/features/missing/run", {})
    assert response.status == 404 and payload["error"]["code"] == "feature_not_found"


def test_feature_errors_and_active_results_are_redacted_and_not_cached(
    tmp_path: Path,
) -> None:
    def call(handler):
        registry = FeatureRegistry.from_entries(((_manifest(), handler),))
        app = WorkbenchApplication(
            UiConfig.build("127.0.0.1", 8765, tmp_path), "csrf", feature_registry=registry
        )
        raw = json.dumps({"target": "input.txt"}).encode()
        return app.handle("POST", "/api/features/hash-file/run", {
            "Host": HOST, "Origin": f"http://{HOST}", "X-Svarog-CSRF": "csrf",
            "Content-Type": "application/json", "Content-Length": str(len(raw)),
        }, io.BytesIO(raw))

    (tmp_path / "input.txt").write_text("demo", encoding="utf-8")
    failed = call(lambda _context, _values: (_ for _ in ()).throw(
        RuntimeError("C:/secret/token=value")
    ))
    assert failed.status == 500
    assert b"secret" not in failed.body and b"token" not in failed.body
    assert json.loads(failed.body)["error"]["code"] == "feature_failed"

    invalid = _result()
    invalid["actions_executed"] = True
    rejected = call(lambda _context, _values: invalid)
    assert rejected.status == 500
    assert json.loads(rejected.body)["error"]["code"] == "invalid_feature_result_schema"


def test_feature_routes_keep_existing_http_security(feature_client) -> None:
    request, calls, _ = feature_client
    response, _ = request("GET", "/api/features/hash-file/run")
    assert response.status == 405

    app_request, _, _ = feature_client
    response, _ = app_request("POST", "/api/features/hash-file/run", {"target": "../outside"})
    assert response.status == 400 and calls == []
