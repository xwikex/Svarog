"""Difference route uses project-scoped persisted snapshots."""

import io
import json

from test_history_api import _request, history_app


def test_manual_compare_and_scope_validation(history_app):
    app, _, snapshot_id = history_app
    response, data = _request(app, "POST", "/api/audit-history/compare", {
        "baseline_snapshot_id": snapshot_id,
        "target_snapshot_id": snapshot_id,
    })
    assert response.status == 200
    assert data["data"]["classification"] == "no_change"
    assert data["data"]["actions_executed"] is False
    assert _request(app, "POST", "/api/audit-history/compare", {
        "baseline_snapshot_id": 999999,
        "target_snapshot_id": snapshot_id,
    })[0].status == 404
    assert _request(app, "POST", "/api/audit-history/compare", {
        "target_snapshot_id": True,
    })[0].status == 400
    assert _request(app, "GET", "/api/audit-history/compare")[0].status == 405


def test_compare_rejects_duplicate_json_keys(history_app):
    app, _, snapshot_id = history_app
    raw = ('{"target_snapshot_id":%d,"target_snapshot_id":%d}' %
           (snapshot_id, snapshot_id)).encode()
    response = app.handle(
        "POST", "/api/audit-history/compare",
        {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765",
         "X-Svarog-CSRF": "token", "Content-Type": "application/json",
         "Content-Length": str(len(raw))},
        io.BytesIO(raw),
    )
    assert response.status == 400
