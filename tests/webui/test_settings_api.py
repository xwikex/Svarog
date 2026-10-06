from __future__ import annotations

import json

import pytest

from svarog.runtime_layout import (
    ProjectIdentity,
    RuntimeLayout,
    RuntimeLayoutError,
    load_project_identity,
    load_settings,
)
from svarog.webui.settings_api import (
    SettingsApiInputError,
    get_project,
    get_settings,
    update_project,
    update_settings,
)


def test_get_settings_returns_only_safe_values_and_read_only_data_directory(tmp_path):
    layout = RuntimeLayout.build(tmp_path)

    result = get_settings(layout)

    assert result == {
        "schema_version": 1,
        "audit_retention_days": 180,
        "data_directory": str(layout.root),
    }
    assert json.loads(json.dumps(result)) == result
    assert str(layout.workspace) not in json.dumps({
        key: value for key, value in result.items() if key != "data_directory"
    })


@pytest.mark.parametrize("days", [3, 365])
def test_update_settings_persists_retention_boundaries(tmp_path, days):
    layout = RuntimeLayout.build(tmp_path)

    result = update_settings(layout, {"audit_retention_days": days})

    assert result == {
        "schema_version": 1,
        "audit_retention_days": days,
        "data_directory": str(layout.root),
    }
    assert load_settings(layout).audit_retention_days == days


@pytest.mark.parametrize("days", [2, 366, True, "180", 3.0, None])
def test_update_settings_rejects_invalid_retention_without_write(tmp_path, days):
    layout = RuntimeLayout.build(tmp_path)

    with pytest.raises(SettingsApiInputError) as raised:
        update_settings(layout, {"audit_retention_days": days})

    assert "audit_retention_days" in raised.value.fields
    assert not layout.settings_file.exists()


@pytest.mark.parametrize("payload", [{}, {"data_directory": "C:/other"},
                                     {"audit_retention_days": 3, "path": "C:/other"},
                                     [], None])
def test_update_settings_rejects_unexpected_or_missing_fields(tmp_path, payload):
    layout = RuntimeLayout.build(tmp_path)

    with pytest.raises(SettingsApiInputError):
        update_settings(layout, payload)

    assert not layout.settings_file.exists()


def test_get_project_does_not_create_missing_identity(tmp_path):
    layout = RuntimeLayout.build(tmp_path)

    result = get_project(layout)

    assert result == {"exists": False}
    assert not layout.project_file.exists()


def test_update_project_creates_and_then_renames_without_changing_identity(tmp_path):
    layout = RuntimeLayout.build(tmp_path)

    first = update_project(layout, {"display_name": "  Example  "})
    second = update_project(layout, {"display_name": "Renamed"})

    assert first["exists"] is True
    assert first["display_name"] == "Example"
    assert second == {
        "exists": True,
        "schema_version": 1,
        "project_id": first["project_id"],
        "display_name": "Renamed",
        "created_at": first["created_at"],
    }
    assert get_project(layout) == second
    assert load_project_identity(layout).project_id == first["project_id"]
    assert json.loads(json.dumps(second)) == second


@pytest.mark.parametrize("name", ["", "   ", "bad\nname", "C:/secret", "/secret", 7, None])
def test_update_project_rejects_invalid_name_without_creating_identity(tmp_path, name):
    layout = RuntimeLayout.build(tmp_path)

    with pytest.raises(SettingsApiInputError) as raised:
        update_project(layout, {"display_name": name})

    assert "display_name" in raised.value.fields
    assert not layout.project_file.exists()


@pytest.mark.parametrize("payload", [{}, {"project_id": "attacker"},
                                     {"display_name": "Safe", "workspace": "/other"},
                                     [], None])
def test_update_project_rejects_unexpected_or_missing_fields(tmp_path, payload):
    layout = RuntimeLayout.build(tmp_path)

    with pytest.raises(SettingsApiInputError):
        update_project(layout, payload)

    assert not layout.project_file.exists()


def test_get_project_does_not_hide_corrupt_identity(tmp_path):
    layout = RuntimeLayout.build(tmp_path)
    ProjectIdentity.load_or_create(layout, "Good")
    layout.project_file.write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeLayoutError):
        get_project(layout)


def test_settings_and_project_http_routes(tmp_path):
    import io
    from svarog.webui.application import WorkbenchApplication
    from svarog.webui.config import UiConfig

    app = WorkbenchApplication(UiConfig.build("127.0.0.1", 8765, tmp_path), "token")

    def request(method, path, data=None):
        raw = json.dumps(data or {}).encode()
        headers = {"Host": "127.0.0.1:8765"}
        if method == "POST":
            headers.update({
                "Origin": "http://127.0.0.1:8765", "X-Svarog-CSRF": "token",
                "Content-Type": "application/json", "Content-Length": str(len(raw)),
            })
        response = app.handle(method, path, headers, io.BytesIO(raw))
        return response, json.loads(response.body)

    assert request("GET", "/api/project")[1]["data"] == {"exists": False}
    assert request("POST", "/api/project", {"display_name": "Example"})[0].status == 200
    assert request("GET", "/api/project")[1]["data"]["display_name"] == "Example"
    assert request("GET", "/api/settings")[1]["data"]["audit_retention_days"] == 180
    assert request("POST", "/api/settings", {"audit_retention_days": 3})[1]["data"]["audit_retention_days"] == 3
    assert request("POST", "/api/settings", {"audit_retention_days": 2})[0].status == 400
    assert request("POST", "/api/settings", {"data_directory": "C:/elsewhere"})[0].status == 400
    assert request("POST", "/api/project", {"project_id": "attacker"})[0].status == 400
    assert request("GET", "/api/settings?foo=bar")[0].status == 400
    assert request("GET", "/api/settings")[0].status == 200
    assert request("GET", "/api/project")[0].status == 200
