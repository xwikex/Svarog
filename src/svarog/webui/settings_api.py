"""Bounded domain adapter for the local settings and project Web APIs.

Request parsing, response envelopes, and mutation security remain with the router.
"""

from __future__ import annotations

from typing import Any

from svarog.runtime_layout import (
    ProjectIdentity,
    RuntimeLayout,
    RuntimeLayoutError,
    RuntimeSettings,
    load_project_identity,
    load_settings,
    save_settings,
)


class SettingsApiInputError(ValueError):
    """Invalid browser fields; ``fields`` is safe to include in a 400 response."""

    def __init__(self, fields: dict[str, str]) -> None:
        super().__init__("invalid_input")
        self.fields = fields


def _one_field(payload: object, name: str) -> Any:
    if type(payload) is not dict:
        raise SettingsApiInputError({name: "请输入有效值。"})
    fields = {key: "不支持的字段。" for key in payload if key != name}
    if name not in payload:
        fields[name] = "此字段必填。"
    if fields:
        raise SettingsApiInputError(fields)
    return payload[name]


def _settings_data(layout: RuntimeLayout, settings: RuntimeSettings) -> dict[str, object]:
    return {
        "schema_version": settings.schema_version,
        "audit_retention_days": settings.audit_retention_days,
        "data_directory": str(layout.root),
    }


def get_settings(layout: RuntimeLayout) -> dict[str, object]:
    """Return persisted settings and the server-derived, read-only data directory."""
    return _settings_data(layout, load_settings(layout))


def update_settings(layout: RuntimeLayout, payload: object) -> dict[str, object]:
    """Persist an integer retention period in the inclusive 3–365 day range."""
    days = _one_field(payload, "audit_retention_days")
    if type(days) is not int or not 3 <= days <= 365:
        raise SettingsApiInputError({"audit_retention_days": "请输入 3..365 的整数。"})
    return _settings_data(layout, save_settings(layout, {"audit_retention_days": days}))


def _project_data(identity: ProjectIdentity) -> dict[str, object]:
    return {
        "exists": True,
        "schema_version": identity.schema_version,
        "project_id": identity.project_id,
        "display_name": identity.display_name,
        "created_at": identity.created_at,
    }


def get_project(layout: RuntimeLayout) -> dict[str, object]:
    """Read identity without creating one; an absent identity is explicit."""
    try:
        identity = load_project_identity(layout)
    except RuntimeLayoutError as error:
        if str(error) == "project_identity_not_found":
            return {"exists": False}
        raise
    return _project_data(identity)


def update_project(layout: RuntimeLayout, payload: object) -> dict[str, object]:
    """Create or rename an identity using runtime-layout display-name rules."""
    display_name = _one_field(payload, "display_name")
    if display_name is None:
        raise SettingsApiInputError({"display_name": "请输入有效项目名称。"})
    try:
        identity = ProjectIdentity.load_or_create(layout, display_name=display_name)
    except RuntimeLayoutError as error:
        if str(error) == "invalid_display_name":
            raise SettingsApiInputError({"display_name": "请输入有效项目名称。"}) from None
        raise
    return _project_data(identity)
