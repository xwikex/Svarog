"""Core-owned validation for trusted feature inputs and display results."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from pathlib import Path

from svarog.webui.config import resolve_workspace_path

from .contracts import FeatureManifest


MAX_FEATURE_RESULT_BYTES = 2 * 1024 * 1024
_SAFE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_RESULT_KEYS = frozenset({"status", "summary", "warnings", "tables", "actions_executed"})


class FeatureInputError(ValueError):
    def __init__(self, fields: dict[str, str]) -> None:
        super().__init__("功能输入无效")
        self.fields = dict(fields)


class FeatureResultError(ValueError):
    """Raised when a module returns a result outside the fixed display contract."""


def _safe_text(value: object, *, maximum: int, allow_empty: bool = False) -> bool:
    return (type(value) is str and len(value) <= maximum
            and (allow_empty or bool(value.strip()))
            and not any(unicodedata.category(character).startswith("C") for character in value))


def validate_feature_input(
    manifest: FeatureManifest,
    raw: object,
    workspace: Path,
) -> dict[str, object]:
    if type(manifest) is not FeatureManifest or type(raw) is not dict:
        raise FeatureInputError({"feature": "功能输入必须是对象。"})
    fields = {field.name: field for field in manifest.fields}
    errors = {name: "不支持此字段。" for name in raw if name not in fields or type(name) is not str}
    values: dict[str, object] = {}
    for name, field in fields.items():
        if name not in raw:
            if field.required:
                errors[name] = "此字段为必填项。"
            continue
        value = raw[name]
        if field.kind == "text":
            if not _safe_text(value, maximum=4096, allow_empty=not field.required):
                errors[name] = "请输入有效文本。"
            else:
                values[name] = value
        elif field.kind == "integer":
            if (type(value) is not int
                    or (field.minimum is not None and value < field.minimum)
                    or (field.maximum is not None and value > field.maximum)):
                errors[name] = "请输入允许范围内的整数。"
            else:
                values[name] = value
        elif field.kind == "boolean":
            if type(value) is not bool:
                errors[name] = "请选择是或否。"
            else:
                values[name] = value
        elif field.kind == "choice":
            if type(value) is not str or value not in field.choices:
                errors[name] = "请选择允许的选项。"
            else:
                values[name] = value
        elif field.kind in {"workspace_file", "workspace_directory"}:
            try:
                if type(value) is not str:
                    raise ValueError("path type")
                values[name] = resolve_workspace_path(
                    workspace, value,
                    kind="file" if field.kind == "workspace_file" else "directory",
                )
            except ValueError:
                noun = "文件" if field.kind == "workspace_file" else "目录"
                errors[name] = f"请选择工作区内已存在的{noun}。"
    if errors:
        raise FeatureInputError(errors)
    return values


def _validate_summary(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) > 20:
        raise FeatureResultError("summary 无效")
    keys: set[str] = set()
    fixed = []
    for item in value:
        if type(item) is not dict or set(item) != {"key", "label", "value"}:
            raise FeatureResultError("summary 项无效")
        key = item["key"]
        scalar = item["value"]
        if (type(key) is not str or _SAFE_KEY.fullmatch(key) is None or key in keys
                or not _safe_text(item["label"], maximum=80)
                or type(scalar) not in {str, int, float, bool}
                or (type(scalar) is float and not math.isfinite(scalar))
                or (type(scalar) is str and not _safe_text(scalar, maximum=500, allow_empty=True))):
            raise FeatureResultError("summary 项无效")
        keys.add(key)
        fixed.append(dict(item))
    return fixed


def _validate_tables(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) > 20:
        raise FeatureResultError("tables 无效")
    table_ids: set[str] = set()
    fixed_tables = []
    for table in value:
        if type(table) is not dict or set(table) != {"id", "title", "columns", "rows"}:
            raise FeatureResultError("table 无效")
        table_id = table["id"]
        columns = table["columns"]
        rows = table["rows"]
        if (type(table_id) is not str or _SAFE_KEY.fullmatch(table_id) is None
                or table_id in table_ids or not _safe_text(table["title"], maximum=100)
                or type(columns) is not list or not 1 <= len(columns) <= 30
                or type(rows) is not list or len(rows) > 5000):
            raise FeatureResultError("table 无效")
        column_keys: list[str] = []
        for column in columns:
            if (type(column) is not dict or set(column) != {"key", "label", "type"}
                    or type(column["key"]) is not str or _SAFE_KEY.fullmatch(column["key"]) is None
                    or column["key"] in column_keys or not _safe_text(column["label"], maximum=80)
                    or column["type"] != "text"):
                raise FeatureResultError("column 无效")
            column_keys.append(column["key"])
        fixed_rows = []
        for row in rows:
            if type(row) is not dict or set(row) != set(column_keys):
                raise FeatureResultError("row 无效")
            for cell in row.values():
                if (cell is not None and type(cell) not in {str, int, float, bool}) or (
                        type(cell) is float and not math.isfinite(cell)) or (
                        type(cell) is str and not _safe_text(cell, maximum=10000, allow_empty=True)):
                    raise FeatureResultError("cell 无效")
            fixed_rows.append(dict(row))
        table_ids.add(table_id)
        fixed_tables.append({"id": table_id, "title": table["title"],
                             "columns": [dict(item) for item in columns], "rows": fixed_rows})
    return fixed_tables


def present_feature_result(manifest: FeatureManifest, result: object) -> dict[str, object]:
    if type(manifest) is not FeatureManifest or not isinstance(result, Mapping):
        raise FeatureResultError("功能结果结构无效")
    result = dict(result)
    if set(result) != _RESULT_KEYS:
        raise FeatureResultError("功能结果结构无效")
    if result.get("status") not in {"completed", "completed_with_warnings"}:
        raise FeatureResultError("功能结果状态无效")
    if result.get("actions_executed") is not False:
        raise FeatureResultError("功能不得执行处置")
    warnings = result.get("warnings")
    if (type(warnings) is not list or len(warnings) > 50
            or any(not _safe_text(item, maximum=2000) for item in warnings)):
        raise FeatureResultError("warnings 无效")
    presented = {
        "schema": "svarog.workbench.feature-result.v1",
        "kind": "trusted_feature",
        "feature_id": manifest.feature_id,
        "title": manifest.title,
        "status": result["status"],
        "summary_cards": _validate_summary(result.get("summary")),
        "warnings": list(warnings),
        "tables": _validate_tables(result.get("tables")),
        "actions_executed": False,
    }
    try:
        encoded = json.dumps(presented, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise FeatureResultError("功能结果无法序列化") from exc
    if len(encoded) > MAX_FEATURE_RESULT_BYTES:
        raise FeatureResultError("功能结果过大")
    return presented


__all__ = [
    "FeatureInputError", "FeatureResultError", "MAX_FEATURE_RESULT_BYTES",
    "present_feature_result", "validate_feature_input",
]
