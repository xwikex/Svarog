"""Immutable contracts shared by trusted feature modules and the workbench."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol


FieldKind = Literal[
    "text", "integer", "boolean", "choice", "workspace_file", "workspace_directory"
]
FeaturePermission = Literal["workspace_read", "network", "database", "token"]
_FIELD_KINDS = frozenset({
    "text", "integer", "boolean", "choice", "workspace_file", "workspace_directory"
})
_PERMISSIONS = frozenset({"workspace_read", "network", "database", "token"})
_FEATURE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _safe_text(value: object, name: str, maximum: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise ValueError(f"{name} 必须是非空短文本")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} 不能包含控制字符")
    return value


@dataclass(frozen=True, slots=True)
class FeatureField:
    name: str
    label: str
    kind: FieldKind
    required: bool
    help_text: str
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

    def __post_init__(self) -> None:
        if type(self.name) is not str or _FIELD_NAME.fullmatch(self.name) is None:
            raise ValueError("字段名必须是安全的小写标识符")
        _safe_text(self.label, "label", 80)
        _safe_text(self.help_text, "help_text", 300)
        if self.kind not in _FIELD_KINDS:
            raise ValueError("kind 不是受支持的字段类型")
        if type(self.required) is not bool:
            raise ValueError("required 必须是布尔值")
        if type(self.choices) is not tuple or any(
                type(item) is not str or not item or len(item) > 100 for item in self.choices):
            raise ValueError("choices 必须是短文本元组")
        if self.kind == "choice":
            if not self.choices or len(set(self.choices)) != len(self.choices):
                raise ValueError("choice 字段必须提供唯一 choices")
        elif self.choices:
            raise ValueError("只有 choice 字段可以提供 choices")
        for value, name in ((self.minimum, "minimum"), (self.maximum, "maximum")):
            if value is not None and type(value) is not int:
                raise ValueError(f"{name} 必须是整数")
        if self.kind != "integer" and (self.minimum is not None or self.maximum is not None):
            raise ValueError("只有 integer 字段可以设置范围")
        if (self.minimum is not None and self.maximum is not None
                and self.minimum > self.maximum):
            raise ValueError("minimum 不能大于 maximum")


@dataclass(frozen=True, slots=True)
class FeatureManifest:
    feature_id: str
    title: str
    description: str
    order: int
    fields: tuple[FeatureField, ...]
    permissions: frozenset[FeaturePermission]

    def __post_init__(self) -> None:
        if type(self.feature_id) is not str or _FEATURE_ID.fullmatch(self.feature_id) is None:
            raise ValueError("feature_id 必须是安全的小写标识符")
        _safe_text(self.title, "title", 80)
        _safe_text(self.description, "description", 500)
        if type(self.order) is not int or not -1000 <= self.order <= 1000:
            raise ValueError("order 必须是 -1000..1000 的整数")
        if type(self.fields) is not tuple or any(type(item) is not FeatureField for item in self.fields):
            raise ValueError("fields 必须是 FeatureField 元组")
        names = [item.name for item in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("字段名不能重复")
        if type(self.permissions) is not frozenset or not self.permissions.issubset(_PERMISSIONS):
            raise ValueError("permissions 包含不受支持的权限")
        if (any(field.kind in {"workspace_file", "workspace_directory"} for field in self.fields)
                and "workspace_read" not in self.permissions):
            raise ValueError("工作区路径字段必须声明 workspace_read 权限")


@dataclass(frozen=True, slots=True)
class FeatureContext:
    workspace: Path
    resolve_workspace_path: Callable[..., Path]


class FeatureHandler(Protocol):
    def __call__(
        self, context: FeatureContext, values: Mapping[str, object]
    ) -> Mapping[str, object]: ...


__all__ = [
    "FeatureContext", "FeatureField", "FeatureHandler", "FeatureManifest",
    "FeaturePermission", "FieldKind",
]
