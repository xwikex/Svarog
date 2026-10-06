"""Bounded, process-local storage for downloadable workbench runs."""

from __future__ import annotations

import json
import math
import re
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock


_DOWNLOAD_MIME = {
    "json": "application/json; charset=utf-8",
    "html": "text/html; charset=utf-8",
}
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    kind: str
    created_at: datetime
    result: dict
    downloads: dict[str, tuple[str, bytes]]


@dataclass(frozen=True, slots=True)
class _StoredRun:
    kind: str
    created_at: datetime
    result_json: bytes
    downloads: tuple[tuple[str, str, bytes], ...]


class RunCache:
    def __init__(
        self,
        max_items: int = 20,
        max_item_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if type(max_items) is not int or max_items <= 0:
            raise ValueError("max_items 必须是真正的正整数")
        if type(max_item_bytes) is not int or max_item_bytes <= 0:
            raise ValueError("max_item_bytes 必须是真正的正整数")
        self._max_items = max_items
        self._max_item_bytes = max_item_bytes
        self._items: OrderedDict[str, _StoredRun] = OrderedDict()
        self._lock = RLock()

    def put(
        self,
        kind: str,
        result: dict,
        downloads: dict[str, tuple[str, bytes]],
    ) -> str:
        if not isinstance(kind, str):
            raise TypeError("kind 必须是文本")
        result_json = _encode_result(result)
        fixed_downloads = _validate_downloads(downloads)
        total_bytes = len(result_json) + sum(len(item[2]) for item in fixed_downloads)
        if total_bytes > self._max_item_bytes:
            raise ValueError("运行结果过大，拒绝缓存")

        with self._lock:
            run_id = secrets.token_urlsafe(24)
            while run_id in self._items:
                run_id = secrets.token_urlsafe(24)
            self._items[run_id] = _StoredRun(
                kind=kind,
                created_at=datetime.now(timezone.utc),
                result_json=result_json,
                downloads=fixed_downloads,
            )
            while len(self._items) > self._max_items:
                self._items.popitem(last=False)
        return run_id

    def get(self, run_id: str) -> RunRecord:
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise ValueError("运行记录不存在")
        with self._lock:
            try:
                stored = self._items[run_id]
            except KeyError:
                raise ValueError("运行记录不存在") from None
            self._items.move_to_end(run_id)
            result = json.loads(stored.result_json)
            downloads = {
                name: (mime, bytes(payload))
                for name, mime, payload in stored.downloads
            }
            return RunRecord(
                run_id=run_id,
                kind=stored.kind,
                created_at=stored.created_at,
                result=result,
                downloads=downloads,
            )


def _encode_result(result: dict) -> bytes:
    try:
        _validate_json_value(result)
        return json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        raise ValueError("结果必须是严格 JSON 对象") from None


def _validate_json_value(value: object) -> None:
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("JSON object keys must be strings")
            _validate_json_value(item)
        return
    raise TypeError("unsupported JSON value")


def _validate_downloads(
    downloads: dict[str, tuple[str, bytes]],
) -> tuple[tuple[str, str, bytes], ...]:
    if type(downloads) is not dict:
        raise ValueError("下载必须是固定映射")
    fixed: list[tuple[str, str, bytes]] = []
    for name, item in downloads.items():
        if name not in _DOWNLOAD_MIME or type(item) is not tuple or len(item) != 2:
            raise ValueError("下载名称或格式无效")
        mime, payload = item
        if mime != _DOWNLOAD_MIME[name] or type(payload) is not bytes:
            raise ValueError("下载 MIME 或内容无效")
        fixed.append((name, mime, payload))
    return tuple(fixed)


__all__ = ["RunCache", "RunRecord"]
