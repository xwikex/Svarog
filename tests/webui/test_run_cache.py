from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone

import pytest

from svarog.webui.history import RunCache


JSON_MIME = "application/json; charset=utf-8"
HTML_MIME = "text/html; charset=utf-8"


def test_put_get_isolated_json_and_fixed_downloads() -> None:
    result = {"nested": {"items": [1]}}
    downloads = {"json": (JSON_MIME, b"{}")}
    cache = RunCache()

    run_id = cache.put("audit", result, downloads)
    result["nested"]["items"].append(2)
    downloads["json"] = (JSON_MIME, b"changed")
    first = cache.get(run_id)
    first.result["nested"]["items"].append(3)
    first.downloads["json"] = (JSON_MIME, b"changed again")
    second = cache.get(run_id)

    assert second.run_id == run_id
    assert second.kind == "audit"
    assert second.created_at.tzinfo is timezone.utc
    assert second.result == {"nested": {"items": [1]}}
    assert second.downloads == {"json": (JSON_MIME, b"{}")}


@pytest.mark.parametrize("name", ["source", "pdf", "JSON", "../json"])
def test_download_names_are_fixed(name: str) -> None:
    with pytest.raises(ValueError, match="下载"):
        RunCache().put("audit", {}, {name: (JSON_MIME, b"data")})


@pytest.mark.parametrize(
    "downloads",
    [
        {"json": ("application/octet-stream", b"{}")},
        {"html": (JSON_MIME, b"<p>x</p>")},
        {"json": (JSON_MIME, "not-bytes")},
    ],
)
def test_download_mime_and_payload_are_not_caller_controlled(downloads: dict) -> None:
    with pytest.raises(ValueError, match="下载"):
        RunCache().put("audit", {}, downloads)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), (1, 2), {1: "x"}, object()])
def test_result_must_be_strict_json(value: object) -> None:
    with pytest.raises((TypeError, ValueError), match="JSON"):
        RunCache().put("audit", {"value": value}, {})


@pytest.mark.parametrize("max_items,max_bytes", [(0, 1), (True, 1), (1, 0), (1, False)])
def test_limits_are_real_positive_integers(max_items: object, max_bytes: object) -> None:
    with pytest.raises(ValueError, match="正整数"):
        RunCache(max_items=max_items, max_item_bytes=max_bytes)  # type: ignore[arg-type]


def test_size_checked_before_insert_and_exact_boundary_allowed() -> None:
    result = {"message": "小"}
    encoded_size = len(
        json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )
    payload = b"abc"
    cache = RunCache(max_item_bytes=encoded_size + len(payload))
    run_id = cache.put("audit", result, {"html": (HTML_MIME, payload)})
    assert cache.get(run_id).downloads["html"][1] == payload

    with pytest.raises(ValueError, match="过大"):
        RunCache(max_item_bytes=encoded_size + len(payload) - 1).put(
            "audit", result, {"html": (HTML_MIME, payload)}
        )


def test_get_promotes_entry_for_lru_eviction() -> None:
    cache = RunCache(max_items=2)
    first = cache.put("a", {}, {})
    second = cache.put("b", {}, {})
    cache.get(first)
    third = cache.put("c", {}, {})

    with pytest.raises(ValueError):
        cache.get(second)
    assert cache.get(first).kind == "a"
    assert cache.get(third).kind == "c"


@pytest.mark.parametrize("run_id", ["", "bad/id", "x" * 129, "missing"])
def test_unknown_or_invalid_id_is_controlled(run_id: str) -> None:
    with pytest.raises(ValueError, match="运行记录"):
        RunCache().get(run_id)


def test_concurrent_put_and_get_is_safe() -> None:
    cache = RunCache(max_items=200)

    def round_trip(index: int) -> int:
        run_id = cache.put("parallel", {"index": index}, {})
        return cache.get(run_id).result["index"]

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sorted(pool.map(round_trip, range(100))) == list(range(100))

