from dataclasses import FrozenInstanceError
from concurrent.futures import ThreadPoolExecutor
import codecs
import gc
import hashlib
import math
import sys
import tracemalloc
from types import SimpleNamespace
import zlib

import pytest

from svarog.audit_history import codec
from svarog.audit_history.codec import (
    EncodedResult,
    HistoryCodecError,
    SnapshotResultCache,
    decode_result,
    encode_result,
)


def test_encoded_result_is_frozen_and_slotted() -> None:
    encoded = EncodedResult(b"compressed", 4, "0" * 64)

    assert not hasattr(encoded, "__dict__")
    with pytest.raises(FrozenInstanceError):
        encoded.size = 5  # type: ignore[misc]


def test_encoding_is_canonical_deterministic_and_preserves_unicode() -> None:
    first = encode_result({"z": [2, 1], "a": "中文"})
    second = encode_result({"a": "中文", "z": [2, 1]})
    canonical = '{"a":"中文","z":[2,1]}'.encode()

    assert first == second
    assert first.compressed == zlib.compress(canonical, level=codec.COMPRESSION_LEVEL)
    assert zlib.decompress(first.compressed) == canonical
    assert first.size == len(canonical)
    assert first.sha256 == hashlib.sha256(canonical).hexdigest()
    assert decode_result(first.compressed, first.size, first.sha256) == {
        "a": "中文",
        "z": [2, 1],
    }


def test_streaming_encoding_matches_legacy_bytes_across_chunk_boundaries() -> None:
    value = {"value": '"\n中文\\' * (codec._OUTPUT_CHUNK_CHARS // 5)}
    canonical = codec.json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    assert len(canonical) > codec._OUTPUT_CHUNK_CHARS
    assert encode_result(value) == EncodedResult(
        compressed=zlib.compress(canonical, level=codec.COMPRESSION_LEVEL),
        size=len(canonical),
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def test_empty_object_round_trips() -> None:
    encoded = encode_result({})

    assert decode_result(encoded.compressed, encoded.size, encoded.sha256) == {}


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"nested": {1: "not a string key"}},
        {"tuple": (1, 2)},
        {"set": {1, 2}},
        {"bytes": b"not JSON"},
    ],
)
def test_encoder_rejects_non_object_roots_and_non_json_values(value: object) -> None:
    with pytest.raises(HistoryCodecError, match="^invalid_result$") as raised:
        encode_result(value)

    assert raised.value.code == "invalid_result"


@pytest.mark.parametrize("number", [math.nan, math.inf, -math.inf])
def test_encoder_rejects_nonfinite_numbers(number: float) -> None:
    with pytest.raises(HistoryCodecError, match="^invalid_result$"):
        encode_result({"nested": [number]})


def test_encoder_rejects_excessive_recursion_with_a_fixed_error() -> None:
    nested: list[object] = []
    for _ in range(2_000):
        nested = [nested]

    with pytest.raises(HistoryCodecError, match="^invalid_result$"):
        encode_result({"nested": nested})


@pytest.mark.parametrize("container_type", ["dict", "list"])
def test_encoder_rejects_cycles_with_a_fixed_error(container_type: str) -> None:
    if container_type == "dict":
        cycle_dict: dict[str, object] = {}
        cycle_dict["self"] = cycle_dict
        cycle: object = cycle_dict
    else:
        cycle_list: list[object] = []
        cycle_list.append(cycle_list)
        cycle = cycle_list

    with pytest.raises(HistoryCodecError, match="^invalid_result$") as raised:
        encode_result({"cycle": cycle})

    assert raised.value.code == "invalid_result"


def test_encoder_rejects_oversized_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", 8)

    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        encode_result({"value": "too large"})


def test_validator_processes_only_the_next_list_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CountingList(list[object]):
        def __init__(self, values: list[object]) -> None:
            super().__init__(values)
            self.items_requested = 0

        def __iter__(self):  # type: ignore[no-untyped-def]
            for item in super().__iter__():
                self.items_requested += 1
                yield item

        def __reversed__(self):  # type: ignore[no-untyped-def]
            for item in super().__reversed__():
                self.items_requested += 1
                yield item

    values = CountingList([object(), *([None] * 10_000)])
    monkeypatch.setattr(codec, "list", CountingList, raising=False)

    with pytest.raises(HistoryCodecError, match="^invalid_result$"):
        codec._validate_json_value(values)

    assert values.items_requested == 1


def test_encoder_does_not_call_full_json_dumps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_dumps(*_args: object, **_kwargs: object) -> str:
        pytest.fail("encode_result must stream JSON instead of calling json.dumps")

    monkeypatch.setattr(codec.json, "dumps", reject_dumps)

    encoded = encode_result({"value": "streamed"})

    assert zlib.decompress(encoded.compressed) == b'{"value":"streamed"}'


def test_encoder_processes_each_iterencode_chunk_before_requesting_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_encoder = codec.json.JSONEncoder
    real_compressobj = codec.zlib.compressobj
    compressed_input_size = 0

    class ObservedEncoder(real_encoder):
        def iterencode(self, value: object, _one_shot: bool = False):  # type: ignore[no-untyped-def]
            nonlocal compressed_input_size
            chunks = ["{", '"value"', ":", '"streamed"', "}"]
            expected_processed = 0
            for chunk in chunks:
                assert compressed_input_size == expected_processed
                yield chunk
                expected_processed += len(chunk.encode("utf-8"))

    class ObservedCompressor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._compressor = real_compressobj(*args, **kwargs)

        def compress(self, data: bytes) -> bytes:
            nonlocal compressed_input_size
            compressed_input_size += len(data)
            return self._compressor.compress(data)

        def flush(self) -> bytes:
            return self._compressor.flush()

    monkeypatch.setattr(codec.json, "JSONEncoder", ObservedEncoder)
    monkeypatch.setattr(codec.zlib, "compressobj", ObservedCompressor)

    encoded = encode_result({"value": "streamed"})

    assert zlib.decompress(encoded.compressed) == b'{"value":"streamed"}'


def test_encoder_aborts_oversized_single_string_in_bounded_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_chunk_chars = 16
    max_result_bytes = 128
    real_incremental_encoder = codecs.getincrementalencoder("utf-8")
    real_compressobj = codec.zlib.compressobj
    encoded_text_sizes: list[int] = []
    compressed_input_sizes: list[int] = []

    class ObservedIncrementalEncoder:
        def __init__(self, errors: str = "strict") -> None:
            self._encoder = real_incremental_encoder(errors)

        def encode(self, text: str, final: bool = False) -> bytes:
            encoded_text_sizes.append(len(text))
            assert len(text) <= text_chunk_chars
            return self._encoder.encode(text, final=final)

    class ObservedCompressor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._compressor = real_compressobj(*args, **kwargs)

        def compress(self, data: bytes) -> bytes:
            compressed_input_sizes.append(len(data))
            return self._compressor.compress(data)

        def flush(self) -> bytes:
            return self._compressor.flush()

    fake_codecs = SimpleNamespace(
        getincrementalencoder=lambda encoding: ObservedIncrementalEncoder
    )
    monkeypatch.setattr(codec, "_preflight_json_size", lambda _value: None)
    monkeypatch.setattr(codec, "codecs", fake_codecs, raising=False)
    monkeypatch.setattr(codec, "_OUTPUT_CHUNK_CHARS", text_chunk_chars, raising=False)
    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", max_result_bytes)
    monkeypatch.setattr(codec.zlib, "compressobj", ObservedCompressor)

    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        encode_result({"value": "\x00" * 100_000})

    assert encoded_text_sizes
    assert max(encoded_text_sizes) <= text_chunk_chars
    assert sum(encoded_text_sizes) <= max_result_bytes + text_chunk_chars
    assert compressed_input_sizes
    assert sum(compressed_input_sizes) <= max_result_bytes


@pytest.mark.parametrize("character", ["\x00", "\\", "中"])
@pytest.mark.parametrize("location", ["value", "key"])
def test_preflight_rejects_huge_strings_and_keys_before_iterencode(
    monkeypatch: pytest.MonkeyPatch,
    character: str,
    location: str,
) -> None:
    iterencode_called = False

    def reject_iterencode(
        _encoder: object,
        _value: object,
        _one_shot: bool = False,
    ) -> object:
        nonlocal iterencode_called
        iterencode_called = True
        pytest.fail("oversized strings must be rejected during preflight")

    huge_string = character * 100_000
    value = {huge_string: "ok"} if location == "key" else {"value": huge_string}
    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", 32)
    monkeypatch.setattr(codec.json.JSONEncoder, "iterencode", reject_iterencode)

    with pytest.raises(HistoryCodecError, match="^result_too_large$") as raised:
        encode_result(value)

    assert raised.value.code == "result_too_large"
    assert not iterencode_called


def test_preflight_accumulates_string_token_sizes_before_iterencode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_iterencode(
        _encoder: object,
        _value: object,
        _one_shot: bool = False,
    ) -> object:
        pytest.fail("cumulative string size must be rejected during preflight")

    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", 12)
    monkeypatch.setattr(codec.json.JSONEncoder, "iterencode", reject_iterencode)

    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        encode_result({"a": "1234", "b": "5678"})


def test_preflight_rejects_surrogates_before_iterencode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_iterencode(
        _encoder: object,
        _value: object,
        _one_shot: bool = False,
    ) -> object:
        pytest.fail("surrogates must be rejected during preflight")

    monkeypatch.setattr(codec.json.JSONEncoder, "iterencode", reject_iterencode)

    with pytest.raises(HistoryCodecError, match="^invalid_result$") as raised:
        encode_result({"value": "\ud800"})

    assert raised.value.code == "invalid_result"


def test_preflight_string_size_matches_canonical_json_escaping() -> None:
    value = '"\\\b\f\n\r\t\x00\x1f\x7f中😀'
    canonical_token = codec.json.dumps(value, ensure_ascii=False).encode("utf-8")

    assert codec._escaped_string_token_size(value, len(canonical_token)) == len(
        canonical_token
    )
    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        codec._escaped_string_token_size(value, len(canonical_token) - 1)


def test_preflight_escaped_string_memory_is_not_proportional_to_token_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", 32)
    small = {"value": "\x00" * 10_000}
    large = {"value": "\x00" * 1_000_000}

    def rejection_peak(value: dict[str, object]) -> int:
        gc.collect()
        tracemalloc.start()
        try:
            with pytest.raises(HistoryCodecError, match="^result_too_large$"):
                encode_result(value)
            _, peak = tracemalloc.get_traced_memory()
            return peak
        finally:
            tracemalloc.stop()

    small_peak = rejection_peak(small)
    large_peak = rejection_peak(large)

    assert large_peak <= small_peak * 6


def test_preflight_rejects_oversized_integer_before_iterencode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digit_limit = sys.get_int_max_str_digits()
    decimal_digits = min(1_000, digit_limit) if digit_limit else 1_000
    huge_integer = 10 ** (decimal_digits - 1)

    def reject_iterencode(
        _encoder: object,
        _value: object,
        _one_shot: bool = False,
    ) -> object:
        pytest.fail("oversized integers must be rejected during preflight")

    monkeypatch.setattr(codec, "MAX_RESULT_BYTES", 32)
    monkeypatch.setattr(codec.json.JSONEncoder, "iterencode", reject_iterencode)

    with pytest.raises(HistoryCodecError, match="^result_too_large$") as raised:
        encode_result({"value": huge_integer})

    assert raised.value.code == "result_too_large"


def test_preflight_preserves_python_integer_digit_limit_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digit_limit = sys.get_int_max_str_digits()
    if digit_limit == 0:
        pytest.skip("Python integer string conversion limit is disabled")

    def reject_iterencode(
        _encoder: object,
        _value: object,
        _one_shot: bool = False,
    ) -> object:
        pytest.fail("digit-limit violations must be rejected during preflight")

    monkeypatch.setattr(codec.json.JSONEncoder, "iterencode", reject_iterencode)

    with pytest.raises(HistoryCodecError, match="^invalid_result$") as raised:
        encode_result({"value": 10**digit_limit})

    assert raised.value.code == "invalid_result"


def _encoded_bytes(payload: bytes) -> tuple[bytes, int, str]:
    return zlib.compress(payload, level=9), len(payload), hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("compressed", bytearray(b"not bytes")),
        ("compressed", memoryview(b"not bytes")),
        ("size", True),
        ("size", -1),
        ("size", "2"),
        ("digest", b"0" * 64),
        ("digest", "A" * 64),
        ("digest", "0" * 63),
        ("digest", "g" * 64),
    ],
)
def test_decoder_rejects_invalid_metadata_types_and_formats(
    field: str,
    replacement: object,
) -> None:
    encoded = encode_result({"ok": True})
    arguments: dict[str, object] = {
        "compressed": encoded.compressed,
        "size": encoded.size,
        "digest": encoded.sha256,
    }
    arguments[field] = replacement

    with pytest.raises(HistoryCodecError, match="^result_corrupt$") as raised:
        decode_result(
            arguments["compressed"],  # type: ignore[arg-type]
            arguments["size"],  # type: ignore[arg-type]
            arguments["digest"],  # type: ignore[arg-type]
        )

    assert raised.value.code == "result_corrupt"


def test_decoder_rejects_declared_oversize_before_decompression() -> None:
    encoded = encode_result({"ok": True})

    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        decode_result(
            encoded.compressed,
            codec.MAX_RESULT_JSON_BYTES + 1,
            encoded.sha256,
        )


@pytest.mark.parametrize("size_delta", [-1, 1])
def test_decoder_rejects_output_length_different_from_declaration(
    size_delta: int,
) -> None:
    encoded = encode_result({"ok": True})

    with pytest.raises(HistoryCodecError, match="^result_corrupt$"):
        decode_result(
            encoded.compressed,
            encoded.size + size_delta,
            encoded.sha256,
        )


def test_decoder_rejects_digest_mismatch() -> None:
    encoded = encode_result({"ok": True})

    with pytest.raises(HistoryCodecError, match="^result_corrupt$"):
        decode_result(encoded.compressed, encoded.size, "0" * 64)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data[:-1],
        lambda data: b"not-zlib-sensitive-details",
        lambda data: data + b"trailing-sensitive-details",
        lambda data: data + data,
    ],
    ids=["truncated", "corrupt", "trailing-bytes", "concatenated-stream"],
)
def test_decoder_rejects_invalid_or_trailing_compressed_data_without_echoing_it(
    mutate: object,
) -> None:
    encoded = encode_result({"ok": True})
    damaged = mutate(encoded.compressed)  # type: ignore[operator]

    with pytest.raises(HistoryCodecError) as raised:
        decode_result(damaged, encoded.size, encoded.sha256)

    assert str(raised.value) == "result_corrupt"
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":"\xff"}',
        b'{"duplicate":1,"duplicate":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'["not", "an", "object"]',
        b'{"not":"finished"',
    ],
    ids=[
        "invalid-utf8",
        "duplicate-keys",
        "nan",
        "positive-infinity",
        "negative-infinity",
        "non-object-root",
        "invalid-json",
    ],
)
def test_decoder_rejects_invalid_json_payloads(payload: bytes) -> None:
    compressed, size, digest = _encoded_bytes(payload)

    with pytest.raises(HistoryCodecError, match="^result_corrupt$"):
        decode_result(compressed, size, digest)


def test_decoder_rejects_excessively_nested_json_safely() -> None:
    payload = b'{"value":' + (b"[" * 2_000) + (b"]" * 2_000) + b"}"
    compressed, size, digest = _encoded_bytes(payload)

    with pytest.raises(HistoryCodecError, match="^result_corrupt$"):
        decode_result(compressed, size, digest)


def test_decoder_bounds_a_decompression_bomb_to_the_configured_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codec, "MAX_RESULT_JSON_BYTES", 64)
    payload = b'{"value":"' + (b"x" * 1_000_000) + b'"}'
    compressed, _, digest = _encoded_bytes(payload)

    with pytest.raises(HistoryCodecError, match="^result_too_large$"):
        decode_result(compressed, 64, digest)


@pytest.mark.parametrize("capacity", [0, -1, True, 1.5, "1"])
def test_cache_requires_a_positive_non_bool_integer_capacity(
    capacity: object,
) -> None:
    with pytest.raises(HistoryCodecError, match="^invalid_cache_capacity$"):
        SnapshotResultCache(capacity=capacity)  # type: ignore[arg-type]


def test_cache_uses_five_entries_by_default_and_evicts_the_lru() -> None:
    cache = SnapshotResultCache()
    for snapshot_id in range(6):
        cache.put(snapshot_id, {"snapshot_id": snapshot_id})

    assert cache.get(0) is None
    assert cache.get(5) == {"snapshot_id": 5}


def test_cache_get_updates_recency() -> None:
    cache = SnapshotResultCache(capacity=2)
    cache.put(1, {"value": 1})
    cache.put(2, {"value": 2})

    assert cache.get(1) == {"value": 1}
    cache.put(3, {"value": 3})

    assert cache.get(2) is None
    assert cache.get(1) == {"value": 1}
    assert cache.get(3) == {"value": 3}


def test_cache_replacement_updates_value_and_recency() -> None:
    cache = SnapshotResultCache(capacity=2)
    cache.put(1, {"value": "old"})
    cache.put(2, {"value": "second"})
    cache.put(1, {"value": "new"})
    cache.put(3, {"value": "third"})

    assert cache.get(1) == {"value": "new"}
    assert cache.get(2) is None
    assert cache.get(3) == {"value": "third"}


def test_cache_discard_and_clear() -> None:
    cache = SnapshotResultCache(capacity=2)
    cache.put(1, {"value": 1})
    cache.put(2, {"value": 2})

    cache.discard(1)
    cache.discard(1)
    assert cache.get(1) is None
    assert cache.get(2) == {"value": 2}

    cache.clear()
    assert cache.get(2) is None


@pytest.mark.parametrize("snapshot_id", [-1, True, False, 1.5, "1", None])
@pytest.mark.parametrize("operation", ["get", "put", "discard"])
def test_cache_rejects_invalid_snapshot_ids(
    snapshot_id: object,
    operation: str,
) -> None:
    cache = SnapshotResultCache()

    with pytest.raises(HistoryCodecError, match="^invalid_snapshot_id$"):
        if operation == "put":
            cache.put(snapshot_id, {"ok": True})  # type: ignore[arg-type]
        else:
            getattr(cache, operation)(snapshot_id)


def test_cache_does_not_leak_mutable_references() -> None:
    cache = SnapshotResultCache()
    original = {"nested": {"values": [1, 2]}}
    cache.put(7, original)

    original["nested"]["values"].append(3)  # type: ignore[index,union-attr]
    first = cache.get(7)
    assert first == {"nested": {"values": [1, 2]}}

    first["nested"]["values"].append(4)  # type: ignore[index,union-attr]
    assert cache.get(7) == {"nested": {"values": [1, 2]}}


def test_cache_instances_do_not_share_entries() -> None:
    first = SnapshotResultCache()
    second = SnapshotResultCache()
    first.put(1, {"owner": "first"})

    assert second.get(1) is None


def test_cache_is_safe_under_thread_stress() -> None:
    cache = SnapshotResultCache(capacity=5)

    def exercise(worker: int) -> None:
        for iteration in range(250):
            snapshot_id = (worker + iteration) % 12
            cache.put(
                snapshot_id,
                {"worker": worker, "iteration": iteration, "items": [snapshot_id]},
            )
            value = cache.get(snapshot_id)
            if value is not None:
                assert value["items"] == [snapshot_id]
            if iteration % 17 == 0:
                cache.discard((snapshot_id + 1) % 12)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(exercise, range(8)))

    cache.clear()
    assert all(cache.get(snapshot_id) is None for snapshot_id in range(12))
