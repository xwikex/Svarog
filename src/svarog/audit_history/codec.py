from __future__ import annotations

from collections.abc import Iterator
from collections import OrderedDict
import codecs
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import sys
from threading import RLock
from typing import Any
import zlib


MAX_RESULT_JSON_BYTES = 16 * 1024 * 1024
MAX_RESULT_BYTES = MAX_RESULT_JSON_BYTES
COMPRESSION_LEVEL = 9
_MAX_NESTING = 256
_INPUT_CHUNK_BYTES = 64 * 1024
_OUTPUT_CHUNK_CHARS = 64 * 1024
_LOG10_2_LOWER_NUMERATOR = 301_029
_LOG10_2_LOWER_DENOMINATOR = 1_000_000
_LOG10_2_UPPER_NUMERATOR = 30_103
_LOG10_2_UPPER_DENOMINATOR = 100_000
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", flags=re.ASCII)


def _zlib_compress_bound(size: int) -> int:
    return size + (size >> 12) + (size >> 14) + (size >> 25) + 13


MAX_COMPRESSED_RESULT_BYTES = _zlib_compress_bound(MAX_RESULT_JSON_BYTES)


class HistoryCodecError(ValueError):
    """A result-codec failure with a stable, non-sensitive public code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class EncodedResult:
    compressed: bytes
    size: int
    sha256: str


class SnapshotResultCache:
    """A small, thread-safe LRU of isolated snapshot result values."""

    def __init__(self, capacity: int = 5) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise HistoryCodecError("invalid_cache_capacity")
        self._capacity = capacity
        self._entries: OrderedDict[int, EncodedResult] = OrderedDict()
        self._lock = RLock()

    def get(self, snapshot_id: int) -> dict[str, object] | None:
        _validate_snapshot_id(snapshot_id)
        with self._lock:
            encoded = self._entries.get(snapshot_id)
            if encoded is None:
                return None
            self._entries.move_to_end(snapshot_id)
        return decode_result(encoded.compressed, encoded.size, encoded.sha256)

    def put(self, snapshot_id: int, value: object) -> None:
        _validate_snapshot_id(snapshot_id)
        encoded = encode_result(value)
        with self._lock:
            self._entries[snapshot_id] = encoded
            self._entries.move_to_end(snapshot_id)
            if len(self._entries) > self._capacity:
                self._entries.popitem(last=False)

    def discard(self, snapshot_id: int) -> None:
        _validate_snapshot_id(snapshot_id)
        with self._lock:
            self._entries.pop(snapshot_id, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _validate_snapshot_id(snapshot_id: int) -> None:
    if type(snapshot_id) is not int or snapshot_id < 0:
        raise HistoryCodecError("invalid_snapshot_id")


def encode_result(value: object) -> EncodedResult:
    if type(value) is not dict:
        raise HistoryCodecError("invalid_result")
    _validate_json_value(value)
    _preflight_json_size(value)

    compressor = zlib.compressobj(level=COMPRESSION_LEVEL)
    digest = hashlib.sha256()
    compressed = bytearray()
    size = 0

    def consume(payload: bytes) -> None:
        nonlocal size
        next_size = size + len(payload)
        if next_size > MAX_RESULT_BYTES:
            raise HistoryCodecError("result_too_large")
        size = next_size
        digest.update(payload)
        compressed.extend(compressor.compress(payload))

    try:
        text_chunks = json.JSONEncoder(
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).iterencode(value)
        utf8_encoder = codecs.getincrementalencoder("utf-8")(errors="strict")
        for text_chunk in text_chunks:
            for offset in range(0, len(text_chunk), _OUTPUT_CHUNK_CHARS):
                consume(
                    utf8_encoder.encode(
                        text_chunk[offset : offset + _OUTPUT_CHUNK_CHARS],
                        final=False,
                    )
                )
        consume(utf8_encoder.encode("", final=True))
        compressed.extend(compressor.flush())
    except HistoryCodecError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise HistoryCodecError("invalid_result") from None
    return EncodedResult(
        compressed=bytes(compressed),
        size=size,
        sha256=digest.hexdigest(),
    )


def _validate_json_value(root: object) -> None:
    active_containers: set[int] = set()
    stack: list[tuple[Iterator[Any], int, int, bool]] = []
    value = root
    depth = 0

    while True:
        value_type = type(value)
        if value is None or value_type in (str, bool, int):
            pass
        elif value_type is float:
            if not math.isfinite(value):
                raise HistoryCodecError("invalid_result")
        else:
            if value_type not in (dict, list) or depth > _MAX_NESTING:
                raise HistoryCodecError("invalid_result")

            identity = id(value)
            if identity in active_containers:
                raise HistoryCodecError("invalid_result")
            active_containers.add(identity)
            if value_type is dict:
                children = iter(value.items())
                validate_keys = True
            else:
                children = iter(value)
                validate_keys = False
            stack.append((children, depth, identity, validate_keys))

        while stack:
            children, parent_depth, identity, validate_keys = stack[-1]
            try:
                child = next(children)
            except StopIteration:
                stack.pop()
                active_containers.remove(identity)
                continue

            if validate_keys:
                key, value = child
                if type(key) is not str:
                    raise HistoryCodecError("invalid_result")
            else:
                value = child
            depth = parent_depth + 1
            break
        else:
            return


def _preflight_json_size(root: object) -> None:
    accounted_size = 0
    stack: list[tuple[Iterator[Any], bool]] = []
    value = root

    while True:
        value_type = type(value)
        if value_type is str:
            accounted_size += _escaped_string_token_size(
                value,
                MAX_RESULT_BYTES - accounted_size,
            )
        elif value_type is int:
            accounted_size += _integer_token_size_lower_bound(
                value,
                MAX_RESULT_BYTES - accounted_size,
            )
        elif value_type is dict:
            stack.append((iter(value.items()), True))
        elif value_type is list:
            stack.append((iter(value), False))
        elif value is not None and value_type not in (bool, float):
            raise HistoryCodecError("invalid_result")

        while stack:
            children, has_keys = stack[-1]
            try:
                child = next(children)
            except StopIteration:
                stack.pop()
                continue

            if has_keys:
                key, value = child
                if type(key) is not str:
                    raise HistoryCodecError("invalid_result")
                accounted_size += _escaped_string_token_size(
                    key,
                    MAX_RESULT_BYTES - accounted_size,
                )
            else:
                value = child
            break
        else:
            return


def _escaped_string_token_size(value: str, remaining: int) -> int:
    size = 2
    if size > remaining:
        raise HistoryCodecError("result_too_large")

    for character in value:
        codepoint = ord(character)
        if codepoint in (0x22, 0x5C, 0x08, 0x09, 0x0A, 0x0C, 0x0D):
            width = 2
        elif codepoint < 0x20:
            width = 6
        elif codepoint <= 0x7F:
            width = 1
        elif codepoint <= 0x7FF:
            width = 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise HistoryCodecError("invalid_result")
        elif codepoint <= 0xFFFF:
            width = 3
        else:
            width = 4

        size += width
        if size > remaining:
            raise HistoryCodecError("result_too_large")
    return size


def _integer_token_size_lower_bound(value: int, remaining: int) -> int:
    lower_digits, upper_digits = _decimal_digit_bounds(value)
    digit_limit = sys.get_int_max_str_digits()
    if digit_limit:
        if lower_digits > digit_limit or (
            upper_digits > digit_limit
            and _magnitude_has_more_than_digits(value, digit_limit)
        ):
            raise HistoryCodecError("invalid_result")

    size = lower_digits + (value < 0)
    if size > remaining:
        raise HistoryCodecError("result_too_large")
    return size


def _decimal_digit_bounds(value: int) -> tuple[int, int]:
    bit_length = value.bit_length()
    if bit_length == 0:
        return 1, 1
    lower = (
        (bit_length - 1) * _LOG10_2_LOWER_NUMERATOR
        // _LOG10_2_LOWER_DENOMINATOR
        + 1
    )
    upper = (
        bit_length * _LOG10_2_UPPER_NUMERATOR
        // _LOG10_2_UPPER_DENOMINATOR
        + 1
    )
    return lower, upper


def _magnitude_has_more_than_digits(value: int, digits: int) -> bool:
    threshold = 10**digits
    if value >= 0:
        return value >= threshold
    return value <= -threshold


def decode_result(
    compressed: bytes,
    declared_size: int,
    declared_sha256: str,
) -> dict[str, object]:
    if (
        type(compressed) is not bytes
        or type(declared_size) is not int
        or declared_size < 0
        or type(declared_sha256) is not str
        or _SHA256_RE.fullmatch(declared_sha256) is None
    ):
        raise HistoryCodecError("result_corrupt")
    if declared_size > MAX_RESULT_JSON_BYTES:
        raise HistoryCodecError("result_too_large")
    if len(compressed) > MAX_COMPRESSED_RESULT_BYTES:
        raise HistoryCodecError("result_too_large")

    payload = _decompress_result(compressed, declared_size)
    if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), declared_sha256):
        raise HistoryCodecError("result_corrupt")

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        if type(value) is not dict:
            raise ValueError
        _validate_json_value(value)
    except (HistoryCodecError, UnicodeError, ValueError, RecursionError):
        raise HistoryCodecError("result_corrupt") from None
    return value


def _decompress_result(compressed: bytes, declared_size: int) -> bytes:
    decompressor = zlib.decompressobj()
    output = bytearray()

    try:
        for offset in range(0, len(compressed), _INPUT_CHUNK_BYTES):
            pending = compressed[offset : offset + _INPUT_CHUNK_BYTES]
            while pending:
                if decompressor.eof:
                    raise HistoryCodecError("result_corrupt")

                remaining = declared_size - len(output)
                limit = remaining if remaining > 0 else 1
                before = len(pending)
                piece = decompressor.decompress(pending, limit)
                pending = decompressor.unconsumed_tail

                if remaining == 0:
                    if piece:
                        code = (
                            "result_too_large"
                            if declared_size >= MAX_RESULT_JSON_BYTES
                            else "result_corrupt"
                        )
                        raise HistoryCodecError(code)
                else:
                    output.extend(piece)

                if decompressor.unused_data:
                    raise HistoryCodecError("result_corrupt")
                if pending and not piece and len(pending) == before:
                    raise HistoryCodecError("result_corrupt")
    except HistoryCodecError:
        raise
    except (ValueError, zlib.error):
        raise HistoryCodecError("result_corrupt") from None

    if (
        not decompressor.eof
        or decompressor.unused_data
        or len(output) != declared_size
    ):
        raise HistoryCodecError("result_corrupt")
    return bytes(output)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> object:
    raise ValueError
