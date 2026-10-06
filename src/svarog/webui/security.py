"""Small, strict security primitives for the local web UI."""

from __future__ import annotations

import base64
import binascii
import hmac
import io
import json
import math
import os
import re
import stat
import unicodedata
import uuid
from collections.abc import Set
from pathlib import Path
from typing import BinaryIO, Mapping
from urllib.parse import urlsplit


class RequestRejected(ValueError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_CONTENT_TYPE_RE = re.compile(
    r"application/json(?:;[ \t]*charset=utf-8)?", re.IGNORECASE
)
_SAFE_SUFFIX_RE = re.compile(r"\.[A-Za-z0-9]+")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _reject(status: int, code: str, message: str) -> RequestRejected:
    return RequestRejected(status, code, message)


def _has_control_or_whitespace(value: str) -> bool:
    return any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    )


def _canonical_authority(authority: str) -> str | None:
    if (
        not isinstance(authority, str)
        or not authority
        or _has_control_or_whitespace(authority)
    ):
        return None
    try:
        parsed = urlsplit(f"//{authority}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        not hostname
        or hostname.endswith(".")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    canonical = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        canonical += f":{port}"
    return canonical


def validate_mutation(
    host: str,
    origin: str,
    csrf_header: str,
    expected_csrf: str,
    allowed_hosts: object,
) -> None:
    try:
        valid_allowed_hosts = isinstance(allowed_hosts, Set) and all(
            isinstance(allowed_host, str) for allowed_host in allowed_hosts
        )
        host_allowed = valid_allowed_hosts and host in allowed_hosts
    except Exception:
        host_allowed = False
    if not host_allowed or _canonical_authority(host) != host:
        raise _reject(400, "invalid_host", "请求主机无效")

    if (
        not isinstance(origin, str)
        or not origin
        or _has_control_or_whitespace(origin)
    ):
        raise _reject(403, "invalid_origin", "请求来源无效")
    try:
        parsed = urlsplit(origin)
        origin_port = parsed.port
    except ValueError as exc:
        raise _reject(403, "invalid_origin", "请求来源无效") from exc
    if (
        parsed.scheme != "http"
        or parsed.netloc != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or _canonical_authority(parsed.netloc) != host
    ):
        raise _reject(403, "invalid_origin", "请求来源无效")
    del origin_port

    csrf_valid = False
    if (
        isinstance(csrf_header, str)
        and csrf_header
        and csrf_header.isascii()
        and isinstance(expected_csrf, str)
        and expected_csrf
        and expected_csrf.isascii()
    ):
        csrf_valid = hmac.compare_digest(
            csrf_header.encode("ascii"), expected_csrf.encode("ascii")
        )
    if not csrf_valid:
        raise _reject(403, "csrf_failed", "请求验证失败")


def _header_values(headers: object, wanted: str) -> list[object]:
    try:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            values = get_all(wanted)
            if values is None:
                return []
            if isinstance(values, (list, tuple)):
                return list(values)
            return [values]
    except Exception:
        return []
    if not isinstance(headers, Mapping):
        return []
    result: list[object] = []
    try:
        for key, value in headers.items():
            if isinstance(key, str) and key.casefold() == wanted.casefold():
                result.append(value)
    except Exception:
        return []
    return result


def _single_text_header(headers: object, name: str) -> str | None:
    values = _header_values(headers, name)
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    return values[0]


def _has_trailing_data(stream: BinaryIO) -> bool:
    if isinstance(stream, io.BytesIO):
        return stream.tell() < stream.getbuffer().nbytes
    try:
        if not stream.seekable():
            return False
        position = stream.tell()
        end = stream.seek(0, os.SEEK_END)
        stream.seek(position, os.SEEK_SET)
        return end > position
    except (AttributeError, OSError, ValueError):
        return False


def _json_object(data: bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8", errors="strict")

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        def finite_float(value: str) -> float:
            parsed = float(value)
            if not math.isfinite(parsed):
                raise ValueError("non-finite number")
            return parsed

        def reject_constant(value: str) -> object:
            raise ValueError("non-finite constant")

        parsed = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise _reject(400, "invalid_json", "JSON 内容无效") from exc
    if not isinstance(parsed, dict):
        raise _reject(400, "invalid_json_object", "JSON 顶层必须是对象")
    return parsed


def _parse_content_length(raw_length: str, maximum: int) -> int:
    if not raw_length or not raw_length.isascii() or not raw_length.isdecimal():
        raise _reject(400, "invalid_content_length", "请求长度无效")
    length = 0
    for character in raw_length:
        digit = ord(character) - ord("0")
        if length > (maximum - digit) // 10:
            raise _reject(413, "body_too_large", "请求内容过大")
        length = length * 10 + digit
    return length


def read_json_body(
    stream: BinaryIO,
    headers: object,
    max_bytes: int,
) -> dict[str, object]:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise _reject(400, "invalid_limit", "请求大小限制无效")

    if _header_values(headers, "Transfer-Encoding"):
        raise _reject(400, "transfer_encoding_forbidden", "不支持传输编码")

    content_type = _single_text_header(headers, "Content-Type")
    if content_type is None or _CONTENT_TYPE_RE.fullmatch(content_type) is None:
        raise _reject(415, "unsupported_media_type", "仅接受 UTF-8 JSON")

    raw_length = _single_text_header(headers, "Content-Length")
    if raw_length is None:
        raise _reject(411, "invalid_content_length", "请求长度无效")
    length = _parse_content_length(raw_length, max_bytes)

    try:
        body = stream.read(length)
    except Exception as exc:
        raise _reject(400, "body_read_failed", "请求内容读取失败") from exc
    if not isinstance(body, bytes) or len(body) != length:
        raise _reject(400, "body_length_mismatch", "请求内容长度不符")
    if _has_trailing_data(stream):
        raise _reject(400, "trailing_body_data", "请求内容长度不符")
    return _json_object(body)


def _valid_display_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and 0 < len(name) <= 255
        and all(
            not unicodedata.category(character).startswith("C") for character in name
        )
    )


def _resolve_owned_directory(temp_dir: object) -> Path:
    try:
        root = Path(temp_dir).resolve(strict=True)  # type: ignore[arg-type]
        details = root.stat()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        raise _reject(400, "invalid_temp_dir", "临时目录无效") from exc
    if not stat.S_ISDIR(details.st_mode):
        raise _reject(400, "invalid_temp_dir", "临时目录无效")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and details.st_uid != getuid():
        raise _reject(403, "temp_dir_not_owned", "临时目录不可用")
    return root


def _decode_base64(data: str, maximum: int) -> bytes:
    length = len(data)
    padding = 2 if data.endswith("==") else 1 if data.endswith("=") else 0
    if length % 4:
        raise _reject(400, "invalid_base64", "上传数据编码无效")
    estimated = (length // 4) * 3 - padding
    if estimated > maximum:
        raise _reject(413, "upload_too_large", "上传内容过大")
    if _BASE64_RE.fullmatch(data) is None:
        raise _reject(400, "invalid_base64", "上传数据编码无效")
    try:
        decoded = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise _reject(400, "invalid_base64", "上传数据编码无效") from exc
    if len(decoded) > maximum:
        raise _reject(413, "upload_too_large", "上传内容过大")
    return decoded


def decode_upload(
    temp_dir: object,
    upload: object,
    max_decoded_bytes: int,
    suffix: str,
) -> Path:
    if type(max_decoded_bytes) is not int or max_decoded_bytes <= 0:
        raise _reject(400, "invalid_limit", "上传大小限制无效")
    if not isinstance(suffix, str) or _SAFE_SUFFIX_RE.fullmatch(suffix) is None:
        raise _reject(400, "invalid_suffix", "上传文件类型无效")
    if type(upload) is not dict:
        raise _reject(400, "invalid_upload", "上传对象无效")
    name = upload.get("name")
    data = upload.get("data")
    if not _valid_display_name(name) or not isinstance(data, str):
        raise _reject(400, "invalid_upload", "上传对象无效")

    root = _resolve_owned_directory(temp_dir)
    decoded = _decode_base64(data, max_decoded_bytes)
    candidate = root / f"{uuid.uuid4().hex}{suffix}"
    if candidate.parent != root:
        raise _reject(400, "invalid_upload_path", "上传路径无效")

    created = False
    completed = False
    fd: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags, 0o600)
        created = True
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        view = memoryview(decoded)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        details = candidate.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size != len(decoded):
            raise OSError("post-write validation failed")
        completed = True
        return candidate
    except RequestRejected:
        raise
    except Exception as exc:
        raise _reject(500, "upload_write_failed", "上传保存失败") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created and not completed:
            try:
                candidate.unlink(missing_ok=True)
            except Exception as exc:
                raise _reject(
                    500, "upload_cleanup_failed", "上传临时文件清理失败"
                ) from exc
