from __future__ import annotations

import base64
import io
import os
import stat
from http.client import parse_headers
from pathlib import Path
from types import SimpleNamespace

import pytest

from svarog.webui import security
from svarog.webui.security import (
    SECURITY_HEADERS,
    RequestRejected,
    decode_upload,
    read_json_body,
    validate_mutation,
)


def rejected(call, *args, **kwargs) -> RequestRejected:
    with pytest.raises(RequestRejected) as caught:
        call(*args, **kwargs)
    assert 400 <= caught.value.status < 600
    assert caught.value.code
    assert caught.value.message == str(caught.value)
    return caught.value


def test_request_rejected_and_security_headers() -> None:
    error = RequestRejected(403, "denied", "请求被拒绝")
    assert (error.status, error.code, error.message) == (403, "denied", "请求被拒绝")
    required = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    assert required.items() <= SECURITY_HEADERS.items()
    assert all("\r" not in key + value and "\n" not in key + value for key, value in SECURITY_HEADERS.items())


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("127.0.0.1:8765", "http://127.0.0.1:8765"),
        ("localhost:8765", "http://localhost:8765"),
        ("[::1]:8765", "http://[::1]:8765"),
    ],
)
def test_validate_mutation_accepts_exact_loopback_authority(host: str, origin: str) -> None:
    validate_mutation(host, origin, "token", "token", {host})


@pytest.mark.parametrize(
    "host",
    ["evil.test:8765", " localhost:8765", "localhost:8765 ", "LOCALHOST:8765", "localhost.:8765"],
)
def test_validate_mutation_rejects_host_not_exactly_allowed(host: str) -> None:
    rejected(validate_mutation, host, "http://localhost:8765", "x", "x", {"localhost:8765"})


def test_validate_mutation_rejects_trailing_dot_even_when_host_is_allowed() -> None:
    rejected(
        validate_mutation,
        "localhost.:8765",
        "http://localhost.:8765",
        "x",
        "x",
        {"localhost.:8765"},
    )


@pytest.mark.parametrize(
    "allowed_hosts",
    [
        "localhost:8765",
        ["localhost:8765"],
        {"localhost:8765", 8765},
    ],
)
def test_validate_mutation_requires_string_only_set_of_allowed_hosts(
    allowed_hosts: object,
) -> None:
    rejected(
        validate_mutation,
        "localhost:8765",
        "http://localhost:8765",
        "x",
        "x",
        allowed_hosts,
    )


@pytest.mark.parametrize(
    "origin",
    [
        "https://localhost:8765",
        "http://user@localhost:8765",
        "http://localhost:8765?x=1",
        "http://localhost:8765#x",
        "http://localhost:9999",
        "http://LOCALHOST:8765",
        "http://localhost.:8765",
        " http://localhost:8765",
        "http://localhost:8765/path",
    ],
)
def test_validate_mutation_rejects_ambiguous_or_mismatched_origin(origin: str) -> None:
    rejected(validate_mutation, "localhost:8765", origin, "x", "x", {"localhost:8765"})


@pytest.mark.parametrize(
    "origin",
    [
        "http://local\rhost:8765",
        "http://local\nhost:8765",
        "http://local\thost:8765",
    ],
)
def test_validate_mutation_rejects_embedded_ascii_controls_before_urlsplit(
    origin: str,
) -> None:
    rejected(
        validate_mutation,
        "localhost:8765",
        origin,
        "x",
        "x",
        {"localhost:8765"},
    )


@pytest.mark.parametrize("csrf", [None, "", "wrong"])
def test_validate_mutation_rejects_csrf_without_leaking_token(csrf: object) -> None:
    error = rejected(
        validate_mutation,
        "localhost:8765",
        "http://localhost:8765",
        csrf,
        "expected-secret",
        {"localhost:8765"},
    )
    assert error.status == 403
    assert "expected-secret" not in error.message


@pytest.mark.parametrize(
    ("csrf_header", "expected_csrf"),
    [("令牌", "令牌"), ("token", "预期密钥")],
)
def test_validate_mutation_rejects_non_ascii_csrf_without_type_error_or_leak(
    csrf_header: str, expected_csrf: str
) -> None:
    error = rejected(
        validate_mutation,
        "localhost:8765",
        "http://localhost:8765",
        csrf_header,
        expected_csrf,
        {"localhost:8765"},
    )
    assert error.status == 403
    assert csrf_header not in error.message
    assert expected_csrf not in error.message


def json_headers(length: object, content_type: object = "application/json") -> dict[str, object]:
    return {"Content-Type": content_type, "Content-Length": length}


def http_message(*header_lines: bytes):
    return parse_headers(io.BytesIO(b"\r\n".join(header_lines) + b"\r\n\r\n"))


def test_read_json_body_accepts_real_http_message_headers() -> None:
    headers = http_message(b"Content-Type: application/json", b"Content-Length: 2")

    assert read_json_body(io.BytesIO(b"{}"), headers, 10) == {}


@pytest.mark.parametrize(
    "duplicate_headers",
    [
        (b"Content-Length: 2", b"Content-Length: 2"),
        (b"Content-Type: application/json", b"Content-Type: application/json"),
    ],
)
def test_read_json_body_rejects_duplicate_real_http_message_headers(
    duplicate_headers: tuple[bytes, bytes],
) -> None:
    defaults = (
        (b"Content-Type: application/json",)
        if duplicate_headers[0].startswith(b"Content-Length")
        else (b"Content-Length: 2",)
    )
    headers = http_message(*defaults, *duplicate_headers)

    error = rejected(read_json_body, io.BytesIO(b"{}"), headers, 10)
    expected_code = (
        "invalid_content_length"
        if duplicate_headers[0].startswith(b"Content-Length")
        else "unsupported_media_type"
    )
    assert error.code == expected_code


def test_read_json_body_detects_transfer_encoding_in_real_http_message() -> None:
    headers = http_message(
        b"Content-Type: application/json",
        b"Content-Length: 2",
        b"Transfer-Encoding: chunked",
    )

    error = rejected(read_json_body, io.BytesIO(b"{}"), headers, 10)
    assert error.code == "transfer_encoding_forbidden"


def test_read_json_body_accepts_utf8_charset_and_exact_limit() -> None:
    body = '{"名称":"值"}'.encode()
    assert read_json_body(io.BytesIO(body), json_headers(str(len(body)), "application/json; charset=utf-8"), len(body)) == {"名称": "值"}


@pytest.mark.parametrize(
    "content_type",
    [None, "text/json", "application/json; charset=latin-1", "application/json; charset=utf-8; charset=utf-8", "application/json; boundary=x", ["application/json", "application/json"]],
)
def test_read_json_body_rejects_invalid_content_type(content_type: object) -> None:
    rejected(read_json_body, io.BytesIO(b"{}"), json_headers("2", content_type), 10)


@pytest.mark.parametrize("length", [None, True, -1, "-1", "+2", "2, 2", " 2", "2 ", ["2", "2"]])
def test_read_json_body_rejects_invalid_or_duplicate_content_length(length: object) -> None:
    rejected(read_json_body, io.BytesIO(b"{}"), json_headers(length), 10)


def test_read_json_body_rejects_transfer_encoding() -> None:
    headers = json_headers("2") | {"Transfer-Encoding": "chunked"}
    rejected(read_json_body, io.BytesIO(b"{}"), headers, 10)


class NoRead(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        raise AssertionError("body was read before size rejection")


def test_read_json_body_rejects_oversize_before_reading() -> None:
    error = rejected(read_json_body, NoRead(b"{}"), json_headers("11"), 10)
    assert error.status == 413


def test_read_json_body_rejects_extremely_long_decimal_length_without_reading() -> None:
    error = rejected(
        read_json_body,
        NoRead(b"{}"),
        json_headers("9" * 10_000),
        10,
    )
    assert error.status in {400, 413}


def test_read_json_body_rejects_short_read_and_trailing_data() -> None:
    rejected(read_json_body, io.BytesIO(b"{}"), json_headers("3"), 10)
    rejected(read_json_body, io.BytesIO(b"{}x"), json_headers("2"), 10)


def test_read_json_body_rejects_bad_utf8_duplicate_keys_and_constants() -> None:
    bad_values = [b'"\xff"', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}']
    for body in bad_values:
        rejected(read_json_body, io.BytesIO(body), json_headers(str(len(body))), 100)


def test_read_json_body_converts_deep_json_recursion_error_to_rejection() -> None:
    body = b'{"x":' + (b"[" * 5_000) + b"0" + (b"]" * 5_000) + b"}"

    rejected(read_json_body, io.BytesIO(body), json_headers(str(len(body))), len(body))


@pytest.mark.parametrize("body", [b"[]", b'"x"', b"1", b"null", b"true"])
def test_read_json_body_requires_top_level_object(body: bytes) -> None:
    rejected(read_json_body, io.BytesIO(body), json_headers(str(len(body))), 100)


@pytest.mark.parametrize("maximum", [True, False, 0, -1, 1.5, "10"])
def test_read_json_body_requires_positive_integer_limit(maximum: object) -> None:
    rejected(read_json_body, io.BytesIO(b"{}"), json_headers("2"), maximum)


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def test_decode_upload_ignores_display_name_for_path_and_uses_exclusive_uuid(tmp_path: Path) -> None:
    result = decode_upload(tmp_path, {"name": "../../escape.json", "data": encoded(b"abc")}, 3, ".json")
    assert result.parent == tmp_path.resolve()
    assert result.name != "escape.json"
    assert result.suffix == ".json"
    assert result.read_bytes() == b"abc"
    assert len(result.stem) == 32


def test_decode_upload_exact_limit_succeeds_and_one_byte_over_fails(tmp_path: Path) -> None:
    assert decode_upload(tmp_path, {"name": "a", "data": encoded(b"abc")}, 3, ".bin").read_bytes() == b"abc"
    error = rejected(decode_upload, tmp_path, {"name": "a", "data": encoded(b"abc")}, 2, ".bin")
    assert error.status == 413


@pytest.mark.parametrize("data", ["Y Q==", "%%%%", "YQ=", "YQ===", "=YQ="])
def test_decode_upload_requires_strict_base64(tmp_path: Path, data: str) -> None:
    rejected(decode_upload, tmp_path, {"name": "a", "data": data}, 100, ".bin")


def test_decode_upload_preflights_size_before_base64_decode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_decode(*args, **kwargs):
        raise AssertionError("decoder called")

    monkeypatch.setattr(security.base64, "b64decode", must_not_decode)
    error = rejected(decode_upload, tmp_path, {"name": "a", "data": encoded(b"abcd")}, 3, ".bin")
    assert error.status == 413


@pytest.mark.parametrize("upload", [None, [], {}, {"name": 1, "data": ""}, {"name": "a", "data": 1}, {"name": "", "data": ""}, {"name": "a\x00b", "data": ""}, {"name": "a" * 256, "data": ""}])
def test_decode_upload_rejects_invalid_upload_metadata(tmp_path: Path, upload: object) -> None:
    rejected(decode_upload, tmp_path, upload, 100, ".bin")


def test_decode_upload_rejects_unicode_format_character_in_display_name(
    tmp_path: Path,
) -> None:
    rejected(
        decode_upload,
        tmp_path,
        {"name": "safe\u202egnp.exe", "data": ""},
        100,
        ".bin",
    )


@pytest.mark.parametrize("suffix", ["json", ".", "..json", ".x/y", ".x\\y", ".tar.gz", ".好", ".x\n"])
def test_decode_upload_rejects_suffix_injection(tmp_path: Path, suffix: str) -> None:
    rejected(decode_upload, tmp_path, {"name": "a", "data": ""}, 100, suffix)


def test_decode_upload_rejects_bad_temp_dir_without_path_leak(tmp_path: Path) -> None:
    missing = tmp_path / "secret-missing"
    regular = tmp_path / "secret-file"
    regular.write_text("x")
    for candidate in (missing, regular):
        error = rejected(decode_upload, candidate, {"name": "a", "data": ""}, 100, ".bin")
        assert str(candidate) not in error.message


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not enforced on Windows")
def test_decode_upload_sets_owner_only_permissions(tmp_path: Path) -> None:
    result = decode_upload(tmp_path, {"name": "a", "data": encoded(b"x")}, 1, ".bin")
    assert stat.S_IMODE(result.stat().st_mode) == 0o600


def test_decode_upload_cleans_partial_file_on_write_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_write = security.os.write
    calls = 0

    def fail_after_partial(fd: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, data[:1])
        raise OSError("disk detail")

    monkeypatch.setattr(security.os, "write", fail_after_partial)
    error = rejected(decode_upload, tmp_path, {"name": "a", "data": encoded(b"abc")}, 3, ".bin")
    assert "disk detail" not in error.message
    assert list(tmp_path.iterdir()) == []


def test_decode_upload_reports_cleanup_failure_without_leaking_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_write(fd: int, data: bytes) -> int:
        raise OSError("write detail")

    def fail_unlink(self: Path, missing_ok: bool = False) -> None:
        raise OSError(f"cleanup detail: {self}")

    monkeypatch.setattr(security.os, "write", fail_write)
    monkeypatch.setattr(Path, "unlink", fail_unlink)

    error = rejected(
        decode_upload,
        tmp_path,
        {"name": "a", "data": encoded(b"abc")},
        3,
        ".bin",
    )
    assert error.code == "upload_cleanup_failed"
    assert str(tmp_path) not in error.message
    assert "write detail" not in error.message
    assert "cleanup detail" not in error.message


def test_decode_upload_exclusive_create_does_not_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security.uuid, "uuid4", lambda: SimpleNamespace(hex="fixed"))
    existing = tmp_path / "fixed.bin"
    existing.write_bytes(b"keep")
    rejected(decode_upload, tmp_path, {"name": "a", "data": encoded(b"new")}, 3, ".bin")
    assert existing.read_bytes() == b"keep"


@pytest.mark.parametrize("maximum", [True, False, 0, -1, 1.5, "10"])
def test_decode_upload_requires_positive_integer_limit(tmp_path: Path, maximum: object) -> None:
    rejected(decode_upload, tmp_path, {"name": "a", "data": ""}, maximum, ".bin")
