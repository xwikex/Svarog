"""Read bounded vulnerability snapshots from a remote vuln-sync API."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name

from .models import (
    AdvisoryRecord,
    AuditIssue,
    DatabaseMetadata,
    VulnerabilitySnapshot,
)
from .repository import (
    MAX_SUMMARY_CHARS,
    MAX_SYNC_MESSAGE_CHARS,
    _advisory_sort_key,
    _bounded,
    _cvss,
    _severity,
)


PAGE_SIZE = 200
MAX_REMOTE_ADVISORIES = 50_000
MAX_REMOTE_PAGES = 250
MAX_REMOTE_PIP_ROWS = 100_000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 15.0


class RemoteVulnerabilityError(ValueError):
    """A fixed, non-sensitive remote vulnerability source failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _UnstableSnapshot(Exception):
    pass


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    content_type: str
    body: bytes


Transport = Callable[[str, Mapping[str, str], float, int], HttpResponse]


@dataclass(frozen=True, slots=True)
class _SyncMetadata:
    last_sync_at: str | None
    status: str | None
    message: str | None


@dataclass(frozen=True, slots=True)
class _RemotePage:
    total: int
    limit: int
    offset: int
    advisory_ids: tuple[str, ...]
    records: tuple[AdvisoryRecord, ...]
    issues: tuple[AuditIssue, ...]

    @property
    def signature(self) -> tuple[object, ...]:
        return self.advisory_ids, self.records, self.issues


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object):
        return None


def normalize_api_base_url(value: str) -> str:
    """Validate and normalize an HTTP(S) API origin without credentials."""

    try:
        split = urlsplit(value)
        port = split.port
    except (AttributeError, TypeError, ValueError):
        raise RemoteVulnerabilityError("invalid_configuration") from None
    scheme = split.scheme.lower()
    hostname = split.hostname
    if (
        scheme not in {"http", "https"}
        or not hostname
        or split.username is not None
        or split.password is not None
        or split.path not in {"", "/"}
        or split.query
        or split.fragment
        or (port is not None and not 1 <= port <= 65535)
        or any(ord(character) <= 32 or ord(character) == 127 for character in hostname)
    ):
        raise RemoteVulnerabilityError("invalid_configuration")
    normalized_host = hostname.lower()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    authority = normalized_host if port is None else f"{normalized_host}:{port}"
    return f"{scheme}://{authority}"


def _default_transport(
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    max_bytes: int,
) -> HttpResponse:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    request = urllib.request.Request(
        url,
        headers=dict(headers),
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length")
            declared_length: int | None = None
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except (TypeError, ValueError):
                    raise RemoteVulnerabilityError("invalid_response") from None
                if declared_length < 0 or declared_length > max_bytes:
                    raise RemoteVulnerabilityError("invalid_response")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes or (
                declared_length is not None and len(body) != declared_length
            ):
                raise RemoteVulnerabilityError("invalid_response")
            return HttpResponse(
                status=int(response.status),
                content_type=response.headers.get("Content-Type", ""),
                body=body,
            )
    except RemoteVulnerabilityError:
        raise
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code <= 399:
            code = "redirect_rejected"
        elif exc.code in {401, 403}:
            code = "authentication_failed"
        elif exc.code == 429:
            code = "rate_limited"
        else:
            code = "http_failed"
        raise RemoteVulnerabilityError(code) from None
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
        raise RemoteVulnerabilityError("unavailable") from None


def _reject_json_constant(_value: str) -> object:
    raise ValueError("invalid_json_constant")


def _request_json(
    base_url: str,
    path: str,
    token: str,
    transport: Transport,
) -> object:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "svarog-security/0.1",
    }
    response = transport(
        base_url + path,
        headers,
        REQUEST_TIMEOUT_SECONDS,
        MAX_RESPONSE_BYTES,
    )
    content_type = response.content_type.split(";", 1)[0].strip().lower()
    if response.status != 200 or content_type != "application/json":
        raise RemoteVulnerabilityError("invalid_response")
    try:
        text = response.body.decode("utf-8", errors="strict")
        return json.loads(text, parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise RemoteVulnerabilityError("invalid_response") from None


def load_remote_vulnerability_snapshot(
    api_url: str,
    token: str,
    *,
    transport: Transport = _default_transport,
) -> VulnerabilitySnapshot:
    """Load one bounded, stability-checked remote pip advisory snapshot."""

    base_url = normalize_api_base_url(api_url)
    if not isinstance(token, str) or not token.strip():
        raise RemoteVulnerabilityError("invalid_configuration")
    for attempt in range(2):
        try:
            return _load_remote_once(base_url, token, transport)
        except _UnstableSnapshot:
            if attempt == 1:
                raise RemoteVulnerabilityError("unstable_snapshot") from None
    raise RemoteVulnerabilityError("unstable_snapshot")


def _load_remote_once(
    base_url: str,
    token: str,
    transport: Transport,
) -> VulnerabilitySnapshot:
    before = _fetch_sync_metadata(base_url, token, transport)
    first_page = _fetch_page(base_url, token, transport, offset=0)
    pages = [first_page]
    received = len(first_page.advisory_ids)
    offset = PAGE_SIZE
    while received < first_page.total:
        if len(pages) >= MAX_REMOTE_PAGES:
            raise RemoteVulnerabilityError("invalid_response")
        page = _fetch_page(base_url, token, transport, offset=offset)
        if page.total != first_page.total:
            raise RemoteVulnerabilityError("invalid_response")
        pages.append(page)
        received += len(page.advisory_ids)
        offset += PAGE_SIZE
    if received != first_page.total:
        raise RemoteVulnerabilityError("invalid_response")

    advisory_ids = tuple(
        advisory_id
        for page in pages
        for advisory_id in page.advisory_ids
    )
    if len(set(advisory_ids)) != len(advisory_ids):
        raise RemoteVulnerabilityError("invalid_response")

    after = _fetch_sync_metadata(base_url, token, transport)
    repeated_first_page = _fetch_page(base_url, token, transport, offset=0)
    if (
        before != after
        or repeated_first_page.total != first_page.total
        or repeated_first_page.signature != first_page.signature
    ):
        raise _UnstableSnapshot

    records = tuple(
        sorted(
            {
                record
                for page in pages
                for record in page.records
            },
            key=_advisory_sort_key,
        )
    )
    if len(records) > MAX_REMOTE_PIP_ROWS:
        raise RemoteVulnerabilityError("invalid_response")
    issues = tuple(
        sorted(
            (issue for page in pages for issue in page.issues),
            key=lambda item: (item.subject or "", item.code, item.message),
        )
    )
    metadata = DatabaseMetadata(
        path=base_url,
        size_bytes=0,
        sources=tuple(sorted({record.source for record in records})),
        last_sync_at=before.last_sync_at,
        last_sync_status=before.status,
        last_sync_message=before.message,
    )
    return VulnerabilitySnapshot(metadata, records, issues)


def _fetch_sync_metadata(
    base_url: str,
    token: str,
    transport: Transport,
) -> _SyncMetadata:
    payload = _request_json(
        base_url,
        "/api/v1/sync/last",
        token,
        transport,
    )
    obj = _object(payload)
    return _SyncMetadata(
        _optional_text(obj.get("last_sync_at"), 64),
        _optional_text(obj.get("status"), 32),
        _optional_text(obj.get("message"), MAX_SYNC_MESSAGE_CHARS),
    )


def _fetch_page(
    base_url: str,
    token: str,
    transport: Transport,
    *,
    offset: int,
) -> _RemotePage:
    payload = _request_json(
        base_url,
        f"/api/v1/advisories?ecosystem=pip&limit={PAGE_SIZE}&offset={offset}",
        token,
        transport,
    )
    obj = _object(payload)
    total = _integer(obj.get("total"))
    limit = _integer(obj.get("limit"))
    returned_offset = _integer(obj.get("offset"))
    items = _array(obj.get("items"))
    if (
        not 0 <= total <= MAX_REMOTE_ADVISORIES
        or limit != PAGE_SIZE
        or returned_offset != offset
    ):
        raise RemoteVulnerabilityError("invalid_response")
    expected = max(0, min(PAGE_SIZE, total - offset))
    if len(items) != expected:
        raise RemoteVulnerabilityError("invalid_response")

    advisory_ids: list[str] = []
    records: list[AdvisoryRecord] = []
    issues: list[AuditIssue] = []
    for value in items:
        advisory_id, mapped, mapped_issues = _map_advisory(value)
        advisory_ids.append(advisory_id)
        records.extend(mapped)
        issues.extend(mapped_issues)
        if len(records) > MAX_REMOTE_PIP_ROWS:
            raise RemoteVulnerabilityError("invalid_response")
    if len(set(advisory_ids)) != len(advisory_ids):
        raise RemoteVulnerabilityError("invalid_response")
    return _RemotePage(
        total,
        limit,
        returned_offset,
        tuple(advisory_ids),
        tuple(records),
        tuple(issues),
    )


def _map_advisory(
    value: object,
) -> tuple[str, tuple[AdvisoryRecord, ...], tuple[AuditIssue, ...]]:
    obj = _object(value)
    ghsa_id = _required_text(obj.get("ghsa_id"), 64)
    cve_id = _optional_text(obj.get("cve_id"), 64)
    state = _optional_text(obj.get("state"), 32) or "unknown"
    withdrawn_at = _optional_text(obj.get("withdrawn_at"), 64)
    summary = _optional_text(obj.get("summary"), MAX_SUMMARY_CHARS) or ""
    source = _optional_text(obj.get("source"), 64) or "unknown"
    updated_at = _optional_text(obj.get("updated_at"), 64)
    severity_value = obj.get("severity")
    severity, severity_issue = _severity(
        severity_value if isinstance(severity_value, str) else None
    )
    score, score_issue = _cvss(obj.get("cvss_score"))
    packages = _array(obj.get("packages"))

    records: list[AdvisoryRecord] = []
    issues: list[AuditIssue] = []
    for package_value in packages:
        package = _object(package_value)
        ecosystem = package.get("ecosystem")
        if ecosystem is None:
            continue
        if not isinstance(ecosystem, str):
            raise RemoteVulnerabilityError("invalid_response")
        if ecosystem != "pip":
            continue
        package_name = _optional_text(package.get("package_name"), 256) or ""
        normalized_package_name = canonicalize_name(package_name)
        if score_issue is not None:
            issues.append(
                AuditIssue(
                    score_issue.code,
                    score_issue.message,
                    normalized_package_name,
                )
            )
        if severity_issue is not None:
            issues.append(
                AuditIssue(
                    severity_issue.code,
                    severity_issue.message,
                    normalized_package_name,
                )
            )
        records.append(
            AdvisoryRecord(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                state=state,
                withdrawn_at=withdrawn_at,
                summary=summary,
                severity=severity,
                cvss_score=score,
                source=source,
                updated_at=updated_at,
                package_name=package_name,
                normalized_package_name=normalized_package_name,
                version_range=(
                    _optional_text(package.get("version_range"), 512) or ""
                ),
                fixed_version=_optional_text(
                    package.get("fixed_version"),
                    128,
                ),
            )
        )
    return ghsa_id, tuple(records), tuple(issues)


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise RemoteVulnerabilityError("invalid_response")
    return value


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise RemoteVulnerabilityError("invalid_response")
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RemoteVulnerabilityError("invalid_response")
    return value


def _required_text(value: object, limit: int) -> str:
    text = _optional_text(value, limit)
    if not text:
        raise RemoteVulnerabilityError("invalid_response")
    return text


def _optional_text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RemoteVulnerabilityError("invalid_response")
    return _bounded(value, limit)
