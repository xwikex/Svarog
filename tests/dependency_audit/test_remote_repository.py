from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
import sqlite3
import urllib.error

import pytest

from svarog.dependency_audit import remote_repository
from svarog.dependency_audit.inventory import inventory_python_environment
from svarog.dependency_audit.repository import load_vulnerability_snapshot
from svarog.dependency_audit.remote_repository import (
    HttpResponse,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    RemoteVulnerabilityError,
    _default_transport,
    _request_json,
    load_remote_vulnerability_snapshot,
    normalize_api_base_url,
)
from svarog.dependency_audit.service import build_dependency_audit_report


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://vm:8000",
        "http://user:pass@vm:8000",
        "http://vm:8000/api",
        "http://vm:8000?token=x",
        "http://vm:8000/#fragment",
        "http:///missing-host",
        "http://vm:invalid-port",
    ],
)
def test_normalize_api_base_url_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(RemoteVulnerabilityError) as caught:
        normalize_api_base_url(value)

    assert caught.value.code == "invalid_configuration"
    if value:
        assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://vm:8000", "http://vm:8000"),
        ("http://vm:8000/", "http://vm:8000"),
        ("HTTPS://Example.Test:8443/", "https://example.test:8443"),
        ("http://[::1]:8000", "http://[::1]:8000"),
    ],
)
def test_normalize_api_base_url_returns_stable_origin(
    value: str,
    expected: str,
) -> None:
    assert normalize_api_base_url(value) == expected


class ScriptedTransport:
    def __init__(self, responses: list[HttpResponse]):
        self.responses = list(responses)
        self.requests: list[tuple[str, Mapping[str, str], float, int]] = []

    def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> HttpResponse:
        self.requests.append((url, headers, timeout, max_bytes))
        return self.responses.pop(0)


def json_response(payload: object) -> HttpResponse:
    return HttpResponse(
        status=200,
        content_type="application/json",
        body=json.dumps(payload).encode("utf-8"),
    )


def sync_payload(
    *,
    synced_at: str = "2026-09-01T12:00:00Z",
    status: str = "ok",
) -> dict[str, object]:
    return {
        "last_sync_at": synced_at,
        "status": status,
        "message": "complete",
    }


def advisory_payload(
    ghsa_id: str,
    *,
    packages: list[dict[str, object]] | None = None,
    severity: object = "high",
    cvss_score: object = 8.1,
    state: object = "published",
    withdrawn_at: object = None,
) -> dict[str, object]:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": "CVE-2026-0001",
        "state": state,
        "summary": "demo advisory",
        "severity": severity,
        "cvss_score": cvss_score,
        "updated_at": "2026-09-01T00:00:00Z",
        "withdrawn_at": withdrawn_at,
        "source": "github_api",
        "packages": packages
        if packages is not None
        else [
            {
                "ecosystem": "pip",
                "package_name": "Demo_Pkg",
                "version_range": "< 2.0",
                "fixed_version": "2.0",
            }
        ],
    }


def page_payload(
    items: list[dict[str, object]],
    *,
    total: int | None = None,
    offset: int = 0,
) -> dict[str, object]:
    return {
        "total": len(items) if total is None else total,
        "limit": 200,
        "offset": offset,
        "items": items,
    }


def stable_responses(
    pages: list[dict[str, object]],
    *,
    sync: dict[str, object] | None = None,
) -> list[HttpResponse]:
    metadata = sync or sync_payload()
    return [
        json_response(metadata),
        *(json_response(page) for page in pages),
        json_response(metadata),
        json_response(pages[0]),
    ]


def test_remote_and_local_sources_build_equivalent_audit_reports(
    tmp_path: Path,
) -> None:
    synced_at = datetime.now(timezone.utc).isoformat()
    environment = tmp_path / "environment"
    site_packages = environment / "Lib" / "site-packages"
    metadata = site_packages / "Demo_Pkg-1.0.dist-info" / "METADATA"
    metadata.parent.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "home = C:\\Python313\n",
        encoding="utf-8",
    )
    metadata.write_text("Name: Demo_Pkg\nVersion: 1.0\n", encoding="utf-8")
    database = tmp_path / "vulnerabilities.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE advisories (
            ghsa_id TEXT PRIMARY KEY, cve_id TEXT, state TEXT, summary TEXT,
            description TEXT, severity TEXT, cvss_score REAL, cvss_vector TEXT,
            published_at TEXT, updated_at TEXT, withdrawn_at TEXT, source TEXT,
            raw_json TEXT, first_seen_at TEXT, last_synced_at TEXT
        );
        CREATE TABLE affected_packages (
            id INTEGER PRIMARY KEY, ghsa_id TEXT, ecosystem TEXT,
            package_name TEXT, version_range TEXT, introduced TEXT,
            fixed_version TEXT
        );
        CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    connection.execute(
        "INSERT INTO advisories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "GHSA-test-0001", "CVE-2026-0001", "published", "demo advisory",
            "unused", "high", 8.1, "unused", "2026-09-01T00:00:00Z",
            "2026-09-01T00:00:00Z", None, "github_api", "unused",
            "2026-09-01T00:00:00Z", synced_at,
        ),
    )
    connection.execute(
        "INSERT INTO affected_packages VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "GHSA-test-0001", "pip", "Demo_Pkg", "< 2.0", None, "2.0"),
    )
    connection.executemany(
        "INSERT INTO sync_meta VALUES (?, ?)",
        (
            ("last_sync_at", synced_at),
            ("last_sync_status", "ok"),
            ("last_sync_message", "complete"),
        ),
    )
    connection.commit()
    connection.close()

    page = page_payload([advisory_payload("GHSA-test-0001")])
    remote_snapshot = load_remote_vulnerability_snapshot(
        "http://vm:8000",
        "secret",
        transport=ScriptedTransport(
            stable_responses(
                [page],
                sync=sync_payload(synced_at=synced_at),
            )
        ),
    )
    inventory = inventory_python_environment(environment)
    local_report = build_dependency_audit_report(
        inventory,
        load_vulnerability_snapshot(database),
    )
    remote_report = build_dependency_audit_report(inventory, remote_snapshot)

    assert remote_report.audit_status == local_report.audit_status
    assert remote_report.summary == local_report.summary
    assert remote_report.findings == local_report.findings
    assert (
        remote_report.indeterminate_findings
        == local_report.indeterminate_findings
    )
    assert remote_report.warnings == local_report.warnings
    assert remote_report.actions_executed is local_report.actions_executed is False


def test_request_json_sends_token_only_in_authorization_header() -> None:
    transport = ScriptedTransport([json_response({"status": "ok"})])
    secret = "private-api-token"

    result = _request_json(
        "http://vm:8000",
        "/api/v1/sync/last",
        secret,
        transport,
    )

    assert result == {"status": "ok"}
    url, headers, timeout, max_bytes = transport.requests[0]
    assert url == "http://vm:8000/api/v1/sync/last"
    assert secret not in url
    assert headers == {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/json",
        "User-Agent": "svarog-security/0.1",
    }
    assert timeout == REQUEST_TIMEOUT_SECONDS
    assert max_bytes == MAX_RESPONSE_BYTES


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(200, "text/plain", b"{}"),
        HttpResponse(200, "application/json", b"\xff"),
        HttpResponse(200, "application/json", b"{"),
        HttpResponse(200, "application/json", b'{"value": NaN}'),
        HttpResponse(204, "application/json", b"{}"),
    ],
)
def test_request_json_rejects_invalid_responses(response: HttpResponse) -> None:
    transport = ScriptedTransport([response])

    with pytest.raises(RemoteVulnerabilityError) as caught:
        _request_json("http://vm:8000", "/api/v1/sync/last", "secret", transport)

    assert caught.value.code == "invalid_response"


class _FakeResponse:
    def __init__(self, body: bytes, *, content_length: str | None = None):
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = "application/json; charset=utf-8"
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._body[:size]


class _FakeOpener:
    def __init__(self, response: object):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, *, timeout: float):
        self.request = request
        self.timeout = timeout
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def test_default_transport_disables_proxies_and_bounds_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_handlers: list[object] = []
    opener = _FakeOpener(_FakeResponse(b'{"ok": true}'))

    def build_opener(*handlers: object):
        captured_handlers.extend(handlers)
        return opener

    monkeypatch.setenv("HTTP_PROXY", "http://untrusted-proxy:8080")
    monkeypatch.setattr(remote_repository.urllib.request, "build_opener", build_opener)

    response = _default_transport(
        "http://vm:8000/api/v1/sync/last",
        {"Authorization": "Bearer secret"},
        3.0,
        128,
    )

    proxy = next(
        handler
        for handler in captured_handlers
        if isinstance(handler, remote_repository.urllib.request.ProxyHandler)
    )
    assert proxy.proxies == {}
    assert any(
        isinstance(handler, remote_repository._NoRedirectHandler)
        for handler in captured_handlers
    )
    assert opener.request.get_method() == "GET"
    assert opener.timeout == 3.0
    assert response.body == b'{"ok": true}'


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (302, "redirect_rejected"),
        (401, "authentication_failed"),
        (403, "authentication_failed"),
        (429, "rate_limited"),
        (500, "http_failed"),
    ],
)
def test_default_transport_maps_http_status_without_response_body(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    expected: str,
) -> None:
    error = urllib.error.HTTPError(
        "http://vm:8000/secret-path",
        status,
        "contains sensitive server text",
        Message(),
        None,
    )
    opener = _FakeOpener(error)
    monkeypatch.setattr(
        remote_repository.urllib.request,
        "build_opener",
        lambda *_handlers: opener,
    )

    with pytest.raises(RemoteVulnerabilityError) as caught:
        _default_transport("http://vm:8000/path", {}, 1.0, 128)

    assert caught.value.code == expected
    assert "sensitive" not in str(caught.value)


def test_default_transport_rejects_declared_or_streamed_oversize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for response in (
        _FakeResponse(b"{}", content_length="129"),
        _FakeResponse(b"x" * 129),
    ):
        monkeypatch.setattr(
            remote_repository.urllib.request,
            "build_opener",
            lambda *_handlers, response=response: _FakeOpener(response),
        )
        with pytest.raises(RemoteVulnerabilityError) as caught:
            _default_transport("http://vm:8000/path", {}, 1.0, 128)
        assert caught.value.code == "invalid_response"


def test_default_transport_rejects_truncated_declared_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(b"{}", content_length="3")
    monkeypatch.setattr(
        remote_repository.urllib.request,
        "build_opener",
        lambda *_handlers: _FakeOpener(response),
    )

    with pytest.raises(RemoteVulnerabilityError) as caught:
        _default_transport("http://vm:8000/path", {}, 1.0, 128)

    assert caught.value.code == "invalid_response"


def test_remote_repository_maps_only_pip_packages() -> None:
    page = page_payload(
        [
            advisory_payload(
                "GHSA-test-0001",
                packages=[
                    {
                        "ecosystem": "pip",
                        "package_name": "Demo_Pkg",
                        "version_range": "< 2.0",
                        "fixed_version": "2.0",
                    },
                    {
                        "ecosystem": "npm",
                        "package_name": "demo",
                        "version_range": "< 9",
                        "fixed_version": "9",
                    },
                ],
            )
        ]
    )
    transport = ScriptedTransport(stable_responses([page]))

    snapshot = load_remote_vulnerability_snapshot(
        "http://vm:8000/",
        "secret",
        transport=transport,
    )

    assert len(snapshot.advisories) == 1
    assert snapshot.advisories[0].normalized_package_name == "demo-pkg"
    assert snapshot.advisories[0].version_range == "< 2.0"
    assert snapshot.metadata.last_sync_status == "ok"
    assert snapshot.metadata.path == "http://vm:8000"
    assert snapshot.metadata.size_bytes == 0
    assert snapshot.metadata.sources == ("github_api",)
    assert snapshot.issues == ()


def test_remote_repository_reads_multiple_pages() -> None:
    first_items = [
        advisory_payload(f"GHSA-test-{index:04d}")
        for index in range(200)
    ]
    last_item = advisory_payload("GHSA-test-0200")
    pages = [
        page_payload(first_items, total=201),
        page_payload([last_item], total=201, offset=200),
    ]
    transport = ScriptedTransport(stable_responses(pages))

    snapshot = load_remote_vulnerability_snapshot(
        "https://vm.example:8443",
        "secret",
        transport=transport,
    )

    assert len(snapshot.advisories) == 201
    requested_urls = [request[0] for request in transport.requests]
    assert any("offset=0" in url for url in requested_urls)
    assert any("offset=200" in url for url in requested_urls)


def test_remote_repository_marks_invalid_severity_and_cvss() -> None:
    item = advisory_payload(
        "GHSA-invalid-fields",
        severity={"unexpected": "object"},
        cvss_score="8.1",
    )
    page = page_payload([item])
    transport = ScriptedTransport(stable_responses([page]))

    snapshot = load_remote_vulnerability_snapshot(
        "http://vm:8000",
        "secret",
        transport=transport,
    )

    assert snapshot.advisories[0].severity.value == "unknown"
    assert snapshot.advisories[0].cvss_score is None
    assert {issue.code for issue in snapshot.issues} == {
        "invalid_cvss",
        "invalid_severity",
    }


def test_remote_repository_rejects_duplicate_ghsa_ids() -> None:
    duplicate = advisory_payload("GHSA-duplicate")
    page = page_payload([duplicate, duplicate])
    transport = ScriptedTransport([json_response(sync_payload()), json_response(page)])

    with pytest.raises(RemoteVulnerabilityError) as caught:
        load_remote_vulnerability_snapshot(
            "http://vm:8000",
            "secret",
            transport=transport,
        )

    assert caught.value.code == "invalid_response"


@pytest.mark.parametrize(
    "page_change",
    [
        {"limit": 199},
        {"offset": 1},
        {"total": -1},
        {"items": {}},
    ],
)
def test_remote_repository_rejects_invalid_page_shape(
    page_change: dict[str, object],
) -> None:
    page = page_payload([advisory_payload("GHSA-invalid-page")])
    page.update(page_change)
    transport = ScriptedTransport([json_response(sync_payload()), json_response(page)])

    with pytest.raises(RemoteVulnerabilityError) as caught:
        load_remote_vulnerability_snapshot(
            "http://vm:8000",
            "secret",
            transport=transport,
        )

    assert caught.value.code == "invalid_response"


def test_remote_repository_retries_unstable_snapshot_once() -> None:
    old_sync = sync_payload(synced_at="2026-09-01T11:00:00Z")
    new_sync = sync_payload(synced_at="2026-09-01T12:00:00Z")
    changing = page_payload([advisory_payload("GHSA-changing")])
    stable = page_payload([advisory_payload("GHSA-stable")])
    transport = ScriptedTransport(
        [
            json_response(old_sync),
            json_response(changing),
            json_response(new_sync),
            json_response(changing),
            *stable_responses([stable], sync=new_sync),
        ]
    )

    snapshot = load_remote_vulnerability_snapshot(
        "http://vm:8000",
        "secret",
        transport=transport,
    )

    assert {item.ghsa_id for item in snapshot.advisories} == {"GHSA-stable"}
    assert len(transport.requests) == 8


def test_remote_repository_fails_after_second_unstable_snapshot() -> None:
    first = page_payload([advisory_payload("GHSA-first")])
    changed = page_payload([advisory_payload("GHSA-changed")])
    responses: list[HttpResponse] = []
    for attempt in range(2):
        before = sync_payload(synced_at=f"2026-09-01T1{attempt}:00:00Z")
        after = sync_payload(synced_at=f"2026-09-01T1{attempt + 1}:00:00Z")
        responses.extend(
            [
                json_response(before),
                json_response(first),
                json_response(after),
                json_response(changed),
            ]
        )
    transport = ScriptedTransport(responses)

    with pytest.raises(RemoteVulnerabilityError) as caught:
        load_remote_vulnerability_snapshot(
            "http://vm:8000",
            "secret",
            transport=transport,
        )

    assert caught.value.code == "unstable_snapshot"
    assert len(transport.requests) == 8


def test_remote_repository_does_not_retry_invalid_response() -> None:
    transport = ScriptedTransport([json_response([])])

    with pytest.raises(RemoteVulnerabilityError) as caught:
        load_remote_vulnerability_snapshot(
            "http://vm:8000",
            "secret",
            transport=transport,
        )

    assert caught.value.code == "invalid_response"
    assert len(transport.requests) == 1
