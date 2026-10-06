"""Loopback-only HTTP lifecycle for the local Svarog workbench."""

from __future__ import annotations

import secrets
import socket
import sys
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from svarog.sop.storage import CaseStore
from svarog.audit_history.database import DatabaseManager
from svarog.runtime_layout import (
    ProjectIdentity, RuntimeLayout, RuntimeSettings, migrate_legacy_cases_db,
)

from .application import WorkbenchApplication
from .config import UiConfig


RequestLogger = Callable[[str, str, int], None]
_HTTP_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _safe_log_path(target: str) -> str:
    path = target.split("?", 1)[0].split("#", 1)[0]
    return "".join(character if 0x21 <= ord(character) <= 0x7E else "?" for character in path)


def _safe_log_method(method: str) -> str:
    return "".join(character if character in _HTTP_TOKEN_CHARACTERS else "?" for character in method)


def _default_request_logger(method: str, path: str, status: int) -> None:
    print(f"{method} {path} {status}", file=sys.stderr, flush=True)


class WorkbenchRequestHandler(BaseHTTPRequestHandler):
    """Translate one HTTP request into one application response."""

    def setup(self) -> None:
        self.request.settimeout(self.server.request_timeout)  # type: ignore[attr-defined]
        super().setup()

    def _handle_request(self) -> None:
        response = self.server.application.handle(  # type: ignore[attr-defined]
            self.command,
            self.path,
            self.headers,
            self.rfile,
        )
        try:
            self.send_response_only(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)
        except OSError:
            pass
        try:
            self.server.request_logger(  # type: ignore[attr-defined]
                _safe_log_method(self.command),
                _safe_log_path(self.path),
                response.status,
            )
        except Exception:
            pass

    do_GET = _handle_request
    do_POST = _handle_request
    do_HEAD = _handle_request
    do_PUT = _handle_request
    do_PATCH = _handle_request
    do_DELETE = _handle_request
    do_OPTIONS = _handle_request

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return self._handle_request
        raise AttributeError(name)

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        del code, size


class WorkbenchHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    max_concurrent_requests = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        application: WorkbenchApplication,
        *,
        request_timeout: float = 15.0,
        request_logger: RequestLogger = _default_request_logger,
    ) -> None:
        self.application = application
        self.request_timeout = request_timeout
        self.request_logger = request_logger
        self._request_slots = threading.BoundedSemaphore(self.max_concurrent_requests)
        self.address_family = socket.AF_INET6 if ":" in server_address[0] else socket.AF_INET
        super().__init__(server_address, WorkbenchRequestHandler)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def _local_url(host: str, port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return f"http://{display_host}:{port}/"


def serve(
    config: UiConfig,
    open_browser: bool = False,
    *,
    browser_opener: Callable[[str], Any] = webbrowser.open,
    server_factory: Callable[..., Any] = WorkbenchHTTPServer,
) -> None:
    """Serve until stopped; dependencies are injectable for socket-free tests."""

    layout = RuntimeLayout.build(config.workspace)
    layout.ensure_directories()
    if config.case_db == layout.case_db:
        migrate_legacy_cases_db(layout)
    ProjectIdentity.load_or_create(layout)
    RuntimeSettings.load_or_create(layout)
    with DatabaseManager.open(layout.history_db):
        pass
    with CaseStore(config.case_db):
        pass
    application = WorkbenchApplication(config, secrets.token_urlsafe(32))
    url = _local_url(config.host, config.port)
    with server_factory(
        (config.host, config.port),
        application,
        request_timeout=15.0,
        request_logger=_default_request_logger,
    ) as server:
        print(f"Svarog 工作台：{url}", flush=True)
        if open_browser:
            try:
                browser_opener(url)
            except (OSError, webbrowser.Error):
                print("[警告] 无法自动打开浏览器，请手动访问上方地址。", file=sys.stderr, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Svarog 工作台已停止。", flush=True)


__all__ = ["WorkbenchHTTPServer", "WorkbenchRequestHandler", "serve"]
