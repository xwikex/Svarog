from __future__ import annotations

import io
import socket
from types import SimpleNamespace

import pytest

from svarog.webui.application import Response
from svarog.webui.config import UiConfig
from svarog.webui.server import WorkbenchHTTPServer, WorkbenchRequestHandler, serve


def test_ui_handler_sets_timeout_before_stream_creation() -> None:
    events = []

    class Socket:
        def settimeout(self, value):
            events.append(("timeout", value))

        def makefile(self, mode, buffering=None):
            events.append(("makefile", mode))
            return io.BytesIO()

    handler = WorkbenchRequestHandler.__new__(WorkbenchRequestHandler)
    handler.request = Socket()
    handler.server = SimpleNamespace(request_timeout=8.0)
    handler.setup()
    assert events[0] == ("timeout", 8.0)


def test_ui_handler_forwards_once_and_redacts_query_from_log() -> None:
    events, logs = [], []

    class App:
        def handle(self, method, target, headers, body):
            events.append((method, target, headers, body))
            return Response(200, "text/plain", b"ok", {"Content-Type": "text/plain", "Content-Length": "2"})

    class Handler(WorkbenchRequestHandler):
        def send_response_only(self, code, message=None):
            events.append(("response", code))

        def send_header(self, name, value):
            events.append(("header", name, value))

        def end_headers(self):
            events.append(("end",))

    handler = Handler.__new__(Handler)
    handler.command, handler.path = "GET", "/api/cases?token=secret"
    handler.headers, handler.rfile, handler.wfile = {"Authorization": "hidden"}, io.BytesIO(), io.BytesIO()
    handler.server = SimpleNamespace(application=App(), request_logger=lambda *item: logs.append(item))
    handler.do_GET()

    assert events[0][:2] == ("GET", "/api/cases?token=secret")
    assert [item for item in events if item[0] == "response"] == [("response", 200)]
    assert handler.wfile.getvalue() == b"ok"
    assert logs == [("GET", "/api/cases", 200)]


def test_ui_handler_forwards_unknown_methods_without_default_server_banner() -> None:
    calls = []

    class App:
        def handle(self, method, target, headers, body):
            calls.append((method, target, headers.get("Host")))
            return Response(
                405,
                "application/json; charset=utf-8",
                b"{}",
                {
                    "Content-Type": "application/json; charset=utf-8",
                    "Content-Length": "2",
                    "X-Content-Type-Options": "nosniff",
                },
            )

    client, request = socket.socketpair()
    try:
        client.settimeout(2)
        client.sendall(b"TRACE /private?token=secret HTTP/1.1\r\nHost: localhost:8765\r\n\r\n")
        server = SimpleNamespace(
            application=App(), request_timeout=2.0, request_logger=lambda *_args: None
        )
        WorkbenchRequestHandler(request, ("127.0.0.1", 1), server)
        response = client.recv(4096)
    finally:
        client.close()
        request.close()

    assert calls == [("TRACE", "/private?token=secret", "localhost:8765")]
    assert response.startswith(b"HTTP/1.0 405")
    assert b"X-Content-Type-Options: nosniff" in response
    assert b"Server:" not in response


def test_ui_handler_hides_disconnects_and_sanitizes_method_logs() -> None:
    logs = []

    class BrokenWriter:
        def write(self, _data):
            raise BrokenPipeError

    class Handler(WorkbenchRequestHandler):
        def send_response_only(self, _code, message=None): pass
        def send_header(self, _name, _value): pass
        def end_headers(self): pass

    handler = Handler.__new__(Handler)
    handler.command, handler.path = "GÉT\n", "/safe?secret=yes"
    handler.headers, handler.rfile, handler.wfile = {}, io.BytesIO(), BrokenWriter()
    handler.server = SimpleNamespace(
        application=SimpleNamespace(
            handle=lambda *_args: Response(
                200, "text/plain", b"ok", {"Content-Length": "2"}
            )
        ),
        request_logger=lambda *item: logs.append(item),
    )
    handler._handle_request()
    assert logs == [("G?T?", "/safe", 200)]


def test_ui_server_safe_threading_defaults_and_keeps_app(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("http.server.ThreadingHTTPServer.__init__", lambda self, address, handler: calls.append((address, handler)))
    app = object()
    server = WorkbenchHTTPServer(("127.0.0.1", 8765), app)
    assert server.application is app
    assert server.daemon_threads is True
    assert server.allow_reuse_address is False
    assert server.max_concurrent_requests == 32
    assert calls == [(('127.0.0.1', 8765), WorkbenchRequestHandler)]


def test_ui_serve_browser_is_opt_in_and_ctrl_c_is_clean(tmp_path, capsys) -> None:
    config = UiConfig.build("127.0.0.1", 8765, tmp_path)
    opened, made = [], []

    class Server:
        def __enter__(self): return self
        def __exit__(self, *_args): self.closed = True
        def serve_forever(self): raise KeyboardInterrupt

    def factory(address, app, **options):
        made.append((address, app, options))
        return Server()

    serve(config, open_browser=True, browser_opener=opened.append, server_factory=factory)
    assert opened == ["http://127.0.0.1:8765/"]
    assert made[0][0] == ("127.0.0.1", 8765)
    assert made[0][2]["request_timeout"] > 0
    assert "工作台已停止" in capsys.readouterr().out


def test_ui_serve_validates_case_database_before_server_and_tolerates_browser_error(
    monkeypatch, tmp_path, capsys
) -> None:
    config = UiConfig.build("127.0.0.1", 8765, tmp_path)
    events = []

    class Store:
        def __init__(self, path):
            events.append(("database", path))
        def __enter__(self): return self
        def __exit__(self, *_args): events.append(("database_closed",))

    class Server:
        def __enter__(self): events.append(("server",)); return self
        def __exit__(self, *_args): events.append(("server_closed",))
        def serve_forever(self): events.append(("served",))

    monkeypatch.setattr("svarog.webui.server.CaseStore", Store)

    def opener(_url):
        raise OSError("private browser path")

    serve(
        config,
        open_browser=True,
        browser_opener=opener,
        server_factory=lambda *_args, **_kwargs: Server(),
    )
    assert events[:2] == [("database", config.case_db), ("database_closed",)]
    assert ("served",) in events
    output = capsys.readouterr()
    assert "无法自动打开浏览器" in output.err
    assert "private browser path" not in output.err


def test_serve_initializes_classified_runtime_data_without_browser(tmp_path):
    from svarog.audit_history.database import DatabaseManager
    from svarog.runtime_layout import RuntimeLayout, load_project_identity, load_settings
    from svarog.sop.storage import CaseStore

    layout = RuntimeLayout.build(tmp_path)
    layout.root.mkdir()
    legacy = layout.root / "cases.sqlite3"
    with CaseStore(legacy):
        pass
    old_bytes = legacy.read_bytes()
    config = UiConfig.build("127.0.0.1", 8765, tmp_path)

    class Server:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def serve_forever(self):
            raise KeyboardInterrupt

    serve(config, open_browser=False, server_factory=lambda *_a, **_k: Server())
    assert layout.history_db.is_file()
    assert layout.case_db.is_file()
    assert legacy.read_bytes() == old_bytes
    assert load_project_identity(layout).display_name == tmp_path.name
    assert load_settings(layout).audit_retention_days == 180
    with DatabaseManager.open(layout.history_db) as database:
        assert database.schema_version >= 2
