from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

import pytest

from svarog.dependency_audit.models import DatabaseMetadata, VulnerabilitySnapshot
from svarog.sop.storage import CaseStore
from svarog.webui import adapters


def _environment(tmp_path: Path) -> Path:
    environment = tmp_path / ".venv"
    (environment / "Lib" / "site-packages" / "demo-1.0.dist-info").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("home = test\n", encoding="utf-8")
    (environment / "Lib" / "site-packages" / "demo-1.0.dist-info" / "METADATA").write_text(
        "Name: demo\nVersion: 1.0\n", encoding="utf-8"
    )
    (environment / "Scripts").mkdir()
    (environment / "Scripts" / "python.exe").write_bytes(b"")
    return environment


def _snapshot() -> VulnerabilitySnapshot:
    return VulnerabilitySnapshot(
        metadata=DatabaseMetadata(
            path="injected", size_bytes=0, sources=("test",),
            last_sync_at="2026-09-09T00:00:00+00:00", last_sync_status="ok",
        ),
        advisories=(),
    )


def _lock_file(tmp_path: Path) -> Path:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n\n[[package]]\nname = "demo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    return lock


def test_analyze_web_log_uses_authoritative_json_report(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text(
        json.dumps({
            "timestamp": "2026-09-08T10:00:00Z", "source_ip": "192.0.2.1",
            "method": "GET", "host": "demo.example", "path": "/.env",
        }) + "\n",
        encoding="utf-8",
    )

    result = adapters.analyze_web_log(source)

    assert result["kind"] == "web_analysis"
    assert result["report"]["summary"]["suspicious_events"] == 1
    assert result["report"]["actions_executed"] is False


@pytest.mark.parametrize("function,extra", [
    (adapters.audit_python, ()),
    (adapters.audit_project, (Path("uv.lock"),)),
    (adapters.run_doctor_check, (Path("uv.lock"), Path("out"))),
])
@pytest.mark.parametrize("vuln_db,vuln_api", [(None, None), (Path("db"), "https://api.test")])
def test_vulnerability_source_is_exclusive(function, extra, vuln_db, vuln_api) -> None:
    with pytest.raises(ValueError, match="一个漏洞来源"):
        function(Path("environment"), *extra, vuln_db=vuln_db, vuln_api=vuln_api)


def test_dependency_and_project_adapters_use_injected_remote_loader_without_token_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    lock = _lock_file(tmp_path)
    secret = "remote-secret"
    calls = []

    def loader(url: str, token: str) -> VulnerabilitySnapshot:
        calls.append((url, token))
        return _snapshot()

    monkeypatch.setattr(adapters, "_remote_snapshot_loader", loader)
    monkeypatch.setenv("SVAROG_VULN_API_TOKEN", secret)

    dependency = adapters.audit_python(environment, vuln_db=None, vuln_api="https://api.test", token="")
    project = adapters.audit_project(
        environment, lock, vuln_db=None, vuln_api="https://api.test", token=None
    )

    assert dependency["kind"] == "dependency_audit"
    assert project["kind"] == "project_audit"
    assert dependency["report"]["actions_executed"] is False
    assert project["report"]["actions_executed"] is False
    assert calls == [("https://api.test", secret), ("https://api.test", secret)]
    assert secret not in json.dumps([dependency, project], ensure_ascii=False)


def test_prepared_audit_retains_inputs_and_defers_report_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    lock = _lock_file(tmp_path)
    snapshot = _snapshot()
    monkeypatch.setattr(adapters, "_remote_snapshot_loader", lambda _url, _token: snapshot)
    calls: list[str] = []
    original = adapters._build_project_audit_report

    def counted(*args, **kwargs):
        calls.append("build")
        return original(*args, **kwargs)

    monkeypatch.setattr(adapters, "_build_project_audit_report", counted)
    prepared = adapters._prepare_audit(
        environment, lock_file=lock, vuln_db=None, vuln_api="https://api.test", token="x"
    )
    assert prepared.inventory.packages
    assert prepared.lock is not None
    assert prepared.vulnerability is snapshot
    assert prepared.report is None
    assert calls == []

    finished = adapters._complete_audit(prepared)
    assert finished.report is not None
    assert finished.result["kind"] == "project_audit"
    assert calls == ["build"]


@pytest.mark.parametrize("with_lock", [False, True])
def test_completed_audit_uses_explicit_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_lock: bool
) -> None:
    environment = _environment(tmp_path)
    lock = _lock_file(tmp_path) if with_lock else None
    monkeypatch.setattr(adapters, "_remote_snapshot_loader", lambda _url, _token: _snapshot())
    prepared = adapters._prepare_audit(
        environment, lock_file=lock, vuln_db=None, vuln_api="https://api.test", token="x"
    )
    completed = adapters._complete_audit(
        prepared, now=datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    )
    assert completed.result is not None
    assert completed.result["report"]["generated_at"] == "2026-09-30T12:00:00+00:00"


def test_remote_loader_exception_propagates_without_becoming_a_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)

    def broken(_url: str, _token: str) -> VulnerabilitySnapshot:
        raise RuntimeError("secret transport detail")

    monkeypatch.setattr(adapters, "_remote_snapshot_loader", broken)
    with pytest.raises(RuntimeError, match="secret transport detail"):
        adapters.audit_python(environment, vuln_db=None, vuln_api="https://api.test", token="x")


def test_doctor_uses_injected_command_and_network_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    lock = _lock_file(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    commands = []
    endpoints = []
    monkeypatch.setattr(adapters, "_doctor_command_runner", lambda argv: commands.append(argv) or True)
    monkeypatch.setattr(
        adapters, "_doctor_tcp_connector",
        lambda endpoint, timeout: endpoints.append((endpoint, timeout)) or nullcontext(),
    )

    result = adapters.run_doctor_check(
        environment, lock, output, vuln_db=None, vuln_api="https://api.test:443"
    )

    assert result["kind"] == "doctor"
    assert result["report"]["overall_status"] == "ready_with_warnings"
    assert commands == [
        (str(environment / "Scripts" / "python.exe"), "--version"),
        ("uv", "--version"),
    ]
    assert endpoints[0][0] == ("api.test", 443)


def test_sop_adapter_loads_advisor_saves_case_and_never_approves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    alert = tmp_path / "alert.json"
    logs = tmp_path / "logs.jsonl"
    config = tmp_path / "agent.toml"
    database = tmp_path / "cases.sqlite3"
    alert.write_text(json.dumps({
        "alert_id": "demo-1", "title": "Demo", "timestamp": "2026-09-08T10:00:00Z",
        "source_ip": "192.0.2.8", "host": "demo.example",
    }), encoding="utf-8")
    logs.write_text(json.dumps({
        "timestamp": "2026-09-08T10:01:00Z", "source_ip": "192.0.2.8",
        "method": "GET", "host": "demo.example", "path": "/.env", "status": 403,
    }) + "\n", encoding="utf-8")
    config.write_text("model config", encoding="utf-8")
    seen = []

    def fake_load(path: Path):
        seen.append(path)
        return lambda context: {
            "summary": "只读建议，需人工复核。", "evidence_ids": [context["evidence"][0]["id"]]
        }

    monkeypatch.setattr(adapters, "_advisor_loader", fake_load)

    result = adapters.run_sop_case(
        alert, logs, case_db=database, log_format="jsonl", log_host=None,
        window_minutes=15, limit=20, agent_config=config,
    )

    assert result["kind"] == "sop_case"
    assert seen == [config]
    assert result["report"]["status"] == "awaiting_review"
    assert result["report"]["actions_executed"] is False
    with CaseStore(database, create=False) as store:
        assert store.get(result["report"]["case_id"]) == result["report"]
