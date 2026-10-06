import json
from dataclasses import replace
from pathlib import Path

import pytest

from svarog.models import NormalizedEvent
from svarog.policy import build_report
from svarog.reporting import render_json, render_terminal, write_json_report
from svarog.text_safety import terminal_safe


def _report():
    event = NormalizedEvent(
        line_number=1,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/search",
        query="id=1 UNION SELECT password FROM users",
    )
    return build_report((event,), (), generated_at="2026-08-03T04:00:00+00:00")


def test_terminal_safe_escapes_control_and_bidi_characters() -> None:
    assert terminal_safe("ok\n\x1b[31m\u202e") == r"ok\n\x1b[31m\u202e"


def test_terminal_report_is_chinese_and_states_read_only_boundary() -> None:
    text = render_terminal(_report())

    assert "Svarog 本地分析报告" in text
    assert "SQL" in text
    assert "未执行任何动作" in text


def test_json_report_has_stable_machine_fields(tmp_path: Path) -> None:
    report = _report()
    rendered = render_json(report)
    payload = json.loads(rendered)

    assert payload["schema_version"] == "0.1.0"
    assert payload["events"][0]["local_severity"] == "high"
    assert payload["actions_executed"] is False

    target = tmp_path / "report.json"
    write_json_report(report, target)
    assert json.loads(target.read_text(encoding="utf-8")) == payload
    assert target.read_bytes() == rendered.encode("utf-8")


def test_json_report_encoding_failure_does_not_truncate_existing_target(tmp_path: Path) -> None:
    report = _report()
    bad_event = replace(report.events[0].event, path="/bad\ud800path")
    bad_analysis = replace(report.events[0], event=bad_event)
    bad_report = replace(report, events=(bad_analysis,))
    target = tmp_path / "report.json"
    original = b"previous-good-report"
    target.write_bytes(original)

    with pytest.raises(UnicodeEncodeError):
        write_json_report(bad_report, target)

    assert target.read_bytes() == original


def test_terminal_report_escapes_control_characters_in_external_fields() -> None:
    event = NormalizedEvent(
        line_number=1,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/search\n伪造报告行\x1b[31m\u202e\u2066",
        query="id=1 UNION SELECT password FROM users",
    )
    report = build_report((event,), (), generated_at="2026-08-03T04:00:00+00:00")

    text = render_terminal(report)

    assert "\\n伪造报告行\\x1b[31m\\u202e\\u2066" in text
    assert "\n伪造报告行" not in text
    assert "\x1b" not in text
    assert "\u202e" not in text
    assert "\u2066" not in text
