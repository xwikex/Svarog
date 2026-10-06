import json
from pathlib import Path

import pytest

from svarog.parsers.nginx_json import MAX_RECORDED_ISSUES, InputFileError, parse_jsonl


def _write_lines(path: Path, records: list[object]) -> None:
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records),
        encoding="utf-8",
    )


def test_parse_jsonl_normalizes_a_valid_event(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    _write_lines(source, [{
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "get",
        "host": "EXAMPLE.TEST",
        "path": "/search",
        "query": "q=安全",
        "status": 200,
    }])

    result = parse_jsonl(source)

    assert len(result.events) == 1
    assert result.events[0].method == "GET"
    assert result.events[0].host == "example.test"
    assert result.issues == ()


def test_parse_jsonl_keeps_valid_events_and_records_bad_lines(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"timestamp":"bad"}\n'
        '{"timestamp":"2026-08-03T12:00:00+08:00","source_ip":"192.0.2.10",'
        '"method":"GET","host":"example.test","path":"/"}\n',
        encoding="utf-8",
    )

    result = parse_jsonl(source)

    assert len(result.events) == 1
    assert result.issues[0].line_number == 1
    assert result.issues[0].code == "invalid_event"


def test_parse_jsonl_caps_individual_issues_and_summarizes_exact_omitted_count(
    tmp_path: Path,
) -> None:
    source = tmp_path / "events.jsonl"
    omitted = 2
    valid_event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/health",
    }
    source.write_text(
        "not json\n" * (MAX_RECORDED_ISSUES + omitted)
        + json.dumps(valid_event)
        + "\n",
        encoding="utf-8",
    )

    result = parse_jsonl(source)

    assert [event.path for event in result.events] == ["/health"]
    assert result.total_issue_count == MAX_RECORDED_ISSUES + omitted
    assert len(result.issues) == MAX_RECORDED_ISSUES + 1
    assert all(issue.code == "invalid_event" for issue in result.issues[:-1])
    assert result.issues[-1].line_number == 0
    assert result.issues[-1].code == "issues_truncated"
    assert result.issues[-1].message == "另有 2 个输入问题未逐条记录"
    assert "not json" not in result.issues[-1].message


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", "2026-08-03T12:00:00+08:00\ud800"),
        ("source_ip", "192.0.2.10\ud800"),
        ("method", "GET\ud800"),
        ("host", "example.test\ud800"),
        ("path", "/search\ud800"),
        ("query", "page=2\ud800"),
        ("user_agent", "Browser/1.0\ud800"),
        ("request_id", "request-1\ud800"),
        ("body_excerpt", "payload\ud800"),
    ],
)
def test_parse_jsonl_rejects_surrogates_in_every_string_field_and_recovers(
    tmp_path: Path, field: str, value: str,
) -> None:
    source = tmp_path / "events.jsonl"
    invalid_event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/search",
        field: value,
    }
    valid_event = {
        "timestamp": "2026-08-03T12:00:01+08:00",
        "source_ip": "192.0.2.11",
        "method": "GET",
        "host": "example.test",
        "path": "/health",
    }
    source.write_text(
        json.dumps(invalid_event) + "\n" + json.dumps(valid_event) + "\n",
        encoding="utf-8",
    )

    result = parse_jsonl(source)

    assert [event.path for event in result.events] == ["/health"]
    assert len(result.issues) == 1
    assert result.issues[0].line_number == 1
    assert result.issues[0].code == "invalid_event"
    assert result.issues[0].message == "字符串字段包含无效 Unicode 代理字符"
    assert value not in result.issues[0].message


def test_parse_jsonl_rejects_a_file_without_valid_events(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text("not json\n", encoding="utf-8")

    with pytest.raises(InputFileError, match="没有有效事件"):
        parse_jsonl(source)


def test_parse_jsonl_recovers_after_deeply_nested_json(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    valid_event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "GET",
        "host": "example.test",
        "path": "/",
    }
    source.write_text(
        "[" * 5000 + "]" * 5000 + "\n" + json.dumps(valid_event),
        encoding="utf-8",
    )

    result = parse_jsonl(source)

    assert len(result.events) == 1
    assert result.issues[0].line_number == 1
    assert result.issues[0].code == "invalid_event"


@pytest.mark.parametrize(
    "timestamp",
    ["2026-08-03", "20260803", "2026-08-03T12:00:00"],
)
def test_parse_jsonl_rejects_timestamps_without_datetime_and_utc_offset(
    tmp_path: Path, timestamp: str
) -> None:
    source = tmp_path / "events.jsonl"
    _write_lines(source, [
        {
            "timestamp": timestamp,
            "source_ip": "192.0.2.10",
            "method": "GET",
            "host": "example.test",
            "path": "/",
        },
        {
            "timestamp": "2026-08-03T12:00:00Z",
            "source_ip": "192.0.2.11",
            "method": "GET",
            "host": "example.test",
            "path": "/",
        },
    ])

    result = parse_jsonl(source)

    assert len(result.events) == 1
    assert result.issues[0].line_number == 1
    assert result.issues[0].code == "invalid_event"
    assert result.issues[0].message == "timestamp 必须包含时间和 UTC 偏移"
