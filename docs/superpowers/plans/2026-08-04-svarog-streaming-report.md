# Svarog Streaming Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert Svarog's CLI analysis path to single-pass streaming, lower no-evidence confidence to `0.04`, and produce bounded reports that default to risk details only while preserving exact whole-input statistics.

**Architecture:** Add a lazy parser iterator that emits one `NormalizedEvent` or `InputIssue` at a time, then feed it into a bounded report accumulator. The accumulator analyzes every valid event, keeps complete counters, retains at most 10,000 prioritized details, and releases suppressed items immediately. Keep `parse_jsonl()` and `build_report()` as compatibility adapters, but route the CLI exclusively through the streaming interfaces.

**Tech Stack:** Python 3.11+, standard library (`argparse`, `collections`, `dataclasses`, `datetime`, `json`, `pathlib`), pytest 8, existing setuptools CLI package; no new runtime dependencies, LLM clients, network access, command execution, database, or background service.

---

## Scope guardrails

Implement only the first approved roadmap item: streaming analysis and compact reports for one local JSONL file on one machine.

Do not add any of the following in this plan:

- file watching, log rotation, checkpoints, Windows services, or Docker orchestration changes;
- multi-server collection, SQLite, queues, or event correlation;
- ground-truth evaluation commands;
- LLM configuration, API calls, retries, quota handling, or network dependencies;
- blocking, command execution, automatic remediation, attribution, or countermeasures.

The report format changes from schema `0.1.0` to `0.2.0`, while the local application remains in the `0.1.x` product stage.

## Files changed

```text
src/svarog/parsers/nginx_json.py   Lazy JSONL iterator and compatibility parser
src/svarog/policy.py               0.04 confidence and bounded report accumulator
src/svarog/cli.py                  --include-normal and streaming orchestration
src/svarog/reporting.py            Compact-report counters in terminal output
tests/parsers/test_nginx_json.py   Streaming parser contracts and regressions
tests/test_policy.py               Filtering, bounds, priority, ordering, counters
tests/test_cli.py                  CLI default/full modes and streaming integration
tests/test_reporting.py            Schema 0.2.0 and terminal summary contract
README.md                          User-visible behavior, limits, and examples
```

Do not modify `src/svarog/models.py`: `AnalysisReport.summary` already accepts new integer fields, and the existing immutable event/report models are sufficient.

## Task 1: Add a lazy JSONL parser interface

**Files:**

- Modify: `src/svarog/parsers/nginx_json.py`
- Modify: `tests/parsers/test_nginx_json.py`

- [ ] **Step 1: Write the streaming parser contract tests**

Update the parser imports in `tests/parsers/test_nginx_json.py`:

```python
from svarog.models import InputIssue, NormalizedEvent
from svarog.parsers.nginx_json import (
    MAX_RECORDED_ISSUES,
    InputFileError,
    iter_jsonl,
    parse_jsonl,
)
```

Add tests proving that the new iterator emits source-order items and still fails when the stream contains no valid events:

```python
def test_iter_jsonl_yields_events_and_issues_in_source_order(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    valid_event = {
        "timestamp": "2026-08-03T12:00:00+08:00",
        "source_ip": "192.0.2.10",
        "method": "get",
        "host": "EXAMPLE.TEST",
        "path": "/health",
    }
    source.write_text(
        "not json\n" + json.dumps(valid_event) + "\n" + "still not json\n",
        encoding="utf-8",
    )

    items = list(iter_jsonl(source))

    assert [type(item) for item in items] == [
        InputIssue,
        NormalizedEvent,
        InputIssue,
    ]
    assert items[0].line_number == 1
    assert items[1].line_number == 2
    assert items[1].method == "GET"
    assert items[2].line_number == 3


def test_iter_jsonl_rejects_a_stream_without_valid_events(tmp_path: Path) -> None:
    source = tmp_path / "invalid.jsonl"
    source.write_text("not json\n", encoding="utf-8")

    with pytest.raises(InputFileError, match="没有有效事件"):
        list(iter_jsonl(source))
```

- [ ] **Step 2: Run the new tests and verify the expected failure**

Run:

```powershell
python -m pytest tests/parsers/test_nginx_json.py::test_iter_jsonl_yields_events_and_issues_in_source_order tests/parsers/test_nginx_json.py::test_iter_jsonl_rejects_a_stream_without_valid_events -v
```

Expected: collection fails because `iter_jsonl` does not exist yet.

- [ ] **Step 3: Implement `iter_jsonl()` without accumulating events**

In `src/svarog/parsers/nginx_json.py`, import `Iterator`, declare the stream item type, and move the current per-line validation into a generator:

```python
from collections.abc import Iterator
from typing import Any

StreamItem = NormalizedEvent | InputIssue


def iter_jsonl(path: Path) -> Iterator[StreamItem]:
    if not path.is_file():
        raise InputFileError(f"输入文件不存在或不是普通文件：{path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InputFileError("输入文件超过 10 MiB 限制")

    found_valid_event = False
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            if len(raw_line) > MAX_LINE_BYTES:
                yield InputIssue(line_number, "line_too_large", "单行超过 1 MiB 限制")
                continue
            try:
                text = raw_line.decode("utf-8")
                payload = json.loads(text)
                event = _normalize_event(payload, line_number)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
                yield InputIssue(line_number, "invalid_event", str(exc))
                continue

            found_valid_event = True
            yield event

    if not found_valid_event:
        raise InputFileError("输入文件没有有效事件")
```

The generator must not keep an `events` list or an unbounded `issues` list. File existence, 10 MiB file size, 1 MiB line size, UTF-8, field limits, timestamps, IP validation, and surrogate rejection remain unchanged.

- [ ] **Step 4: Rebuild `parse_jsonl()` as a compatibility adapter**

Replace the old `parse_jsonl()` loop with consumption of `iter_jsonl()`:

```python
def parse_jsonl(path: Path) -> ParseResult:
    events: list[NormalizedEvent] = []
    issues: list[InputIssue] = []
    total_issue_count = 0

    for item in iter_jsonl(path):
        if isinstance(item, NormalizedEvent):
            events.append(item)
            continue

        total_issue_count += 1
        if len(issues) < MAX_RECORDED_ISSUES:
            issues.append(item)

    omitted_issue_count = total_issue_count - len(issues)
    if omitted_issue_count:
        issues.append(InputIssue(
            0,
            "issues_truncated",
            f"另有 {omitted_issue_count} 个输入问题未逐条记录",
        ))
    return ParseResult(tuple(events), tuple(issues), total_issue_count)
```

This adapter is allowed to accumulate because it exists only for backward compatibility. The CLI must stop using it in Task 3.

- [ ] **Step 5: Run parser tests and confirm all prior limits still pass**

Run:

```powershell
python -m pytest tests/parsers/test_nginx_json.py -v
```

Expected: all parser tests pass, including issue truncation, deep JSON recovery, invalid Unicode surrogate handling, timestamp validation, and no-valid-event failure.

- [ ] **Step 6: Commit the parser task**

```powershell
git add src/svarog/parsers/nginx_json.py tests/parsers/test_nginx_json.py
git commit -m "refactor: stream nginx jsonl parsing"
```

## Task 2: Build bounded streaming reports

**Files:**

- Modify: `src/svarog/policy.py`
- Modify: `tests/test_policy.py`

- [ ] **Step 1: Extend the policy test helper for source-order scenarios**

Change `_event()` in `tests/test_policy.py` so tests can create distinct lines:

```python
def _event(query: str = "", *, line_number: int = 1) -> NormalizedEvent:
    return NormalizedEvent(
        line_number=line_number,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/search",
        query=query,
    )
```

Update imports:

```python
from svarog.policy import (
    MAX_REPORTED_EVENTS,
    analyze_event,
    build_report,
    build_streaming_report,
)
```

- [ ] **Step 2: Write failing tests for confidence and default filtering**

Change the old no-match assertion from `0.2` to `0.04`, then add:

```python
def test_streaming_report_default_keeps_only_risk_details() -> None:
    report = build_streaming_report((
        _event("page=2", line_number=1),
        _event("id=1 UNION SELECT password FROM users", line_number=2),
    ), generated_at="2026-08-03T04:00:00+00:00")

    assert report.schema_version == "0.2.0"
    assert report.summary["total_events"] == 2
    assert report.summary["suspicious_events"] == 1
    assert report.summary["reported_events"] == 1
    assert report.summary["suppressed_normal_events"] == 1
    assert report.summary["truncated_detail_events"] == 0
    assert [item.event.line_number for item in report.events] == [2]


def test_streaming_report_all_normal_events_have_empty_details() -> None:
    report = build_streaming_report((
        _event("page=1", line_number=1),
        _event("page=2", line_number=2),
    ))

    assert report.summary["total_events"] == 2
    assert report.summary["suspicious_events"] == 0
    assert report.summary["reported_events"] == 0
    assert report.summary["suppressed_normal_events"] == 2
    assert report.events == ()
```

- [ ] **Step 3: Write failing tests for limits, risk priority, and ordering**

Use an injected test cap so the suite does not need to allocate 10,001 analyses:

```python
def test_streaming_report_limit_is_ten_thousand() -> None:
    assert MAX_REPORTED_EVENTS == 10_000


def test_streaming_report_truncates_risk_details_but_keeps_true_counts() -> None:
    events = tuple(
        _event("id=1 UNION SELECT password FROM users", line_number=line_number)
        for line_number in range(1, 4)
    )

    report = build_streaming_report(events, max_reported_events=2)

    assert report.summary["total_events"] == 3
    assert report.summary["suspicious_events"] == 3
    assert report.summary["reported_events"] == 2
    assert report.summary["truncated_detail_events"] == 1
    assert [item.event.line_number for item in report.events] == [1, 2]
    assert any("全部有效事件仍已完成本地分析" in item for item in report.warnings)


def test_include_normal_evicts_later_normal_for_later_risk_and_sorts_output() -> None:
    report = build_streaming_report(
        (
            _event("page=1", line_number=1),
            _event("page=2", line_number=2),
            _event("id=1 UNION SELECT password FROM users", line_number=3),
        ),
        include_normal=True,
        max_reported_events=2,
    )

    assert report.summary["total_events"] == 3
    assert report.summary["suspicious_events"] == 1
    assert report.summary["reported_events"] == 2
    assert report.summary["suppressed_normal_events"] == 0
    assert report.summary["truncated_detail_events"] == 1
    assert [item.event.line_number for item in report.events] == [1, 3]
```

- [ ] **Step 4: Write a failing streaming input-issue cap test**

Add:

```python
def test_streaming_report_caps_issue_details_and_preserves_true_total() -> None:
    items = (
        *(InputIssue(line_number, "invalid_event", "invalid") for line_number in range(1, 1003)),
        _event("page=2", line_number=1003),
    )

    report = build_streaming_report(items)

    assert report.summary["input_issues"] == 1002
    assert len(report.input_issues) == 1001
    assert report.input_issues[-1].code == "issues_truncated"
    assert report.input_issues[-1].message == "另有 2 个输入问题未逐条记录"
```

- [ ] **Step 5: Run focused tests and verify they fail for the intended reasons**

Run:

```powershell
python -m pytest tests/test_policy.py -v
```

Expected: failures show the old `0.2` confidence, missing `build_streaming_report`, missing `MAX_REPORTED_EVENTS`, old schema, and unfiltered report behavior.

- [ ] **Step 6: Add the report limit and lower no-evidence confidence**

In `src/svarog/policy.py`, import `Iterable`, add the limit, and change only the no-evidence confidence:

```python
from collections.abc import Iterable

MAX_REPORTED_EVENTS = 10_000
```

```python
        return EventAnalysis(
            event=event,
            local_severity=Severity.INFO,
            conclusion=ConclusionStatus.INSUFFICIENT_EVIDENCE,
            confidence=0.04,
            evidence=(),
            attack_mappings=(),
            recommendations=("未发现明显规则命中；如仍有怀疑，请结合更多日志继续调查。",),
        )
```

- [ ] **Step 7: Add a private bounded event accumulator**

Add this class below `analyze_event()` in `src/svarog/policy.py`:

```python
class _ReportAccumulator:
    def __init__(self, *, include_normal: bool, max_reported_events: int) -> None:
        if (
            isinstance(max_reported_events, bool)
            or not isinstance(max_reported_events, int)
            or max_reported_events < 1
        ):
            raise ValueError("max_reported_events 必须是正整数")
        self.include_normal = include_normal
        self.max_reported_events = max_reported_events
        self.total_events = 0
        self.suspicious_events = 0
        self.severity_counts: Counter[str] = Counter()
        self.risk_events: list[EventAnalysis] = []
        self.normal_events: list[EventAnalysis] = []

    def add_event(self, event: NormalizedEvent) -> None:
        analysis = analyze_event(event)
        self.total_events += 1
        self.severity_counts[analysis.local_severity.value] += 1

        if analysis.evidence:
            self.suspicious_events += 1
            if len(self.risk_events) < self.max_reported_events:
                self.risk_events.append(analysis)
                if len(self.risk_events) + len(self.normal_events) > self.max_reported_events:
                    self.normal_events.pop()
            return

        if (
            self.include_normal
            and len(self.risk_events) + len(self.normal_events) < self.max_reported_events
        ):
            self.normal_events.append(analysis)

    def finish(
        self,
        input_issues: tuple[InputIssue, ...],
        total_input_issues: int,
        *,
        generated_at: str | None,
    ) -> AnalysisReport:
        reported = tuple(sorted(
            (*self.risk_events, *self.normal_events),
            key=lambda item: item.event.line_number,
        ))
        normal_event_count = self.total_events - self.suspicious_events
        suppressed_normal_events = 0 if self.include_normal else normal_event_count
        eligible_event_count = self.total_events if self.include_normal else self.suspicious_events
        truncated_detail_events = eligible_event_count - len(reported)
        summary = {
            "total_events": self.total_events,
            "suspicious_events": self.suspicious_events,
            "input_issues": total_input_issues,
            "reported_events": len(reported),
            "suppressed_normal_events": suppressed_normal_events,
            "truncated_detail_events": truncated_detail_events,
            **{
                f"severity_{severity.value}": self.severity_counts.get(severity.value, 0)
                for severity in Severity
            },
        }
        warnings: list[str] = []
        if total_input_issues:
            warnings.append("部分输入行无效，详见 input_issues。")
        if truncated_detail_events:
            warnings.append("报告明细因上限被截断；全部有效事件仍已完成本地分析。")
        return AnalysisReport(
            schema_version="0.2.0",
            generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
            analysis_status="completed_local",
            summary=summary,
            events=reported,
            input_issues=input_issues,
            warnings=tuple(warnings),
        )
```

Why this is bounded:

- `risk_events` never exceeds `max_reported_events`;
- `normal_events` only uses capacity not occupied by risk events;
- every retained risk event can evict the latest retained normal event;
- once risk events fill the cap, later risk events are counted but not retained;
- final sorting operates on at most 10,000 items.

- [ ] **Step 8: Add the public streaming report builder**

Import `StreamItem` and `MAX_RECORDED_ISSUES` from the parser module, then add:

```python
def build_streaming_report(
    items: Iterable[StreamItem],
    *,
    include_normal: bool = False,
    max_reported_events: int = MAX_REPORTED_EVENTS,
    generated_at: str | None = None,
) -> AnalysisReport:
    accumulator = _ReportAccumulator(
        include_normal=include_normal,
        max_reported_events=max_reported_events,
    )
    input_issues: list[InputIssue] = []
    total_input_issues = 0

    for item in items:
        if isinstance(item, NormalizedEvent):
            accumulator.add_event(item)
            continue
        if not isinstance(item, InputIssue):
            raise TypeError("流式输入项必须是 NormalizedEvent 或 InputIssue")
        total_input_issues += 1
        if len(input_issues) < MAX_RECORDED_ISSUES:
            input_issues.append(item)

    omitted_issue_count = total_input_issues - len(input_issues)
    if omitted_issue_count:
        input_issues.append(InputIssue(
            0,
            "issues_truncated",
            f"另有 {omitted_issue_count} 个输入问题未逐条记录",
        ))
    return accumulator.finish(
        tuple(input_issues),
        total_input_issues,
        generated_at=generated_at,
    )
```

- [ ] **Step 9: Rework `build_report()` as a compatibility adapter**

Keep its existing signature compatible, add the two new optional controls, validate the explicit input-issue total as before, and feed events through the same accumulator:

```python
def build_report(
    events: tuple[NormalizedEvent, ...],
    input_issues: tuple[InputIssue, ...],
    *,
    total_input_issues: int | None = None,
    include_normal: bool = False,
    max_reported_events: int = MAX_REPORTED_EVENTS,
    generated_at: str | None = None,
) -> AnalysisReport:
    input_issue_count = len(input_issues) if total_input_issues is None else total_input_issues
    if (
        isinstance(input_issue_count, bool)
        or not isinstance(input_issue_count, int)
        or input_issue_count < len(input_issues)
    ):
        raise ValueError("total_input_issues 必须是不小于已保留问题数的整数")

    accumulator = _ReportAccumulator(
        include_normal=include_normal,
        max_reported_events=max_reported_events,
    )
    for event in events:
        accumulator.add_event(event)
    return accumulator.finish(
        input_issues,
        input_issue_count,
        generated_at=generated_at,
    )
```

Remove the now-unused batch-only summary code. `Counter` remains needed by `_ReportAccumulator`.

- [ ] **Step 10: Run policy tests and the parser-policy subset**

Run:

```powershell
python -m pytest tests/test_policy.py tests/parsers/test_nginx_json.py -v
```

Expected: all focused tests pass. In particular, the exact issue total remains 1002, normal confidence is `0.04`, default details are compact, risk detail ordering is `[1, 2]`, and risk priority produces `[1, 3]`.

- [ ] **Step 11: Commit the policy task**

```powershell
git add src/svarog/policy.py tests/test_policy.py
git commit -m "feat: bound streaming report details"
```

## Task 3: Route the CLI through the streaming path

**Files:**

- Modify: `src/svarog/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add failing CLI argument and compact-output tests**

Extend `test_cli_exposes_analyze_command()`:

```python
def test_cli_exposes_analyze_command() -> None:
    args = build_parser().parse_args(["analyze", "events.jsonl"])

    assert args.command == "analyze"
    assert str(args.input) == "events.jsonl"
    assert args.include_normal is False
```

Add:

```python
def test_analyze_default_suppresses_normal_detail(tmp_path: Path, capsys) -> None:
    source = tmp_path / "normal.jsonl"
    target = tmp_path / "report.json"
    _write_event(source, query="page=2")

    exit_code = main(["analyze", str(source), "--json-out", str(target)])

    captured = capsys.readouterr()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["summary"]["total_events"] == 1
    assert payload["summary"]["suspicious_events"] == 0
    assert payload["summary"]["reported_events"] == 0
    assert payload["summary"]["suppressed_normal_events"] == 1
    assert payload["events"] == []
    assert captured.err == ""


def test_analyze_include_normal_keeps_normal_detail(tmp_path: Path, capsys) -> None:
    source = tmp_path / "normal.jsonl"
    target = tmp_path / "report.json"
    _write_event(source, query="page=2")

    exit_code = main([
        "analyze",
        str(source),
        "--include-normal",
        "--json-out",
        str(target),
    ])

    captured = capsys.readouterr()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["summary"]["reported_events"] == 1
    assert payload["summary"]["suppressed_normal_events"] == 0
    assert payload["events"][0]["confidence"] == 0.04
    assert captured.err == ""
```

- [ ] **Step 2: Update the Unicode JSON regression to request full details**

In `test_module_entrypoint_degrades_unencodable_terminal_text_but_keeps_json_unicode`, add `--include-normal` before `--json-out`. The event in that test is normal and therefore must opt into normal details before asserting `payload["events"][0]`.

```python
        [
            sys.executable,
            "-m",
            "svarog",
            "analyze",
            str(source),
            "--include-normal",
            "--json-out",
            str(target),
        ],
```

- [ ] **Step 3: Run the focused CLI tests and verify expected failures**

Run:

```powershell
python -m pytest tests/test_cli.py::test_cli_exposes_analyze_command tests/test_cli.py::test_analyze_default_suppresses_normal_detail tests/test_cli.py::test_analyze_include_normal_keeps_normal_detail -v
```

Expected: failures show that `--include-normal` and the new compact summary are not wired into the CLI yet.

- [ ] **Step 4: Add `--include-normal` and switch CLI imports**

In `src/svarog/cli.py`, replace the batch imports:

```python
from svarog.parsers.nginx_json import InputFileError, iter_jsonl
from svarog.policy import build_streaming_report
```

Add the option in `build_parser()`:

```python
    analyze.add_argument(
        "--include-normal",
        action="store_true",
        help="在报告明细中包含未命中本地规则的正常事件",
    )
```

Replace only the parsing/report construction inside `_run_analyze()`:

```python
    try:
        report = build_streaming_report(
            iter_jsonl(args.input),
            include_normal=args.include_normal,
        )
    except (InputFileError, OSError):
        _write_stream(sys.stderr, "[错误] 无法读取或分析输入文件。\n")
        return 1
```

Preserve input/output alias protection, fixed Chinese errors, terminal encoding degradation, report-writing behavior, and exit codes exactly as they are.

- [ ] **Step 5: Run all CLI tests**

```powershell
python -m pytest tests/test_cli.py -v
```

Expected: all CLI tests pass. Existing tests still prove safe handling of invalid input, surrogates, write failures, hard-link aliases, prompt-injection text, Windows encoding, and Docker boundaries.

- [ ] **Step 6: Confirm the CLI production path no longer references `parse_jsonl`**

Run:

```powershell
rg "parse_jsonl" src/svarog/cli.py
```

Expected: no matches and exit code 1 from `rg`. References may remain in the parser module and parser compatibility tests.

- [ ] **Step 7: Commit the CLI task**

```powershell
git add src/svarog/cli.py tests/test_cli.py
git commit -m "feat: stream compact cli analysis"
```

## Task 4: Expose the new report semantics to users

**Files:**

- Modify: `src/svarog/reporting.py`
- Modify: `tests/test_reporting.py`
- Modify: `README.md`

- [ ] **Step 1: Update the JSON schema assertion and add terminal counter assertions**

In `tests/test_reporting.py`, change the schema expectation and extend the terminal test:

```python
def test_terminal_report_is_chinese_and_states_read_only_boundary() -> None:
    text = render_terminal(_report())

    assert "Svarog 本地分析报告" in text
    assert "事件总数：1" in text
    assert "可疑事件：1" in text
    assert "报告明细：1" in text
    assert "已省略正常事件：0" in text
    assert "明细截断：0" in text
    assert "SQL" in text
    assert "未执行任何动作" in text
```

```python
    assert payload["schema_version"] == "0.2.0"
```

Add an all-normal terminal test:

```python
def test_terminal_report_cleanly_handles_no_retained_details() -> None:
    event = NormalizedEvent(
        line_number=1,
        timestamp="2026-08-03T12:00:00+08:00",
        source_ip="192.0.2.10",
        method="GET",
        host="example.test",
        path="/health",
    )
    report = build_report((event,), (), generated_at="2026-08-03T04:00:00+00:00")

    text = render_terminal(report)

    assert "报告明细：0" in text
    assert "已省略正常事件：1" in text
    assert "安全边界：本次分析未执行任何动作。" in text
```

- [ ] **Step 2: Run reporting tests and verify the new terminal labels fail**

```powershell
python -m pytest tests/test_reporting.py -v
```

Expected: schema assertions pass after Task 2, while new terminal counter assertions fail until `render_terminal()` is updated.

- [ ] **Step 3: Render all compact-report counters**

In `src/svarog/reporting.py`, change the terminal heading block to:

```python
    lines = [
        "Svarog 本地分析报告",
        f"事件总数：{report.summary['total_events']}",
        f"可疑事件：{report.summary['suspicious_events']}",
        f"报告明细：{report.summary['reported_events']}",
        f"已省略正常事件：{report.summary['suppressed_normal_events']}",
        f"明细截断：{report.summary['truncated_detail_events']}",
        f"输入问题：{report.summary['input_issues']}",
        "",
    ]
```

Do not add a special-case fake event when `report.events` is empty. The summary, warnings, and final safety boundary are the complete valid output for an all-normal compact report.

- [ ] **Step 4: Document default compact mode and explicit full mode**

Update `README.md` with these exact behavioral points:

- every valid line is still analyzed locally;
- default `events` contains only evidence-bearing risk details;
- `--include-normal` includes normal details for debugging;
- both modes retain at most 10,000 event details and prioritize risk events;
- `summary` always describes all valid events, including suppressed or truncated details;
- `schema_version` is now `0.2.0`;
- no-evidence confidence is `0.04` and means insufficient evidence, not confirmed safety;
- this phase still performs no LLM/API/network/action behavior.

Add this runnable full-detail example after the existing JSON report example:

```powershell
python -m svarog analyze samples/nginx-normal.jsonl --include-normal --json-out full-report.json
```

In “预期结果”, clarify that the normal and prompt-injection samples have empty `events` by default but retain correct `total_events` and `suspicious_events` counts. In “输入格式”, document the three new summary fields and the 10,000-detail cap.

- [ ] **Step 5: Run reporting and CLI tests together**

```powershell
python -m pytest tests/test_reporting.py tests/test_cli.py -v
```

Expected: all tests pass and terminal output contains the new counters without changing the final read-only safety statement.

- [ ] **Step 6: Commit reporting and documentation**

```powershell
git add src/svarog/reporting.py tests/test_reporting.py README.md
git commit -m "docs: explain compact report semantics"
```

## Task 5: Run the release gate and validate the 1000-line sample

**Files:**

- Verify only: all tracked project files
- Optional local input: `samples/nginx-evasive-1000.jsonl`
- Do not stage: `Svarog.doc`, generated JSON reports, or ground-truth/sample files that were already untracked before implementation

- [ ] **Step 1: Run the complete automated suite**

```powershell
python -m pytest -v
```

Expected: all tests pass. The total should be greater than the current 79 tests because this plan adds parser, policy, CLI, and reporting coverage.

- [ ] **Step 2: Check formatting defects and unintended production capabilities**

```powershell
git diff --check
rg -n "requests|httpx|urllib\.request|subprocess|os\.system|socket|openai|deepseek" src
```

Expected:

- `git diff --check` prints nothing and exits 0;
- the capability scan prints no production matches and exits 1;
- `subprocess` remains acceptable in tests only, where it launches the local module entry point.

- [ ] **Step 3: Run compact and full analysis against the 1000-line sample when present**

First check that the optional local sample exists:

```powershell
Test-Path .\samples\nginx-evasive-1000.jsonl
```

If it prints `True`, run:

```powershell
python -m svarog analyze .\samples\nginx-evasive-1000.jsonl --json-out .\report-compact.json
python -m svarog analyze .\samples\nginx-evasive-1000.jsonl --include-normal --json-out .\report-full.json
python -c "import json, pathlib; compact=json.loads(pathlib.Path('report-compact.json').read_text(encoding='utf-8')); full=json.loads(pathlib.Path('report-full.json').read_text(encoding='utf-8')); assert compact['schema_version']=='0.2.0'; assert compact['summary']['total_events']==1000; assert compact['summary']['reported_events']==len(compact['events']); assert compact['summary']['suppressed_normal_events']==1000-compact['summary']['suspicious_events']; assert full['summary']['total_events']==1000; assert full['summary']['reported_events']==1000; assert full['summary']['suppressed_normal_events']==0; assert full['summary']['truncated_detail_events']==0; assert len(full['events'])==1000; assert pathlib.Path('report-compact.json').stat().st_size < pathlib.Path('report-full.json').stat().st_size"
```

Expected: both commands exit 0; the final assertion command exits 0; compact output is smaller than full output while both summaries describe all 1000 valid events.

If the sample is absent, record that the optional manual check was skipped; do not make the automated suite depend on an untracked local artifact.

- [ ] **Step 4: Inspect the final repository state without staging unrelated files**

```powershell
git status --short
git log --oneline -5
```

Expected: no uncommitted implementation changes. Pre-existing untracked files may still appear and must remain unmodified and unstaged. The task commits should be limited to the exact tracked files listed in Tasks 1–4.

## Acceptance checklist

- [ ] CLI reads valid JSONL events through `iter_jsonl()` rather than `parse_jsonl()`.
- [ ] Every valid event is analyzed exactly once and contributes to total, suspicious, and severity counters.
- [ ] No-evidence confidence is exactly `0.04` and still uses `INSUFFICIENT_EVIDENCE`.
- [ ] Default mode retains only evidence-bearing details.
- [ ] `--include-normal` retains normal details when capacity permits.
- [ ] At most 10,000 event details are retained in every mode.
- [ ] Later risk details displace retained normal details before risk details are dropped.
- [ ] Retained details are sorted by original line number.
- [ ] Input issues remain capped at 1,000 details plus one exact truncation summary.
- [ ] `reported_events`, `suppressed_normal_events`, and `truncated_detail_events` match serialized output semantics.
- [ ] Any detail truncation produces an explicit warning that all valid events were still analyzed.
- [ ] Report schema is `0.2.0`; application scope remains local `0.1.x`.
- [ ] Existing Unicode, path-alias, write-safety, prompt-injection-data, and action-boundary regressions pass.
- [ ] No LLM, API, network, command, database, watcher, correlation, or automatic-response capability is introduced.
