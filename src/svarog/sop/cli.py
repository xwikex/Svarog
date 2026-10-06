from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from svarog.sop.reporting import write_reports
from svarog.sop.service import run_case
from svarog.sop.storage import CaseStore
from svarog.text_safety import terminal_safe


def register_sop_commands(subparsers):
    run = subparsers.add_parser('sop-run', help='从告警和本地日志启动只读 SOP 调查')
    run.add_argument('alert', type=Path)
    run.add_argument('--logs', type=Path, required=True)
    run.add_argument('--log-format', choices=['jsonl', 'nginx-combined'], default='jsonl')
    run.add_argument('--log-host', help='Nginx combined 日志所属主机（显式指定）')
    run.add_argument('--window-minutes', type=int, default=15)
    run.add_argument('--limit', type=int, default=200)
    run.add_argument('--agent-config', type=Path, help='显式启用可选模型的 TOML 配置')
    for name, parser in [('sop-run', run),
                         ('sop-report', subparsers.add_parser('sop-report', help='从案件库重新导出 SOP 报告')),
                         ('sop-review', subparsers.add_parser('sop-review', help='记录人工复核；不会执行处置'))]:
        parser.add_argument('--case-db', type=Path, required=True)
        if name != 'sop-run':
            parser.add_argument('case_id')
        if name == 'sop-review':
            parser.add_argument('--decision', required=True, choices=['approve', 'reject', 'needs_investigation'])
            parser.add_argument('--reviewer', required=True)
            parser.add_argument('--note', required=True)
        else:
            parser.add_argument('--json-out', type=Path)
            parser.add_argument('--html-out', type=Path)
        parser.set_defaults(handler=_run)


def _same_path(a: Path, b: Path) -> bool:
    if os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve())):
        return True
    return a.exists() and b.exists() and os.path.samefile(a, b)


def _validate_paths(args):
    inputs = [getattr(args, field, None) for field in ('alert', 'logs', 'agent_config')]
    inputs = [p for p in inputs if p is not None]
    db_paths = [Path(str(base) + suffix) for base in (args.case_db, args.case_db.resolve())
                for suffix in ('', '-wal', '-shm', '-journal')]
    outputs = [getattr(args, field, None) for field in ('json_out', 'html_out')]
    outputs = [p for p in outputs if p is not None]
    for i, path in enumerate(outputs):
        if any(_same_path(path, other) for other in inputs + db_paths + outputs[:i]):
            raise ValueError('输出路径不能覆盖输入、案件库、SQLite 辅助文件或另一份报告')
    if any(_same_path(a, b) for a in inputs for b in db_paths):
        raise ValueError('案件库及 SQLite 辅助文件不能与输入共用路径')
    if args.command == 'sop-report' and not outputs:
        raise ValueError('sop-report 至少需要 --json-out 或 --html-out')


def _print(message, error=False):
    stream = sys.stderr if error else sys.stdout
    safe = terminal_safe(message) + '\n'
    encoding = getattr(stream, 'encoding', None) or 'utf-8'
    stream.write(safe.encode(encoding, 'backslashreplace').decode(encoding))


def _run(args):
    saved_id = None
    try:
        _validate_paths(args)
        if args.command == 'sop-run':
            advisor = None
            if args.agent_config:
                from svarog.sop.agent import load_advisor
                advisor = load_advisor(args.agent_config)
            # Validate/open the dedicated DB before calling an optional remote service.
            with CaseStore(args.case_db) as store:
                case = run_case(args.alert, args.logs, window_minutes=args.window_minutes, limit=args.limit,
                    log_format=args.log_format, log_host=args.log_host, advisor=advisor)
                if args.agent_config:
                    case['source_files'].append(str(args.agent_config.resolve()))
                store.save(case)
                saved_id = case['case_id']
            write_reports(case, args.json_out, args.html_out)
        elif args.command == 'sop-review':
            with CaseStore(args.case_db, create=False) as store:
                store.review(args.case_id, args.decision, args.reviewer, args.note)
                case = store.get(args.case_id)
        else:
            with CaseStore(args.case_db, create=False) as store:
                case = store.get(args.case_id)
            for output in (args.json_out, args.html_out):
                if output is not None and any(_same_path(output, Path(p)) for p in case.get('source_files', [])):
                    raise ValueError('重新导出的报告不能覆盖该案件的原始输入')
            write_reports(case, args.json_out, args.html_out)
        _print(f"案件 {case['case_id']} | 状态 {case['status']} | 未执行任何处置动作")
        if args.command == 'sop-run':
            _print(f"分析模式 {case['agent']['mode']} | 关联日志 {case['query']['retained']}/{case['query']['matched']}")
            for warning in case['warnings']:
                _print('提醒：' + warning)
        return 0
    except (OSError, ValueError, sqlite3.Error, RecursionError, OverflowError) as exc:
        # Do not print data-bearing exception strings (JSON, SQL, HTTP or credentials).
        _print('SOP 失败：请检查文件格式、路径冲突、案件库兼容性及参数；复核记录不能重复写入。', error=True)
        if saved_id:
            _print(f'案件已保存：{saved_id}；报告导出失败，可使用 sop-report 重试。', error=True)
        return 1
