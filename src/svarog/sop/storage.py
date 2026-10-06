from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path

from svarog.sop.inputs import checked_text
from svarog.sop.service import utc_now

APPLICATION_ID = 0x53534F50
SCHEMA_VERSION = 2
MAX_CASE_BYTES = 16 * 1024 * 1024
_DECISIONS = {'approve': 'approved', 'reject': 'rejected', 'needs_investigation': 'needs_investigation'}
_DISPLAY_STATUSES = frozenset({'awaiting_review', *_DECISIONS.values()})
_SEVERITIES = frozenset({'unknown', 'info', 'low', 'medium', 'high', 'critical'})

_CASES_V1_SQL = (
    'CREATE TABLE cases ('
    'case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, result_json TEXT NOT NULL)'
)
_CASES_SQL = (
    'CREATE TABLE cases ('
    'case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, alert_id TEXT NOT NULL, '
    'title TEXT NOT NULL, severity TEXT NOT NULL, result_json TEXT NOT NULL)'
)
_REVIEWS_SQL = (
    'CREATE TABLE reviews ('
    'case_id TEXT PRIMARY KEY REFERENCES cases(case_id), '
    "decision TEXT NOT NULL CHECK(decision IN ('approve','reject','needs_investigation')), "
    'reviewer TEXT NOT NULL, note TEXT NOT NULL, reviewed_at TEXT NOT NULL)'
)
_CREATED_AT_INDEX_SQL = 'CREATE INDEX cases_created_at_idx ON cases(created_at DESC, case_id)'
_ALERT_ID_INDEX_SQL = 'CREATE INDEX cases_alert_id_idx ON cases(alert_id)'

_STATUS_SQL = (
    "CASE r.decision WHEN 'approve' THEN 'approved' WHEN 'reject' THEN 'rejected' "
    "WHEN 'needs_investigation' THEN 'needs_investigation' ELSE 'awaiting_review' END"
)
_FILTER_SQL = (
    f'WHERE (? IS NULL OR {_STATUS_SQL} = ?) '
    "AND (? = '' OR c.case_id LIKE ? ESCAPE '\\' "
    "OR c.alert_id LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\')"
)
_COUNT_SQL = 'SELECT count(*) FROM cases c LEFT JOIN reviews r ON r.case_id=c.case_id ' + _FILTER_SQL
_PAGE_SQL = (
    'SELECT c.case_id, c.created_at, c.alert_id, c.title, c.severity, '
    f'{_STATUS_SQL}, r.reviewed_at '
    'FROM cases c LEFT JOIN reviews r ON r.case_id=c.case_id '
    + _FILTER_SQL
    + ' ORDER BY c.created_at DESC, c.case_id ASC LIMIT ? OFFSET ?'
)


def _columns(connection: sqlite3.Connection, table: str) -> list[tuple]:
    return [(row[1], row[2].upper(), row[3], row[4], row[5])
            for row in connection.execute(f'PRAGMA table_info({table})')]


def _normalized_sql(value: str | None) -> str:
    """Normalize only insignificant SQL spelling, preserving all semantic tokens."""
    sql = value or ''
    normalized: list[str] = []
    index = 0
    while index < len(sql):
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if char == "'":
            start = index
            index += 1
            while index < len(sql):
                if sql[index] == "'":
                    index += 1
                    if index < len(sql) and sql[index] == "'":
                        index += 1
                        continue
                    break
                index += 1
            normalized.append(sql[start:index])
            continue
        if char == '"':
            index += 1
            identifier: list[str] = []
            while index < len(sql):
                if sql[index] == '"':
                    index += 1
                    if index < len(sql) and sql[index] == '"':
                        identifier.append('"')
                        index += 1
                        continue
                    break
                identifier.append(sql[index])
                index += 1
            normalized.append(''.join(identifier).lower())
            continue
        normalized.append(char.lower())
        index += 1
    return ''.join(normalized)


def _table_sql(connection: sqlite3.Connection, table: str) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return None if row is None else row[0]


def _reviews_schema_matches(connection: sqlite3.Connection) -> bool:
    expected_columns = [
        ('case_id', 'TEXT', 0, None, 1),
        ('decision', 'TEXT', 1, None, 0),
        ('reviewer', 'TEXT', 1, None, 0),
        ('note', 'TEXT', 1, None, 0),
        ('reviewed_at', 'TEXT', 1, None, 0),
    ]
    if _columns(connection, 'reviews') != expected_columns:
        return False
    foreign_keys = [(row[2], row[3], row[4], row[5], row[6], row[7])
                    for row in connection.execute('PRAGMA foreign_key_list(reviews)')]
    if foreign_keys != [('cases', 'case_id', 'case_id', 'NO ACTION', 'NO ACTION', 'NONE')]:
        return False
    return _normalized_sql(_table_sql(connection, 'reviews')) == _normalized_sql(_REVIEWS_SQL)


def _index_shape(connection: sqlite3.Connection, name: str) -> list[tuple[str, int]]:
    return [(row[2], row[3]) for row in connection.execute(f'PRAGMA index_xinfo({name})') if row[5]]


def _schema_matches(connection: sqlite3.Connection, version: int) -> bool:
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if tables != {'cases', 'reviews'} or not _reviews_schema_matches(connection):
        return False
    if connection.execute(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('view','trigger')"
    ).fetchone()[0]:
        return False

    if version == 1:
        expected_cases = [
            ('case_id', 'TEXT', 0, None, 1),
            ('created_at', 'TEXT', 1, None, 0),
            ('result_json', 'TEXT', 1, None, 0),
        ]
        explicit_indexes = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchone()[0]
        return (
            _columns(connection, 'cases') == expected_cases
            and _normalized_sql(_table_sql(connection, 'cases')) == _normalized_sql(_CASES_V1_SQL)
            and explicit_indexes == 0
        )

    if version != SCHEMA_VERSION:
        return False
    expected_cases = [
        ('case_id', 'TEXT', 0, None, 1),
        ('created_at', 'TEXT', 1, None, 0),
        ('alert_id', 'TEXT', 1, None, 0),
        ('title', 'TEXT', 1, None, 0),
        ('severity', 'TEXT', 1, None, 0),
        ('result_json', 'TEXT', 1, None, 0),
    ]
    indexes = {row[0]: row[1] for row in connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
    )}
    return (
        _columns(connection, 'cases') == expected_cases
        and _normalized_sql(_table_sql(connection, 'cases')) == _normalized_sql(_CASES_SQL)
        and set(indexes) == {'cases_created_at_idx', 'cases_alert_id_idx'}
        and _normalized_sql(indexes['cases_created_at_idx']) == _normalized_sql(_CREATED_AT_INDEX_SQL)
        and _normalized_sql(indexes['cases_alert_id_idx']) == _normalized_sql(_ALERT_ID_INDEX_SQL)
        and _index_shape(connection, 'cases_created_at_idx') == [('created_at', 1), ('case_id', 0)]
        and _index_shape(connection, 'cases_alert_id_idx') == [('alert_id', 0)]
    )


def _summary(case: dict) -> tuple[str, str, str]:
    alert = case.get('alert') if isinstance(case, dict) else None
    if not isinstance(alert, dict):
        raise ValueError('alert 必须是对象')
    alert_id = checked_text(alert.get('alert_id'), 'alert_id')
    title = checked_text(alert.get('title'), 'title')
    severity = checked_text(alert.get('severity'), 'severity', 16)
    if severity not in _SEVERITIES:
        raise ValueError('severity 不在允许范围内')
    return alert_id, title, severity


def _reject_json_constant(value: str):
    raise ValueError(f'不允许的 JSON 常量: {value}')


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError('JSON 浮点数超出有限范围')
    return parsed


def _json_object_without_duplicates(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('JSON 对象包含重复字段')
        result[key] = value
    return result


def _strict_json_object(payload: str) -> dict:
    try:
        case = json.loads(
            payload,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
            object_pairs_hook=_json_object_without_duplicates,
        )
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ValueError('案件载荷不是严格有效的 JSON') from exc
    if not isinstance(case, dict):
        raise ValueError('案件载荷必须是 JSON 对象')
    return case


def _create_v2(connection: sqlite3.Connection) -> None:
    connection.execute(_CASES_SQL)
    connection.execute(_REVIEWS_SQL)
    connection.execute(_CREATED_AT_INDEX_SQL)
    connection.execute(_ALERT_ID_INDEX_SQL)


def _migrate_v1(connection: sqlite3.Connection) -> None:
    oversized = connection.execute(
        "SELECT 1 FROM cases "
        "WHERE typeof(result_json) != 'text' "
        "OR length(CAST(result_json AS BLOB)) > ? LIMIT 1",
        (MAX_CASE_BYTES,),
    ).fetchone()
    if oversized is not None:
        raise ValueError('案件载荷超过上限或格式无效')

    connection.execute(_CASES_SQL.replace('cases (', 'cases_v2 (', 1))
    connection.execute(_REVIEWS_SQL.replace('reviews (', 'reviews_v2 (', 1).replace(
        'REFERENCES cases(case_id)', 'REFERENCES cases_v2(case_id)', 1
    ))
    rows = connection.execute('SELECT case_id, created_at, result_json FROM cases')
    for case_id, created_at, payload in rows:
        if not isinstance(payload, str) or len(payload.encode('utf-8')) > MAX_CASE_BYTES:
            raise ValueError('案件载荷超过上限或格式无效')
        case = _strict_json_object(payload)
        alert_id, title, severity = _summary(case)
        connection.execute(
            'INSERT INTO cases_v2 '
            '(case_id, created_at, alert_id, title, severity, result_json) VALUES (?, ?, ?, ?, ?, ?)',
            (case_id, created_at, alert_id, title, severity, payload),
        )
    connection.execute(
        'INSERT INTO reviews_v2 (case_id, decision, reviewer, note, reviewed_at) '
        'SELECT case_id, decision, reviewer, note, reviewed_at FROM reviews'
    )
    connection.execute('DROP TABLE reviews')
    connection.execute('DROP TABLE cases')
    connection.execute('ALTER TABLE cases_v2 RENAME TO cases')
    connection.execute('ALTER TABLE reviews_v2 RENAME TO reviews')
    connection.execute(_CREATED_AT_INDEX_SQL)
    connection.execute(_ALERT_ID_INDEX_SQL)
    connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')


class CaseStore:
    """Dedicated local case database. Never migrate dependency/vulnerability databases."""

    def __init__(self, path: Path, *, create: bool = True):
        path = Path(path).resolve()
        if not create and not path.is_file():
            raise ValueError('案件库不存在，请先运行 sop-run')
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation distinguishes a new database from an unrelated empty file.
        new_file = False
        if create:
            try:
                with path.open('xb'):
                    pass
                new_file = True
            except FileExistsError:
                pass
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=10)
            self.connection = connection
            self.connection.execute('PRAGMA foreign_keys=ON')
            self.connection.execute('BEGIN IMMEDIATE')
            app_id = self.connection.execute('PRAGMA application_id').fetchone()[0]
            version = self.connection.execute('PRAGMA user_version').fetchone()[0]
            tables = {r[0] for r in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if new_file and app_id == 0 and version == 0 and not tables:
                _create_v2(self.connection)
                self.connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
                self.connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            elif app_id != APPLICATION_ID:
                raise ValueError('不是兼容的 SOP 案件库，拒绝修改已有数据库')
            elif version == 1 and _schema_matches(self.connection, 1):
                _migrate_v1(self.connection)
            elif version != SCHEMA_VERSION or not _schema_matches(self.connection, SCHEMA_VERSION):
                raise ValueError('不是兼容的 SOP 案件库，拒绝修改已有数据库')
            self.connection.commit()
        except BaseException:
            if connection is not None:
                connection.rollback()
                connection.close()
            if new_file:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.connection.close()

    def save(self, case: dict) -> None:
        if case['status'] != 'awaiting_review' or case['review'] is not None or case['actions_executed'] is not False:
            raise ValueError('只能保存待人工复核且未执行操作的案件')
        alert_id, title, severity = _summary(case)
        payload = json.dumps(case, ensure_ascii=False, allow_nan=False)
        if len(payload.encode('utf-8')) > MAX_CASE_BYTES:
            raise ValueError('案件过大，请缩小日志查询范围')
        with self.connection:
            self.connection.execute(
                'INSERT INTO cases '
                '(case_id, created_at, alert_id, title, severity, result_json) VALUES (?, ?, ?, ?, ?, ?)',
                (case['case_id'], case['created_at'], alert_id, title, severity, payload),
            )

    def get(self, case_id: str) -> dict:
        row = self.connection.execute(
            'SELECT length(CAST(c.result_json AS BLOB)), '
            "CASE WHEN typeof(c.result_json) = 'text' "
            'AND length(CAST(c.result_json AS BLOB)) <= ? THEN c.result_json ELSE NULL END, '
            'r.decision, r.reviewer, r.note, r.reviewed_at '
            'FROM cases c LEFT JOIN reviews r ON r.case_id=c.case_id WHERE c.case_id=?',
            (MAX_CASE_BYTES, case_id),
        ).fetchone()
        if row is None:
            raise ValueError('案件不存在')
        if not isinstance(row[0], int) or row[0] > MAX_CASE_BYTES:
            raise ValueError('案件载荷超过上限')
        if not isinstance(row[1], str):
            raise ValueError('案件载荷格式无效')
        case = _strict_json_object(row[1])
        if row[2] is not None:
            case['review'] = dict(zip(('decision', 'reviewer', 'note', 'reviewed_at'), row[2:]))
            case['status'] = _DECISIONS[row[2]]
            case['steps'][-1]['status'] = case['status']
        case['actions_executed'] = False
        return case

    def list_cases(self, *, status: str | None, query: str, limit: int, offset: int) -> dict:
        if status is not None and (not isinstance(status, str) or status not in _DISPLAY_STATUSES):
            raise ValueError('无效的案件状态')
        if not isinstance(query, str) or len(query) > 256:
            raise ValueError('query 必须是不超过 256 字符的文本')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('limit 必须是 1..100 的整数')
        if type(offset) is not int or not 0 <= offset <= 100000:
            raise ValueError('offset 必须是 0..100000 的整数')

        escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        pattern = f'%{escaped}%'
        parameters = (status, status, query, pattern, pattern, pattern)
        total = self.connection.execute(_COUNT_SQL, parameters).fetchone()[0]
        rows = self.connection.execute(_PAGE_SQL, (*parameters, limit, offset)).fetchall()
        names = ('case_id', 'created_at', 'alert_id', 'title', 'severity', 'status', 'reviewed_at')
        return {'total': total, 'items': [dict(zip(names, row)) for row in rows]}

    def review(self, case_id: str, decision: str, reviewer: str, note: str) -> None:
        if decision not in _DECISIONS:
            raise ValueError('无效的复核决定')
        reviewer = checked_text(reviewer, 'reviewer', 128)
        note = checked_text(note, 'note', 2000)
        with self.connection:
            self.connection.execute('BEGIN IMMEDIATE')
            if self.get(case_id)['review'] is not None:
                raise ValueError('该案件已复核；不可覆盖已有决定，请重新分析创建新案件')
            self.connection.execute('INSERT INTO reviews VALUES (?, ?, ?, ?, ?)',
                                    (case_id, decision, reviewer, note, utc_now()))
