import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from svarog.sop import storage
from svarog.sop.storage import APPLICATION_ID, CaseStore


_V1_CASES_DDL = (
    'CREATE TABLE cases ('
    'case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, result_json TEXT NOT NULL)'
)
_V1_REVIEWS_DDL = (
    'CREATE TABLE reviews ('
    'case_id TEXT PRIMARY KEY REFERENCES cases(case_id), '
    "decision TEXT NOT NULL CHECK(decision IN ('approve','reject','needs_investigation')), "
    'reviewer TEXT NOT NULL, note TEXT NOT NULL, reviewed_at TEXT NOT NULL)'
)


@pytest.fixture
def sample_case():
    return {
        'schema_version': 'svarog-sop/1',
        'case_id': 'case_v1_sample',
        'created_at': '2026-09-08T10:00:00+00:00',
        'status': 'awaiting_review',
        'actions_executed': False,
        'alert': {
            'alert_id': 'alert-001',
            'title': 'Suspicious login',
            'severity': 'high',
        },
        'steps': [{'number': 7, 'name': '人工确认', 'status': 'awaiting_review'}],
        'review': None,
    }


@pytest.fixture
def v1_database(tmp_path, sample_case):
    """Build the exact current v1 schema without invoking CaseStore."""
    path = tmp_path / 'cases-v1.sqlite3'
    with sqlite3.connect(path) as connection:
        connection.execute(_V1_CASES_DDL)
        connection.execute(_V1_REVIEWS_DDL)
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute('PRAGMA user_version=1')
        connection.execute(
            'INSERT INTO cases VALUES (?, ?, ?)',
            (sample_case['case_id'], sample_case['created_at'], json.dumps(sample_case)),
        )
        connection.execute(
            'INSERT INTO reviews VALUES (?, ?, ?, ?, ?)',
            (sample_case['case_id'], 'approve', 'analyst', 'checked', '2026-09-08T11:00:00+00:00'),
        )
    return path


def _case(case_id, created_at, *, alert_id=None, title=None, severity='medium'):
    return {
        'schema_version': 'svarog-sop/1',
        'case_id': case_id,
        'created_at': created_at,
        'status': 'awaiting_review',
        'actions_executed': False,
        'alert': {
            'alert_id': alert_id or f'alert-{case_id}',
            'title': title or f'Title {case_id}',
            'severity': severity,
        },
        'steps': [{'number': 7, 'name': '人工确认', 'status': 'awaiting_review'}],
        'review': None,
    }


def _create_v1(path, rows, reviews=(), *, cases_ddl=_V1_CASES_DDL, reviews_ddl=_V1_REVIEWS_DDL):
    """Create v1 with the released DDL, independent of the implementation under test."""
    with sqlite3.connect(path) as connection:
        connection.execute(cases_ddl)
        connection.execute(reviews_ddl)
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute('PRAGMA user_version=1')
        connection.executemany('INSERT INTO cases VALUES (?, ?, ?)', rows)
        connection.executemany('INSERT INTO reviews VALUES (?, ?, ?, ?, ?)', reviews)


def _database_state(path):
    with sqlite3.connect(path) as connection:
        return {
            'version': connection.execute('PRAGMA user_version').fetchone()[0],
            'tables': connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall(),
            'cases': connection.execute('SELECT * FROM cases ORDER BY case_id').fetchall(),
            'reviews': connection.execute('SELECT * FROM reviews ORDER BY case_id').fetchall(),
        }


def test_v1_fixture_migrates_and_keeps_review(v1_database, sample_case):
    with sqlite3.connect(v1_database) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 1

    with CaseStore(v1_database) as store:
        listing = store.list_cases(status='approved', query='', limit=10, offset=0)
        restored = store.get(sample_case['case_id'])

    assert listing == {
        'total': 1,
        'items': [{
            'case_id': sample_case['case_id'],
            'created_at': sample_case['created_at'],
            'alert_id': 'alert-001',
            'title': 'Suspicious login',
            'severity': 'high',
            'status': 'approved',
            'reviewed_at': '2026-09-08T11:00:00+00:00',
        }],
    }
    assert restored['status'] == 'approved'
    assert restored['review']['reviewer'] == 'analyst'
    with sqlite3.connect(v1_database) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
    with CaseStore(v1_database, create=False) as reopened:
        assert reopened.list_cases(status='approved', query='', limit=10, offset=0)['total'] == 1
        assert reopened.get(sample_case['case_id'])['review']['note'] == 'checked'


def test_new_v2_schema_indexes_application_id_and_reopen(tmp_path, sample_case):
    path = tmp_path / 'new.sqlite3'
    with CaseStore(path) as store:
        store.save(sample_case)
        columns = [row[1] for row in store.connection.execute('PRAGMA table_info(cases)')]
        indexes = {
            row[0]: row[1]
            for row in store.connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
            )
        }
        assert columns == ['case_id', 'created_at', 'alert_id', 'title', 'severity', 'result_json']
        assert indexes == {
            'cases_created_at_idx': 'CREATE INDEX cases_created_at_idx ON cases(created_at DESC, case_id)',
            'cases_alert_id_idx': 'CREATE INDEX cases_alert_id_idx ON cases(alert_id)',
        }
        assert store.connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID
        assert store.connection.execute('PRAGMA user_version').fetchone()[0] == 2

    with CaseStore(path, create=False) as reopened:
        assert reopened.get(sample_case['case_id'])['alert']['title'] == 'Suspicious login'


@pytest.mark.parametrize(
    'bad_payload',
    [
        '{bad json',
        json.dumps({'alert': {'alert_id': 'a', 'title': 't'}}),
        json.dumps({'alert': {'alert_id': 'a', 'title': 't', 'severity': 'urgent'}}),
    ],
    ids=['invalid-json', 'missing-severity', 'invalid-severity'],
)
def test_migration_validation_failure_rolls_back(tmp_path, sample_case, bad_payload):
    path = tmp_path / 'bad-v1.sqlite3'
    good = json.dumps(sample_case)
    _create_v1(
        path,
        [
            ('case_good', '2026-09-08T09:00:00+00:00', good),
            ('case_bad', '2026-09-08T10:00:00+00:00', bad_payload),
        ],
        [('case_good', 'approve', 'analyst', 'keep me', '2026-09-08T11:00:00+00:00')],
    )
    before = _database_state(path)

    with pytest.raises((ValueError, json.JSONDecodeError)):
        CaseStore(path)

    assert _database_state(path) == before
    assert {name for name, _ in before['tables']} == {'cases', 'reviews'}


def test_migration_oversized_json_rolls_back(tmp_path, sample_case, monkeypatch):
    path = tmp_path / 'oversized-v1.sqlite3'
    payload = json.dumps(sample_case)
    _create_v1(path, [(sample_case['case_id'], sample_case['created_at'], payload)])
    before = _database_state(path)
    monkeypatch.setattr(storage, 'MAX_CASE_BYTES', len(payload.encode('utf-8')) - 1)

    with pytest.raises(ValueError, match='上限|过大'):
        CaseStore(path)

    assert _database_state(path) == before


@pytest.mark.parametrize('invalid_kind', ['nan', 'infinity', 'overflow', 'duplicate', 'deep'])
def test_migration_strict_json_failure_rolls_back_everything(tmp_path, sample_case, invalid_kind):
    base = json.dumps(sample_case)
    if invalid_kind == 'nan':
        payload = base[:-1] + ', "invalid": NaN}'
    elif invalid_kind == 'infinity':
        payload = base[:-1] + ', "invalid": Infinity}'
    elif invalid_kind == 'overflow':
        payload = base[:-1] + ', "invalid": 1e999}'
    elif invalid_kind == 'duplicate':
        payload = base.replace(
            '"alert_id": "alert-001"',
            '"alert_id": "first", "alert_id": "alert-001"',
            1,
        )
    else:
        payload = base[:-1] + ', "deep": ' + '[' * 5000 + '0' + ']' * 5000 + '}'

    path = tmp_path / f'strict-{invalid_kind}.sqlite3'
    _create_v1(
        path,
        [(sample_case['case_id'], sample_case['created_at'], payload)],
        [(sample_case['case_id'], 'approve', 'analyst', 'preserve', '2026-09-08T11:00:00+00:00')],
    )
    before = _database_state(path)
    with pytest.raises(ValueError):
        CaseStore(path)
    assert _database_state(path) == before


def test_migration_streams_rows_without_fetchall(tmp_path, monkeypatch):
    path = tmp_path / 'streaming-v1.sqlite3'
    cases = [
        _case(f'case-{index}', f'2026-09-08T0{index}:00:00+00:00')
        for index in range(1, 4)
    ]
    _create_v1(
        path,
        [(case['case_id'], case['created_at'], json.dumps(case)) for case in cases],
    )
    real_connect = sqlite3.connect

    class CursorWithoutFetchall:
        def __init__(self, cursor):
            self.cursor = cursor

        def __iter__(self):
            return iter(self.cursor)

        def fetchone(self):
            return self.cursor.fetchone()

        def fetchall(self):
            raise AssertionError('migration must stream rows instead of fetchall')

    class StreamingConnection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            cursor = super().execute(*args, **kwargs)
            if args[0].strip() == 'SELECT case_id, created_at, result_json FROM cases':
                return CursorWithoutFetchall(cursor)
            return cursor

    def connect_without_fetchall(*args, **kwargs):
        return real_connect(*args, factory=StreamingConnection, **kwargs)

    monkeypatch.setattr(storage.sqlite3, 'connect', connect_without_fetchall)
    with CaseStore(path) as store:
        assert store.list_cases(status=None, query='', limit=10, offset=0)['total'] == 3


@pytest.mark.parametrize(
    ('cases_ddl', 'reviews_ddl'),
    [
        (
            'CREATE TABLE cases (case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, '
            'result_json TEXT NOT NULL CHECK(length(result_json) > 0))',
            _V1_REVIEWS_DDL,
        ),
        (
            'CREATE TABLE cases (case_id TEXT PRIMARY KEY COLLATE NOCASE, '
            'created_at TEXT NOT NULL UNIQUE, result_json TEXT NOT NULL)',
            _V1_REVIEWS_DDL,
        ),
        (
            _V1_CASES_DDL,
            'CREATE TABLE reviews (case_id TEXT PRIMARY KEY REFERENCES cases(case_id) '
            'DEFERRABLE INITIALLY DEFERRED, decision TEXT NOT NULL '
            "CHECK(decision IN ('approve','reject','needs_investigation')), "
            'reviewer TEXT NOT NULL, note TEXT NOT NULL, reviewed_at TEXT NOT NULL)',
        ),
    ],
    ids=['extra-check', 'unique-collate', 'deferred-foreign-key'],
)
def test_v1_semantically_different_ddl_is_rejected_unchanged(
    tmp_path, sample_case, cases_ddl, reviews_ddl
):
    path = tmp_path / 'different-v1.sqlite3'
    _create_v1(
        path,
        [(sample_case['case_id'], sample_case['created_at'], json.dumps(sample_case))],
        [(sample_case['case_id'], 'approve', 'analyst', 'preserve', '2026-09-08T11:00:00+00:00')],
        cases_ddl=cases_ddl,
        reviews_ddl=reviews_ddl,
    )
    before = _database_state(path)
    with pytest.raises(ValueError):
        CaseStore(path)
    assert _database_state(path) == before


def test_migration_rejects_non_object_alert_and_empty_limited_fields(tmp_path, sample_case):
    invalid_alerts = [None, [], {'alert_id': '', 'title': 't', 'severity': 'high'},
                      {'alert_id': 'a', 'title': ' ', 'severity': 'high'},
                      {'alert_id': 'a', 'title': 't', 'severity': ''}]
    for index, alert in enumerate(invalid_alerts):
        path = tmp_path / f'invalid-alert-{index}.sqlite3'
        case = deepcopy(sample_case)
        case['alert'] = alert
        payload = json.dumps(case)
        _create_v1(path, [(case['case_id'], case['created_at'], payload)])
        before = _database_state(path)
        with pytest.raises(ValueError):
            CaseStore(path)
        assert _database_state(path) == before


def test_list_cases_paginates_sorts_counts_and_filters_status(tmp_path):
    path = tmp_path / 'history.sqlite3'
    cases = [
        _case('case_b', '2026-09-08T12:00:00+00:00'),
        _case('case_a', '2026-09-08T12:00:00+00:00'),
        _case('case_c', '2026-09-08T11:00:00+00:00'),
        _case('case_d', '2026-09-08T10:00:00+00:00'),
    ]
    with CaseStore(path) as store:
        for case in cases:
            store.save(case)
        store.review('case_a', 'approve', 'a', 'ok')
        store.review('case_c', 'reject', 'a', 'no')
        store.review('case_d', 'needs_investigation', 'a', 'more')

        page = store.list_cases(status=None, query='', limit=2, offset=1)
        assert page['total'] == 4
        assert [item['case_id'] for item in page['items']] == ['case_b', 'case_c']
        assert all('result_json' not in item for item in page['items'])

        expected = {
            'awaiting_review': 'case_b',
            'approved': 'case_a',
            'rejected': 'case_c',
            'needs_investigation': 'case_d',
        }
        for status, case_id in expected.items():
            result = store.list_cases(status=status, query='', limit=100, offset=0)
            assert result['total'] == 1
            assert [item['case_id'] for item in result['items']] == [case_id]
            assert result['items'][0]['status'] == status


@pytest.mark.parametrize(
    ('query', 'expected'),
    [('%', 'case-percent'), ('_', 'case-underscore'), ('\\', 'case-backslash')],
)
def test_list_query_treats_like_metacharacters_as_literals(tmp_path, query, expected):
    path = tmp_path / 'literal-search.sqlite3'
    cases = [
        _case('case-percent', '2026-09-08T10:00:00+00:00', title='CPU 100%'),
        _case('case-underscore', '2026-09-08T09:00:00+00:00', title='host_name'),
        _case('case-backslash', '2026-09-08T08:00:00+00:00', title=r'C:\logs'),
        _case('case-plain', '2026-09-08T07:00:00+00:00', title='ordinary'),
    ]
    with CaseStore(path) as store:
        for case in cases:
            store.save(case)
        result = store.list_cases(status=None, query=query, limit=100, offset=0)
    assert result['total'] == 1
    assert [item['case_id'] for item in result['items']] == [expected]


def test_list_query_searches_case_alert_and_title(tmp_path):
    with CaseStore(tmp_path / 'search.sqlite3') as store:
        store.save(_case('needle-case', '2026-09-08T10:00:00+00:00'))
        store.save(_case('other-a', '2026-09-08T09:00:00+00:00', alert_id='needle-alert'))
        store.save(_case('other-b', '2026-09-08T08:00:00+00:00', title='needle title'))
        result = store.list_cases(status=None, query='needle', limit=100, offset=0)
    assert result['total'] == 3


def test_list_never_reads_or_decodes_result_json(tmp_path, sample_case):
    path = tmp_path / 'corrupt-payload.sqlite3'
    with CaseStore(path) as store:
        store.save(sample_case)
        store.connection.execute(
            'UPDATE cases SET result_json=? WHERE case_id=?', ('{broken', sample_case['case_id'])
        )
        listing = store.list_cases(status=None, query='', limit=10, offset=0)
        assert listing['items'][0]['title'] == 'Suspicious login'
        with pytest.raises(ValueError):
            store.get(sample_case['case_id'])


@pytest.mark.parametrize('status', ['', 'approve', 'unknown', 1])
def test_list_rejects_invalid_status(tmp_path, status):
    with CaseStore(tmp_path / 'validation.sqlite3') as store:
        with pytest.raises(ValueError):
            store.list_cases(status=status, query='', limit=10, offset=0)


@pytest.mark.parametrize('query', [None, 1, b'text', 'x' * 257])
def test_list_rejects_invalid_query(tmp_path, query):
    with CaseStore(tmp_path / 'validation.sqlite3') as store:
        with pytest.raises(ValueError):
            store.list_cases(status=None, query=query, limit=10, offset=0)


@pytest.mark.parametrize('limit', [True, False, 1.0, 0, 101])
def test_list_rejects_invalid_limit(tmp_path, limit):
    with CaseStore(tmp_path / 'validation.sqlite3') as store:
        with pytest.raises(ValueError):
            store.list_cases(status=None, query='', limit=limit, offset=0)


@pytest.mark.parametrize('offset', [True, False, 1.0, -1, 100001])
def test_list_rejects_invalid_offset(tmp_path, offset):
    with CaseStore(tmp_path / 'validation.sqlite3') as store:
        with pytest.raises(ValueError):
            store.list_cases(status=None, query='', limit=10, offset=offset)


def test_save_writes_validated_normalized_summary_columns(tmp_path, sample_case):
    sample_case['alert'].update(alert_id=' alert-001 ', title=' Suspicious login ', severity='high')
    with CaseStore(tmp_path / 'save.sqlite3') as store:
        store.save(sample_case)
        row = store.connection.execute(
            'SELECT alert_id, title, severity, result_json FROM cases WHERE case_id=?',
            (sample_case['case_id'],),
        ).fetchone()
    assert row[:3] == ('alert-001', 'Suspicious login', 'high')
    assert json.loads(row[3])['alert']['title'] == ' Suspicious login '


@pytest.mark.parametrize(
    'alert',
    [None, [], {}, {'alert_id': 'a', 'title': 't', 'severity': 'urgent'},
     {'alert_id': '', 'title': 't', 'severity': 'high'},
     {'alert_id': 'a', 'title': '', 'severity': 'high'}],
)
def test_save_rejects_invalid_alert_summary(tmp_path, sample_case, alert):
    sample_case['alert'] = alert
    with CaseStore(tmp_path / 'invalid-save.sqlite3') as store:
        with pytest.raises(ValueError):
            store.save(sample_case)
        assert store.connection.execute('SELECT count(*) FROM cases').fetchone()[0] == 0


def test_concurrent_open_serializes_single_v1_migration(v1_database):
    def open_and_list(_):
        with CaseStore(v1_database) as store:
            return store.list_cases(status=None, query='', limit=10, offset=0)['total']

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(open_and_list, range(2))) == [1, 1]
    with sqlite3.connect(v1_database) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        assert {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )} == {'cases', 'reviews'}


@pytest.mark.parametrize('version', [0, 3])
def test_known_application_with_unsupported_version_is_unchanged(tmp_path, version):
    path = tmp_path / f'version-{version}.sqlite3'
    case = _case('case_a', '2026-09-08T10:00:00+00:00')
    _create_v1(path, [(case['case_id'], case['created_at'], json.dumps(case))])
    with sqlite3.connect(path) as connection:
        connection.execute(f'PRAGMA user_version={version}')
    before = _database_state(path)
    with pytest.raises(ValueError):
        CaseStore(path)
    assert _database_state(path) == before


def test_mismatched_v2_schema_is_unchanged(tmp_path):
    path = tmp_path / 'mismatch.sqlite3'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE cases (case_id TEXT PRIMARY KEY)')
        connection.execute(
            'CREATE TABLE reviews ('
            'case_id TEXT PRIMARY KEY REFERENCES cases(case_id), '
            "decision TEXT NOT NULL CHECK(decision IN ('approve','reject','needs_investigation')), "
            'reviewer TEXT NOT NULL, note TEXT NOT NULL, reviewed_at TEXT NOT NULL)'
        )
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute('PRAGMA user_version=2')
    before = path.read_bytes()
    with pytest.raises(ValueError):
        CaseStore(path)
    assert path.read_bytes() == before


def test_new_database_is_removed_when_initialization_fails(tmp_path, monkeypatch):
    path = tmp_path / 'failed-new.sqlite3'

    def fail_create(_connection):
        raise RuntimeError('injected initialization failure')

    monkeypatch.setattr(storage, '_create_v2', fail_create)
    with pytest.raises(RuntimeError, match='injected'):
        CaseStore(path)
    assert not path.exists()


def test_preexisting_empty_database_is_never_removed_on_open_failure(tmp_path):
    path = tmp_path / 'preexisting-empty.sqlite3'
    path.touch()
    with pytest.raises(ValueError):
        CaseStore(path)
    assert path.is_file()
    assert path.read_bytes() == b''


def test_unrelated_database_is_unchanged(tmp_path):
    path = tmp_path / 'unrelated.sqlite3'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE valuable (secret TEXT)')
        connection.execute("INSERT INTO valuable VALUES ('keep')")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        CaseStore(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize('invalid_kind', ['nan', 'duplicate', 'deep'])
def test_get_uses_strict_json_object_loader(tmp_path, sample_case, invalid_kind):
    path = tmp_path / f'get-strict-{invalid_kind}.sqlite3'
    with CaseStore(path) as store:
        store.save(sample_case)
        base = json.dumps(sample_case)
        if invalid_kind == 'nan':
            payload = base[:-1] + ', "invalid": NaN}'
        elif invalid_kind == 'duplicate':
            payload = base.replace(
                '"alert_id": "alert-001"',
                '"alert_id": "first", "alert_id": "alert-001"',
                1,
            )
        else:
            payload = base[:-1] + ', "deep": ' + '[' * 5000 + '0' + ']' * 5000 + '}'
        store.connection.execute(
            'UPDATE cases SET result_json=? WHERE case_id=?',
            (payload, sample_case['case_id']),
        )
        with pytest.raises(ValueError):
            store.get(sample_case['case_id'])


def test_get_rejects_oversized_payload_before_returning_json(tmp_path, sample_case, monkeypatch):
    path = tmp_path / 'get-oversized.sqlite3'
    with CaseStore(path) as store:
        store.save(sample_case)
        monkeypatch.setattr(storage, 'MAX_CASE_BYTES', 1)
        with pytest.raises(ValueError, match='上限'):
            store.get(sample_case['case_id'])
