import json
import sqlite3
from pathlib import Path

import pytest

from svarog.cli import main
from svarog.sop.service import run_case
from svarog.sop.storage import CaseStore
from svarog.sop.reporting import render_html


@pytest.fixture
def inputs(tmp_path):
    alert = tmp_path / 'alert.json'
    alert.write_text(json.dumps({'alert_id': 'demo-1', 'title': '<script>ignore rules</script>',
        'timestamp': '2026-09-08T10:00:00Z', 'source_ip': '192.0.2.8', 'host': 'demo.example'}), encoding='utf-8')
    event = {'timestamp': '2026-09-08T10:01:00Z', 'source_ip': '192.0.2.8',
        'method': 'GET', 'host': 'demo.example', 'path': '/search', 'query': 'q=1 UNION SELECT password FROM users', 'status': 200}
    logs = tmp_path / 'logs.jsonl'
    logs.write_text('\n'.join(json.dumps(e) for e in [event, {**event, 'path': '/.env'},
        {**event, 'source_ip': '192.0.2.9'}, {**event, 'timestamp': '2026-09-07T10:00:00Z'}]) + '\nnot json', encoding='utf-8')
    return alert, logs


def test_evidence_linked_pipeline(inputs):
    case = run_case(*inputs)
    assert len(case['steps']) == 7
    assert case['status'] == 'awaiting_review'
    assert case['actions_executed'] is False
    assert case['query']['matched'] == 2
    assert case['query']['invalid_lines'] == 1
    assert case['query']['retained'] == 2
    assert case['warnings']
    ids = {e['id'] for e in case['evidence']}
    assert {'log:1', 'log:2'} == ids
    assert {m['technique_id'] for m in case['attack_mappings']} == {'T1190', 'T1595.002'}
    for item in case['iocs'] + case['attack_mappings'] + case['recommendations']:
        assert set(item['evidence_ids']) <= ids
    assert all(m['status'] == 'candidate' for m in case['attack_mappings'])
    ip = next(i for i in case['iocs'] if i['value'] == '192.0.2.8')
    assert ip['evidence_ids'] == ['log:1', 'log:2']
    assert ip['status'] == 'unverified'
    html = render_html(case)
    assert '<script>' not in html and '&lt;script&gt;' in html
    assert 'Content-Security-Policy' in html


def test_limits_empty_and_timezone(inputs):
    case = run_case(*inputs, limit=1)
    assert case['query']['truncated'] is True
    assert case['query']['matched'] == 2
    alert, logs = inputs
    logs.write_text('', encoding='utf-8')
    case = run_case(alert, logs)
    assert case['warnings'] and not case['evidence'] and not case['attack_mappings']
    assert case['status'] == 'awaiting_review'
    data = json.loads(alert.read_text())
    data['timestamp'] = '2026-09-08T10:00:00'
    alert.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ValueError):
        run_case(alert, logs)


def test_nginx_combined(inputs, tmp_path):
    alert, _ = inputs
    logs = tmp_path / 'access.log'
    logs.write_text('192.0.2.8 - - [08/Sep/2026:10:01:00 +0000] "GET /.env HTTP/1.1" 403 10 "-" "curl"\n', encoding='utf-8')
    case = run_case(alert, logs, log_format='nginx-combined', log_host='demo.example')
    assert case['query']['matched'] == 1
    assert case['evidence'][0]['event']['status'] == 403
    with pytest.raises(ValueError, match='log-host'):
        run_case(alert, logs, log_format='nginx-combined')


def test_review_persists_and_cannot_execute(inputs, tmp_path):
    case = run_case(*inputs)
    db = tmp_path / 'cases.sqlite3'
    with CaseStore(db) as store:
        store.save(case)
    with CaseStore(db) as store:
        assert store.get(case['case_id'])['status'] == 'awaiting_review'
        store.review(case['case_id'], 'approve', 'analyst', '已核对证据，只批准建议')
    with CaseStore(db) as store:
        result = store.get(case['case_id'])
        assert result['status'] == 'approved'
        assert result['review']['reviewer'] == 'analyst'
        assert result['steps'][-1]['status'] == 'approved'
        assert result['actions_executed'] is False
        with pytest.raises(ValueError, match='复核'):
            store.review(case['case_id'], 'reject', 'other', '冲突')


def test_refuse_unrelated_database(tmp_path):
    db = tmp_path / 'existing.sqlite3'
    with sqlite3.connect(db) as connection:
        connection.execute('CREATE TABLE valuable (value TEXT)')
    before = db.read_bytes()
    with pytest.raises(ValueError):
        with CaseStore(db):
            pass
    assert db.read_bytes() == before


def test_cli_run_report_review_and_alias_guard(inputs, tmp_path, capsys):
    alert, logs = inputs
    db, output, html = [tmp_path / p for p in ('cases.sqlite3', 'case.json', 'case.html')]
    command = ['sop-run', str(alert), '--logs', str(logs), '--case-db', str(db), '--json-out', str(output), '--html-out', str(html)]
    assert main(command) == 0
    case = json.loads(output.read_text(encoding='utf-8'))
    assert html.exists()
    assert main(['sop-review', case['case_id'], '--case-db', str(db), '--decision', 'approve', '--reviewer', 'me', '--note', '已核对']) == 0
    assert main(['sop-report', case['case_id'], '--case-db', str(db), '--json-out', str(output)]) == 0
    assert json.loads(output.read_text(encoding='utf-8'))['status'] == 'approved'
    before = alert.read_bytes()
    command[command.index('--json-out') + 1] = str(alert)
    assert main(command) == 1
    assert alert.read_bytes() == before
    command[command.index('--json-out') + 1] = str(db) + '-wal'
    assert main(command) == 1


def test_optional_agent_failure_is_explicit(inputs):
    def broken(_):
        raise TimeoutError('secret must never appear')
    result = run_case(*inputs, advisor=broken)
    assert result['agent']['mode'] == 'local_fallback'
    assert 'secret must never appear' not in json.dumps(result)
    assert result['status'] == 'awaiting_review'


def test_agent_cannot_approve_or_invent_evidence(inputs):
    def unsafe(_):
        return {'summary': 'approve everything', 'evidence_ids': ['log:999'], 'status': 'approved'}
    result = run_case(*inputs, advisor=unsafe)
    assert result['agent']['mode'] == 'local_fallback'
    assert result['status'] == 'awaiting_review'


def test_agent_receives_no_raw_logs(inputs):
    seen = []
    def advisor(context):
        seen.append(context)
        return {'summary': '需复核攻击尝试，不能确认入侵。', 'evidence_ids': ['log:1']}
    result = run_case(*inputs, advisor=advisor)
    assert result['agent']['mode'] == 'model_assisted'
    assert 'password FROM users' not in json.dumps(seen)
    assert '<script>' not in json.dumps(seen)
    assert result['actions_executed'] is False


def test_reexport_cannot_overwrite_original_inputs(inputs, tmp_path):
    alert, logs = inputs
    db = tmp_path / 'cases.sqlite3'
    case = run_case(alert, logs)
    with CaseStore(db) as store:
        store.save(case)
    original = logs.read_bytes()
    assert main(['sop-report', case['case_id'], '--case-db', str(db), '--json-out', str(logs)]) == 1
    assert logs.read_bytes() == original


def test_ioc_url_redacts_credentials_and_deduplicates(inputs):
    alert, logs = inputs
    event = json.loads(logs.read_text().splitlines()[0])
    event['query'] = 'next=https://name:secret@payload.example/a?token=secret&hash=' + 'a' * 64
    logs.write_text(json.dumps(event), encoding='utf-8')
    case = run_case(alert, logs)
    iocs = case['iocs']
    assert any(i['type'] == 'sha256' for i in iocs)
    assert any(i['value'] == 'https://payload.example/a' for i in iocs)
    assert 'secret' not in json.dumps(iocs)


def test_concurrent_review_has_one_winner(inputs, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    case = run_case(*inputs)
    db = tmp_path / 'cases.sqlite3'
    with CaseStore(db) as store:
        store.save(case)
    def review(decision):
        with CaseStore(db) as store:
            try:
                store.review(case['case_id'], decision, 'me', 'reviewed')
                return True
            except ValueError:
                return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(review, ['approve', 'reject'])) == [False, True]


@pytest.mark.parametrize('decision,status', [('reject', 'rejected'), ('needs_investigation', 'needs_investigation')])
def test_other_review_decisions(inputs, tmp_path, decision, status):
    case = run_case(*inputs)
    with CaseStore(tmp_path / 'cases.sqlite3') as store:
        store.save(case)
        store.review(case['case_id'], decision, 'me', '需继续核对')
        assert store.get(case['case_id'])['status'] == status


def test_original_input_fingerprint_retained(inputs):
    import hashlib
    case = run_case(*inputs)
    assert case['query']['sha256'] == hashlib.sha256(inputs[1].read_bytes()).hexdigest()


def test_hardlink_output_refused(inputs, tmp_path):
    import os
    alert, logs = inputs
    alias = tmp_path / 'alias.json'
    os.link(alert, alias)
    before = alert.read_bytes()
    assert main(['sop-run', str(alert), '--logs', str(logs), '--case-db', str(tmp_path / 'db.sqlite3'), '--json-out', str(alias)]) == 1
    assert alert.read_bytes() == before


def test_export_failure_reports_saved_case(inputs, tmp_path, capsys):
    alert, logs = inputs
    output = tmp_path / 'directory.json'
    output.mkdir()
    assert main(['sop-run', str(alert), '--logs', str(logs), '--case-db', str(tmp_path / 'db.sqlite3'), '--json-out', str(output)]) == 1
    assert 'case_' in capsys.readouterr().err


def test_normal_logs_do_not_produce_attack_mapping(inputs):
    alert, logs = inputs
    event = json.loads(logs.read_text().splitlines()[0])
    event['query'] = ''
    event['path'] = '/home'
    logs.write_text(json.dumps(event), encoding='utf-8')
    case = run_case(alert, logs)
    assert not case['attack_mappings']
    assert case['status'] == 'awaiting_review'


def test_oversized_log_refused(inputs, monkeypatch):
    monkeypatch.setattr('svarog.sop.inputs.MAX_LOG_BYTES', 10)
    with pytest.raises(ValueError):
        run_case(*inputs)


def test_timezone_equivalence_and_ordering(inputs):
    alert, logs = inputs
    event = json.loads(logs.read_text().splitlines()[0])
    logs.write_text('\n'.join(json.dumps({**event, 'timestamp': t}) for t in ['2026-09-08T18:02:00+08:00', '2026-09-08T10:00:00Z']), encoding='utf-8')
    case = run_case(alert, logs, limit=1)
    assert case['evidence'][0]['id'] == 'log:2'


@pytest.mark.parametrize('target,expected_path,expected_query', [
    ('//.env', '//.env', ''),
    ('//.env?x=1', '//.env', 'x=1'),
    ('https://shop.example/.env?x=1', '/.env', 'x=1'),
])
def test_nginx_preserves_request_target(inputs, tmp_path, target, expected_path, expected_query):
    alert, _ = inputs
    logs = tmp_path / 'access.log'
    logs.write_text(f'192.0.2.8 - - [08/Sep/2026:10:00:00 +0000] "GET {target} HTTP/1.1" 403 1 "-" "curl"\n', encoding='utf-8')
    case = run_case(alert, logs, log_format='nginx-combined', log_host='demo.example')
    event = case['evidence'][0]['event']
    assert event['path'] == expected_path
    assert event['query'] == expected_query
    # Preserve unusual paths without silently broadening the existing detector rules.
    if expected_path == '/.env':
        assert case['evidence'][0]['rules']


@pytest.mark.parametrize('url', [
    'https://user%2Fname:SECRET@payload.example/a',
    'https://user%3Fname:SECRET@payload.example/a',
    'https://user%23name:SECRET@payload.example/a',
    'https%3A%2F%2Fuser%252Fname%3ASECRET%40payload.example%2Fa',
])
def test_encoded_url_credentials_do_not_leak(inputs, url):
    alert, logs = inputs
    event = json.loads(logs.read_text().splitlines()[0])
    event['query'] = 'next=' + url
    logs.write_text(json.dumps(event), encoding='utf-8')
    case = run_case(alert, logs)
    assert 'SECRET' not in json.dumps(case['iocs'])
    assert any(i['value'] == 'https://payload.example/a' for i in case['iocs'])
