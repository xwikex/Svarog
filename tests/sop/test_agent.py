import io
import json
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from svarog.sop.agent import load_advisor, NoRedirect


def config(tmp_path, **options):
    values = {'base_url': 'https://model.example/v1', 'model': 'test-model', **options}
    path = tmp_path / 'agent.toml'
    path.write_text('\n'.join(f'{k} = {json.dumps(v)}' for k, v in values.items()), encoding='utf-8')
    return path


@pytest.mark.parametrize('url', ['http://model.example/v1', 'https://user:password@example.com', 'https://example.com?key=secret', 'file:///tmp/key', 'https://example.com/#fragment'])
def test_endpoint_validation(tmp_path, url):
    with pytest.raises(ValueError):
        load_advisor(config(tmp_path, base_url=url))


def test_missing_key_no_request(tmp_path, monkeypatch):
    monkeypatch.delenv('SVAROG_AGENT_API_KEY', raising=False)
    advisor = load_advisor(config(tmp_path))
    with pytest.raises(ValueError):
        advisor({'evidence': []})


def test_bounded_chat_request_and_response(tmp_path, monkeypatch):
    monkeypatch.setenv('SVAROG_AGENT_API_KEY', 'fake-test-key')
    seen = []
    class Opener:
        def open(self, request, timeout):
            seen.append((request, timeout))
            return io.BytesIO(json.dumps({'choices': [{'message': {'content': json.dumps({'summary': '复核', 'evidence_ids': []})}}]}).encode())
    monkeypatch.setattr('svarog.sop.agent.build_opener', lambda *handlers: Opener())
    advisor = load_advisor(config(tmp_path))
    assert advisor({'evidence': []})['summary'] == '复核'
    request, timeout = seen[0]
    assert request.full_url == 'https://model.example/v1/chat/completions'
    assert request.get_header('Authorization') == 'Bearer fake-test-key'
    assert timeout == 30
    body = json.loads(request.data)
    assert 'tools' not in body
    assert body['response_format'] == {'type': 'json_object'}


def test_oversized_response(tmp_path, monkeypatch):
    monkeypatch.setenv('SVAROG_AGENT_API_KEY', 'fake-test-key')
    class Opener:
        def open(self, *a, **k):
            return io.BytesIO(b'x' * 131073)
    monkeypatch.setattr('svarog.sop.agent.build_opener', lambda *handlers: Opener())
    with pytest.raises(ValueError):
        load_advisor(config(tmp_path))({'evidence': []})


def test_redirect_does_not_forward_secret():
    with pytest.raises(HTTPError):
        NoRedirect().redirect_request(Request('https://original.example'), None, 302, 'redirect', {}, 'https://other.example')


@pytest.mark.parametrize('options', [{'timeout': 0}, {'timeout': 61}, {'timeout': True}, {'api_key': 'do-not-store-me'}, {'unknown': 'value'}])
def test_strict_config(tmp_path, options):
    with pytest.raises(ValueError):
        load_advisor(config(tmp_path, **options))
