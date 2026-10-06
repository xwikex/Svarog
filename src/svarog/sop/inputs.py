from __future__ import annotations

import bisect
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

# Reuse the same strict event contract as the existing analyzer.
from svarog.parsers.nginx_json import _normalize_event

MAX_LOG_BYTES = 10 * 1024 * 1024
_COMBINED = re.compile(
    r'^(\S+) \S+ \S+ \[([^]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (?:\d+|-) '
    r'"(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)"\s*$'
)
_MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}


def read_bounded(path: Path, limit: int) -> bytes:
    path = Path(path)
    if not path.is_file():
        raise ValueError('输入必须是现有普通文件')
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'输入超过 {limit} 字节上限')
    return data


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or 'T' not in value or len(value) > 64:
        raise ValueError('timestamp 必须是带时区的 ISO 8601 时间')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('timestamp 必须包含时区')
    return parsed.astimezone(timezone.utc)


def checked_text(value, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'{name} 必须是 1..{limit} 字符的非空文本')
    if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(f'{name} 含不支持的控制字符')
    return value.strip()


def load_alert(path: Path) -> tuple[dict, str]:
    data = read_bounded(path, 65536)
    payload = json.loads(data.decode('utf-8-sig'))
    if not isinstance(payload, dict):
        raise ValueError('告警必须是 JSON 对象')
    alert = {'title': checked_text(payload.get('title'), 'title'),
             'timestamp': timestamp(payload.get('timestamp')).isoformat(),
             'alert_id': checked_text(payload.get('alert_id', 'local-alert'), 'alert_id'),
             'description': checked_text(payload.get('description') or '未提供补充描述', 'description', 4096),
             'severity': payload.get('severity', 'unknown')}
    if alert['severity'] not in ('unknown', 'info', 'low', 'medium', 'high', 'critical'):
        raise ValueError('severity 不在允许范围内')
    if payload.get('source_ip'):
        alert['source_ip'] = str(ip_address(checked_text(payload['source_ip'], 'source_ip', 64)))
    if payload.get('host'):
        alert['host'] = checked_text(payload['host'], 'host').lower().rstrip('.')
    if not (alert.get('source_ip') or alert.get('host')):
        raise ValueError('告警至少提供 source_ip 或 host，避免无范围查询')
    return alert, hashlib.sha256(data).hexdigest()


def _combined(raw: str, host: str) -> dict:
    match = _COMBINED.fullmatch(raw)
    if not match:
        raise ValueError('不是受支持的 Nginx combined 行')
    source, date, request, status, user_agent = match.groups()
    # Explicit English month mapping avoids depending on Windows/Linux locale.
    time_match = re.fullmatch(r'(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})', date)
    if not time_match:
        raise ValueError('无效的 Nginx 时间')
    day, month, year, hour, minute, second, offset = time_match.groups()
    month_number = _MONTHS.get(month)
    if month_number is None:
        raise ValueError('无效月份')
    iso = f'{year}-{month_number:02}-{day}T{hour}:{minute}:{second}{offset[:3]}:{offset[3:]}'
    method, target, protocol = request.split(' ')
    if not protocol.startswith('HTTP/'):
        raise ValueError('无效请求协议')
    if target.lower().startswith(('http://', 'https://')):
        parts = urlsplit(target)
        path, query = parts.path or '/', parts.query
    else:
        # An origin-form //path is not a URL authority. Preserve its bytes.
        path, _, query = target.partition('?')
    return {'timestamp': iso, 'source_ip': source, 'method': method, 'host': host,
            'path': path, 'query': query, 'status': int(status), 'user_agent': user_agent}


def query_logs(alert: dict, path: Path, *, window_minutes: int = 15, limit: int = 200,
               log_format: str = 'jsonl', log_host: str | None = None) -> tuple[list, dict]:
    if not 1 <= window_minutes <= 1440 or not 1 <= limit <= 500:
        raise ValueError('window-minutes 必须为 1..1440，limit 必须为 1..500')
    if log_format not in ('jsonl', 'nginx-combined'):
        raise ValueError('不支持的日志格式')
    if log_format == 'nginx-combined':
        if not log_host:
            raise ValueError('Nginx combined 缺少主机信息，必须显式提供 --log-host')
        log_host = checked_text(log_host, 'log-host')
    center = timestamp(alert['timestamp'])
    start, end = center - timedelta(minutes=window_minutes), center + timedelta(minutes=window_minutes)
    data = read_bounded(path, MAX_LOG_BYTES)
    stats = {'start': start.isoformat(), 'end': end.isoformat(), 'selectors': {
        k: alert[k] for k in ('source_ip', 'host') if k in alert},
        'format': log_format, 'log_host': log_host, 'sha256': hashlib.sha256(data).hexdigest(),
        'scanned': 0, 'valid': 0, 'invalid_lines': 0, 'issues': [], 'matched': 0, 'limit': limit}
    retained = []
    for line_no, raw in enumerate(data.splitlines(), 1):
        if not raw.strip():
            continue
        stats['scanned'] += 1
        try:
            if len(raw) > 1024 * 1024:
                raise ValueError('单行过大')
            text = raw.decode('utf-8-sig' if line_no == 1 else 'utf-8')
            payload = json.loads(text) if log_format == 'jsonl' else _combined(text, log_host)
            event = _normalize_event(payload, line_no)
            when = timestamp(event.timestamp)
        except (ValueError, UnicodeError, RecursionError):
            stats['invalid_lines'] += 1
            if len(stats['issues']) < 50:
                stats['issues'].append({'line': line_no, 'reason': '无效行或超过大小限制'})
            continue
        stats['valid'] += 1
        if not start <= when <= end:
            continue
        if alert.get('source_ip') and str(ip_address(event.source_ip)) != alert['source_ip']:
            continue
        if alert.get('host') and event.host.lower().rstrip('.') != alert['host']:
            continue
        stats['matched'] += 1
        bisect.insort(retained, (when, line_no, event))
        if len(retained) > limit:
            retained.pop()
    stats['retained'] = len(retained)
    stats['truncated'] = stats['matched'] > len(retained)
    stats['selection'] = 'earliest_timestamp_then_line_number'
    return [item[2] for item in retained], stats
