from __future__ import annotations

import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from svarog.policy import analyze_event
from svarog.sop.inputs import load_alert, query_logs, checked_text

STEPS = ['告警接入', 'Agent 初步分析', '查询日志', 'IOC 提取', 'ATT&CK 映射', '生成处置建议', '人工确认']
_MAPPINGS = {
    'sql_injection': ('T1190', 'Exploit Public-Facing Application'),
    'path_traversal': ('T1190', 'Exploit Public-Facing Application'),
    'scanning': ('T1595.002', 'Vulnerability Scanning'),
}
_URL = re.compile(r'https?://[^\s<>"\x27]+', re.I)
_ENCODED_URL = re.compile(r'https?%3a%2f%2f[^\s<>"\x27]+', re.I)
_HASH = re.compile(r'(?<![a-zA-Z0-9])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![a-zA-Z0-9])')


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iocs(events) -> tuple[list, bool]:
    found = {}
    truncated = False

    def add(kind, value, role, ref, field):
        nonlocal truncated
        key = (kind, value, role)
        if key not in found:
            if len(found) >= 500:
                truncated = True
                return
            found[key] = {'type': kind, 'value': value, 'role': role,
                          'status': 'unverified', 'evidence_ids': [], 'fields': []}
        item = found[key]
        if ref not in item['evidence_ids']:
            item['evidence_ids'].append(ref)
        if field not in item['fields']:
            item['fields'].append(field)

    for event in events:
        ref = f'log:{event.line_number}'
        add('ip', str(ip_address(event.source_ip)), 'request_source', ref, 'source_ip')
        add('host', event.host.lower().rstrip('.'), 'target_asset', ref, 'host')
        for field in ('path', 'query', 'body_excerpt', 'user_agent'):
            raw_text = getattr(event, field)
            text = unquote(raw_text)
            for match in _HASH.finditer(text):
                value = match.group().lower()
                add({32: 'md5', 40: 'sha1', 64: 'sha256'}[len(value)], value, 'observed_in_request', ref, field)
            # Parse literal URLs before decoding: %2F in userinfo is not a path separator.
            # Only decode a whole URL once when its scheme itself is percent-encoded.
            urls = [m.group() for m in _URL.finditer(raw_text)]
            urls.extend(unquote(m.group()) for m in _ENCODED_URL.finditer(raw_text))
            for url in urls:
                try:
                    parts = urlsplit(url.rstrip('.,);'))
                    host = parts.hostname
                    if not host or len(host) > 255:
                        continue
                    # Exclude URL credentials/query/fragment from candidate displays.
                    host = host.lower()
                    netloc = f'[{host}]' if ':' in host else host
                    if parts.port:
                        netloc += f':{parts.port}'
                    value = urlunsplit((parts.scheme.lower(), netloc, parts.path, '', ''))[:2048]
                    add('url', value, 'observed_in_request', ref, field)
                    try:
                        add('ip', str(ip_address(host)), 'observed_in_request', ref, field)
                    except ValueError:
                        add('domain', host, 'observed_in_request', ref, field)
                except ValueError:
                    continue
    return list(found.values()), truncated


def validate_advice(value, allowed: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != {'summary', 'evidence_ids'}:
        raise ValueError('模型返回字段不符合受限协议')
    summary = checked_text(value['summary'], 'summary', 2000)
    refs = value['evidence_ids']
    if not isinstance(refs, list) or len(refs) > 50 or not all(isinstance(i, str) and i in allowed for i in refs):
        raise ValueError('模型引用不存在的证据')
    if allowed and not refs:
        raise ValueError('模型解读必须引用证据')
    return {'summary': summary, 'evidence_ids': list(dict.fromkeys(refs)), 'status': 'unverified_model_advice'}


def run_case(alert_path, log_path, *, window_minutes=15, limit=200, log_format='jsonl', log_host=None, advisor=None):
    alert, alert_hash = load_alert(alert_path)
    events, query = query_logs(alert, log_path, window_minutes=window_minutes, limit=limit,
                               log_format=log_format, log_host=log_host)
    warnings = ['日志与模型输出是不可信数据；IOC 和 ATT&CK 均为待验证候选，HTTP 状态码不能证明入侵成功。']
    if query['invalid_lines']:
        warnings.append('部分日志行无效，查询覆盖不完整。')
    if query['truncated']:
        warnings.append('关联日志超过保留上限，仅分析时间最早的记录；请缩小窗口或提高 limit。')
    if not events:
        warnings.append('未找到关联日志，证据不足；不能据此判断告警误报或系统安全。')
    evidence, mappings, recommendations = [], {}, {}
    for event in events:
        analysis = analyze_event(event)
        ref = f'log:{event.line_number}'
        event_dict = asdict(event)
        for field in ('path', 'query', 'user_agent', 'body_excerpt'):
            if len(event_dict[field]) > 1024:
                event_dict[field] = event_dict[field][:1024] + '…[展示截断]'
        evidence.append({'id': ref, 'line_number': event.line_number, 'event': event_dict,
                         'rules': [asdict(item) for item in analysis.evidence]})
        for hit in analysis.evidence:
            mapping = _MAPPINGS.get(hit.category)
            if not mapping:
                continue
            tid, name = mapping
            if tid not in mappings:
                mappings[tid] = {'technique_id': tid, 'name': name, 'status': 'candidate',
                    'source': f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/',
                    'evidence_ids': [], 'rationale': '规则显示攻击/扫描尝试；需确认暴露面及后续行为，不能确认成功。'}
            if ref not in mappings[tid]['evidence_ids']:
                mappings[tid]['evidence_ids'].append(ref)
        for suggestion in analysis.recommendations:
            if suggestion not in recommendations:
                recommendations[suggestion] = {'id': f'action:{len(recommendations) + 1}', 'text': suggestion,
                    'evidence_ids': [], 'requires_human_confirmation': True,
                    'precondition': '人工核对日志、资产归属和业务影响后决定。',
                    'impact': '限流、封禁或配置修改可能影响合法业务；本工具不执行这些操作。'}
            recommendations[suggestion]['evidence_ids'].append(ref)
    if not recommendations:
        recommendations['empty'] = {'id': 'action:1', 'text': '核对时间、时区、来源和日志主机，补充证据后重新分析。',
            'evidence_ids': [], 'requires_human_confirmation': True,
            'precondition': '当前没有关联日志。', 'impact': '仅调查建议，不执行操作。'}
    iocs, ioc_truncated = _iocs(events)
    if ioc_truncated:
        warnings.append('IOC 候选超过 500 项，仅保留前 500 项。')
    agent = {'mode': 'local_rules', 'query_plan': '使用显式时间窗口与 source_ip / host 的交集，只读查询指定文件。',
             'summary': '检测到规则迹象，需人工核对。' if any(e['rules'] for e in evidence) else '规则证据不足，需进一步调查。'}
    if advisor is not None:
        # Only a bounded structured digest crosses the optional model boundary.
        # Raw alert text, IP/host, paths, queries, bodies and rule excerpts stay local.
        context = {'coverage': {k: query[k] for k in ('matched', 'retained', 'invalid_lines', 'truncated')},
            'evidence': [{'id': e['id'], 'categories': sorted({r['category'] for r in e['rules']})} for e in evidence[:50]],
            'task': '仅依据证据类别解释调查方向，不能确认入侵或执行/批准任何动作。'}
        try:
            advice = validate_advice(advisor(context), {e['id'] for e in context['evidence']})
            agent.update(mode='model_assisted', advice=advice)
        except Exception:
            # Remote errors may contain credentials or response contents. Never persist them.
            agent['mode'] = 'local_fallback'
            warnings.append('模型不可用或输出校验失败，已降级到本地规则；没有静默伪造模型结果。')
    steps = [{'number': i + 1, 'name': name, 'status': 'completed'} for i, name in enumerate(STEPS)]
    steps[1]['detail'] = '本地规则编排查询；如配置模型，在收集证据后追加辅助解读。'
    steps[2]['status'] = 'partial' if query['invalid_lines'] or query['truncated'] else ('no_evidence' if not events else 'completed')
    steps[-1]['status'] = 'awaiting_review'
    return {'schema_version': 'svarog-sop/1', 'case_id': 'case_' + uuid.uuid4().hex,
            'source_files': [str(Path(p).resolve()) for p in (alert_path, log_path)],
            'created_at': utc_now(), 'status': 'awaiting_review', 'actions_executed': False,
            'alert': alert, 'alert_sha256': alert_hash, 'steps': steps, 'agent': agent,
            'query': query, 'evidence': evidence, 'iocs': iocs, 'attack_mappings': list(mappings.values()),
            'recommendations': list(recommendations.values()), 'review': None, 'warnings': warnings}
