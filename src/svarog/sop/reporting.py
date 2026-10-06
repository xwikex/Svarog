from __future__ import annotations

import html
import json
import os
import tempfile
from pathlib import Path

_STATUS = {'awaiting_review': '待人工确认', 'approved': '已批准建议（未执行）', 'rejected': '已拒绝',
           'needs_investigation': '需补充调查', 'completed': '已完成', 'partial': '部分覆盖', 'no_evidence': '无关联证据'}


def _escape(value) -> str:
    return html.escape(str(value), quote=True)


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)


def render_html(case: dict) -> str:
    e = _escape
    steps = ''.join(f'<li><b>{s["number"]:02}</b><h3>{e(s["name"])}</h3><span>{e(_STATUS.get(s["status"], s["status"]))}</span></li>' for s in case['steps'])
    warnings = ''.join(f'<li>{e(w)}</li>' for w in case['warnings'])
    rows = ''.join(f'<tr><td><a href="#{e(i["id"])}">{e(i["id"])}</a></td><td>{e(i["event"]["timestamp"])}</td>'
                   f'<td>{e(i["event"]["source_ip"])}</td><td>{e(i["event"]["method"])} {e(i["event"]["path"])}</td>'
                   f'<td>{e(", ".join(r["category"] for r in i["rules"]) or "无规则命中")}</td></tr>' for i in case['evidence'])

    def refs(item):
        return ' '.join(f'<a href="#{e(ref)}">{e(ref)}</a>' for ref in item['evidence_ids']) or '证据不足'

    iocs = ''.join(f'<tr><td>{e(i["type"])}</td><td>{e(i["value"])}</td><td>{e(i["role"])}</td><td>待验证</td><td>{refs(i)}</td></tr>' for i in case['iocs'])
    maps = ''.join(f'<article><h3>{e(i["technique_id"])} · {e(i["name"])}</h3><p>候选映射：{e(i["rationale"])}</p><p>{refs(i)}</p></article>' for i in case['attack_mappings']) or '<p>未产生候选映射；不代表没有攻击。</p>'
    actions = ''.join(f'<article><h3>{e(i["id"])} · {e(i["text"])}</h3><p>{e(i["precondition"])}</p><p>{e(i["impact"])}</p><p>{refs(i)}</p></article>' for i in case['recommendations'])
    evidence = ''.join(f'<details id="{e(i["id"])}"><summary>{e(i["id"])} · 原始文件第 {i["line_number"]} 行（展示可能截断）</summary><pre>{e(_json(i))}</pre></details>' for i in case['evidence'])
    review = '<p>案件等待人工复核。使用 sop-review 记录决定，再用 sop-report 重新导出；此离线页面不会自行保存决定。</p>' if case['review'] is None else f'<pre>{e(_json(case["review"]))}</pre>'
    q = case['query']
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Svarog · 告警调查报告</title><style>
:root{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;background:#f2f5f8;color:#162638;font:15px/1.7 system-ui,sans-serif}}main{{max-width:1220px;margin:auto;padding:36px 24px}}header{{background:#10283f;color:white;padding:32px;border-radius:16px}}h1{{margin:8px 0;font-size:30px}}h2{{font-size:21px;margin-top:0}}h3{{font-size:15px}}.tag{{color:#a4ebd9}}.steps{{display:grid;grid-template-columns:repeat(7,1fr);gap:8px;padding:0;list-style:none;margin:24px 0}}.steps li,section{{background:white;border:1px solid #dbe3eb;border-radius:12px;padding:18px}}.steps b{{color:#147e6b;font-size:23px}}.steps span{{font-size:12px}}section{{margin:16px 0}}.notice{{border-left:5px solid #d5931e;background:#fff9e9}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}article{{border-top:1px solid #e1e8ef;padding:12px 0}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #e1e8ef;vertical-align:top;overflow-wrap:anywhere}}a{{color:#096b65}}pre{{white-space:pre-wrap;word-break:break-word;background:#f5f7fa;padding:16px;border-radius:8px;font-size:12px}}details{{padding:10px 0}}summary{{cursor:pointer}}.scroll{{overflow-x:auto}}.meta{{overflow-wrap:anywhere;font-size:12px;opacity:.85}}@media(max-width:850px){{.steps{{grid-template-columns:repeat(2,1fr)}}.grid{{grid-template-columns:1fr}}main{{padding:12px}}}}
</style></head><body><main>
<header><div class="tag">SVAROG / READ-ONLY SECURITY WORKFLOW</div><h1>{e(case['alert']['title'])}</h1><p>{e(_STATUS[case['status']])} · 未执行任何处置动作</p><div class="meta">{e(case['case_id'])} · {e(case['created_at'])}</div></header>
<ol class="steps">{steps}</ol>
<section class="notice"><h2>调查边界</h2><ul>{warnings}</ul></section>
<div class="grid"><section><h2>告警与查询计划</h2><pre>{e(_json(case['alert']))}</pre><p>{e(case['agent']['query_plan'])}</p></section>
<section><h2>Agent 分析</h2><p>模式：{e(case['agent']['mode'])}</p><p>{e(case['agent']['summary'])}</p><p>模型仅追加证据解读；其文字建议仍需人工核对。</p><pre>{e(_json(case['agent'].get('advice', {'说明':'未启用或未获得有效模型解读'})))}</pre></section></div>
<section><h2>日志关联与覆盖</h2><p>读取 {q['scanned']} 行 · 有效 {q['valid']} · 匹配 {q['matched']} · 保留 {q['retained']} · 无效 {q['invalid_lines']}</p><p>{e(q['start'])} 至 {e(q['end'])}</p><div class="scroll"><table><thead><tr><th>证据</th><th>时间</th><th>来源</th><th>请求</th><th>规则类别</th></tr></thead><tbody>{rows}</tbody></table></div><details><summary>查询参数、文件指纹与输入问题</summary><pre>{e(_json(q))}</pre></details></section>
<section><h2>IOC 候选 · 不等于恶意指标</h2><div class="scroll"><table><thead><tr><th>类型</th><th>值</th><th>角色</th><th>状态</th><th>证据</th></tr></thead><tbody>{iocs}</tbody></table></div></section>
<section><h2>ATT&amp;CK 候选映射</h2>{maps}</section>
<section><h2>处置建议 · 必须人工确认</h2>{actions}</section>
<section><h2>人工确认记录</h2>{review}<p>批准仅记录意见，不代表已封禁、修复或确认入侵。复核姓名是本地自述身份。</p></section>
<section><h2>证据详情</h2>{evidence}</section>
<footer class="meta">Svarog SOP v1 · 本地静态报告 · 分享前检查敏感信息 · JSON 是结构化事实源</footer>
</main></body></html>'''


def _atomic_write(path: Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.svarog-sop-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(case: dict, json_out=None, html_out=None) -> None:
    if json_out is not None:
        _atomic_write(json_out, _json(case) + '\n')
    if html_out is not None:
        _atomic_write(html_out, render_html(case))
