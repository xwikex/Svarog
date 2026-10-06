# Svarog 告警调查 SOP 使用说明

## 这次新增了什么

原有分析和 Python 依赖审计保留，新加独立的只读调查流程：

**告警 → Agent 初步分析 → 查询日志 → IOC 提取 → ATT&CK 候选映射 → 处置建议 → 人工确认**

默认完全本地：Agent 是确定性规则编排器，不是假装调用大模型。可选模型在证据收集后提供辅助解读，不决定查询文件、执行命令或替人批准。

三个新命令：`sop-run` 创建案件、`sop-review` 保存人工决定、`sop-report` 重新导出报告。案件库是独立 SQLite 文件，**不能使用 Linux 上的漏洞数据库或已有依赖历史数据库**。这些命令不需要访问漏洞 API。

## Windows 从项目文件夹开始

把更新后的完整 Svarog 文件夹复制进 Windows 虚拟机，打开项目文件夹中的 PowerShell。不要复制宿主机的 `.venv`，在目标系统重新创建环境；无需激活：

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m svarog --help
```

Python 需要 3.11+；帮助中应出现 `sop-run`、`sop-review`、`sop-report`。如果没有，核对当前文件夹以及使用的解释器，重新执行上面的可编辑安装。此功能没有新增第三方运行依赖。

### 1. 一行命令跑通演示

```powershell
.\.venv\Scripts\python.exe -m svarog sop-run .\samples\sop\alert.json --logs .\samples\sop\events.jsonl --case-db .\reports\sop-demo\cases.sqlite3 --json-out .\reports\sop-demo\case.json --html-out .\reports\sop-demo\case.html
```

输出目录会自动创建，随后打开报告：

```powershell
Start-Process .\reports\sop-demo\case.html
```

预期：9 个非空输入行、8 个有效事件、5 条匹配并保留、1 条坏行；其他来源、其他主机和时间窗口外的记录不进入证据。报告显示 `awaiting_review`、`local_rules` 和 `actions_executed: false`。演示包含提示词注入文本，不应引发任何执行。

HTML 无脚本、无外部图片/字体/样式资源，断网也可打开。报告中的证据链接可跳到原始文件行号对应的详情。数据库和 JSON 保存告警/日志 SHA-256，用于核对当时输入内容；JSON 也保留绝对输入路径以防再次导出覆盖输入，分享前应检查路径隐私。

### 2. 保存人工确认

先从 JSON 读取案件 ID，避免手工输入错：

```powershell
$CaseId = (Get-Content .\reports\sop-demo\case.json -Raw -Encoding UTF8 | ConvertFrom-Json).case_id
.\.venv\Scripts\python.exe -m svarog sop-review $CaseId --case-db .\reports\sop-demo\cases.sqlite3 --decision approve --reviewer "我的名字" --note "已核对证据，同意继续调查；未授权自动处置"
```

`--decision` 可选：

| 参数 | 含义 |
|---|---|
| `approve` | 批准建议，案件显示 approved，**仍然不执行** |
| `reject` | 拒绝建议，显示 rejected |
| `needs_investigation` | 要求补充调查 |

每个案件只接受一次复核，防止覆盖决定；如有新证据，重新运行 `sop-run` 创建新案件。本版不做案件合并/去重。姓名和备注只是个人本地记录，不是登录认证或数字签名。

### 3. 更新可查看的报告

```powershell
.\.venv\Scripts\python.exe -m svarog sop-report $CaseId --case-db .\reports\sop-demo\cases.sqlite3 --json-out .\reports\sop-demo\case.json --html-out .\reports\sop-demo\case.html
```

刷新浏览器后才能看到新状态。静态 HTML 不是在线审批界面，不会直接修改 SQLite，也没有伪造的“确认成功”按钮。

## 换成自己的数据

告警使用 UTF-8 JSON 对象：

```json
{"alert_id":"my-alert-001","title":"可疑 Web 请求","timestamp":"2026-09-08T10:00:00+08:00","severity":"high","source_ip":"192.0.2.44","host":"shop.example"}
```

- `title`、带时区的 `timestamp` 必填；`source_ip`、`host` 至少一个。两个都提供时用 AND 匹配。
- 时间窗口默认告警前后各 15 分钟；可用 `--window-minutes 30` 修改（1..1440）。
- 默认保留 200 条，可用 `--limit 500` 修改（1..500）；按时间、行号选取最早记录，不是风险排名。超过上限会明确警告。
- JSONL 字段沿用原有 analyzer：timestamp/source_ip/method/host/path，支持 query/status/user_agent/request_id/body_excerpt。
- JSONL 字段不是 Nginx 任意变量名的自动转换。使用自定义 log_format 时请导出成上述字段；当前不自动读取 syslog、CSV、压缩包或多文件。
- 当前扫描一个最多 10 MiB 的日志文件，单行最多 1 MiB；坏行计数并记录前 50 个行号。先导出与告警有关的日志片段，而不是传整个生产日志目录。

### Nginx 普通 combined 日志

```powershell
.\.venv\Scripts\python.exe -m svarog sop-run .\samples\sop\alert.json --logs .\samples\sop\access.log --log-format nginx-combined --log-host shop.example --case-db .\reports\sop-demo\cases.sqlite3 --html-out .\reports\sop-demo\nginx-case.html
```

标准 combined 行没有主机字段，必须由你明确提供 `--log-host`；不要将多个虚拟主机混在同一文件再指定一个主机名。此样例匹配两条日志。IP 是观测来源，可能为代理/CDN，并非真实人员身份；当前不自动信任 X-Forwarded-For。

## 可选：接入兼容模型

仅当你主动传 `--agent-config` 时联网；先复制并编辑示例 TOML，填写你自己的服务基础地址和已开通的 Chat Completions 模型名称。示例的 example 域名是占位符，不能直接调用。

```powershell
Copy-Item .\samples\sop\agent.example.toml .\sop-agent.local.toml
# 编辑 sop-agent.local.toml 后，在当前进程配置密钥（不要提交到 Git）
$env:SVAROG_AGENT_API_KEY = "你的密钥"
.\.venv\Scripts\python.exe -m svarog sop-run .\samples\sop\alert.json --logs .\samples\sop\events.jsonl --case-db .\reports\sop-demo\cases.sqlite3 --agent-config .\sop-agent.local.toml --html-out .\reports\sop-demo\model-case.html
```

- 仅发送覆盖计数、最多 50 条证据 ID 与规则类别，不发送告警原文、IP/主机、路径、请求参数、正文或命中片段。这会限制模型的深入研判能力，但先保护本地日志隐私。
- 服务必须支持 `/chat/completions`、`response_format: json_object` 和 `max_tokens`。未验证所有兼容厂商；本次只用模拟接口测试，**没有用真实密钥实测**。
- 强制 HTTPS；仅 localhost/127.0.0.1/::1 可用 HTTP。禁止重定向，不继承系统代理；不提供关闭证书验证开关。
- 请求上下文 ≤64 KiB，响应 ≤128 KiB，网络操作超时默认 30 秒（可配 1..60 秒），不自动重试。
- 模型没有工具权限，只允许返回解读与已有证据引用。引用检查不能证明文字事实正确；模型解读始终待人工验证。
- 密钥缺失、额度/认证错误、超时、响应过大或结构不合规时显示 `local_fallback`，本地调查仍保存且返回 0；配置本身无效则返回 1。
- 可参考 [Chat Completions 协议](https://developers.openai.com/api/reference/resources/chat)。这不是无限循环 Agent，也不会替你访问 IOC 地址。

## 边界与验收

- IOC 包括观测来源 IP、目标主机、请求中 URL/URL 主机及 MD5/SHA1/SHA256 形状的字符串；不做全格式威胁情报解析，哈希样式不代表已验证文件哈希。最多 500 项，去重并保留证据引用。
- URL 候选会移除用户凭据、查询参数与片段，但**本地完整证据仍可能含敏感数据**；报告和案件库不会全面脱敏。Windows 使用受限账户目录，Linux 设置好目录权限。
- ATT&CK 仅使用少量手工候选规则，不是完整知识库。SQL 注入/路径遍历候选 [T1190](https://attack.mitre.org/techniques/T1190/)；扫描候选 [T1595.002](https://attack.mitre.org/techniques/T1595/002/)。参考页核对日期：2026-09-08。映射还需人工确认暴露面与行为上下文；XSS 不强行映射。
- 证据不足、坏行或截断都不意味着安全；HTTP 200 也不意味着攻击成功。
- 每次运行新建案件，SQLite 保存完整结构化结果及独立复核表；只有主键索引，本版无跨案件搜索和历史比较。
- 本版不是服务端监控平台：无自动告警订阅、SIEM/EDR 接口、多人审批、自动封禁、知识库增强或可执行处置。

```powershell
.\.venv\Scripts\python.exe -m pytest tests/sop -v -p no:cacheprovider
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider
```

返回 0 表示调查/导出操作成功，不代表告警已解决；1 表示输入、案件库、路径、复核状态或导出失败；2 表示命令参数格式错误。若提示案件已保存但报告导出失败，修正输出路径后运行 `sop-report`，不必重新审计。
