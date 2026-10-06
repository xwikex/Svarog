# Svarog 0.2

Svarog 0.2 是一个本地运行、默认只读的安全分析工作台。它提供告警调查、日志分析、Python 环境和项目依赖审计，并在本地保存审计历史、生成差异报告和 CycloneDX SBOM。Web UI 是本机网页；原有命令行功能仍可使用。

默认日志分析不调用 LLM。新增 SOP 可以通过显式配置启用模型辅助解读；无论是否启用，都不会执行命令、封禁、反制或其他处置动作。原有 Python 审计的远程知识库配置保持不变。

## 5 分钟打开 Web UI

### 最简单的 Windows 安装方式

准备一台安装了 **Python 3.11 或更高版本**的 Windows 电脑或虚拟机，然后：

1. 从 GitHub 下载项目 ZIP，并完整解压到桌面；
2. 双击项目目录中的 `install.bat`，等待出现“安装完成”；
3. 双击 `start-ui.bat`，保持弹出的终端窗口打开；
4. 在这台 Windows 电脑或虚拟机的浏览器访问 [http://127.0.0.1:8765/](http://127.0.0.1:8765/)；
5. 使用结束后回到终端按 `Ctrl+C` 停止服务。

首次安装需要网络连接以下载 Python 依赖。工作台只监听本机回环地址，其他电脑无法直接访问。`start-ui.bat` 不会替你打开浏览器。

### PowerShell 安装方式

在项目目录打开 PowerShell，依次执行：

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m svarog ui --host 127.0.0.1 --port 8765 --workspace .
```

保持最后一个命令运行，再打开 `http://127.0.0.1:8765/`。不要把服务改为 `0.0.0.0`，也不要为它配置公网端口转发。

| 遇到的问题 | 处理方法 |
| --- | --- |
| 提示找不到 Python | 从 Python 官网安装 3.11+，安装时勾选“Add Python to PATH” |
| PowerShell 不允许激活脚本 | 无须激活，直接使用 `.\.venv\Scripts\python.exe` |
| 端口 8765 被占用 | 在 PowerShell 启动命令末尾改用 `--port 8766`，随后访问 `http://127.0.0.1:8766/` |
| 页面仍是旧版本 | 停止旧服务，重新安装项目并按 `Ctrl+F5` 刷新 |

## 本地可视化工作台

Svarog 提供只绑定 `127.0.0.1` 的浅色本地工作台，集中使用 SOP、案件复核、Web 日志分析、Python/项目审计、审计历史、差异对比、SBOM 和 Doctor：

```powershell
python -m svarog ui --workspace .
```

启动后手动打开终端打印的本地地址。审计历史与案件分别保存在工作区 `.svarog/database/` 中；审计历史默认保留 180 天，可在设置中选择 3–365 天。请勿把 `.svarog`、Token、真实日志或数据库上传到 GitHub。完整的 Windows 虚拟机部署、逐项验证、Linux 漏洞 API 连接、备份和故障排查见 [UI 使用说明](docs/UI使用说明.md)。

工作台还支持项目内的**可信功能模块**：在 `src/svarog/features` 下新增带 `manifest.py` 和 `handler.py` 的模块，重启 UI 后即可自动生成菜单、表单和受控结果页面，无需修改核心前端。内置 `file-hash` 可用于验证该扩展机制；第一版不加载第三方目录或模块自带的任意网页脚本。功能模块是与工作台进程同权限运行的 Python 代码，权限标签不是系统沙箱，因此只能加入并运行已经人工审查的自有模块。

## 新增：告警调查 SOP

在原有功能上增加：**告警 → Agent 初步分析 → 查询本地 JSONL / Nginx 日志 → IOC 提取 → ATT&CK 候选映射 → 处置建议 → 人工确认**。

```powershell
python -m svarog sop-run samples/sop/alert.json --logs samples/sop/events.jsonl --case-db reports/sop-demo/cases.sqlite3 --json-out reports/sop-demo/case.json --html-out reports/sop-demo/case.html
```

新增 `sop-run`、`sop-review`、`sop-report`。默认本地规则，独立 SQLite 案件库、离线 HTML 与 JSON 报告；人工批准只记录决定，不执行处置。完整部署、复核与可选模型步骤见 [SOP 使用说明](docs/SOP使用说明.md)。

## Windows PowerShell 安装

需要 Python 3.11 或更高版本。先确认 `python --version` 显示 3.11+，再创建独立环境：

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

激活后可以使用 `svarog` 命令，也可以始终使用 `python -m svarog`。

如果 PowerShell 的执行策略阻止激活脚本，可以不激活环境，直接运行虚拟环境中的 Python：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

如果 `python` 不是准备使用的 3.11+ 版本，可将命令替换为本机对应解释器的完整路径。

## 运行示例

分析正常流量样例：

```powershell
python -m svarog analyze samples/nginx-normal.jsonl
```

分析攻击样例：

```powershell
python -m svarog analyze samples/nginx-attacks.jsonl
```

分析包含提示词注入文本的样例：

```powershell
python -m svarog analyze samples/nginx-prompt-injection.jsonl
```

如需同时保存机器可读的 JSON 报告，增加 `--json-out`：

```powershell
python -m svarog analyze samples/nginx-attacks.jsonl --json-out report.json
```

已激活虚拟环境时，也可以将以上命令中的 `python -m svarog` 替换为 `svarog`。未激活时，将其替换为 `.\.venv\Scripts\python.exe -m svarog`。

## 预期结果

- 正常样例包含 1 个事件，应报告 0 个可疑事件。
- 攻击样例包含 4 个事件，应报告 4 个可疑事件，并分别给出 SQL 注入、XSS、路径遍历和扫描迹象的规则证据。
- 提示词注入样例中的文字只作为不可信日志数据处理，应报告 0 个可疑事件，并且不会执行其中的指令。
- 所有报告都应显示未执行任何动作；JSON 顶层字段 `actions_executed` 应为 `false`。

规则未命中只表示当前证据不足，不能据此确认系统安全。

## 输入格式

输入文件必须是 UTF-8 编码的 JSONL：每行一个 JSON 对象。一个最小事件如下：

```json
{"timestamp":"2026-08-03T12:00:00+08:00","source_ip":"192.0.2.10","method":"GET","host":"demo.local","path":"/products"}
```

必填字段为：

- `timestamp`：带明确时区的 ISO 8601 时间。
- `source_ip`：有效的 IPv4 或 IPv6 地址。
- `method`：HTTP 方法。
- `host`：请求主机名。
- `path`：请求路径。

可选字段包括 `query`、`status`、`user_agent`、`request_id` 和 `body_excerpt`。输入文件最大 10 MiB，单行最大 1 MiB；无效行会记录为输入问题，有效行仍会继续分析。报告最多逐条保留 1000 个输入问题，超过上限时会额外记录一条 `issues_truncated` 汇总；终端和 JSON 摘要中的输入问题数仍表示真实总数。如果文件中没有任何有效事件，分析失败。

## 验证

运行全部自动化测试：

```powershell
python -m pytest -v
```

未激活虚拟环境时：

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

也可以执行一次完整的命令级检查：

```powershell
python -m svarog analyze samples/nginx-normal.jsonl
python -m svarog analyze samples/nginx-attacks.jsonl --json-out report.json
python -m svarog analyze samples/nginx-prompt-injection.jsonl
python -c "import json; data=json.load(open('report.json', encoding='utf-8')); assert data['summary']['suspicious_events'] == 4; assert data['actions_executed'] is False"
```

## 退出码

- `0`：分析及请求的报告写入成功。
- `1`：输入不可读取、没有有效事件、分析失败，或 JSON 报告无法写入。
- `2`：命令或参数格式错误，由 Python 参数解析器返回。

## Windows 控制台兼容性

当 Windows 控制台编码无法表示日志中的某些字符（例如部分 emoji）时，终端报告会将这些字符转换为可见的转义形式，避免程序因编码错误中断。使用 `--json-out` 生成的 UTF-8 JSON 报告会保留原始字符。

## 安全边界

- 日志分析默认本地、只读；SOP 仅写入显式指定的独立案件库与报告，不修改业务数据。
- SOP 模型必须显式配置才会联网；依赖审计的远程知识库选项独立。任何模式都不执行日志里的文字、命令、封禁、自动处置或外部反制。
- `source_ip` 只表示观测到的网络来源，不等同于真实人员、组织或攻击者身份，不能作为身份归因结论。
- 规则命中表示发现了需要复核的局部证据，不代表完成了身份溯源；规则未命中则表示证据不足，不代表确认安全。
- 输入日志始终按不可信数据处理。使用者仍应控制日志访问权限，并在分享报告前检查其中可能包含的敏感信息。

## 后续规划

SOP 已提供独立 TOML 配置的可选 Chat Completions 接口，模型名称和 `base_url` 由用户指定，API key 仅从环境变量读取。调用失败会明确标记本地降级；目前仅发送规则类别与证据 ID，不上传原始日志。后续可在真实接口验证后逐步扩展日志连接器和更深入的证据研判。

## Docker（可选）

项目不依赖 Docker；在已经安装 Docker Desktop 的 Windows 虚拟机上，可以用容器获得一致的 Python 3.11 运行环境：

```powershell
docker build --tag svarog:0.1 .
docker run --rm svarog:0.1 analyze /app/samples/nginx-normal.jsonl
docker run --rm svarog:0.1 analyze /app/samples/nginx-attacks.jsonl
```

容器默认以 UID 10001 的非 root 用户 `svarog` 运行。当前机器若没有 Docker，可以先完成全部 Python 测试，再到装有 Docker Desktop 的 Windows 虚拟机执行上面三条命令。

分析宿主机日志并保存 JSON 报告时，应把输入文件只读挂载，把报告写入另一个可写目录；不要让输入与输出指向同一个文件：

```powershell
$inputFile = (Resolve-Path .\events.jsonl).Path
$outputDir = (New-Item -ItemType Directory -Force .\svarog-output).FullName
docker run --rm --mount "type=bind,source=$inputFile,target=/data/input/events.jsonl,readonly" --mount "type=bind,source=$outputDir,target=/output" svarog:0.1 analyze /data/input/events.jsonl --json-out /output/report.json
```
