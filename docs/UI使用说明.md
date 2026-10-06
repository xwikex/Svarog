# Svarog 可视化工作台使用说明

## 1. 功能和安全边界

Svarog 工作台是浅色、本地网页界面，集中提供：

- 告警调查 SOP：告警 → Agent 分析 → 日志查询 → IOC 提取 → ATT&CK 映射 → 处置建议 → 人工确认；
- 案件历史、人工复核及案件 JSON/单文件 HTML 下载；
- Web JSONL 日志分析；
- Python 环境依赖审计；
- `uv.lock` / `poetry.lock` 项目审计；
- Python 环境与项目审计历史、语义差异、CycloneDX 1.7 SBOM；
- Doctor 就绪检查；
- 自动发现的本地可信功能模块，例如 `file-hash` 文件哈希检查。

Svarog 自带的核心分析流程均以只读为原则。页面中的“批准”只记录人工复核意见，**未自动执行处置**，不会封禁 IP、修改配置、执行日志中的命令或自动调用系统管理操作。后续自行编写的可信功能模块属于独立扩展，其代码需要单独审查。

工作台只允许绑定 `127.0.0.1`、`localhost` 或 `::1`。不要通过端口转发、反向代理或虚拟机网络映射把它暴露给其他设备，也不要尝试改为 `0.0.0.0`。

## 2. 从复制到 Windows 虚拟机开始部署

以下示例假定已经把完整项目文件夹复制到：

```text
C:\Users\Administrator\Desktop\Svarog
```

打开 PowerShell，进入项目目录：

```powershell
cd C:\Users\Administrator\Desktop\Svarog
```

确认 Python 版本。Svarog 需要 Python 3.11 或更高版本：

```powershell
python --version
```

如果 `python` 指向错误版本，可以尝试：

```powershell
py -3.11 --version
py -3.11 -m venv .venv
```

如果版本正确，创建虚拟环境并安装项目：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

先运行自动化测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 3. 启动工作台

在一个单独的 PowerShell 窗口保持 UI 服务运行：

```powershell
cd C:\Users\Administrator\Desktop\Svarog
.\.venv\Scripts\python.exe -m svarog ui --workspace .
```

终端会打印本地地址。手动在 Windows 虚拟机浏览器中打开：

```text
http://127.0.0.1:8765/
```

默认不会自动打开浏览器。完成测试后回到运行服务的 PowerShell，按 `Ctrl+C` 停止。

如果 8765 端口被占用：

```powershell
.\.venv\Scripts\python.exe -m svarog ui --workspace . --port 8766
```

然后手动打开 `http://127.0.0.1:8766/`。

## 4. 工作区路径规则

启动命令中的 `--workspace .` 表示当前 Svarog 文件夹。网页内的环境目录、锁文件、数据库和输出目录必须填写相对于该工作区的路径，例如：

```text
.venv
uv.lock
data/vulnerabilities.sqlite3
reports
README.md
```

不要填写 `C:\...` 绝对路径，也不能填写 `..\` 逃逸路径。Windows 上暂时不进行 Python 环境自动发现，必须由用户明确填写环境相对路径。

## 5. 逐项验证功能

### 5.1 概览

首次打开应看到案件数、待复核数、Doctor“尚未检查”和最近运行说明。概览里的最近运行是临时展示；Python 环境和项目审计另有持久历史，重启后仍可在“审计历史”查看。SOP 案件保存在独立的 SQLite 中。

### 5.2 Web 日志分析

选择项目内的 `samples/nginx-attacks.jsonl` 上传。预期显示事件、规则证据、处置建议和 JSON 下载，不应执行任何动作。

### 5.3 新建调查和案件复核

使用：

```text
samples/sop/alert.json
samples/sop/events.jsonl
```

完成后应自动进入案件详情。检查七个 SOP 步骤、证据、IOC、ATT&CK 候选映射和处置建议，然后提交人工决定。批准、拒绝或继续调查都只写入复核记录。

### 5.4 Python 环境审计

环境填写 `.venv`。漏洞来源必须二选一：工作区内 SQLite，或 Linux 虚拟机提供的远程 API。

### 5.5 项目审计

环境填写 `.venv`，锁文件只使用 `uv.lock` 或 `poetry.lock`。Svarog 只读取锁文件，不解释平台标记，并把锁文件中出现的所有版本纳入审计。第一阶段不支持 `requirements.txt`、`pyproject.toml` 或根据 `.venv` 自动推断锁文件。

### 5.6 Doctor

Doctor 只检查三组事项：

1. Python 环境与对应的 `uv`/`poetry` 工具是否可用；
2. SQLite 或远程漏洞 API 数据源是否就绪；
3. 核心目录与明确远程端点的权限和可达性。

它不会收集 CPU、内存、完整 PATH 或网络测速信息。

### 5.7 文件哈希扩展功能

侧边栏“扩展功能”下应出现“文件哈希检查”。目标文件填写 `README.md`，运行后应显示文件名、字节数和 SHA-256。该功能只读取文件。

### 5.8 审计历史、差异、SBOM 和设置

完成一次 Python 环境审计或项目审计后，打开“审计历史”。可按类型、状态、日期和复用状态筛选，点击“详情”查看依赖与漏洞。相同输入再次审计时会复用快照，但仍新增一条运行记录。

“差异对比”默认填入最新成功运行和同类型的上一次成功运行；也可以填写任意两个同项目、同审计类型的快照编号。首次审计可以留空基线，与空状态比较。结果区分项目变化、知识库变化或两者同时变化；锁文件按依赖语义而非文件行数比较。

“SBOM”选择项目审计快照，查看组件、依赖边、未解析依赖包和 SHA-256，再下载 CycloneDX 1.7 JSON。未解析关系会明确标记为不完整；不要把它当作完整依赖树。导出的 SBOM 不包含漏洞对象。

“设置”可改项目显示名称及历史保留期。默认 180 天，最短 3 天、最长 365 天；更改后在下一次**成功**审计后清理过期运行。更改显示名称不会修改项目标识或已有历史。数据目录只读展示，不允许在网页中改成其他路径。

运行数据按用途分开放在工作区：

```text
.svarog/
├─ config/       项目标识与工作台设置
├─ database/     审计历史和 SOP 案件 SQLite 数据库
└─ temp/         运行时临时数据
```

备份前先停止工作台，再复制整个 `.svarog` 目录到安全位置。不要只复制单个数据库文件而遗漏可能存在的 SQLite 辅助文件。恢复时同样先停止工作台，再替换该目录；请勿手工修改其中的 JSON 或 SQLite 表。`.svarog` 已被 Git 忽略，不能上传到公开仓库。

## 6. 连接 Linux 虚拟机漏洞知识库

假设 Windows 虚拟机地址是 `192.168.159.139`，Linux 虚拟机 API 地址是 `192.168.159.140:8001`。先检查网络：

```powershell
$LinuxVmIp = "192.168.159.140"
$VulnApi = "http://${LinuxVmIp}:8001"
Test-NetConnection $LinuxVmIp -Port 8001
```

`TcpTestSucceeded : True` 表示 Windows 虚拟机能够连接该端口。注意 URL 应写成 `http://`，不要写成 `http\://`。

如果 API 需要 Token，只通过环境变量提供，然后在同一个 PowerShell 窗口启动 Svarog：

```powershell
$env:SVAROG_VULN_API_TOKEN = "替换为实际Token"
.\.venv\Scripts\python.exe -m svarog ui --workspace .
```

网页远程 API 字段填写：

```text
http://192.168.159.140:8001
```

Token 不会写入网页存储、报告或案件数据库。测试结束可清除当前终端中的变量：

```powershell
Remove-Item Env:SVAROG_VULN_API_TOKEN
```

## 7. 添加自己的可信功能模块

可信模块位于：

```text
src/svarog/features/<模块目录>/
```

每个模块至少包含：

```text
__init__.py
manifest.py
handler.py
```

`manifest.py` 声明菜单名称和输入字段，`handler.py` 提供 `run_feature(context, values)`。模块返回摘要卡片、警告和纯文本表格，并且必须返回：

```python
"actions_executed": False
```

**重要信任边界：**功能模块是与工作台进程拥有相同操作系统权限的 Python 代码。清单中的权限标签用于界面提示和输入约束，并不是文件系统、网络或进程级沙箱；`actions_executed` 也是结果契约，不会撤销模块已经执行的代码。因此只能放入并运行你本人编写、已经审查且确认只读的模块，不要复制来源不明的模块。

新增模块不需要修改 `application.py`、`index.html` 或 `app.js`。使用可编辑安装时，增加模块文件后重启 `python -m svarog ui`；使用 Wheel 安装时，需要重新构建并安装 Wheel 后再重启。

第一版不允许功能模块携带自定义 HTML、JavaScript、Markdown、可点击命令或外部资源。需要复杂展示时，应先扩展核心受控组件，而不是在模块中注入脚本。

可参考内置 `file-hash`：

```text
src/svarog/features/file_hash/manifest.py
src/svarog/features/file_hash/handler.py
```

## 8. 常见问题

### `audit-python` 不是有效命令

通常表示虚拟环境中仍安装着旧版本，或当前目录不是更新后的项目。重新执行：

```powershell
cd C:\Users\Administrator\Desktop\Svarog
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m svarog --help
```

### 找不到文件或路径无效

确认文件确实位于 `--workspace` 内，并在网页中填写相对路径。绝对路径、`..` 路径和会逃逸工作区的符号链接会被主动拒绝；仍指向工作区内部的普通输入符号链接可能被允许。功能模块源码目录中的符号链接或 Windows junction 会被拒绝。

### 页面没有出现新模块

确认模块是 `src/svarog/features` 的直接子包，三个文件齐全，功能 ID 唯一且只包含小写字母、数字和连字符。查看测试结果后重启 UI。模块加载失败只会禁用该模块，不会阻止工作台启动。

### 防火墙提示或其他机器无法访问

工作台本来就只能由运行它的 Windows 虚拟机本机访问。不要为它创建入站防火墙规则，不要配置 NAT 端口映射，也不要改成 `0.0.0.0`。

### 页面仍显示旧代码

先按 `Ctrl+C` 停止服务，重新执行可编辑安装命令并再次启动，然后在虚拟机浏览器中刷新页面。

## 9. 验收边界

自动化测试验证路由、安全头、路径边界、结果结构、模块发现和静态资源。最终字体、布局、键盘操作和浏览器交互由你在 Windows 虚拟机中验收。未连接真实模型服务时，不能把本地替身测试描述为真实模型兼容性验证。
