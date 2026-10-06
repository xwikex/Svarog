# Svarog 第二阶段历史、差异与 SBOM 设计

**状态：** 已批准并冻结  
**日期：** 2026-09-03  
**方案：** C——内容快照、执行记录、规范化索引与压缩 JSON 的混合模型

## 1. 背景

Svarog 第一阶段已经能够显式读取用户指定的 Python 虚拟环境和
`poetry.lock`/`uv.lock`，使用本地只读 SQLite 漏洞库或远程
`vuln-sync` API 完成项目依赖漏洞审计，并输出权威 JSON 与无外部依赖的单文件
HTML。

第二阶段在不破坏现有无状态用法的前提下增加：

1. 历史审计摘要存储；
2. 基于哈希的无变化判定；
3. 可锚定的历史差异报告；
4. CycloneDX SBOM 导出。

设计必须解决以下实际问题：

- 项目复制、移动或跨平台后历史记录仍能归属于同一项目；
- 无变化执行不能重复保存完整报告，但必须保留“本次确实执行过”的证据；
- 差异报告的基线不能随以后新增的审计发生漂移；
- 锁文件必须进行语义比较，而不是逐行比较；
- 查询某漏洞的首次出现时间和对应版本时不能反复解析历史 JSON；
- 当前解析策略忽略 marker，不能伪造所谓“完整依赖树”。

## 2. 强制范围

### 2.1 本阶段包含

- 用户显式提供稳定的 `project_id`；
- 用户显式提供历史 SQLite 数据库路径；
- 每次执行均保存轻量运行记录；
- 仅在语义输入变化时保存新的审计内容快照；
- 原始锁文件哈希和语义锁文件哈希；
- Python 环境语义哈希；
- 与当前项目相关的漏洞知识内容哈希；
- 策略、引擎和时间健康状态指纹；
- 自动选择并固定差异基线；
- 可选手动指定差异基线；
- 项目变化、知识库变化和混合变化分类；
- 锁文件包集合、版本集合和来源类型的语义差异；
- 漏洞新增、消失、持续和内容变化；
- CycloneDX 1.7 JSON `components` 导出；
- 使用 CycloneDX composition 表达依赖关系完整性未知；
- Windows 和 Linux 使用同一数据库结构与相同语义。

### 2.2 本阶段不包含

- 根据目录自动发现历史数据库或项目标识；
- 执行 Poetry、uv、pip 或目标 Python；
- 解释平台、Python 版本、extra、group 或其他 marker；
- 从 `pyproject.toml`、`requirements.txt` 或 Pipfile 读取依赖；
- 伪造 CycloneDX `dependencies`；
- 承诺完整父子依赖树；
- 在项目和知识库同时变化时猜测单个漏洞变化的唯一原因；
- 为当前数据规模提前引入复杂的事件溯源或生命周期物化系统。

## 3. 方案选择

### 3.1 未采用：每天保存完整报告

该方案实现简单，但相同结果每天重复存储。首次出现查询必须扫描并解析多个
JSON 文档，长期维护成本高。

### 3.2 未采用：只保存变化事件

该方案存储最少，但恢复任意历史时点、重新生成报告、处理事件版本迁移都较复杂，
不适合当前个人项目规模。

### 3.3 采用：内容寻址快照与执行记录分离

审计内容按语义指纹去重保存。每次命令执行仍产生独立 `run_id`，运行记录引用
已有或新建的内容快照。查询所需字段进入规范化表，权威结果载荷以压缩 JSON
保存。

该模型同时满足：

- 避免重复审计结果和明细存储；
- 保留每日执行证据；
- 能快速查询结构化历史；
- 能从历史快照重新渲染 JSON、HTML 和 SBOM；
- 项目状态回退到旧状态时仍能基于最近一次执行生成正确差异。

## 4. CLI 契约

现有命令在不提供历史参数时保持无状态行为。

历史模式至少需要：

```powershell
svarog audit-project `
  --project-id my-web-app `
  --history-db C:\SvarogData\history.db `
  --environment C:\project\demo\.venv `
  --lock-file C:\project\demo\uv.lock `
  --vuln-api http://192.168.159.140:8001 `
  --json-out C:\project\demo\reports\audit.json
```

规则：

- `project_id` 可以由 `--project-id` 或环境变量 `SVAROG_PROJECT_ID` 提供，CLI 参数优先；
- `--history-db` 存在但两种项目标识都缺失时，以固定、可操作的错误退出；
- 已解析出项目标识但未提供 `--history-db` 时同样固定失败，避免用户误以为已经保存历史；
- 核心审计命令不进入交互式提示，不根据路径生成临时项目 ID，以保持计划任务、管道和
  CI 行为一致；
- `project_id` 是用户负责保持稳定的逻辑标识，不从路径推断；
- `project_id` 使用有界、可显示的安全字符集；
- `--baseline-run-id` 仅在历史模式中有效；
- 历史数据库不能与漏洞库、锁文件、报告文件或包元数据互为别名；
- 历史数据库不能位于目标虚拟环境内部；
- Windows 不进行任何历史库或项目标识自发现。

后续历史查询入口提供：

- 按项目列出最近执行；
- 根据 `run_id` 显示历史摘要；
- 根据 GHSA/CVE 查询首次出现时间和版本；
- 根据两个 `run_id` 重新生成差异报告。

具体命令名称在实施计划中以最小一致 CLI 为准，不改变上述语义契约。

## 5. 历史锚定

### 5.1 项目锚点

`project_id` 由用户显式传入，例如 `my-web-app`。绝对路径只作为该次运行的目标
信息，不作为项目身份。个人用户可以设置一次 `SVAROG_PROJECT_ID`，避免每天重复输入
参数；这仍属于用户显式配置，不改变历史身份语义。

### 5.2 运行锚点

每次命令执行生成新的 UUID `run_id`。运行可以是：

- `completed_computed`：创建了新内容快照；
- `completed_reused`：复用了已有内容快照；
- `failed`：审计未完成，只保存固定失败码；
- `interrupted`：数据库中存在已开始但未完成的运行。

失败和中断运行不参与默认基线选择。

### 5.3 基线锚点

默认基线是同一 `project_id` 上一次成功运行，而不是上一次内容快照。目标运行
永久保存明确的 `baseline_run_id`。以后新增运行不会改变已有差异报告的含义。

用户可以通过 `--baseline-run-id` 指定同一项目中的其他成功运行。跨项目基线拒绝
执行。

项目恢复为历史上的旧状态时，可以复用旧内容快照，但新运行仍与最近一次成功运行
比较，从而正确报告“回退”产生的差异。

## 6. SQLite 数据模型

### 6.1 `schema_meta`

保存结构版本、创建时间和最近迁移版本。SQLite `PRAGMA user_version` 同时作为快速
兼容性检查，但迁移不能只依赖该值。

### 6.2 `projects`

主要字段：

- `project_id TEXT PRIMARY KEY`；
- `created_at TEXT NOT NULL`；
- `last_seen_at TEXT NOT NULL`。

### 6.3 `audit_snapshots`

每个唯一审计内容一行：

- `snapshot_id TEXT PRIMARY KEY`；
- `project_id TEXT NOT NULL`；
- `composite_hash TEXT NOT NULL`；
- `project_state_hash TEXT NOT NULL`；
- `semantic_lock_hash TEXT NOT NULL`；
- `environment_hash TEXT NOT NULL`；
- `knowledge_content_hash TEXT NOT NULL`；
- `policy_hash TEXT NOT NULL`；
- `engine_hash TEXT NOT NULL`；
- `evaluation_context_hash TEXT NOT NULL`；
- `audit_status TEXT NOT NULL`；
- 有界摘要计数；
- `result_json_zlib BLOB NOT NULL`；
- `result_json_sha256 TEXT NOT NULL`；
- `result_json_size INTEGER NOT NULL`；
- `created_at TEXT NOT NULL`。

以 `(project_id, composite_hash)` 建立唯一约束。同一项目、同一复合指纹只允许一个
快照。并发插入冲突时读取已存在快照并转为复用，
不创建重复数据。

压缩载荷只保存稳定的审计结果部分。运行时间、当前路径、知识库地址和基线等易变元数据
保存在运行记录中，输出报告时重新组合。这样项目移动后既可保持逻辑项目身份，也不会在
新报告中显示旧路径。

压缩载荷读取统一通过 `get_snapshot_result(snapshot_id)` 一类的有界接口完成，接口负责
长度和 SHA-256 校验。本阶段是短生命周期 CLI，不加入 LRU 内存缓存；未来只有在长期运行
的 Dashboard 服务中经过性能测量确认重复解压成为瓶颈后，才允许增加有界缓存。

### 6.4 `audit_runs`

每次命令执行一行：

- `run_id TEXT PRIMARY KEY`；
- `project_id TEXT NOT NULL`；
- `snapshot_id TEXT NULL`；
- `baseline_run_id TEXT NULL`；
- `started_at TEXT NOT NULL`；
- `finished_at TEXT NULL`；
- `run_status TEXT NOT NULL`；
- `reused INTEGER NOT NULL`；
- `raw_lock_hash TEXT NULL`；
- `target_metadata_json TEXT NULL`；
- `database_metadata_json TEXT NULL`；
- `knowledge_metadata_hash TEXT NULL`；
- `knowledge_health_state TEXT NULL`；
- `failure_code TEXT NULL`。

不保存 Token、远程响应正文、原始异常或完整 PATH 环境变量。

### 6.5 `snapshot_packages`

结构化保存环境和锁文件包：

- `snapshot_id`；
- `evidence_layer`：`environment` 或 `lock`；
- `normalized_name`；
- `display_name`；
- `version`；
- `version_valid`；
- `source_kind`。

唯一键至少覆盖快照、证据层、规范化包名、版本和来源类型。

### 6.6 `snapshot_findings`

结构化保存确认项和无法判断项：

- `snapshot_id`；
- `evidence_layer`；
- `finding_status`；
- `advisory_key`；
- `ghsa_id`；
- `cve_id`；
- `normalized_name`；
- `package_version`；
- `severity`；
- `affected_range`；
- `fixed_version`；
- `reason_code`；
- `finding_fingerprint`。

`advisory_key` 采用稳定的公告身份，不依赖标题和严重度等可变字段；
`finding_fingerprint` 则包含版本、范围、状态和证据层，用于判断同一公告结果是否发生变化。

### 6.7 `run_diffs`

保存默认或显式生成的固定差异：

- `diff_id TEXT PRIMARY KEY`；
- `project_id TEXT NOT NULL`；
- `baseline_run_id TEXT NULL`；
- `target_run_id TEXT NOT NULL`；
- `classification TEXT NOT NULL`；
- 摘要计数；
- 压缩差异 JSON、SHA-256 和原始长度；
- `created_at TEXT NOT NULL`。

同一基线与目标在同一差异算法版本下只保存一份结果。

### 6.8 索引

至少建立：

- `audit_runs(project_id, finished_at DESC)`；
- `audit_runs(project_id, snapshot_id, finished_at)`；
- `audit_snapshots(project_state_hash, knowledge_content_hash)`；
- `snapshot_packages(snapshot_id, evidence_layer, normalized_name, version)`；
- `snapshot_findings(advisory_key, normalized_name, package_version)`；
- `snapshot_findings(snapshot_id, evidence_layer, finding_status)`；
- `run_diffs(project_id, baseline_run_id, target_run_id)`。

每天一份、每份几十个包的历史量对 SQLite 很小。首次出现查询通过索引连接运行与
快照，不解析 JSON。第二阶段不增加生命周期物化表；只有基准测试证明规范化查询成为
瓶颈后才允许增加派生缓存。

## 7. 哈希模型

所有哈希使用带域分隔符和格式版本的 SHA-256。参与哈希的对象先转换为 UTF-8
规范 JSON：键排序、固定分隔符、数组确定性排序、禁止 NaN。

### 7.1 原始锁文件哈希

`raw_lock_hash` 对安全读取到的原始字节计算。它用于发现文本变化，但不直接决定是否
重新进行漏洞匹配。

### 7.2 锁文件语义哈希

`semantic_lock_hash` 包含：

- 锁文件格式；
- 规范化包名；
- 版本原文；
- 版本有效性；
- 来源类型；
- 解析问题的稳定码及主体；
- `marker_policy=ignored`；
- `version_policy=all_distinct_versions`。

不包含绝对路径、TOML 排版、注释、条目顺序和 marker 原文。

### 7.3 环境哈希

`environment_hash` 包含规范化包名、版本、版本有效性、歧义状态和有界清点问题。
同时包含目标虚拟环境的规范 Python 版本及版本信息来源。不包含 `METADATA` 绝对路径和
目录顺序。

显式目标环境的 Python 版本从有界、安全读取的 `pyvenv.cfg` 中解析，不得错误使用运行
Svarog 的 `sys.version_info`，也不得执行目标环境解释器。仅当目标就是当前运行环境时才可
使用 `sys.version_info`。无法可靠确定时写入固定 `unknown` 并产生问题记录。

### 7.4 项目状态哈希

`project_state_hash` 由锁文件语义哈希和环境哈希组合。原始锁文件发生排版或 marker
变化而项目语义状态不变时，不重新执行漏洞匹配，但运行记录会保留原始哈希变化。

### 7.5 知识内容哈希

`knowledge_content_hash` 只使用与环境及锁文件包名并集有关的公告记录和相关数据库
问题。每条公告包含会影响匹配或报告的所有字段，包括撤销状态、版本范围、修复版本、
严重度、CVSS、来源和更新时间。

不直接对 SQLite 文件字节计算哈希，因为 WAL、vacuum、页布局和并发同步会让文件哈希
发生与漏洞语义无关的变化。

远程 API 当前没有不可变快照 ID 或 ETag，因此必须先完成稳定快照读取，再计算内容
哈希。无变化优化可以跳过后续匹配、报告构建和明细写入，但不能不安全地跳过远程数据
读取。未来服务端若提供可信快照 ID，可增加传输级快速路径。

### 7.6 知识元数据与时间状态

同步时间、同步状态、来源集合等计算独立 `knowledge_metadata_hash`。它不混入漏洞内容
哈希，以区分内容变化和仅元数据变化。

现有审计会根据当前时间和同步状态判断知识库是否健康，因此运行还保存规范化
`knowledge_health_state`。由知识库健康状态及其他会影响结论的时间条件计算
`evaluation_context_hash`。健康状态跨越阈值或发生变化时必须创建新的结果快照，不能
直接沿用旧审计状态。

### 7.7 策略和引擎哈希

`policy_hash` 至少包含 marker 策略、版本选择策略、匹配算法版本、撤销公告策略、明细
上限和知识库新鲜度阈值。

`engine_hash` 包含 Svarog 版本、结果 schema 版本和哈希格式版本。

### 7.8 复合哈希

`composite_hash` 由项目状态、知识内容、策略、引擎和评估上下文哈希组成。命中已有
快照时不重复漏洞匹配。不会影响审计结论的知识元数据和运行目标信息不改变内容快照，
但会写入新的运行记录并用于重新组合该次运行的权威 JSON。

## 8. 无变化处理

每次历史模式审计按以下顺序执行：

1. 安全打开或创建历史数据库；
2. 创建 `started` 运行记录；
3. 读取环境、锁文件和稳定漏洞快照；
4. 计算分层哈希；
5. 查询同一项目的相同 `composite_hash`；
6. 命中时复用内容快照，不执行版本范围匹配；
7. 未命中时执行审计并事务性保存新快照、包、漏洞和压缩结果；
8. 选择并固定基线；
9. 生成或复用差异；
10. 完成运行记录并输出报告。

即使完全无变化，也产生轻量 `audit_runs` 行。终端和 JSON 明确显示：

- 本次 `run_id`；
- 复用的 `snapshot_id`；
- `reused=true`；
- 固定 `baseline_run_id`；
- 无语义变化原因。

## 9. 锁文件语义差异

比较单位是规范化包集合，不是文本行。

锁文件变化包括：

- `package_added`；
- `package_removed`；
- `version_set_changed`；
- `source_kind_changed`；
- `version_validity_changed`。

环境变化独立记录：

- 安装包新增或删除；
- 实际安装版本集合改变；
- 歧义状态或版本有效性改变。

同一包在锁文件中出现多个版本时按版本集合比较，不进行任意的一对一配对。

因为 marker 被明确忽略，所以 marker、平台、extra 和 group 的文本变化不属于语义依赖
变化。若原始哈希变化而锁文件语义哈希相同，差异中记录
`non_semantic_lock_change=true`，并继续提醒适用性未经验证。

## 10. 差异分类

报告级分类：

- `initial`：没有基线；
- `no_change`：内容快照相同；
- `project_only`：项目状态变化，知识内容未变；
- `knowledge_only`：知识内容变化，项目状态未变；
- `mixed`：项目与知识内容均变化；
- `evaluation_context_changed`：知识新鲜度等时间状态变化；
- `incompatible`：策略、哈希格式或引擎语义版本不可比较。

漏洞级变化：

- `introduced`：目标存在、基线不存在；
- `resolved`：基线存在、目标不存在；
- `persisting`：稳定身份和内容均保持；
- `changed`：同一公告身份仍存在，但版本、状态、严重度、范围、修复版本或适用性变化。

不会影响审计结论的知识元数据变化合并到 `no_change`，并在详情中设置
`knowledge_metadata_changed=true` 及固定说明。若同步状态或新鲜度变化影响审计状态或
警告，则使用 `evaluation_context_changed`。

当只有项目或知识库一侧变化时，漏洞变化可归因到该侧。当两侧都变化时，只标记
`mixed`，不伪造精确因果。精确反事实归因需要保存并交叉运行旧项目/新知识和新项目/旧
知识两个额外组合，不属于本阶段。

JSON 是差异报告的权威输出；如实现 HTML，则 HTML 只渲染同一 JSON 语义，不重新计算
差异。

## 11. CycloneDX SBOM

### 11.1 版本与格式

本阶段输出 CycloneDX 1.7 JSON，建议文件名为 `*.cdx.json`。输出至少包含：

- `$schema`；
- `bomFormat`；
- `specVersion`；
- 唯一 `serialNumber`；
- `version`；
- `metadata`；
- `components`；
- `compositions`。

CycloneDX 官方规范说明组件和依赖关系使用 `bom-ref` 关联；未出现在依赖图中的组件应
被视为关系未知，而不是没有依赖。composition 用 `aggregate=unknown` 表达本阶段的依赖
关系完整性。

### 11.2 组件生成

- 软件包组件类型为 `library`；
- registry 包使用 `pkg:pypi/<normalized-name>@<encoded-version>`；
- 可安全构造时以 PURL 作为 `bom-ref`；
- Git、URL、path、editable、workspace 等来源无法可靠声称为 PyPI 包时，不伪造 PyPI
  PURL，改用确定性 `urn:svarog:component:sha256:<digest>`；
- 备用摘要只使用规范化包名、版本、来源类型，以及解析器未来可能安全保留的稳定非本地
  来源身份；绝不包含绝对路径、用户名、主机名、环境目录或时间戳；
- 在当前只保留来源类型的模型中，只保证相同规范输入产生相同 `bom-ref`，不声称仅靠
  `git`/`url` 类型即可获得全球组件身份；
- 环境和锁文件中名称、版本、来源身份相同的组件合并；
- 使用有命名空间的 properties 表达环境证据、锁文件证据、版本有效性、来源类型及
  `dependency-graph-status=not_available`；
- 多版本包保留多个不同组件和不同 `bom-ref`；
- 输出顺序确定，方便审阅和测试；
- 每次实际导出生成新的 BOM serial number，serial number 不参与审计无变化判定。

### 11.3 依赖图边界

本阶段不输出空的或推测的 `dependencies` 数组。完整父子树要求正确处理：

- marker；
- Python 和平台分辨率；
- extra 与 dependency group；
- workspace；
- 同名多版本和冲突集合；
- Git、path 和 editable 身份；
- 环和共享子图。

这与当前“忽略 marker、只读取锁文件、不执行包管理工具”的策略冲突。uv 官方还明确
说明 `uv.lock` 不是稳定公共格式，复杂图查询应优先使用 workspace metadata；该元数据
仍要求从明确根节点结合 marker 和冲突语义遍历。

未来图解析使用三个可信状态：

- `not_available`；
- `partial`；
- `complete`。

只有所有选定根节点和所有边都能唯一解析且通过一致性验证时，才能声明 `complete`。

### 11.4 规范验证

运行时不依赖网络。测试固定使用经过校验的 CycloneDX 1.7 官方 JSON Schema 副本验证
样例输出。Schema 文件记录来源版本和 SHA-256；开发期校验依赖只进入 dev 依赖，不增加
最终 SBOM 导出的运行时网络依赖。

## 12. 安全与健壮性

- 历史数据库路径显式提供；
- 拒绝符号链接、非普通文件和已存在的多硬链接目标；
- 创建前固定并复查父目录，降低路径切换风险；
- 历史库不能覆盖漏洞库、锁文件、报告或虚拟环境元数据；
- 所有 SQL 值使用参数绑定，表名和迁移 SQL 只来自内部常量；
- 启用外键、busy timeout 和明确事务；
- 单写事务使用 `BEGIN IMMEDIATE`，尽快结束；耗时的快照读取、哈希和漏洞匹配均在写
  事务外完成；
- 保存阶段获得写锁后必须再次查询 `(project_id, composite_hash)`：若已存在则无缝转为
  `reused=true`；若不存在才插入；
- 唯一约束仍作为最终并发保险。捕获 `sqlite3.IntegrityError` 后必须回滚并重新查询完全
  匹配的快照，只有确实存在时才能转为复用，其他约束错误必须固定失败，不能伪装成并发
  命中；
- 新快照、明细和运行完成状态在同一事务中提交；
- 进程崩溃后保留的 `started` 记录在下次打开时可识别为 `interrupted`；
- 压缩载荷保存未压缩长度和 SHA-256，读取时限制最大长度并验证摘要；
- 损坏、版本过新或迁移失败时固定失败，不自动删除历史库；
- 不在历史库中保存 Token、HTTP Authorization、响应正文或原始异常；
- POSIX 创建文件后尽力限制为当前用户读写；Windows 使用当前用户目录和系统 ACL，
  不尝试以不可靠的标准库逻辑重写 ACL；
- 报告生成继续执行现有输出路径和别名安全检查。

## 13. 测试策略

继续采用“冒烟测试早于编码”：

1. 先为数据库创建、重开和版本拒绝写测试；
2. 再为首次运行、新快照、无变化复用和失败记录写测试；
3. 为锁文件重排、注释变化、marker 变化和真实版本变化写语义哈希测试；
4. 为项目变化、知识变化、混合变化和策略不兼容写差异测试；
5. 为项目状态回退但基线仍指向最近运行写锚定测试；
6. 为并发唯一约束、事务回滚、损坏压缩载荷和路径别名写健壮性测试；
7. 使用现有真实 `poetry.lock`、`uv.lock` 固件验证跨格式行为；
8. 使用固定 CycloneDX 1.7 Schema 离线验证 SBOM，并记录官方来源 URL 与文件 SHA-256；
9. 在 Windows 和 Linux 路径样例上验证哈希不包含平台绝对路径；
10. 使用足够大的合成历史验证查询计划命中索引，不把易受机器影响的绝对毫秒数作为
    单元测试断言。

## 14. 实施顺序与检查点

### 14.1 历史存储

- 数据库安全打开与创建；
- schema v1 与迁移框架；
- 项目、运行、快照、包和漏洞表；
- 压缩权威结果；
- 基础历史查询。

检查点：现有无状态审计测试不回归，历史存储测试通过。

### 14.2 哈希与复用

- 规范 JSON 编码；
- 分层哈希；
- 无变化快照复用；
- 每次执行记录；
- 并发去重和崩溃状态。

检查点：同一输入连续执行只产生一个内容快照和两个运行记录。

### 14.3 差异报告

- 自动及显式基线；
- 包、环境和漏洞差异；
- 报告级变化分类；
- JSON 权威输出和可选单文件 HTML 壳。

检查点：项目回退、知识库撤销公告、混合变化和不可比较策略均有固定测试。

### 14.4 SBOM

- CycloneDX 1.7 components-only 映射；
- PURL 与确定性备用 `bom-ref`；
- composition unknown；
- 原子文件写入；
- 离线 schema 验证。

检查点：不得出现虚假的完整依赖图声明。

## 15. 冻结决策

以下决策经用户确认，在实施期间不得无审批扩大：

1. 采用方案 C 混合存储；
2. 使用显式 `--project-id`；
3. 无变化时保存轻量运行记录并复用内容快照；
4. 默认基线是同项目上一次成功运行，同时允许显式基线；
5. 第二阶段 SBOM 只保证 components 正确，dependencies 暂缓；
6. SQLite 使用规范化查询表和压缩权威结果载荷；
7. 不因当前小数据量提前增加复杂生命周期物化表；
8. 不牺牲正确性来跳过必要的漏洞快照读取。
9. 不在核心审计命令中加入交互式路径指纹项目 ID；使用 CLI 参数或
   `SVAROG_PROJECT_ID`；
10. 目标 Python 版本来自被审计环境，不得用 Svarog 运行时版本替代；
11. 快照读取先封装校验接口，CLI 阶段不增加 LRU；
12. 无影响的知识元数据变化并入 `no_change`；
13. 并发保存使用写锁后二次查询和唯一约束兜底。

## 16. 参考资料

- CycloneDX Specification Overview：
  https://cyclonedx.org/specification/overview/
- CycloneDX Software Dependencies：
  https://cyclonedx.org/use-cases/software-dependencies/
- CycloneDX Dependency Relationship Compositions：
  https://cyclonedx.org/use-cases/compositions-dependencies/
- CycloneDX 1.7 Software Components：
  https://cyclonedx.org/use-cases/software-components/
- uv Workspace Metadata：
  https://docs.astral.sh/uv/reference/internals/metadata/
- uv Project Layout and Lockfile：
  https://docs.astral.sh/uv/concepts/projects/layout/
