# Svarog 本地可信功能模块设计

## 目标

让 Svarog 在不修改核心路由、主导航和通用结果渲染器的情况下，自动发现由项目所有者编写的本地可信功能模块。新增模块只需在 `src/svarog/features/` 下增加一个 Python 包；工作台启动后，该功能自动出现在 Web 菜单中，并可通过统一表单执行。

本设计只覆盖随 Svarog 源码一起审查、打包和部署的可信模块。第一版不加载外部目录、Python entry point、在线市场或任意第三方 HTML/JavaScript。

## 方案选择

采用“自动发现 + 声明式界面”。每个模块提供结构化清单和 Python 处理函数，核心工作台负责生成菜单、输入表单、请求路由和结果展示。

不采用以下方案：

- 模块自带任意 HTML/JavaScript：自由度高，但会扩大 XSS、样式冲突和前端兼容风险。
- 手动维护中央功能列表：实现简单，但新增模块仍需修改核心文件，不满足扩展目标。

## 目录与模块边界

```text
src/svarog/features/
├── __init__.py
└── example_feature/
    ├── __init__.py
    ├── manifest.py
    ├── handler.py
    └── tests/
```

生产模块必须位于 `svarog.features` 包中。发现器只枚举该包的直接子包，并按功能清单中的顺序和功能 ID 进行稳定排序。以下来源不会被扫描：

- 当前工作目录中的同名目录；
- 用户主目录或环境变量指定的目录；
- 已安装包的 entry point；
- 网络下载内容；
- 符号链接指向的包外路径。

发现器不会把导入异常扩散为整个 UI 启动失败。失败模块会出现在诊断信息中，但不会注册菜单或执行路由。

## Python 接口

核心提供不可变的数据类型：

```python
@dataclass(frozen=True, slots=True)
class FeatureField:
    name: str
    label: str
    kind: Literal["text", "integer", "boolean", "choice", "workspace_file", "workspace_directory"]
    required: bool
    help_text: str
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

@dataclass(frozen=True, slots=True)
class FeatureManifest:
    feature_id: str
    title: str
    description: str
    order: int
    fields: tuple[FeatureField, ...]
    permissions: frozenset[Literal["workspace_read", "network", "database", "token"]]

@dataclass(frozen=True, slots=True)
class FeatureContext:
    workspace: Path
    resolve_workspace_path: Callable[..., Path]

class FeatureHandler(Protocol):
    def __call__(self, context: FeatureContext, values: Mapping[str, object]) -> Mapping[str, object]: ...
```

每个模块的 `manifest.py` 导出且只导出一个 `FEATURE_MANIFEST`，`handler.py` 导出 `run_feature`。功能 ID 必须匹配 `[a-z][a-z0-9-]{0,63}`，并且在一次启动中唯一。

模块处理函数返回统一结果：

```json
{
  "status": "completed",
  "summary": [{"key": "items", "label": "项目", "value": 3}],
  "warnings": [],
  "tables": [{
    "id": "results",
    "title": "结果",
    "columns": [{"key": "name", "label": "名称", "type": "text"}],
    "rows": [{"name": "示例"}]
  }],
  "actions_executed": false
}
```

第一版仅允许 `text` 类型的结果列。链接、HTML、Markdown、图片、命令按钮和自动处置动作不属于模块接口。核心会校验结果大小、字段类型、唯一键和 `actions_executed is False`，校验失败时不缓存也不展示部分结果。

## 自动发现与注册

新增 `FeatureRegistry` 负责：

1. 使用 `pkgutil.iter_modules(svarog.features.__path__)` 枚举直接子包；
2. 导入固定的 `<包>.manifest` 和 `<包>.handler`；
3. 验证清单、字段名、权限声明和处理函数；
4. 拒绝重复功能 ID；
5. 生成不可变的已启用模块快照和经过脱敏的加载错误列表。

注册表在 `WorkbenchApplication` 创建时构建一次，运行期间不热重载。添加或修改模块后，用户重启 Svarog UI 即可看到变化。这避免请求期间模块集合变化导致的竞态条件。

当前硬编码功能继续使用原有路由和页面。可信模块作为新的“扩展功能”区域加入，不在本阶段迁移现有功能，从而降低回归风险。

## HTTP 与数据流

新增两个固定核心路由：

- `GET /api/features`：返回已启用模块的公开清单以及不含绝对路径和异常详情的禁用模块摘要；
- `POST /api/features/<feature_id>/run`：执行对应模块。

执行流程：

1. 复用现有 Host、Origin、CSRF、Content-Type 和请求大小检查；
2. 路由只接受注册表中存在的功能 ID；
3. 核心根据清单拒绝未知字段并验证类型和范围；
4. `workspace_file` 和 `workspace_directory` 复用现有工作区路径解析与符号链接逃逸防护；
5. 核心构造最小 `FeatureContext` 后调用处理函数；
6. 核心把结果转换为 `svarog.workbench.feature-result.v1` 固定展示结构；
7. 合法结果进入现有有界内存下载缓存和最近运行摘要。

模块不能获得 HTTP 请求对象、CSRF Token、漏洞 API Token或 `WorkbenchApplication` 实例。声明权限只用于提示和拒绝未声明的输入能力，不作为操作系统级沙箱。因为模块是可信 Python 代码，代码审查仍是安全边界。

## 声明式 Web 界面

工作台加载时请求 `/api/features`，使用 `document.createElement` 和 `textContent` 生成：

- “扩展功能”导航组；
- 每个模块的标题、说明和权限提示；
- 与 `FeatureField` 对应的有标签表单；
- 统一的加载、字段错误、全局错误和下载区域；
- 通用摘要卡片、警告列表和可横向滚动表格。

前端不执行服务端返回的 HTML、脚本、事件属性、CSS、URL 或 Markdown。功能 ID 只用于经过白名单校验的 DOM 数据属性和 API 路径。模块结果继续使用 `textContent` 渲染。

如果清单版本或结果 Schema 不受支持，页面显示明确的“不支持的功能结构”，不会尝试猜测或降级执行。单个模块失败不会隐藏其他模块。

## 错误处理

- 导入失败：模块禁用，诊断只显示功能包名和稳定错误码，不返回 traceback、绝对路径或异常文本。
- 清单无效或 ID 冲突：相关模块禁用，不采用“后加载覆盖前加载”。
- 输入无效：返回 `400 invalid_feature_input` 和字段级错误。
- 未注册功能：返回 `404 feature_not_found`。
- 模块执行异常：返回 `500 feature_failed`，日志和响应均不包含用户数据、Token 或原始异常文本。
- 结果结构无效：返回 `500 invalid_feature_result_schema`，不创建下载记录。
- 功能超时：第一版不在线程中强制终止 Python 代码；耗时功能必须由模块自身设置有界 I/O 超时。界面明确显示处理中状态。

## 并发与状态

`FeatureRegistry` 在初始化后只读，可安全由请求线程共享。模块处理函数不得依赖可变模块级状态；需要持久化时必须使用模块自己的 SQLite 表或现有领域服务，并自行保证事务边界。

核心继续限制并发请求数和请求体大小。结果下载使用现有有界 `RunCache`，不会把上传文件内容、Token 或原始请求保存到浏览器存储。

## 测试策略

测试使用测试包和注入式发现器，不向生产目录放置虚假功能。覆盖：

- 合法模块自动发现、稳定排序及菜单生成；
- 重复 ID、非法 ID、未知字段类型、无效权限和导入失败的隔离；
- 未注册路由、错误方法、CSRF、Host、Origin 和请求大小限制；
- 工作区路径逃逸与符号链接逃逸；
- 输入字段类型、范围、选项和未知字段拒绝；
- 模块异常脱敏、无效结果拒绝、超大结果拒绝；
- `actions_executed=True` 必须失败；
- 前端不使用 `innerHTML`、动态脚本、外部资源或模块提供的 URL；
- 添加测试模块后，无需修改核心路由和导航源码即可出现在功能清单并成功运行；
- 现有工作台和领域测试全部保持通过。

不在物理机启动服务或打开浏览器。协议和前端行为继续通过应用层测试、socketpair 测试和无浏览器 JavaScript 行为测试验证，最终视觉交互由用户在 Windows 虚拟机中验收。

## 扩展模块的使用步骤

未来增加功能时，开发者只需：

1. 创建 `src/svarog/features/<package_name>/`；
2. 编写 `manifest.py` 和 `handler.py`；
3. 添加该模块的单元测试；
4. 重新安装或重新打包 Svarog；
5. 重启 `svarog ui`。

不需要修改 `application.py`、`index.html`、`app.js` 的路由或导航列表。若新功能超出声明式字段和文本表格能力，应先扩展受控的核心组件 Schema，而不是让单个模块注入任意前端代码。

## 验收标准

- 测试模块仅通过新增模块文件即可出现在 `/api/features` 和 Web 导航中；
- 测试模块可接收经过核心校验的输入并返回固定结果；
- 删除或损坏一个测试模块不会影响 UI 及其他模块；
- 所有模块结果都明确为只读分析，不能执行或宣称已执行处置；
- 新架构不改变当前七个功能的既有路由、响应兼容字段和用户操作；
- 完整测试套件零失败，平台相关跳过项单独记录；
- 物理机验收过程不绑定监听端口、不启动 UI、不打开浏览器。
