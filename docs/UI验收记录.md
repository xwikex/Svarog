# Svarog 本地工作台验收记录

## 1. 验收范围

- 验收日期：2026-09-10
- 验收环境：Windows，Python 3.13.7
- 验收对象：本地 Web 工作台、SOP 案件流程、可信功能模块自动发现、Wheel 打包
- 安全边界：仅允许回环地址；Svarog 核心流程负责分析、展示和人工复核，不自动执行处置
- 本次未在物理机启动 HTTP 服务，也未打开浏览器。真实视觉与交互验收留给 Windows 虚拟机完成。

## 2. 自动化测试结果

### 工作台与 SOP 定向测试

执行：

```powershell
python -m pytest -p no:cacheprovider -o addopts='' tests/webui tests/sop -v --basetemp=.test-tmp-targeted
```

结果：`357 passed, 4 skipped`。4 项跳过均来自当前 Windows 环境无法创建符号链接或无法验证 POSIX 文件权限，不计为通过。

### 完整回归测试

执行：

```powershell
python -m pytest -p no:cacheprovider -o addopts='' -q -rs --basetemp=.test-tmp-full
```

最终复核后结果：`767 passed, 28 skipped`，没有失败。

跳过项类别：

- Windows 无法创建测试所需的文件或目录符号链接；
- 仅 POSIX 支持的 FIFO、`O_NOFOLLOW`、目录 `fsync` 和目录替换语义；
- Windows 不强制执行 POSIX mode bits；
- 依赖真实 POSIX 权限语义的测试。

## 3. 静态安全检查

检查范围：`src/svarog/webui` 与 `src/svarog/features`。

- 未发现 `innerHTML`、`insertAdjacentHTML`、`eval(`、`exec(` 或 `shell=True`；
- 未发现绑定 `0.0.0.0` 的实现；
- URL 命中仅包括本地服务显示地址和服务器生成的固定 MITRE ATT&CK 技术链接；
- HTML、CSS、JavaScript 不加载外部字体、脚本、样式或图片；
- `git diff --check` 未发现空白错误或冲突标记；
- 功能模块目录拒绝直接符号链接或 Windows junction；模块导入失败只返回稳定错误码，不返回异常内容；
- 功能输入只接受清单声明字段；工作区路径统一进行边界校验；
- 功能输出采用固定结构、固定文本表格类型、2 MiB 总大小限制，并强制 `actions_executed=false`；
- 内置文件哈希功能限制为 512 MiB，并在读取过程中再次执行累计大小限制。

可信功能模块仍是与工作台进程同权限运行的 Python 代码。权限声明和 `actions_executed=false` 是显示及结果契约，不构成操作系统沙箱，也无法约束恶意模块已经执行的副作用；因此第一版的安全边界是“仅运行经过人工审查的自有模块”。

## 4. UI 静态验收

已确认：

- 浅色主题使用统一语义色变量和系统字体；
- 页面包含跳转到主内容的链接、可见焦点环、表单标签、帮助文本和 ARIA 状态区；
- 按钮、输入框、导航项和结果展开控件的最小高度为 44px；
- 899px 和 759px 断点分别处理导航与单列布局，表格容器允许横向滚动；
- 页面禁止横向整体溢出；
- `prefers-reduced-motion` 会关闭动画与平滑滚动；
- 状态同时显示文字，不只依赖颜色；提交期间按钮会禁用并提供状态反馈；
- 主要对比度：正文/白色 `14.70:1`，次要文字/白色 `5.54:1`，白色/主按钮 `5.51:1`，白色/危险色 `6.57:1`。

未在物理机浏览器进行像素级或真实辅助技术验收。虚拟机仍需检查 375、768、1024、1440 像素宽度、键盘 Tab 顺序、缩放到 200%、高对比度模式以及长表格实际滚动效果。

## 5. 可扩展功能验收

- `svarog.features` 下的直接子包可通过 `manifest.py` 与 `handler.py` 自动发现；
- 新模块不需要修改核心路由、HTML 或 JavaScript；
- 前端根据声明式字段动态生成导航、表单、结果表格和下载入口；
- 未知字段、重复功能 ID、非法清单、异常处理器和非法结果均失败关闭；
- 当前仅支持随源码维护的可信 Python 模块，不支持第三方目录、入口点、插件市场、自定义 HTML 或自定义 JavaScript；
- `file-hash` 作为内置示例模块已通过发现、运行、结果下载和 Wheel 安装后发现测试。

## 6. Wheel 验收

执行：

```powershell
python -m pip wheel --no-cache-dir --no-deps --no-build-isolation . --wheel-dir <临时目录>
python -m zipfile -l <wheel文件>
python -m pip install --no-cache-dir --no-deps --target <隔离目录> <wheel文件>
```

结果：成功构建 `svarog_security-0.1.0-py3-none-any.whl`，最终构建记录中的 SHA-256 为 `94a91c40b2323a053666cc1d01ce398ec2a5d59d9a3e7df56e0ec822efce38e8`。Wheel 包含全部 `svarog.webui` Python 模块、三项前端资源、功能模块框架和 `file_hash` 示例；自动检查的 6 项必需条目全部存在。

隔离安装后仅执行导入和命令解析，结果为：

```text
ISOLATED_IMPORT_OK command=ui feature=file-hash
```

此过程没有调用 `serve`，没有绑定端口，也没有打开浏览器。

## 7. 代码审查结果

独立审查未发现 Critical 问题，也未发现 DOM 注入、异常详情泄漏、明显输入/结果校验绕过或打包安全问题。已处理审查中的可执行建议：

- 在界面、README 和使用说明中明确：可信模块与工作台同权限运行，权限标签不是系统沙箱；
- 模块发现除顶层目录外，还检查包根和包内子项的符号链接、Windows junction 及规范化边界；
- 文件哈希在打开后使用文件描述符身份再次核对目标，并保留读取过程大小限制；
- 将文档中的“拒绝所有符号链接”修正为实际策略：拒绝绝对路径、父级逃逸、工作区逃逸链接和功能源码链接。

检查与导入之间仍无法抵御已经拥有本机源码写权限的恶意进程并发替换。对于当前个人、本机、仅加载人工审查自有模块的范围，这不作为独立安全边界；若未来支持第三方插件，必须改用受限子进程、签名白名单或操作系统沙箱，而不能沿用本阶段的信任模型。

## 8. 虚拟机人工验收清单

按照《UI使用说明》在 Windows 虚拟机中完成：

1. 启动后手动打开打印出的 `http://127.0.0.1:8765/`；
2. 逐页验证概览、新建调查、案件历史、Web 日志分析、Python 环境审计、项目审计和 Doctor；
3. 验证 SOP 的创建、查询、打开、人工复核及 JSON 下载；
4. 验证 `file-hash` 自动出现在“扩展功能”，并可计算工作区文件 SHA-256；
5. 检查窄屏、宽屏、键盘、200% 缩放和 Windows 高对比度显示；
6. 使用实际 Linux 漏洞知识库 API 验证网络审计。

未使用用户实际模型服务，因此不能据此声明真实 Agent 模型兼容性；该项需要用户在虚拟机配置真实服务后单独确认。
