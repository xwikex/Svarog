# Svarog GitHub 干净发布快照设计

## 1. 目标

在 `C:\Users\18201\Desktop\project\release\Svarog` 生成一个不包含开发现场和本机数据的干净项目目录。该目录可以直接初始化为 Git 仓库并上传 GitHub，也可以由普通 Windows 用户下载后在 5 分钟内完成安装并打开本地 Web UI。

项目作者统一标记为 `xwikex`，采用 MIT License。

## 2. 发布目录内容

保留：

- `src/`：Svarog 源码和打包所需前端资源；
- `samples/`：可直接用于 UI 验证的示例数据；
- `tests/`：公开供贡献者和发布者验证项目；
- 面向用户的 `docs/` 文档；
- `README.md`、`pyproject.toml`、`Dockerfile`、`.gitignore`、`.dockerignore`、`.gitattributes`；
- `LICENSE`、`SECURITY.md`、`install.bat` 和 `start-ui.bat`。

不复制：

- `.git`、`.worktrees`、`.venv`、IDE 配置、缓存、构建目录；
- SQLite 数据库、日志、报告、Token、环境变量文件；
- `docs/superpowers/` 内部设计和实施过程记录；
- 临时测试目录及 Python 字节码。

发布目录不包含自己的嵌套 `.git`，用户可直接在其中执行 `git init`，或通过 GitHub 网页上传全部文件。

## 3. 五分钟安装体验

README 第一屏使用普通用户语言提供两种等价方式：

1. 双击 `install.bat` 创建 `.venv` 并安装 Svarog；
2. 双击 `start-ui.bat` 启动工作台；
3. 浏览器打开终端显示的 `http://127.0.0.1:8765/`；
4. 保持启动窗口打开，按 `Ctrl+C` 停止。

同时保留可复制的 PowerShell 命令，方便虚拟机、远程桌面和故障排查。安装脚本只安装运行依赖，不安装测试依赖；开发者可另行执行 `python -m pip install -e ".[dev]"`。

批处理脚本必须：

- 从脚本自身所在目录工作，不能依赖用户当前目录；
- 优先使用 Windows `py -3`，缺失时回退到 `python`；
- 明确验证 Python 3.11 或更高版本；
- 每一步失败都返回非零退出码并显示可理解的中文提示；
- `start-ui.bat` 只绑定 `127.0.0.1`，不自动打开浏览器，不使用 `0.0.0.0`。

## 4. GitHub 元数据

- `pyproject.toml` 增加作者 `xwikex`、MIT 许可证声明和项目关键词；
- `LICENSE` 使用标准 MIT 文本，版权行为 `Copyright (c) 2026 xwikex`；
- `SECURITY.md` 说明安全问题不要公开附带真实 Token、日志或业务数据；
- README 说明用途、安全边界、功能、快速启动、验证、Linux 漏洞 API、目录结构和贡献入口；
- 不写入尚未确定的 GitHub 用户名或仓库 URL，避免生成失效链接。

## 5. 安全与隐私检查

输出前按允许清单复制，不采用“复制全部后再尽量删除”的方式。输出后检查：

- 不存在 `.git`、`.env`、SQLite、报告、缓存和临时目录；
- 不出现常见私钥头、硬编码 Token、Authorization Bearer 或当前 Windows 用户绝对路径；
- 前端资源、功能模块和用户文档均包含在发布目录；
- `git status` 不受输出过程影响，源工作树保持干净。

静态扫描只能发现常见模式，不能替代发布者对样例与文档的人工复核。

## 6. 验证标准

1. 从发布目录构建 Wheel 成功，Wheel 包含 Web UI 静态资源和可信功能模块。
2. 在隔离目录安装 Wheel 后，`python -m svarog --help` 和 `ui` 参数解析成功。
3. 批处理脚本内容测试覆盖解释器检测、虚拟环境创建、安装、回环启动和错误退出。
4. 完整自动化测试零失败；Windows/POSIX 平台差异跳过项单独记录。
5. 不在当前物理机启动 HTTP 服务或打开浏览器；实际页面由用户在 Windows 虚拟机验收。

## 7. 交付结果

最终交付目录：

```text
C:\Users\18201\Desktop\project\release\Svarog
```

该目录是独立干净快照。后续源分支继续开发时，发布目录不会自动更新，需要重新生成并验证。
