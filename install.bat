@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

echo [Svarog] 正在检查 Python 3.11 或更高版本...
set "PY_CMD="

where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 set "PY_CMD=py -3"
)

if not defined PY_CMD (
  where python >nul 2>&1
  if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
  )
)

if not defined PY_CMD (
  echo [错误] 未找到 Python 3.11 或更高版本。
  echo 请安装新版 Python，并勾选 Add Python to PATH。
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [Svarog] 正在创建独立运行环境...
  %PY_CMD% -m venv .venv
  if errorlevel 1 (
    echo [错误] 创建虚拟环境失败。
    pause
    exit /b 1
  )
)

".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if errorlevel 1 (
  echo [错误] 现有 .venv 的 Python 版本低于 3.11。
  echo 请删除 .venv 文件夹后重新运行 install.bat。
  pause
  exit /b 1
)

echo [Svarog] 正在安装运行依赖，请保持网络连接...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check .
if errorlevel 1 (
  echo [错误] 安装失败。请检查网络连接和上方错误信息。
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -c "import svarog" >nul 2>&1
if errorlevel 1 (
  echo [错误] 安装后的导入检查失败。
  pause
  exit /b 1
)

echo.
echo [完成] Svarog 已安装。现在可以双击 start-ui.bat。
pause
exit /b 0
