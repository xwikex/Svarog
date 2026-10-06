@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [错误] 尚未安装 Svarog，请先双击 install.bat。
  pause
  exit /b 1
)

echo [Svarog] 正在启动本地工作台...
echo 浏览器地址：http://127.0.0.1:8765/
echo 请保持此窗口打开。停止服务时按 Ctrl+C。
echo.

".venv\Scripts\python.exe" -m svarog ui --host 127.0.0.1 --port 8765 --workspace "."
if errorlevel 1 (
  echo.
  echo [错误] 工作台未能启动。请检查端口是否被占用，或重新运行 install.bat。
  pause
  exit /b 1
)

echo [Svarog] 工作台已停止。
pause
exit /b 0
