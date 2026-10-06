from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_project_metadata_identifies_author_and_mit_license() -> None:
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    license_text = _read("LICENSE")

    assert project["authors"] == [{"name": "xwikex"}]
    assert project["version"] == "0.2.0"
    assert project["license"] == {"file": "LICENSE"}
    assert "License :: OSI Approved :: MIT License" in project["classifiers"]
    assert {"security", "log-analysis", "vulnerability-audit", "sbom"}.issubset(
        project["keywords"]
    )
    assert "MIT License" in license_text
    assert "Copyright (c) 2026 xwikex" in license_text


def test_readme_leads_with_a_five_minute_windows_ui_path() -> None:
    readme = _read("README.md")

    assert readme.index("## 5 分钟打开 Web UI") < readme.index("## 本地可视化工作台")
    for phrase in (
        "Python 3.11", "install.bat", "start-ui.bat", "http://127.0.0.1:8765/",
        "Ctrl+C", "PowerShell",
    ):
        assert phrase in readme


def test_security_guidance_protects_real_user_data() -> None:
    guidance = _read("SECURITY.md")

    for phrase in ("Token", "日志", "SQLite", "业务数据", "公开 Issue"):
        assert phrase in guidance


def test_gitignore_excludes_local_runtime_and_build_data() -> None:
    ignored = set(_read(".gitignore").splitlines())

    for pattern in (
        ".venv/", ".svarog/", ".env", "*.sqlite3", "*.db", "report*.json",
        "__pycache__/", ".pytest_cache/", "*.egg-info/", "build/", "dist/",
    ):
        assert pattern in ignored


def test_install_launcher_is_location_independent_and_fail_fast() -> None:
    launcher = _read("install.bat")
    lowered = launcher.lower()

    assert 'cd /d "%~dp0"' in launcher
    assert "py -3" in launcher and "python" in launcher
    assert "sys.version_info >= (3, 11)" in launcher
    assert "-m venv .venv" in launcher
    assert '".venv\\Scripts\\python.exe" -m pip install --disable-pip-version-check .' in launcher
    assert lowered.count("if errorlevel 1") >= 4
    assert "--index-url" not in lowered
    assert "http://" not in lowered and "https://" not in lowered


def test_ui_launcher_is_loopback_only_and_never_opens_browser() -> None:
    launcher = _read("start-ui.bat")
    lowered = launcher.lower()

    assert 'cd /d "%~dp0"' in launcher
    assert 'if not exist ".venv\\Scripts\\python.exe"' in launcher
    assert (
        '".venv\\Scripts\\python.exe" -m svarog ui --host 127.0.0.1 --port 8765 '
        '--workspace "."'
    ) in launcher
    assert "--case-db" not in launcher
    assert "http://127.0.0.1:8765/" in launcher
    assert "0.0.0.0" not in launcher
    assert "--open-browser" not in lowered
    assert "start http" not in lowered
    assert "start-process" not in lowered
