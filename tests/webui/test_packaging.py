from __future__ import annotations

import importlib.resources
import tomllib
from pathlib import Path

from svarog.features.registry import FeatureRegistry


ROOT = Path(__file__).resolve().parents[2]


def test_assets_are_package_resources() -> None:
    assets = importlib.resources.files("svarog.webui").joinpath("assets")
    assert assets.joinpath("index.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert ":root" in assets.joinpath("app.css").read_text(encoding="utf-8")
    assert "function" in assets.joinpath("app.js").read_text(encoding="utf-8")
    for name in ("components/table.js", "pages/history.js", "pages/diff.js",
                 "pages/sbom.js", "pages/settings.js"):
        assert assets.joinpath(name).read_text(encoding="utf-8").strip()


def test_pyproject_packages_web_assets_and_feature_subpackages() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["setuptools"]["package-data"]["svarog.webui"] == [
        "assets/*.html", "assets/*.css", "assets/*.js", "assets/**/*.js",
    ]
    assert config["tool"]["setuptools"]["package-data"]["svarog.sbom"] == [
        "schemas/cyclonedx/1.7/*.json", "schemas/cyclonedx/1.7/SHA256SUMS",
    ]
    assert config["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    assert FeatureRegistry.discover().get("file-hash") is not None


def test_documentation_covers_windows_vm_and_module_extension() -> None:
    guide = (ROOT / "docs" / "UI使用说明.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for phrase in (
        "Windows 虚拟机", "python -m svarog ui", "127.0.0.1", "Ctrl+C",
        "未自动执行处置", "src/svarog/features", "manifest.py", "handler.py",
        "file-hash", "0.0.0.0",
    ):
        assert phrase in guide
    assert "docs/UI使用说明.md" in readme
    assert "可信功能模块" in readme
