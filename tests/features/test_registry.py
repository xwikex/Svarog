from __future__ import annotations

from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from svarog.features.contracts import FeatureField, FeatureManifest
from svarog.features.registry import FeatureRegistry


def _manifest(feature_id: str, *, order: int = 10) -> FeatureManifest:
    return FeatureManifest(
        feature_id=feature_id,
        title=f"Feature {feature_id}",
        description="只读测试功能",
        order=order,
        fields=(FeatureField(
            name="target", label="目标", kind="workspace_file", required=True,
            help_text="工作区内文件",
        ),),
        permissions=frozenset({"workspace_read"}),
    )


def test_manifest_rejects_unsafe_or_ambiguous_fields() -> None:
    with pytest.raises(ValueError, match="feature_id"):
        _manifest("../escape")
    with pytest.raises(ValueError, match="字段名"):
        FeatureManifest(
            feature_id="duplicate", title="Duplicate", description="test", order=1,
            fields=(
                FeatureField("target", "目标", "text", True, "说明"),
                FeatureField("target", "目标 2", "text", False, "说明"),
            ), permissions=frozenset(),
        )
    with pytest.raises(ValueError, match="choices"):
        FeatureField("mode", "模式", "choice", True, "说明")
    with pytest.raises(ValueError, match="permissions"):
        FeatureManifest(
            feature_id="bad-permission", title="Bad", description="test", order=1,
            fields=(), permissions=frozenset({"shell"}),
        )


def test_registry_discovers_valid_modules_sorts_and_isolates_failures() -> None:
    package = ModuleType("svarog.features")
    package.__path__ = ["trusted"]
    modules: dict[str, object] = {
        "svarog.features.alpha.manifest": SimpleNamespace(FEATURE_MANIFEST=_manifest("alpha", order=20)),
        "svarog.features.alpha.handler": SimpleNamespace(run_feature=lambda _context, _values: {}),
        "svarog.features.beta.manifest": SimpleNamespace(FEATURE_MANIFEST=_manifest("beta", order=10)),
        "svarog.features.beta.handler": SimpleNamespace(run_feature=lambda _context, _values: {}),
    }

    def importer(name: str):
        if name.startswith("svarog.features.broken"):
            raise RuntimeError("C:/secret/token=value")
        return modules[name]

    entries = [
        SimpleNamespace(name="alpha", ispkg=True),
        SimpleNamespace(name="ignored.py", ispkg=False),
        SimpleNamespace(name="broken", ispkg=True),
        SimpleNamespace(name="beta", ispkg=True),
    ]
    registry = FeatureRegistry.discover(
        package=package, importer=importer,
        iterator=lambda _paths: entries,
    )

    assert [item.feature_id for item in registry.features] == ["beta", "alpha"]
    assert registry.get("alpha").manifest.title == "Feature alpha"
    assert registry.get("missing") is None
    assert registry.errors == ({"package": "broken", "code": "feature_load_failed"},)
    assert "secret" not in repr(registry.errors)


def test_registry_rejects_duplicate_ids_without_last_module_winning() -> None:
    package = ModuleType("svarog.features")
    package.__path__ = ["trusted"]
    manifests = {
        "one": _manifest("same", order=1),
        "two": _manifest("same", order=2),
    }

    def importer(name: str):
        _, package_name, leaf = name.rsplit(".", 2)
        if leaf == "manifest":
            return SimpleNamespace(FEATURE_MANIFEST=manifests[package_name])
        return SimpleNamespace(run_feature=lambda _context, _values: {})

    registry = FeatureRegistry.discover(
        package=package,
        importer=importer,
        iterator=lambda _paths: [SimpleNamespace(name="one", ispkg=True),
                                 SimpleNamespace(name="two", ispkg=True)],
    )

    assert registry.features == ()
    assert registry.errors == (
        {"package": "one", "code": "duplicate_feature_id"},
        {"package": "two", "code": "duplicate_feature_id"},
    )


def test_registry_rejects_symlinked_feature_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = ModuleType("svarog.features")
    package.__path__ = [str(tmp_path)]
    candidate = tmp_path / "linked"
    candidate.mkdir()
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == candidate or original_is_symlink(path),
    )

    def importer(_name: str) -> object:
        raise AssertionError("符号链接功能目录不应被导入")

    registry = FeatureRegistry.discover(
        package=package,
        importer=importer,
        iterator=lambda _paths: [SimpleNamespace(name="linked", ispkg=True)],
    )

    assert registry.features == ()
    assert registry.errors == (
        {"package": "linked", "code": "feature_path_rejected"},
    )


def test_registry_rejects_symlinked_feature_source_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = ModuleType("svarog.features")
    package.__path__ = [str(tmp_path)]
    candidate = tmp_path / "linked_file"
    candidate.mkdir()
    for name in ("__init__.py", "manifest.py", "handler.py"):
        (candidate / name).write_text("", encoding="utf-8")
    linked_handler = candidate / "handler.py"
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == linked_handler or original_is_symlink(path),
    )

    def importer(_name: str) -> object:
        raise AssertionError("符号链接源文件不应被导入")

    registry = FeatureRegistry.discover(
        package=package,
        importer=importer,
        iterator=lambda _paths: [SimpleNamespace(name="linked_file", ispkg=True)],
    )

    assert registry.features == ()
    assert registry.errors == (
        {"package": "linked_file", "code": "feature_path_rejected"},
    )


def test_catalog_contains_only_declarative_public_fields() -> None:
    manifest = _manifest("hash-file")
    registry = FeatureRegistry.from_entries(((manifest, lambda _context, _values: {}),))

    assert registry.catalog() == {
        "schema": "svarog.workbench.features.v1",
        "features": [{
            "feature_id": "hash-file", "title": "Feature hash-file",
            "description": "只读测试功能", "order": 10,
            "permissions": ["workspace_read"],
            "fields": [{
                "name": "target", "label": "目标", "kind": "workspace_file",
                "required": True, "help_text": "工作区内文件", "choices": [],
                "minimum": None, "maximum": None,
            }],
        }],
        "disabled": [],
    }
