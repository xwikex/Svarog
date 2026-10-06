from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from svarog.features.contracts import FeatureContext
from svarog.features.file_hash import handler as file_hash_handler
from svarog.features.file_hash.handler import run_feature
from svarog.features.file_hash.manifest import FEATURE_MANIFEST
from svarog.features.registry import FeatureRegistry
from svarog.features.runtime import present_feature_result
from svarog.webui.config import resolve_workspace_path


def test_file_hash_is_a_discovered_read_only_feature(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"svarog")
    context = FeatureContext(tmp_path.resolve(), resolve_workspace_path)

    result = run_feature(context, {"target": source.resolve()})
    presented = present_feature_result(FEATURE_MANIFEST, result)

    assert FEATURE_MANIFEST.feature_id == "file-hash"
    assert FEATURE_MANIFEST.permissions == frozenset({"workspace_read"})
    assert presented["actions_executed"] is False
    assert presented["tables"][0]["rows"] == [{
        "file": "sample.bin",
        "sha256": hashlib.sha256(b"svarog").hexdigest(),
    }]
    assert str(tmp_path.resolve()) not in str(presented)
    assert FeatureRegistry.discover().get("file-hash") is not None


def test_file_hash_handler_rejects_unvalidated_path(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"outside")
    try:
        with pytest.raises(ValueError, match="工作区"):
            run_feature(
                FeatureContext(tmp_path.resolve(), resolve_workspace_path),
                {"target": outside.resolve()},
            )
    finally:
        outside.unlink(missing_ok=True)


def test_file_hash_stops_if_file_grows_past_limit_while_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "growing.bin"
    source.write_bytes(b"x")
    monkeypatch.setattr(file_hash_handler, "MAX_FILE_BYTES", 4)
    original_open = Path.open

    def growing_open(path: Path, mode: str):
        if path == source.resolve():
            with open(source, "wb") as replacement:
                replacement.write(b"12345")
        return original_open(path, mode)

    monkeypatch.setattr(Path, "open", growing_open)

    with pytest.raises(ValueError, match="大小限制"):
        run_feature(
            FeatureContext(tmp_path.resolve(), resolve_workspace_path),
            {"target": source.resolve()},
        )


def test_file_hash_rejects_target_replaced_between_stat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.bin"
    replacement = tmp_path / "replacement.bin"
    source.write_bytes(b"safe")
    replacement.write_bytes(b"different file")
    resolved_source = source.resolve()
    original_open = Path.open

    def swapped_open(path: Path, mode: str):
        return original_open(replacement if path == resolved_source else path, mode)

    monkeypatch.setattr(Path, "open", swapped_open)
    with pytest.raises(ValueError, match="读取期间发生变化"):
        run_feature(
            FeatureContext(tmp_path.resolve(), resolve_workspace_path),
            {"target": resolved_source},
        )
