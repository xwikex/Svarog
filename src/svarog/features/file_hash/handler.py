"""Bounded, read-only implementation of the file hash feature."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from pathlib import Path

from svarog.features.contracts import FeatureContext


MAX_FILE_BYTES = 512 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


def run_feature(context: FeatureContext, values: Mapping[str, object]) -> dict[str, object]:
    target = values.get("target")
    if not isinstance(target, Path):
        raise ValueError("目标必须是经过验证的工作区文件")
    try:
        workspace = context.workspace.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(workspace)
        details = resolved.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("目标必须位于工作区") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
        raise ValueError("工作区文件无效或超过大小限制")

    digest = hashlib.sha256()
    bytes_read = 0
    try:
        with resolved.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (details.st_dev, details.st_ino)):
                raise ValueError("工作区文件在读取期间发生变化")
            while chunk := handle.read(_CHUNK_BYTES):
                bytes_read += len(chunk)
                if bytes_read > MAX_FILE_BYTES:
                    raise ValueError("工作区文件无效或超过大小限制")
                digest.update(chunk)
    except OSError as exc:
        raise ValueError("无法安全读取工作区文件") from exc
    return {
        "status": "completed",
        "summary": [
            {"key": "files", "label": "已检查文件", "value": 1},
            {"key": "bytes", "label": "文件字节数", "value": bytes_read},
        ],
        "warnings": [],
        "tables": [{
            "id": "results",
            "title": "SHA-256 结果",
            "columns": [
                {"key": "file", "label": "文件", "type": "text"},
                {"key": "sha256", "label": "SHA-256", "type": "text"},
            ],
            "rows": [{"file": resolved.name, "sha256": digest.hexdigest()}],
        }],
        "actions_executed": False,
    }


__all__ = ["MAX_FILE_BYTES", "run_feature"]
