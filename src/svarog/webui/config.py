"""Security-sensitive configuration for the local web UI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _resolve_workspace(workspace: str | Path) -> Path:
    try:
        resolved = Path(workspace).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("workspace 必须是已存在的目录") from exc
    if not resolved.is_dir():
        raise ValueError("workspace 必须是已存在的目录")
    return resolved


def _require_within_workspace(path: Path, workspace: Path) -> None:
    try:
        path.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("路径不得逃逸 workspace") from exc


def _validate_host_and_port(host: str, port: int) -> None:
    if host not in _LOOPBACK_HOSTS:
        raise ValueError("host 仅允许回环地址")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port 必须是 1..65535 范围内的整数")


def _validate_canonical_paths(workspace: Path, case_db: Path) -> None:
    if not isinstance(workspace, Path) or not isinstance(case_db, Path):
        raise ValueError("workspace 和 case_db 必须是规范化 Path")

    resolved_workspace = _resolve_workspace(workspace)
    if workspace != resolved_workspace:
        raise ValueError("workspace 必须是规范化绝对路径")

    try:
        resolved_case_db = case_db.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("case_db 路径无效") from exc
    if case_db != resolved_case_db:
        raise ValueError("case_db 必须是规范化绝对路径")

    _require_within_workspace(case_db, workspace)
    if case_db == workspace or case_db.is_dir():
        raise ValueError("case_db 必须是文件路径，不能是目录")
    if case_db.name.casefold().endswith(_SQLITE_SIDECAR_SUFFIXES):
        raise ValueError("case_db 不能使用 SQLite sidecar 文件名")


@dataclass(frozen=True, slots=True)
class UiConfig:
    host: str
    port: int
    workspace: Path
    case_db: Path
    max_request_bytes: int = 14 * 1024 * 1024

    def __post_init__(self) -> None:
        _validate_host_and_port(self.host, self.port)
        _validate_canonical_paths(self.workspace, self.case_db)
        if type(self.max_request_bytes) is not int or self.max_request_bytes <= 0:
            raise ValueError("max_request_bytes 必须是正整数")

    @classmethod
    def build(
        cls,
        host: str,
        port: int,
        workspace: str | Path,
        case_db: str | Path | None = None,
    ) -> UiConfig:
        _validate_host_and_port(host, port)

        resolved_workspace = _resolve_workspace(workspace)
        raw_case_db = Path(case_db) if case_db is not None else Path(".svarog/database/cases.sqlite3")
        if not raw_case_db.is_absolute():
            raw_case_db = resolved_workspace / raw_case_db

        try:
            resolved_case_db = raw_case_db.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ValueError("case_db 路径无效") from exc

        return cls(
            host=host,
            port=port,
            workspace=resolved_workspace,
            case_db=resolved_case_db,
        )


def resolve_workspace_path(
    workspace: str | Path,
    raw_path: str | Path,
    *,
    kind: str,
) -> Path:
    if kind not in {"file", "directory"}:
        raise ValueError("kind 必须是 'file' 或 'directory'")

    raw_text = str(raw_path)
    path = Path(raw_path)
    if not raw_text.strip() or path == Path("."):
        raise ValueError("路径必须是非空相对路径")
    if path.is_absolute() or path.drive or path.root or path.anchor:
        raise ValueError("路径必须是相对路径")

    resolved_workspace = _resolve_workspace(workspace)
    try:
        resolved = (resolved_workspace / path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("路径必须存在") from exc

    _require_within_workspace(resolved, resolved_workspace)
    if resolved == resolved_workspace:
        raise ValueError("路径必须指向 workspace 内的项目")
    if kind == "file" and not resolved.is_file():
        raise ValueError("路径必须是文件")
    if kind == "directory" and not resolved.is_dir():
        raise ValueError("路径必须是目录")
    return resolved
