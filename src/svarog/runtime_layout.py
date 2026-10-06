from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import unicodedata
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from uuid import UUID, uuid4

if os.name == "nt":
    import ctypes
    from ctypes import wintypes


class RuntimeLayoutError(RuntimeError):
    """A runtime path, configuration value, or persisted document is invalid."""


class RuntimeConfigError(RuntimeLayoutError):
    """A runtime configuration document is invalid or could not be saved."""


class RuntimeMigrationError(RuntimeLayoutError):
    """The legacy cases database could not be migrated safely."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(key)
        result[key] = value
    return result


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _metadata_is_link(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_tag = getattr(metadata, "st_reparse_tag", 0)
    mount_point_tag = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", None)
    if mount_point_tag is not None and reparse_tag == mount_point_tag:
        return True
    return bool(reparse_tag)


def _is_link(path: Path) -> bool:
    try:
        metadata = _lstat_or_none(path)
    except (OSError, UnicodeError):
        raise RuntimeLayoutError("runtime_metadata_failed") from None
    return metadata is not None and _metadata_is_link(metadata)


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    if left is right:
        return True
    try:
        return _metadata_identity(left) == _metadata_identity(right)
    except AttributeError:
        return False


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_open_flags(flags: int) -> int:
    return flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


_HAS_OPENAT = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
_HAS_MKDIRAT = os.mkdir in os.supports_dir_fd
_HAS_LINKAT = os.link in os.supports_dir_fd
_HAS_UNLINKAT = os.unlink in os.supports_dir_fd
_HAS_REPLACEAT = os.replace in os.supports_dir_fd
_SQLITE_SERIALIZATION_SUPPORTED = all(
    callable(getattr(sqlite3.Connection, name, None))
    for name in ("deserialize", "serialize")
)


if os.name == "nt":
    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]


    try:
        _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _CREATE_FILE = _KERNEL32.CreateFileW
        _CREATE_FILE.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        _CREATE_FILE.restype = wintypes.HANDLE
        _GET_FILE_INFORMATION = _KERNEL32.GetFileInformationByHandle
        _GET_FILE_INFORMATION.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        _GET_FILE_INFORMATION.restype = wintypes.BOOL
        _SET_FILE_POINTER = _KERNEL32.SetFilePointerEx
        _SET_FILE_POINTER.argtypes = (
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        )
        _SET_FILE_POINTER.restype = wintypes.BOOL
        _READ_FILE = _KERNEL32.ReadFile
        _READ_FILE.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        _READ_FILE.restype = wintypes.BOOL
        _CLOSE_HANDLE = _KERNEL32.CloseHandle
        _CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
        _CLOSE_HANDLE.restype = wintypes.BOOL
    except (AttributeError, OSError):
        _CREATE_FILE = None
        _GET_FILE_INFORMATION = None
        _SET_FILE_POINTER = None
        _READ_FILE = None
        _CLOSE_HANDLE = None
else:
    _CREATE_FILE = None
    _GET_FILE_INFORMATION = None
    _SET_FILE_POINTER = None
    _READ_FILE = None
    _CLOSE_HANDLE = None


_FILE_READ_ATTRIBUTES = 0x00000080
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_INVALID_HANDLE_VALUE = -1


def _windows_information_identity(information: Any) -> tuple[int, int, bool]:
    file_index = (information.file_index_high << 32) | information.file_index_low
    is_directory = bool(information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY)
    return information.volume_serial_number, file_index, is_directory


class _WindowsExistingPathHandle:
    """Keep one existing Windows path from being renamed or replaced."""

    def __init__(
        self,
        path: Path,
        expected: os.stat_result,
        *,
        directory: bool,
        unsafe_error: str,
    ) -> None:
        if (
            os.name != "nt"
            or _CREATE_FILE is None
            or _GET_FILE_INFORMATION is None
            or _SET_FILE_POINTER is None
            or _READ_FILE is None
            or _CLOSE_HANDLE is None
        ):
            raise RuntimeLayoutError("runtime_metadata_failed")
        self.path = path
        self._unsafe_error = unsafe_error
        self._handle: int | None = None
        handle = _CREATE_FILE(
            str(path),
            # GENERIC_READ makes the omitted FILE_SHARE_DELETE effective for
            # rename/delete sharing while FILE_READ_ATTRIBUTES supports metadata.
            _GENERIC_READ | _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle in (None, _INVALID_HANDLE_VALUE, ctypes.c_void_p(-1).value):
            raise RuntimeLayoutError("runtime_path_changed")
        self._handle = handle
        try:
            information = self._information()
            attributes = information.file_attributes
            if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise RuntimeLayoutError(unsafe_error)
            if bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
                raise RuntimeLayoutError("runtime_path_changed")
            identity = _windows_information_identity(information)
            if expected.st_ino != identity[1]:
                raise RuntimeLayoutError("runtime_path_changed")
            self._identity = identity
            self.verify()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> _WindowsExistingPathHandle:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _information(self) -> Any:
        if self._handle is None or _GET_FILE_INFORMATION is None:
            raise RuntimeLayoutError("runtime_path_changed")
        information = _ByHandleFileInformation()
        if not _GET_FILE_INFORMATION(self._handle, ctypes.byref(information)):
            raise RuntimeLayoutError("runtime_path_changed")
        return information

    def verify(self) -> None:
        information = self._information()
        if information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeLayoutError(self._unsafe_error)
        if _windows_information_identity(information) != self._identity:
            raise RuntimeLayoutError("runtime_path_changed")
        try:
            metadata = os.lstat(self.path)
        except (OSError, UnicodeError):
            raise RuntimeLayoutError("runtime_path_changed") from None
        if _metadata_is_link(metadata):
            raise RuntimeLayoutError(self._unsafe_error)
        if metadata.st_ino != self._identity[1]:
            raise RuntimeLayoutError("runtime_path_changed")

    def read_all(self) -> bytes:
        if self._handle is None or _SET_FILE_POINTER is None or _READ_FILE is None:
            raise RuntimeLayoutError("runtime_path_changed")
        position = ctypes.c_longlong()
        if not _SET_FILE_POINTER(self._handle, 0, ctypes.byref(position), os.SEEK_SET):
            raise RuntimeLayoutError("runtime_path_changed")
        chunks: list[bytes] = []
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            read = wintypes.DWORD()
            if not _READ_FILE(
                self._handle,
                buffer,
                len(buffer),
                ctypes.byref(read),
                None,
            ):
                raise RuntimeLayoutError("runtime_path_changed")
            if read.value == 0:
                return b"".join(chunks)
            chunks.append(buffer.raw[: read.value])

    def close(self) -> None:
        if self._handle is not None:
            handle = self._handle
            self._handle = None
            if _CLOSE_HANDLE is None or not _CLOSE_HANDLE(handle):
                raise RuntimeLayoutError("runtime_metadata_failed")


@dataclass(frozen=True, slots=True)
class _OwnedTemporaryFile:
    name: str
    path: Path
    metadata: os.stat_result


class _SafeDirectory:
    """A narrow, checked anchor for operations in a managed directory."""

    def __init__(self, layout: RuntimeLayout, path: Path) -> None:
        self._layout = layout
        self.path = path
        self._snapshots = self._capture_chain()
        self._descriptor: int | None = None
        self._windows_handles: list[_WindowsExistingPathHandle] = []
        try:
            if os.name == "nt":
                for guarded_path, metadata in self._snapshots:
                    self._windows_handles.append(
                        _WindowsExistingPathHandle(
                            guarded_path,
                            metadata,
                            directory=True,
                            unsafe_error="unsafe_runtime_symlink",
                        )
                    )
            elif _HAS_OPENAT:
                self._descriptor = self._open_anchored_directory()
            self.verify()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> _SafeDirectory:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            finally:
                self._descriptor = None
        close_error: RuntimeLayoutError | None = None
        while self._windows_handles:
            handle = self._windows_handles.pop()
            try:
                handle.close()
            except RuntimeLayoutError as error:
                close_error = error
        if close_error is not None:
            raise close_error

    def _chain(self) -> tuple[Path, ...]:
        try:
            relative = self.path.relative_to(self._layout.workspace)
        except ValueError:
            raise RuntimeLayoutError("runtime_path_changed") from None
        paths = [self._layout.workspace]
        current = self._layout.workspace
        for part in relative.parts:
            current = current / part
            paths.append(current)
        return tuple(paths)

    def _capture_chain(self) -> tuple[tuple[Path, os.stat_result], ...]:
        snapshots: list[tuple[Path, os.stat_result]] = []
        try:
            for path in self._chain():
                metadata = os.lstat(path)
                if _metadata_is_link(metadata):
                    raise RuntimeLayoutError("unsafe_runtime_symlink")
                if not stat.S_ISDIR(metadata.st_mode):
                    raise RuntimeLayoutError("runtime_path_changed")
                snapshots.append((path, metadata))
        except FileNotFoundError:
            raise RuntimeLayoutError("runtime_path_changed") from None
        except (OSError, UnicodeError):
            raise RuntimeLayoutError("runtime_metadata_failed") from None
        return tuple(snapshots)

    def _open_anchored_directory(self) -> int:
        descriptor: int | None = None
        try:
            descriptor = os.open(self._layout.workspace, _directory_open_flags())
            if not _same_identity(os.fstat(descriptor), self._snapshots[0][1]):
                raise RuntimeLayoutError("runtime_path_changed")
            for part, (_, expected) in zip(
                self.path.relative_to(self._layout.workspace).parts,
                self._snapshots[1:],
                strict=True,
            ):
                child = os.open(part, _directory_open_flags(), dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                if not _same_identity(os.fstat(descriptor), expected):
                    raise RuntimeLayoutError("runtime_path_changed")
            return descriptor
        except RuntimeLayoutError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except (OSError, UnicodeError):
            if descriptor is not None:
                os.close(descriptor)
            raise RuntimeLayoutError("runtime_path_changed") from None

    def verify(self) -> None:
        try:
            for handle in self._windows_handles:
                handle.verify()
            for path, expected in self._snapshots:
                current = os.lstat(path)
                if _metadata_is_link(current):
                    raise RuntimeLayoutError("unsafe_runtime_symlink")
                if not _same_identity(current, expected):
                    raise RuntimeLayoutError("runtime_path_changed")
            if self._descriptor is not None and not _same_identity(
                os.fstat(self._descriptor), self._snapshots[-1][1]
            ):
                raise RuntimeLayoutError("runtime_path_changed")
        except FileNotFoundError:
            raise RuntimeLayoutError("runtime_path_changed") from None
        except RuntimeLayoutError:
            raise
        except (OSError, UnicodeError):
            raise RuntimeLayoutError("runtime_metadata_failed") from None

    def child_metadata(self, name: str) -> os.stat_result | None:
        self.verify()
        try:
            first = self._child_metadata_once(name)
            self.verify()
            second = self._child_metadata_once(name)
        except (OSError, UnicodeError):
            raise RuntimeLayoutError("runtime_metadata_failed") from None
        if first is None:
            return second
        if second is None:
            raise RuntimeLayoutError("runtime_path_changed")
        if not _same_identity(first, second):
            raise RuntimeLayoutError("runtime_path_changed")
        return second

    def _child_metadata_once(self, name: str) -> os.stat_result | None:
        try:
            if self._descriptor is not None:
                return os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
            return _lstat_or_none(self.path / name)
        except FileNotFoundError:
            return None

    def mkdir_child(self, name: str) -> None:
        self.verify()
        try:
            if self._descriptor is not None and _HAS_MKDIRAT:
                os.mkdir(name, mode=0o700, dir_fd=self._descriptor)
            else:
                os.mkdir(self.path / name, mode=0o700)
        except FileExistsError:
            pass
        except (OSError, UnicodeError):
            raise RuntimeLayoutError("runtime_directory_creation_failed") from None
        self.verify()
        metadata = self.child_metadata(name)
        if metadata is None or _metadata_is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeLayoutError("runtime_directory_creation_failed")

    def open_regular(
        self,
        name: str,
        *,
        unsafe_error: str,
    ) -> tuple[int | None, os.stat_result, _WindowsExistingPathHandle | None]:
        metadata = self.child_metadata(name)
        if metadata is None:
            raise RuntimeLayoutError("runtime_path_changed")
        if _metadata_is_link(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeLayoutError(unsafe_error)
        descriptor: int | None = None
        windows_handle: _WindowsExistingPathHandle | None = None
        try:
            if os.name == "nt":
                windows_handle = _WindowsExistingPathHandle(
                    self.path / name,
                    metadata,
                    directory=False,
                    unsafe_error=unsafe_error,
                )
                self.verify_owned(name, metadata)
                windows_handle.verify()
                return None, metadata, windows_handle
            if self._descriptor is not None:
                descriptor = os.open(name, _file_open_flags(os.O_RDONLY), dir_fd=self._descriptor)
            else:
                descriptor = os.open(self.path / name, _file_open_flags(os.O_RDONLY))
            opened = os.fstat(descriptor)
            if not _same_identity(opened, metadata):
                raise RuntimeLayoutError("runtime_path_changed")
            self.verify_owned(name, opened)
            return descriptor, opened, None
        except RuntimeLayoutError:
            if descriptor is not None:
                os.close(descriptor)
            if windows_handle is not None:
                windows_handle.close()
            raise
        except (OSError, UnicodeError):
            if descriptor is not None:
                os.close(descriptor)
            if windows_handle is not None:
                windows_handle.close()
            raise RuntimeLayoutError("runtime_path_changed") from None

    def create_temporary(self, prefix: str, suffix: str = ".tmp") -> tuple[int, _OwnedTemporaryFile]:
        self.verify()
        for _ in range(100):
            name = f".{prefix}.{secrets.token_hex(16)}{suffix}"
            path = self.path / name
            try:
                if self._descriptor is not None:
                    descriptor = os.open(
                        name,
                        _file_open_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL),
                        0o600,
                        dir_fd=self._descriptor,
                    )
                else:
                    descriptor = os.open(
                        path,
                        _file_open_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL),
                        0o600,
                    )
            except FileExistsError:
                continue
            except (OSError, UnicodeError):
                raise RuntimeLayoutError("runtime_path_changed") from None
            metadata = os.fstat(descriptor)
            try:
                self.verify_owned(name, metadata)
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor, _OwnedTemporaryFile(name, path, metadata)
        raise RuntimeLayoutError("runtime_path_changed")

    def verify_owned(self, name: str, expected: os.stat_result) -> None:
        self.verify()
        metadata = self.child_metadata(name)
        if metadata is None or _metadata_is_link(metadata) or not _same_identity(metadata, expected):
            raise RuntimeLayoutError("runtime_path_changed")

    def unlink_owned(self, temporary: _OwnedTemporaryFile) -> None:
        self.verify_owned(temporary.name, temporary.metadata)
        try:
            if self._descriptor is not None and _HAS_UNLINKAT:
                os.unlink(temporary.name, dir_fd=self._descriptor)
            else:
                os.unlink(temporary.path)
        except FileNotFoundError:
            return
        self.verify()
        self._fsync()

    def publish_no_clobber(self, temporary: _OwnedTemporaryFile, name: str) -> bool:
        self.verify_owned(temporary.name, temporary.metadata)
        existing = self.child_metadata(name)
        if existing is not None:
            if _metadata_is_link(existing):
                raise RuntimeLayoutError("unsafe_runtime_symlink")
            return False
        try:
            if self._descriptor is not None and _HAS_LINKAT:
                os.link(
                    temporary.name,
                    name,
                    src_dir_fd=self._descriptor,
                    dst_dir_fd=self._descriptor,
                    follow_symlinks=False,
                )
            else:
                os.link(temporary.path, self.path / name, follow_symlinks=False)
        except FileExistsError:
            winner = self.child_metadata(name)
            if winner is None or _metadata_is_link(winner):
                raise RuntimeLayoutError("runtime_path_changed") from None
            return False
        self.verify_owned(name, temporary.metadata)
        self._fsync()
        return True

    def replace(self, temporary: _OwnedTemporaryFile, name: str) -> None:
        self.verify_owned(temporary.name, temporary.metadata)
        existing = self.child_metadata(name)
        if existing is not None and _metadata_is_link(existing):
            raise RuntimeLayoutError("unsafe_runtime_symlink")
        try:
            if self._descriptor is not None and _HAS_REPLACEAT:
                os.replace(
                    temporary.name,
                    name,
                    src_dir_fd=self._descriptor,
                    dst_dir_fd=self._descriptor,
                )
            else:
                os.replace(temporary.path, self.path / name)
        except (OSError, UnicodeError):
            raise RuntimeConfigError("atomic_write_failed") from None
        self.verify_owned(name, temporary.metadata)
        self._fsync()

    def _fsync(self) -> None:
        if self._descriptor is None:
            return
        try:
            os.fsync(self._descriptor)
        except OSError:
            pass


def _read_json_object(layout: RuntimeLayout, path: Path, document: str) -> dict[str, Any]:
    try:
        with _SafeDirectory(layout, path.parent) as directory:
            descriptor, metadata, windows_handle = directory.open_regular(
                path.name,
                unsafe_error="unsafe_runtime_symlink",
            )
            try:
                if windows_handle is not None:
                    raw = windows_handle.read_all().decode("utf-8")
                elif descriptor is not None:
                    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                        descriptor = None
                        raw = handle.read()
                else:
                    raise RuntimeLayoutError("runtime_path_changed")
                directory.verify_owned(path.name, metadata)
                if windows_handle is not None:
                    windows_handle.verify()
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if windows_handle is not None:
                    windows_handle.close()
        value = json.loads(
            raw,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except RuntimeLayoutError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise RuntimeConfigError(f"invalid_{document}_json") from None
    if not isinstance(value, dict):
        raise RuntimeConfigError(f"invalid_{document}_json")
    return value


def _read_all_from_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all_to_descriptor(descriptor: int, payload: bytes) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError
        remaining = remaining[written:]
    os.fsync(descriptor)


def _atomic_write_json(
    layout: RuntimeLayout,
    path: Path,
    value: dict[str, Any],
    *,
    no_clobber: bool = False,
) -> bool:
    directory: _SafeDirectory | None = None
    descriptor: int | None = None
    temporary: _OwnedTemporaryFile | None = None
    published = False
    try:
        directory = _SafeDirectory(layout, path.parent)
        descriptor, temporary = directory.create_temporary(path.name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = None
            json.dump(value, handle, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        directory.verify_owned(temporary.name, temporary.metadata)
        if no_clobber:
            published = directory.publish_no_clobber(temporary, path.name)
            directory.unlink_owned(temporary)
        else:
            directory.replace(temporary, path.name)
            published = True
        temporary = None
        return published
    except RuntimeLayoutError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError):
        raise RuntimeConfigError("atomic_write_failed") from None
    finally:
        cleanup_failed = False
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None and directory is not None:
            try:
                directory.unlink_owned(temporary)
            except (OSError, UnicodeError, RuntimeLayoutError):
                if not published:
                    cleanup_failed = True
        if directory is not None:
            directory.close()
        if cleanup_failed:
            raise RuntimeConfigError("atomic_write_cleanup_failed") from None


def _validated_display_name(value: Any) -> str:
    if type(value) is not str:
        raise RuntimeLayoutError("invalid_display_name")
    display_name = value.strip()
    if not display_name or len(display_name) > 128:
        raise RuntimeLayoutError("invalid_display_name")
    if any(unicodedata.category(character) == "Cc" for character in display_name):
        raise RuntimeLayoutError("invalid_display_name")
    if PurePosixPath(display_name).is_absolute() or PureWindowsPath(display_name).is_absolute():
        raise RuntimeLayoutError("invalid_display_name")
    return display_name


def _validated_project_id(value: Any) -> str:
    if type(value) is not str or len(value) != 37 or not value.startswith("proj_"):
        raise RuntimeConfigError("invalid_project_id")
    hexadecimal = value[5:]
    try:
        parsed = UUID(hex=hexadecimal)
    except (ValueError, AttributeError):
        raise RuntimeConfigError("invalid_project_id") from None
    if parsed.hex != hexadecimal or parsed.version != 4:
        raise RuntimeConfigError("invalid_project_id")
    return value


def _validated_created_at(value: Any) -> str:
    if type(value) is not str:
        raise RuntimeConfigError("invalid_project_created_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        raise RuntimeConfigError("invalid_project_created_at") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RuntimeConfigError("invalid_project_created_at")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    workspace: Path
    root: Path
    config_dir: Path
    database_dir: Path
    backup_dir: Path
    reports_dir: Path
    cache_dir: Path
    logs_dir: Path
    temp_dir: Path
    project_file: Path
    settings_file: Path
    history_db: Path
    case_db: Path

    @classmethod
    def build(cls, workspace: str | Path) -> RuntimeLayout:
        try:
            resolved = Path(workspace).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, TypeError):
            raise RuntimeLayoutError("invalid_workspace") from None
        if not resolved.is_dir():
            raise RuntimeLayoutError("invalid_workspace")

        root = resolved / ".svarog"
        config_dir = root / "config"
        database_dir = root / "database"
        reports_dir = root / "reports"
        return cls(
            workspace=resolved,
            root=root,
            config_dir=config_dir,
            database_dir=database_dir,
            backup_dir=database_dir / "backups",
            reports_dir=reports_dir,
            cache_dir=root / "cache",
            logs_dir=root / "logs",
            temp_dir=root / "temp",
            project_file=config_dir / "project.json",
            settings_file=config_dir / "settings.json",
            history_db=database_dir / "audit-history.sqlite3",
            case_db=database_dir / "cases.sqlite3",
        )

    def _managed_directories(self) -> tuple[Path, ...]:
        return (
            self.root,
            self.config_dir,
            self.database_dir,
            self.backup_dir,
            self.reports_dir,
            self.reports_dir / "audits",
            self.reports_dir / "differences",
            self.reports_dir / "sbom",
            self.reports_dir / "cases",
            self.cache_dir,
            self.logs_dir,
            self.temp_dir,
        )

    def ensure_directories(self) -> None:
        if _is_link(self.workspace):
            raise RuntimeLayoutError("unsafe_runtime_symlink")
        if not self.workspace.is_dir():
            raise RuntimeLayoutError("invalid_workspace")
        for directory in self._managed_directories():
            parent = directory.parent
            try:
                with _SafeDirectory(self, parent) as safe_parent:
                    metadata = safe_parent.child_metadata(directory.name)
                    if metadata is None:
                        safe_parent.mkdir_child(directory.name)
                    elif _metadata_is_link(metadata):
                        raise RuntimeLayoutError("unsafe_runtime_symlink")
                    elif not stat.S_ISDIR(metadata.st_mode):
                        raise RuntimeLayoutError("runtime_directory_creation_failed")
                with _SafeDirectory(self, directory):
                    pass
            except RuntimeLayoutError as error:
                if str(error) in {
                    "unsafe_runtime_symlink",
                    "runtime_path_changed",
                    "runtime_metadata_failed",
                }:
                    raise
                raise RuntimeLayoutError("runtime_directory_creation_failed") from None


@dataclass(frozen=True, slots=True)
class ProjectIdentity:
    schema_version: int
    project_id: str
    display_name: str
    created_at: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise RuntimeConfigError("invalid_project_schema")
        _validated_project_id(self.project_id)
        if _validated_display_name(self.display_name) != self.display_name:
            raise RuntimeLayoutError("invalid_display_name")
        _validated_created_at(self.created_at)

    @classmethod
    def load_or_create(
        cls,
        layout: RuntimeLayout,
        display_name: str | None = None,
    ) -> ProjectIdentity:
        layout.ensure_directories()
        with _SafeDirectory(layout, layout.config_dir) as directory:
            project_metadata = directory.child_metadata(layout.project_file.name)
        if project_metadata is not None:
            identity = load_project_identity(layout)
            if display_name is None:
                return identity
            normalized = _validated_display_name(display_name)
            if normalized == identity.display_name:
                return identity
            updated = cls(
                schema_version=identity.schema_version,
                project_id=identity.project_id,
                display_name=normalized,
                created_at=identity.created_at,
            )
            _atomic_write_json(layout, layout.project_file, _project_identity_payload(updated))
            return updated
        initial_name = layout.workspace.name if display_name is None else display_name
        try:
            return create_project_identity(layout, initial_name)
        except RuntimeLayoutError as error:
            if str(error) != "project_identity_exists":
                raise
            return cls.load_or_create(layout, display_name=display_name)


def _project_identity_payload(identity: ProjectIdentity) -> dict[str, Any]:
    return {
        "schema_version": identity.schema_version,
        "project_id": identity.project_id,
        "display_name": identity.display_name,
        "created_at": identity.created_at,
    }


def create_project_identity(layout: RuntimeLayout, display_name: str) -> ProjectIdentity:
    layout.ensure_directories()
    with _SafeDirectory(layout, layout.config_dir) as directory:
        if directory.child_metadata(layout.project_file.name) is not None:
            raise RuntimeLayoutError("project_identity_exists")
    identity = ProjectIdentity(
        schema_version=1,
        project_id=f"proj_{uuid4().hex}",
        display_name=_validated_display_name(display_name),
        created_at=_utc_now(),
    )
    if _atomic_write_json(
        layout,
        layout.project_file,
        _project_identity_payload(identity),
        no_clobber=True,
    ):
        return identity
    return load_project_identity(layout)


def load_project_identity(layout: RuntimeLayout) -> ProjectIdentity:
    layout.ensure_directories()
    with _SafeDirectory(layout, layout.config_dir) as directory:
        metadata = directory.child_metadata(layout.project_file.name)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        if metadata is not None and _metadata_is_link(metadata):
            raise RuntimeLayoutError("unsafe_runtime_symlink")
        raise RuntimeLayoutError("project_identity_not_found")
    data = _read_json_object(layout, layout.project_file, "project")
    if set(data) != {"schema_version", "project_id", "display_name", "created_at"}:
        raise RuntimeConfigError("invalid_project_schema")
    return ProjectIdentity(
        schema_version=data["schema_version"],
        project_id=data["project_id"],
        display_name=data["display_name"],
        created_at=data["created_at"],
    )


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    schema_version: int = 1
    audit_retention_days: int = 180

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise RuntimeConfigError("invalid_settings_schema")
        if (
            type(self.audit_retention_days) is not int
            or not 3 <= self.audit_retention_days <= 365
        ):
            raise RuntimeLayoutError("invalid_retention_days")

    @classmethod
    def load_or_create(cls, layout: RuntimeLayout) -> RuntimeSettings:
        return load_settings(layout)

    def update(self, layout: RuntimeLayout, *, audit_retention_days: int) -> RuntimeSettings:
        return save_settings(layout, {"audit_retention_days": audit_retention_days})


def _settings_payload(settings: RuntimeSettings) -> dict[str, int]:
    return {
        "schema_version": settings.schema_version,
        "audit_retention_days": settings.audit_retention_days,
    }


def load_settings(layout: RuntimeLayout) -> RuntimeSettings:
    layout.ensure_directories()
    with _SafeDirectory(layout, layout.config_dir) as directory:
        metadata = directory.child_metadata(layout.settings_file.name)
    if metadata is not None and _metadata_is_link(metadata):
        raise RuntimeLayoutError("unsafe_runtime_symlink")
    if metadata is None:
        settings = RuntimeSettings()
        if _atomic_write_json(
            layout,
            layout.settings_file,
            _settings_payload(settings),
            no_clobber=True,
        ):
            return settings
        return load_settings(layout)
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeConfigError("invalid_settings_schema")
    data = _read_json_object(layout, layout.settings_file, "settings")
    if set(data) != {"schema_version", "audit_retention_days"}:
        raise RuntimeConfigError("invalid_settings_schema")
    return RuntimeSettings(
        schema_version=data["schema_version"],
        audit_retention_days=data["audit_retention_days"],
    )


def save_settings(layout: RuntimeLayout, values: Mapping[str, Any]) -> RuntimeSettings:
    if not isinstance(values, Mapping) or set(values) != {"audit_retention_days"}:
        raise RuntimeConfigError("invalid_settings_schema")
    settings = RuntimeSettings(audit_retention_days=values["audit_retention_days"])
    layout.ensure_directories()
    with _SafeDirectory(layout, layout.config_dir) as directory:
        metadata = directory.child_metadata(layout.settings_file.name)
    if metadata is not None and _metadata_is_link(metadata):
        raise RuntimeLayoutError("unsafe_runtime_symlink")
    _atomic_write_json(layout, layout.settings_file, _settings_payload(settings))
    return settings


def migrate_legacy_cases_db(layout: RuntimeLayout) -> bool:
    """Copy the legacy cases database into the managed database directory once."""
    layout.ensure_directories()
    source = layout.root / "cases.sqlite3"
    destination = layout.case_db
    source_descriptor: int | None = None
    source_windows_handle: _WindowsExistingPathHandle | None = None
    temporary_descriptor: int | None = None
    temporary: _OwnedTemporaryFile | None = None
    destination_directory: _SafeDirectory | None = None
    try:
        with _SafeDirectory(layout, layout.root) as source_directory:
            destination_directory = _SafeDirectory(layout, layout.database_dir)
            source_metadata = source_directory.child_metadata(source.name)
            destination_metadata = destination_directory.child_metadata(destination.name)

            if destination_metadata is not None and _metadata_is_link(destination_metadata):
                raise RuntimeMigrationError("unsafe_legacy_case_destination")
            if source_metadata is not None and (
                _metadata_is_link(source_metadata)
                or not stat.S_ISREG(source_metadata.st_mode)
            ):
                raise RuntimeMigrationError("unsafe_legacy_case_source")
            if destination_metadata is not None or source_metadata is None:
                return False
            if not _SQLITE_SERIALIZATION_SUPPORTED:
                raise RuntimeMigrationError("legacy_case_migration_failed")

            source_descriptor, opened_source, source_windows_handle = (
                source_directory.open_regular(
                    source.name,
                    unsafe_error="unsafe_legacy_case_source",
                )
            )
            sidecar_names = tuple(
                source.name + suffix for suffix in ("-wal", "-shm", "-journal")
            )

            def reject_sidecars() -> None:
                if any(
                    source_directory.child_metadata(name) is not None
                    for name in sidecar_names
                ):
                    raise RuntimeMigrationError("legacy_case_migration_failed")

            def read_source_bytes() -> bytes:
                if source_windows_handle is not None:
                    return source_windows_handle.read_all()
                if source_descriptor is None:
                    raise RuntimeMigrationError("legacy_case_migration_failed")
                return _read_all_from_descriptor(source_descriptor)

            reject_sidecars()
            first_source_bytes = read_source_bytes()
            reject_sidecars()
            second_source_bytes = read_source_bytes()
            reject_sidecars()
            if first_source_bytes != second_source_bytes:
                raise RuntimeMigrationError("legacy_case_migration_failed")
            source_directory.verify_owned(source.name, opened_source)
            if source_windows_handle is not None:
                source_windows_handle.verify()

            with closing(sqlite3.connect(":memory:")) as source_connection:
                source_connection.deserialize(first_source_bytes)
                if source_connection.execute("PRAGMA quick_check").fetchall() != [
                    ("ok",)
                ]:
                    raise sqlite3.DatabaseError("integrity")
                with closing(sqlite3.connect(":memory:")) as destination_connection:
                    source_connection.backup(destination_connection)
                    if destination_connection.execute("PRAGMA quick_check").fetchall() != [
                        ("ok",)
                    ]:
                        raise sqlite3.DatabaseError("integrity")
                    destination_bytes = destination_connection.serialize()
            if not isinstance(destination_bytes, bytes):
                raise sqlite3.DatabaseError("serialization")

            temporary_descriptor, temporary = destination_directory.create_temporary(
                destination.name,
                suffix=".sqlite3.tmp",
            )
            _write_all_to_descriptor(temporary_descriptor, destination_bytes)
            written_temporary = os.fstat(temporary_descriptor)
            if not _same_identity(written_temporary, temporary.metadata):
                raise RuntimeMigrationError("legacy_case_migration_failed")
            destination_directory.verify_owned(
                temporary.name,
                temporary.metadata,
            )
            source_directory.verify_owned(source.name, opened_source)
            if source_windows_handle is not None:
                source_windows_handle.verify()
            reject_sidecars()
            published = destination_directory.publish_no_clobber(
                temporary,
                destination.name,
            )
            os.close(temporary_descriptor)
            temporary_descriptor = None
            destination_directory.unlink_owned(temporary)
            temporary = None
            return published
    except RuntimeMigrationError:
        raise
    except (RuntimeLayoutError, sqlite3.Error, OSError, UnicodeError):
        raise RuntimeMigrationError("legacy_case_migration_failed") from None
    finally:
        cleanup_failed = False
        close_failed = False
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
        if source_windows_handle is not None:
            try:
                source_windows_handle.close()
            except RuntimeLayoutError:
                close_failed = True
        if temporary_descriptor is not None:
            try:
                os.close(temporary_descriptor)
            except OSError:
                pass
        if temporary is not None and destination_directory is not None:
            try:
                destination_directory.unlink_owned(temporary)
            except (OSError, UnicodeError, RuntimeLayoutError):
                cleanup_failed = True
        if destination_directory is not None:
            try:
                destination_directory.close()
            except RuntimeLayoutError:
                close_failed = True
        if cleanup_failed:
            raise RuntimeMigrationError("legacy_case_migration_cleanup_failed") from None
        if close_failed:
            raise RuntimeMigrationError("legacy_case_migration_failed") from None
