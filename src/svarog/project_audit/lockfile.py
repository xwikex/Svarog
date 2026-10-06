"""Bounded, non-executing readers for Poetry and uv lock files."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import posixpath
import re
import stat
import tomllib
from typing import Callable
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import LockedDependency, LockedPackage, LockIssue, LockSnapshot


MAX_LOCKFILE_BYTES = 8 * 1024 * 1024
MAX_LOCK_PACKAGE_ENTRIES = 50_000
MAX_LOCK_ISSUES = 1_000
MAX_LOCK_NAME_CHARS = 256
MAX_LOCK_VERSION_CHARS = 128
MAX_LOCK_DEPENDENCY_VERSION_CHARS = 512
MAX_LOCK_SOURCE_CHARS = 2_048
MAX_LOCK_DEPENDENCIES_PER_PACKAGE = 10_000
MAX_LOCK_DEPENDENCIES_TOTAL = 200_000

MARKER_WARNING = (
    "Svarog 未解释锁文件中的平台、Python 版本、extra 或依赖组标记。"
    "报告已审计锁文件中出现的所有不同版本，因此部分结果可能不适用于当前环境。"
)

_VALID_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_SOURCE_KINDS = (
    "registry",
    "git",
    "url",
    "path",
    "editable",
    "virtual",
    "workspace",
)
_LOCAL_SOURCE_KINDS = frozenset({"path", "editable", "virtual", "workspace"})
_POETRY_SOURCE_KINDS = {
    "directory": "path",
    "file": "path",
    "git": "git",
    "legacy": "registry",
    "url": "url",
}
_WINDOWS_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:", flags=re.ASCII)
_DNS_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
    flags=re.ASCII,
)
_IMMUTABLE_GIT_REVISION = re.compile(
    r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$",
    flags=re.ASCII,
)
_SHA256 = re.compile(r"^(?:sha256:|sha256=)?([0-9A-Fa-f]{64})$", flags=re.ASCII)
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class LockfileError(ValueError):
    """A fixed, non-sensitive lock-file failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def load_lock_snapshot(path: Path) -> LockSnapshot:
    """Read package names and versions without interpreting lock markers."""

    candidate = Path(path)
    if candidate.name == "poetry.lock":
        lock_format = "poetry"
    elif candidate.name == "uv.lock":
        lock_format = "uv"
    else:
        raise LockfileError("unsupported_lockfile")

    payload, resolved = _read_regular_file(candidate)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        raise LockfileError("invalid_encoding") from None
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        raise LockfileError("invalid_toml") from None
    if not isinstance(document, dict):
        raise LockfileError("invalid_structure")
    entries = document.get("package")
    if not isinstance(entries, list):
        raise LockfileError("invalid_structure")
    if len(entries) > MAX_LOCK_PACKAGE_ENTRIES:
        raise LockfileError("too_many_lock_packages")

    packages: dict[
        tuple[str, str, str, str | None],
        LockedPackage,
    ] = {}
    package_dependencies: dict[
        tuple[str, str, str, str | None],
        dict[tuple[str, str | None, str | None], LockedDependency],
    ] = {}
    issues: list[LockIssue] = []
    total_issue_count = 0

    def record_issue(code: str, message: str, subject: str | None = None) -> None:
        nonlocal total_issue_count
        total_issue_count += 1
        if len(issues) < MAX_LOCK_ISSUES:
            issues.append(LockIssue(code=code, message=message, subject=subject))

    total_dependencies = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        dependency_count = _declared_dependency_count(
            entry.get("dependencies"), lock_format
        )
        if dependency_count > MAX_LOCK_DEPENDENCIES_PER_PACKAGE:
            raise LockfileError("too_many_lock_dependencies")
        total_dependencies += dependency_count
        if total_dependencies > MAX_LOCK_DEPENDENCIES_TOTAL:
            raise LockfileError("too_many_lock_dependencies")

    for index, entry in enumerate(entries):
        subject = f"package[{index}]"
        if not isinstance(entry, dict):
            record_issue(
                "invalid_lock_package",
                "锁文件 package 条目不是对象，已跳过。",
                subject,
            )
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name.strip():
            record_issue(
                "lock_package_missing_name",
                "锁文件 package 条目缺少有效名称，已跳过。",
                subject,
            )
            continue
        name = name.strip()
        if len(name) > MAX_LOCK_NAME_CHARS or not _VALID_NAME.fullmatch(name):
            record_issue(
                "invalid_lock_name",
                "锁文件包名无效或超出长度限制，已跳过。",
                subject,
            )
            continue
        if not isinstance(version, str) or not version.strip():
            record_issue(
                "lock_package_missing_version",
                "锁文件 package 条目缺少版本，已跳过。",
                name,
            )
            continue
        version = version.strip()
        if (
            len(version) > MAX_LOCK_VERSION_CHARS
            or _has_control_characters(version)
        ):
            record_issue(
                "invalid_lock_version",
                "锁文件版本无效或超出长度限制，已跳过。",
                name,
            )
            continue
        try:
            Version(version)
            version_valid = True
        except InvalidVersion:
            version_valid = False
            record_issue(
                "invalid_lock_version",
                "锁文件版本不符合 PEP 440，将作为无法判断项保留。",
                name,
            )

        normalized_name = canonicalize_name(name)
        source_kind, source_identity, source_notes, _ = _source_information(
            entry.get("source"), missing_kind="unknown"
        )
        for note in source_notes:
            if note == "credentials_removed":
                record_issue(
                    "lock_source_credentials_removed",
                    "锁文件来源中的凭据已移除。",
                    name,
                )
            elif note == "unsafe_path":
                record_issue(
                    "unsafe_lock_source_path",
                    "锁文件来源包含不安全的本地路径，来源标识已省略。",
                    name,
                )
            else:
                record_issue(
                    "invalid_lock_source",
                    "锁文件来源无效，来源标识已省略。",
                    name,
                )
        dependencies = _parse_dependencies(
            entry.get("dependencies"),
            lock_format=lock_format,
            package_subject=subject,
            record_issue=record_issue,
        )
        package = LockedPackage(
            name=name,
            normalized_name=normalized_name,
            version=version,
            version_valid=version_valid,
            source_kind=source_kind,
            source_identity=source_identity,
            dependencies=dependencies,
        )
        key = (
            normalized_name,
            version,
            source_kind,
            source_identity,
        )
        previous = packages.get(key)
        if previous is None or package.name < previous.name:
            packages[key] = LockedPackage(
                name=package.name,
                normalized_name=package.normalized_name,
                version=package.version,
                version_valid=package.version_valid,
                source_kind=package.source_kind,
                source_identity=package.source_identity,
            )
        dependency_map = package_dependencies.setdefault(key, {})
        for dependency in package.dependencies:
            dependency_key = _dependency_identity_key(dependency)
            previous_dependency = dependency_map.get(dependency_key)
            if previous_dependency is None:
                if len(dependency_map) >= MAX_LOCK_DEPENDENCIES_PER_PACKAGE:
                    raise LockfileError("too_many_lock_dependencies")
                dependency_map[dependency_key] = dependency
            elif _dependency_sort_key(dependency) < _dependency_sort_key(
                previous_dependency
            ):
                dependency_map[dependency_key] = dependency

    merged_packages = (
        LockedPackage(
            name=package.name,
            normalized_name=package.normalized_name,
            version=package.version,
            version_valid=package.version_valid,
            source_kind=package.source_kind,
            source_identity=package.source_identity,
            dependencies=tuple(
                sorted(package_dependencies[key].values(), key=_dependency_sort_key)
            ),
        )
        for key, package in packages.items()
    )
    ordered_packages = tuple(sorted(merged_packages, key=_package_sort_key))
    return LockSnapshot(
        path=str(resolved),
        lock_format=lock_format,
        packages=ordered_packages,
        issues=tuple(issues),
        total_package_entries=len(entries),
        total_issue_count=total_issue_count,
        truncated_issue_count=max(0, total_issue_count - len(issues)),
        warnings=(MARKER_WARNING,),
    )


def _declared_dependency_count(value: object, lock_format: str) -> int:
    if value is None:
        return 0
    if lock_format == "uv":
        return len(value) if isinstance(value, list) else 1
    if not isinstance(value, dict):
        return 1

    count = 0
    for declaration in value.values():
        count += max(1, len(declaration)) if isinstance(declaration, list) else 1
        if count > MAX_LOCK_DEPENDENCIES_PER_PACKAGE:
            return count
    return count


def _parse_dependencies(
    value: object,
    *,
    lock_format: str,
    package_subject: str,
    record_issue: Callable[[str, str, str | None], None],
) -> tuple[LockedDependency, ...]:
    if value is None:
        return ()

    declarations: list[tuple[object, object, str]] = []
    if lock_format == "uv":
        if not isinstance(value, list):
            record_issue(
                "invalid_lock_dependencies",
                "锁文件 dependencies 不是数组，已忽略。",
                package_subject,
            )
            return ()
        declarations.extend(
            (
                declaration.get("name")
                if isinstance(declaration, dict)
                else None,
                declaration,
                f"{package_subject}.dependency[{index}]",
            )
            for index, declaration in enumerate(value)
        )
    else:
        if not isinstance(value, dict):
            record_issue(
                "invalid_lock_dependencies",
                "锁文件 dependencies 不是对象，已忽略。",
                package_subject,
            )
            return ()
        ordinal = 0
        for name, raw in sorted(value.items()):
            if isinstance(raw, list):
                if not raw:
                    record_issue(
                        "invalid_lock_dependency",
                        "锁文件依赖声明无效，已跳过。",
                        f"{package_subject}.dependency[{ordinal}]",
                    )
                    ordinal += 1
                    continue
                for declaration in raw:
                    declarations.append(
                        (name, declaration, f"{package_subject}.dependency[{ordinal}]")
                    )
                    ordinal += 1
            else:
                declarations.append(
                    (name, raw, f"{package_subject}.dependency[{ordinal}]")
                )
                ordinal += 1

    selected: dict[tuple[str, str | None, str | None], LockedDependency] = {}
    for name_value, declaration, subject in declarations:
        dependency = _parse_dependency(
            name_value,
            declaration,
            lock_format=lock_format,
            subject=subject,
            record_issue=record_issue,
        )
        if dependency is None:
            continue
        key = _dependency_identity_key(dependency)
        previous = selected.get(key)
        if previous is None or _dependency_sort_key(dependency) < _dependency_sort_key(
            previous
        ):
            selected[key] = dependency
    return tuple(sorted(selected.values(), key=_dependency_sort_key))


def _parse_dependency(
    name_value: object,
    declaration: object,
    *,
    lock_format: str,
    subject: str,
    record_issue: Callable[[str, str, str | None], None],
) -> LockedDependency | None:
    if lock_format == "uv":
        if not isinstance(declaration, dict):
            record_issue(
                "invalid_lock_dependency",
                "锁文件依赖声明无效，已跳过。",
                subject,
            )
            return None
        version_value = declaration.get("version")
    elif isinstance(declaration, str):
        version_value = declaration
        declaration = {}
    elif isinstance(declaration, dict):
        version_value = declaration.get("version")
    else:
        record_issue(
            "invalid_lock_dependency",
            "锁文件依赖声明无效，已跳过。",
            subject,
        )
        return None

    if not isinstance(name_value, str) or not name_value.strip():
        record_issue(
            "invalid_lock_dependency_name",
            "锁文件依赖名称无效，已跳过。",
            subject,
        )
        return None
    name = name_value.strip()
    if len(name) > MAX_LOCK_NAME_CHARS or _VALID_NAME.fullmatch(name) is None:
        record_issue(
            "invalid_lock_dependency_name",
            "锁文件依赖名称无效，已跳过。",
            subject,
        )
        return None

    version: str | None = None
    if version_value is not None:
        if not isinstance(version_value, str) or not version_value.strip():
            record_issue(
                "invalid_lock_dependency_version",
                "锁文件依赖版本无效，已跳过。",
                subject,
            )
            return None
        version = version_value.strip()
        if (
            len(version) > MAX_LOCK_DEPENDENCY_VERSION_CHARS
            or _has_control_characters(version)
        ):
            record_issue(
                "invalid_lock_dependency_version",
                "锁文件依赖版本无效或超出长度限制，已跳过。",
                subject,
            )
            return None

    source_kind, source_notes, source_valid = _dependency_source_information(
        declaration
    )
    if not source_valid:
        record_issue(
            "invalid_lock_dependency_source",
            "锁文件依赖来源无效，已跳过。",
            subject,
        )
        return None
    if "unsafe_path" in source_notes:
        record_issue(
            "unsafe_lock_dependency_source",
            "锁文件依赖来源包含不安全的本地路径，来源标识已省略。",
            subject,
        )
    elif "invalid" in source_notes:
        record_issue(
            "invalid_lock_dependency_source",
            "锁文件依赖来源无效，来源标识已省略。",
            subject,
        )
    if "credentials_removed" in source_notes:
        record_issue(
            "lock_dependency_source_credentials_removed",
            "锁文件依赖来源中的凭据已移除。",
            subject,
        )

    return LockedDependency(
        name=name,
        normalized_name=canonicalize_name(name),
        version=version,
        source_kind=source_kind,
    )


def _dependency_source_information(
    declaration: dict[str, object],
) -> tuple[str | None, tuple[str, ...], bool]:
    nested = declaration.get("source")
    direct_source = any(key in declaration for key in _SOURCE_KINDS)
    if isinstance(nested, dict):
        kind, _, notes, valid = _source_information(nested, missing_kind=None)
        return kind, notes, valid or kind is not None
    if nested is not None and not direct_source:
        if not isinstance(nested, str):
            return None, ("invalid",), False
        source_name = nested.strip()
        if (
            not source_name
            or len(source_name) > MAX_LOCK_SOURCE_CHARS
            or _has_control_characters(source_name)
        ):
            return None, ("invalid",), False
        return "registry", (), True
    kind, _, notes, valid = _source_information(
        declaration if direct_source else None,
        missing_kind=None,
    )
    return kind, notes, valid or kind is not None


def _source_information(
    value: object,
    *,
    missing_kind: str | None,
) -> tuple[str | None, str | None, tuple[str, ...], bool]:
    if value is None:
        return missing_kind, None, (), True
    if not isinstance(value, dict):
        return missing_kind, None, ("invalid",), False

    source_type = value.get("type")
    if source_type is not None:
        if not isinstance(source_type, str):
            return missing_kind, None, ("invalid",), False
        normalized_type = source_type.strip().casefold()
        if (
            not normalized_type
            or len(normalized_type) > MAX_LOCK_SOURCE_CHARS
            or _has_control_characters(normalized_type)
        ):
            return missing_kind, None, ("invalid",), False
        kind = _POETRY_SOURCE_KINDS.get(normalized_type)
        if kind is None:
            return missing_kind, None, ("invalid",), False
        if kind == "path" and value.get("develop") is True:
            kind = "editable"
        candidate = value.get("url")
    else:
        present_kinds = [kind for kind in _SOURCE_KINDS if kind in value]
        if len(present_kinds) > 1:
            return missing_kind, None, ("invalid",), False
        if not present_kinds:
            return missing_kind, None, ("invalid",), False
        kind = present_kinds[0]
        if kind == "path" and value.get("develop") is True:
            kind = "editable"
        candidate = value.get(kind)
        if kind == "editable" and "editable" not in value:
            candidate = value.get("path")

    digest = _source_digest(value)
    if digest is False:
        return kind, None, ("invalid",), False
    if isinstance(digest, str):
        return kind, digest, (), True

    if kind == "git":
        revision, revision_valid = _source_revision(value)
        if not revision_valid:
            return kind, None, ("invalid",), False
        if revision is not None:
            return kind, revision, (), True

    if candidate is True and kind in {"workspace", "virtual"}:
        candidate = "."
    if not isinstance(candidate, str) or not candidate.strip():
        return kind, None, ("invalid",), False
    candidate = candidate.strip()
    if len(candidate) > MAX_LOCK_SOURCE_CHARS or _has_control_characters(candidate):
        return kind, None, ("invalid",), False

    if kind in _LOCAL_SOURCE_KINDS:
        identity = _normalize_relative_source_path(candidate)
        if identity is None:
            return kind, None, ("unsafe_path",), False
        return kind, identity, (), True

    identity, credentials_removed, fragment_identity = _sanitize_source_url(
        candidate, git_source=kind == "git"
    )
    if identity is None:
        return kind, None, ("invalid",), False
    notes = ("credentials_removed",) if credentials_removed else ()
    return kind, fragment_identity or identity, notes, True


def _source_digest(value: dict[str, object]) -> str | bool | None:
    for key in ("hash", "sha256"):
        if key not in value:
            continue
        raw = value[key]
        if not isinstance(raw, str) or _has_control_characters(raw):
            return False
        matched = _SHA256.fullmatch(raw.strip())
        if matched is None:
            return False
        return f"sha256:{matched.group(1).lower()}"
    return None


def _source_revision(value: dict[str, object]) -> tuple[str | None, bool]:
    for key in (
        "resolved_reference",
        "resolved-revision",
        "resolved_revision",
        "commit",
        "rev",
        "reference",
    ):
        if key not in value:
            continue
        raw = value[key]
        if not isinstance(raw, str):
            return None, False
        revision = raw.strip()
        if len(revision) > MAX_LOCK_SOURCE_CHARS or _has_control_characters(revision):
            return None, False
        if _IMMUTABLE_GIT_REVISION.fullmatch(revision) is not None:
            return revision.lower(), True
    return None, True


def _sanitize_source_url(
    value: str,
    *,
    git_source: bool,
) -> tuple[str | None, bool, str | None]:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return None, False, None
    if parsed.scheme.casefold() not in {"http", "https"} or not hostname:
        return None, False, None
    raw_userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else None
    if (
        "\\" in parsed.netloc
        or "\\" in parsed.path
        or parsed.netloc.count("@") > 1
        or (raw_userinfo is not None and "%" in raw_userinfo)
        or not _url_component_has_safe_encoding(parsed.netloc, reject_whitespace=True)
        or not _url_component_has_safe_encoding(parsed.path)
    ):
        return None, False, None

    credentials_removed = parsed.username is not None or parsed.password is not None
    normalized_host = _normalize_url_hostname(hostname)
    if normalized_host is None:
        return None, credentials_removed, None
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    sanitized = urlunsplit(
        SplitResult(parsed.scheme.casefold(), netloc, parsed.path, "", "")
    )
    if len(sanitized) > MAX_LOCK_SOURCE_CHARS:
        return None, credentials_removed, None

    fragment_identity: str | None = None
    fragment = parsed.fragment.strip()
    digest_match = _SHA256.fullmatch(fragment)
    if git_source and _IMMUTABLE_GIT_REVISION.fullmatch(fragment) is not None:
        fragment_identity = fragment.lower()
    elif digest_match is not None:
        fragment_identity = f"sha256:{digest_match.group(1).lower()}"
    return sanitized, credentials_removed, fragment_identity


def _url_component_has_safe_encoding(
    value: str,
    *,
    reject_whitespace: bool = False,
) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in "0123456789abcdefABCDEF"
            or value[index + 2] not in "0123456789abcdefABCDEF"
        ):
            return False
        index += 3
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except (UnicodeError, ValueError):
        return False
    if _has_control_characters(decoded):
        return False
    return not reject_whitespace or not any(character.isspace() for character in decoded)


def _normalize_url_hostname(hostname: str) -> str | None:
    if "%" in hostname or _has_control_characters(hostname):
        return None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.replace(".", "").isdigit():
            return None
        trailing_dot = hostname.endswith(".")
        dns_name = hostname[:-1] if trailing_dot else hostname
        try:
            ascii_name = dns_name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if (
            not ascii_name
            or len(ascii_name) > 253
            or any(_DNS_LABEL.fullmatch(label) is None for label in ascii_name.split("."))
        ):
            return None
        return ascii_name.casefold() + ("." if trailing_dot else "")
    return address.compressed.casefold()


def _normalize_relative_source_path(value: str) -> str | None:
    slash_path = value.replace("\\", "/")
    if (
        slash_path.startswith(("/", "~"))
        or slash_path.casefold().startswith("file:")
        or _WINDOWS_DRIVE_PREFIX.match(slash_path) is not None
        or ":" in slash_path
    ):
        return None
    normalized = posixpath.normpath(slash_path)
    if normalized == ".." or normalized.startswith("../"):
        return None
    if normalized.startswith("//") or any(
        part == ".." for part in normalized.split("/")
    ):
        return None
    for part in normalized.split("/"):
        windows_name = part.split(".", 1)[0].rstrip(" ").casefold()
        if windows_name in _WINDOWS_RESERVED_NAMES:
            return None
    return normalized


def _has_control_characters(value: str) -> bool:
    return any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    )


def _dependency_sort_key(
    dependency: LockedDependency,
) -> tuple[str, int, str, int, str, str]:
    return (
        dependency.normalized_name,
        dependency.version is not None,
        dependency.version or "",
        dependency.source_kind is not None,
        dependency.source_kind or "",
        dependency.name,
    )


def _dependency_identity_key(
    dependency: LockedDependency,
) -> tuple[str, str | None, str | None]:
    return (
        dependency.normalized_name,
        dependency.version,
        dependency.source_kind,
    )


def _package_sort_key(
    package: LockedPackage,
) -> tuple[object, ...]:
    return (
        package.normalized_name,
        package.version,
        package.source_kind,
        package.source_identity or "",
        tuple(_dependency_sort_key(item) for item in package.dependencies),
        package.name,
    )


def _read_regular_file(path: Path) -> tuple[bytes, Path]:
    try:
        before = path.lstat()
    except (OSError, RuntimeError, TypeError):
        raise LockfileError("lockfile_unreadable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LockfileError("unsafe_lockfile")
    if before.st_size > MAX_LOCKFILE_BYTES:
        raise LockfileError("lockfile_too_large")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise LockfileError("unsafe_lockfile")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise LockfileError("unsafe_lockfile")
        if opened.st_size > MAX_LOCKFILE_BYTES:
            raise LockfileError("lockfile_too_large")
        chunks: list[bytes] = []
        remaining = MAX_LOCKFILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_LOCKFILE_BYTES:
            raise LockfileError("lockfile_too_large")
        resolved = path.resolve(strict=True)
    except LockfileError:
        raise
    except (OSError, RuntimeError, TypeError):
        raise LockfileError("lockfile_unreadable") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return payload, resolved
