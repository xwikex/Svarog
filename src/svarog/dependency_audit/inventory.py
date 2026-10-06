"""Read installed Python distribution metadata without executing the environment."""

from email import policy
from email.parser import BytesParser
import os
import heapq
from pathlib import Path
import stat
import sys
import sysconfig

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import AuditIssue, InstalledPackage, InventoryResult


MAX_METADATA_BYTES = 1024 * 1024
MAX_METADATA_DIRS = 10_000
MAX_NAME_CHARS = 256
MAX_VERSION_CHARS = 128


class InventoryError(ValueError):
    """A non-sensitive error while validating an environment path."""


def inventory_python_environment(path: Path) -> InventoryResult:
    """Inventory direct ``*.dist-info/METADATA`` files in a virtual environment."""
    environment = _resolve_environment(path)
    _validate_configuration(environment)
    site_packages = _find_site_packages(environment)
    return _inventory_roots(environment, site_packages)


def inventory_current_python_environment() -> InventoryResult:
    """Inventory the Python environment currently running Svarog."""
    environment = _resolve_environment(Path(sys.prefix))
    site_packages = _current_site_packages(environment)
    return _inventory_roots(environment, site_packages)


def _inventory_roots(
    environment: Path,
    site_packages: tuple[Path, ...],
) -> InventoryResult:

    issues: list[AuditIssue] = []
    candidates: list[InstalledPackage] = []
    metadata_directories, total_metadata_dirs = _select_metadata_directories(
        site_packages, issues, limit=MAX_METADATA_DIRS
    )
    for site_root, metadata_dir in metadata_directories:
        package = _read_package(metadata_dir, site_root, issues)
        if package is not None:
            candidates.append(package)

    packages, aggregate_issues, ambiguous_names = _aggregate_packages(candidates)
    issues.extend(aggregate_issues)
    return InventoryResult(
        environment_path=str(environment),
        site_packages=tuple(str(root) for root in site_packages),
        packages=packages,
        ambiguous_names=frozenset(ambiguous_names),
        issues=tuple(issues),
        total_metadata_dirs=total_metadata_dirs,
        truncated_metadata_dirs=max(0, total_metadata_dirs - MAX_METADATA_DIRS),
    )


def _resolve_environment(path: Path) -> Path:
    try:
        environment = Path(path).resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        raise InventoryError("invalid_environment") from None
    if not environment.is_dir():
        raise InventoryError("invalid_environment")
    return environment


def _validate_configuration(environment: Path) -> None:
    configuration = environment / "pyvenv.cfg"
    try:
        resolved = configuration.resolve(strict=True)
    except (OSError, RuntimeError):
        raise InventoryError("invalid_environment") from None
    if not _within(resolved, environment):
        raise InventoryError("environment_configuration_escape")
    try:
        regular_file = resolved.is_file()
    except OSError:
        regular_file = False
    if not regular_file:
        raise InventoryError("invalid_environment")


def _find_site_packages(environment: Path) -> tuple[Path, ...]:
    return _validated_site_packages(
        environment,
        _site_package_candidates(environment),
    )


def _current_site_packages(environment: Path) -> tuple[Path, ...]:
    try:
        paths = sysconfig.get_paths()
        candidates = tuple(
            Path(value)
            for key in ("purelib", "platlib")
            if isinstance((value := paths.get(key)), str) and value
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        raise InventoryError("invalid_site_packages_count") from None
    return _validated_site_packages(environment, candidates)


def _validated_site_packages(
    environment: Path,
    candidates,
) -> tuple[Path, ...]:
    resolved_roots: dict[tuple[int, int], Path] = {}
    try:
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError, TypeError):
                raise InventoryError("invalid_site_packages_count") from None
            if not _within(resolved, environment):
                raise InventoryError("site_packages_escape")
            try:
                if not resolved.is_dir():
                    raise InventoryError("invalid_site_packages_count")
                root_stat = resolved.stat()
            except OSError:
                raise InventoryError("invalid_site_packages_count") from None
            identity = (root_stat.st_dev, root_stat.st_ino)
            if identity not in resolved_roots:
                resolved_roots[identity] = resolved
                if len(resolved_roots) > 2:
                    raise InventoryError("invalid_site_packages_count")
    except (OSError, RuntimeError):
        raise InventoryError("invalid_site_packages_count") from None

    roots = tuple(sorted(resolved_roots.values(), key=str))
    if not 1 <= len(roots) <= 2:
        raise InventoryError("invalid_site_packages_count")
    return roots


def _site_package_candidates(environment: Path):
    for base in ("lib", "lib64"):
        yield from environment.glob(f"{base}/python*/site-packages")
    windows = environment / "Lib" / "site-packages"
    if windows.exists():
        yield windows


def _select_metadata_directories(
    site_packages: tuple[Path, ...], issues: list[AuditIssue], limit: int
) -> tuple[list[tuple[Path, Path]], int]:
    """Return the stable first ``limit`` metadata directories without retaining all."""
    selected: list[tuple[_ReverseKey, Path, Path]] = []
    total = 0
    for site_root in site_packages:
        try:
            for child in site_root.iterdir():
                if not child.name.endswith(".dist-info"):
                    continue
                try:
                    if not child.is_dir():
                        continue
                except OSError:
                    issues.append(_issue("metadata_directory_unreadable", child))
                    continue
                total += 1
                if limit <= 0:
                    continue
                key = _ReverseKey((str(site_root), child.name))
                if len(selected) < limit:
                    heapq.heappush(selected, (key, site_root, child))
                elif key.value < selected[0][0].value:
                    heapq.heapreplace(selected, (key, site_root, child))
        except OSError:
            issues.append(_issue("site_packages_read_error", site_root))
    stable = sorted(((site_root, child) for _, site_root, child in selected), key=lambda item: (str(item[0]), item[1].name))
    return stable, total


class _ReverseKey:
    """Invert lexical ordering so ``heapq`` exposes the largest retained key."""

    def __init__(self, value: tuple[str, str]) -> None:
        self.value = value

    def __lt__(self, other: "_ReverseKey") -> bool:
        return self.value > other.value


def _read_package(metadata_dir: Path, site_root: Path, issues: list[AuditIssue]) -> InstalledPackage | None:
    metadata = metadata_dir / "METADATA"
    try:
        resolved = metadata.resolve(strict=True)
    except FileNotFoundError:
        issues.append(_issue("metadata_missing", metadata))
        return None
    except (OSError, RuntimeError):
        issues.append(_issue("metadata_unreadable", metadata))
        return None
    if not _within(resolved, site_root):
        issues.append(_issue("metadata_escape", resolved))
        return None
    contents, read_error = _read_metadata_file(metadata_dir, site_root)
    if read_error is not None:
        issues.append(_issue(read_error, resolved))
        return None

    try:
        parsed = BytesParser(policy=policy.default).parsebytes(contents)
        name = _field_value(parsed.get("Name"))
        version = _field_value(parsed.get("Version"))
    except Exception:
        issues.append(_issue("invalid_metadata", resolved))
        return None
    if not name or not version:
        issues.append(_issue("missing_package_identity", resolved))
        return None
    if not _valid_identity(name, MAX_NAME_CHARS) or not _valid_identity(version, MAX_VERSION_CHARS):
        issues.append(_issue("invalid_metadata", resolved))
        return None

    try:
        Version(version)
        version_valid = True
    except InvalidVersion:
        version_valid = False
    return InstalledPackage(name, canonicalize_name(name), version, version_valid, str(resolved))


def _read_metadata_file(metadata_dir: Path, site_root: Path) -> tuple[bytes | None, str | None]:
    """Read METADATA through a bounded descriptor, without following file links."""
    if os.name == "posix":
        return _read_metadata_file_posix(metadata_dir, site_root)
    return _read_metadata_file_fallback(metadata_dir)


def _read_metadata_file_posix(metadata_dir: Path, site_root: Path) -> tuple[bytes | None, str | None]:
    try:
        resolved_directory = metadata_dir.resolve(strict=True)
    except FileNotFoundError:
        return None, "metadata_missing"
    except (OSError, RuntimeError):
        return None, "metadata_unreadable"
    if not _within(resolved_directory, site_root):
        return None, "metadata_escape"

    directory_fd = -1
    metadata_fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(site_root, flags)
        for component in resolved_directory.relative_to(site_root).parts:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        metadata_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        metadata_fd = os.open("METADATA", metadata_flags, dir_fd=directory_fd)
        return _read_open_metadata(metadata_fd)
    except FileNotFoundError:
        return None, "metadata_missing"
    except OSError:
        return None, "metadata_unreadable"
    finally:
        if metadata_fd >= 0:
            os.close(metadata_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def _read_metadata_file_fallback(metadata_dir: Path) -> tuple[bytes | None, str | None]:
    metadata = metadata_dir / "METADATA"
    try:
        metadata_stat = metadata.lstat()
        if not stat.S_ISREG(metadata_stat.st_mode):
            return None, "metadata_not_regular_file"
        descriptor = os.open(metadata, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        return None, "metadata_missing"
    except OSError:
        return None, "metadata_unreadable"
    try:
        return _read_open_metadata(descriptor)
    finally:
        os.close(descriptor)


def _read_open_metadata(descriptor: int) -> tuple[bytes | None, str | None]:
    try:
        metadata_stat = os.fstat(descriptor)
    except OSError:
        return None, "metadata_unreadable"
    if not stat.S_ISREG(metadata_stat.st_mode):
        return None, "metadata_not_regular_file"
    if metadata_stat.st_size > MAX_METADATA_BYTES:
        return None, "metadata_too_large"

    chunks: list[bytes] = []
    total = 0
    try:
        while total <= MAX_METADATA_BYTES:
            chunk = os.read(descriptor, MAX_METADATA_BYTES + 1 - total)
            if not chunk:
                return b"".join(chunks), None
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None, "metadata_unreadable"
    return None, "metadata_too_large"


def _field_value(value: object | None) -> str:
    return "" if value is None else str(value).strip()


def _valid_identity(value: str, maximum_length: int) -> bool:
    return len(value) <= maximum_length and not any(ord(character) <= 31 or ord(character) == 127 for character in value)


def _aggregate_packages(
    candidates: list[InstalledPackage],
) -> tuple[tuple[InstalledPackage, ...], list[AuditIssue], set[str]]:
    unique: dict[tuple[str, str], InstalledPackage] = {}
    versions_by_name: dict[str, set[str]] = {}
    issues: list[AuditIssue] = []
    for package in candidates:
        key = (package.normalized_name, package.version)
        if key in unique:
            issues.append(_issue("duplicate_metadata", Path(package.metadata_path)))
            continue
        unique[key] = package
        versions_by_name.setdefault(package.normalized_name, set()).add(package.version)

    ambiguous_names = {name for name, versions in versions_by_name.items() if len(versions) > 1}
    for name in sorted(ambiguous_names):
        issues.append(AuditIssue("ambiguous_versions", "ambiguous_versions", name))
    packages = tuple(sorted(unique.values(), key=lambda package: (package.normalized_name, package.version)))
    return packages, issues, ambiguous_names


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _issue(code: str, path: Path) -> AuditIssue:
    return AuditIssue(code, code, str(path))
