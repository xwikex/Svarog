"""Read target Python identity without running the target interpreter."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat


_MAX_CONFIG_BYTES = 64 * 1024
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z", re.ASCII)
_VERSION = re.compile(
    r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z",
    re.ASCII,
)
_PLAUSIBLE_VERSION = re.compile(
    r"[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}(?:(?:a|b|rc)[0-9]{1,9})?\Z",
    re.ASCII,
)
_IMPLEMENTATION = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}\Z", re.ASCII)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _read_configuration(environment: Path) -> str:
    try:
        root = Path(environment).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("invalid_target_python")
        configuration = root / "pyvenv.cfg"
        resolved = configuration.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("invalid_target_python") from None
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("target_python_escape") from None
    try:
        # Disallow even in-tree config links to avoid a check/open symlink swap.
        if configuration.is_symlink():
            raise ValueError("invalid_target_python")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(configuration, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CONFIG_BYTES:
                raise ValueError("invalid_target_python")
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ValueError("invalid_target_python")
        return raw.decode("utf-8-sig", errors="strict")
    except (OSError, RuntimeError, TypeError, UnicodeError):
        raise ValueError("invalid_target_python") from None


def read_target_python(environment: Path) -> tuple[str, tuple[int, int, int] | str]:
    """Return validated implementation/version; absent facts remain ``unknown``."""
    contents = _read_configuration(environment)
    if _CONTROL.search(contents):
        raise ValueError("invalid_target_python")
    fields: dict[str, str] = {}
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("invalid_target_python")
        key, value = (part.strip() for part in line.split("=", 1))
        if not _KEY.fullmatch(key):
            raise ValueError("invalid_target_python")
        key = key.lower()
        if key in fields and key in {"version", "implementation"}:
            raise ValueError("invalid_target_python")
        fields[key] = value

    version: tuple[int, int, int] | str = "unknown"
    if "version" in fields:
        match = _VERSION.fullmatch(fields["version"])
        if match is None:
            value = fields["version"]
            if len(value) > 32 or _PLAUSIBLE_VERSION.fullmatch(value) is None:
                raise ValueError("invalid_target_python")
        else:
            version = tuple(int(part) for part in match.groups())

    implementation = fields.get("implementation", "unknown")
    if not _IMPLEMENTATION.fullmatch(implementation):
        raise ValueError("invalid_target_python")
    return implementation.lower(), version
