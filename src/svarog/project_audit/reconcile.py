"""Compare installed package versions with every version present in a lockfile."""

from __future__ import annotations

from collections import defaultdict

from svarog.dependency_audit.models import InventoryResult

from .models import DifferenceStatus, LockSnapshot, VersionDifference

__all__ = [
    "DifferenceStatus",
    "VersionDifference",
    "reconcile_environment_with_lock",
]


def reconcile_environment_with_lock(
    inventory: InventoryResult,
    lock: LockSnapshot,
) -> tuple[VersionDifference, ...]:
    """Return one deterministic comparison result per normalized package name."""

    installed: dict[str, list[object]] = defaultdict(list)
    locked: dict[str, list[object]] = defaultdict(list)
    for package in inventory.packages:
        installed[package.normalized_name].append(package)
    for package in lock.packages:
        locked[package.normalized_name].append(package)

    results: list[VersionDifference] = []
    for normalized_name in sorted(set(installed) | set(locked)):
        installed_packages = installed.get(normalized_name, [])
        locked_packages = locked.get(normalized_name, [])
        installed_versions = tuple(sorted({item.version for item in installed_packages}))
        locked_versions = tuple(sorted({item.version for item in locked_packages}))

        if normalized_name in inventory.ambiguous_names or len(installed_versions) > 1:
            status = DifferenceStatus.AMBIGUOUS
        elif any(not item.version_valid for item in installed_packages + locked_packages):
            status = DifferenceStatus.INDETERMINATE
        elif installed_packages and locked_packages:
            status = (
                DifferenceStatus.MATCHED
                if installed_versions[0] in locked_versions
                else DifferenceStatus.VERSION_MISMATCH
            )
        elif locked_packages:
            status = DifferenceStatus.MISSING
        else:
            status = DifferenceStatus.UNEXPECTED

        display_names = [item.name for item in locked_packages] or [
            item.name for item in installed_packages
        ]
        results.append(
            VersionDifference(
                name=sorted(display_names, key=lambda value: (value.casefold(), value))[0],
                normalized_name=normalized_name,
                installed_versions=installed_versions,
                locked_versions=locked_versions,
                status=status,
            )
        )

    return tuple(results)
