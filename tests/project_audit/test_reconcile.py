from __future__ import annotations

import pytest

from svarog.dependency_audit.models import InstalledPackage, InventoryResult
from svarog.project_audit.models import LockedPackage, LockSnapshot
from svarog.project_audit.reconcile import (
    DifferenceStatus,
    reconcile_environment_with_lock,
)


def _inventory(
    *packages: tuple[str, str, bool],
    ambiguous: frozenset[str] = frozenset(),
) -> InventoryResult:
    return InventoryResult(
        environment_path="C:/project/.venv",
        site_packages=("C:/project/.venv/Lib/site-packages",),
        packages=tuple(
            InstalledPackage(
                name=name,
                normalized_name=name,
                version=version,
                version_valid=valid,
                metadata_path=f"C:/metadata/{name}-{version}",
            )
            for name, version, valid in packages
        ),
        ambiguous_names=ambiguous,
        issues=(),
        total_metadata_dirs=len(packages),
        truncated_metadata_dirs=0,
    )


def _lock(*packages: tuple[str, str, bool]) -> LockSnapshot:
    return LockSnapshot(
        path="C:/project/uv.lock",
        lock_format="uv",
        packages=tuple(
            LockedPackage(
                name=name,
                normalized_name=name,
                version=version,
                version_valid=valid,
                source_kind="registry",
            )
            for name, version, valid in packages
        ),
        issues=(),
        total_package_entries=len(packages),
        total_issue_count=0,
        truncated_issue_count=0,
    )


@pytest.mark.parametrize(
    ("inventory", "lock", "expected"),
    [
        (
            _inventory(("demo", "1.0", True)),
            _lock(("demo", "1.0", True)),
            DifferenceStatus.MATCHED,
        ),
        (
            _inventory(("demo", "3.0", True)),
            _lock(("demo", "1.0", True), ("demo", "2.0", True)),
            DifferenceStatus.VERSION_MISMATCH,
        ),
        (
            _inventory(),
            _lock(("demo", "1.0", True)),
            DifferenceStatus.MISSING,
        ),
        (
            _inventory(("demo", "1.0", True)),
            _lock(),
            DifferenceStatus.UNEXPECTED,
        ),
        (
            _inventory(("demo", "1.0", True), ambiguous=frozenset({"demo"})),
            _lock(("demo", "1.0", True)),
            DifferenceStatus.AMBIGUOUS,
        ),
        (
            _inventory(("demo", "invalid", False)),
            _lock(("demo", "invalid", False)),
            DifferenceStatus.INDETERMINATE,
        ),
    ],
)
def test_reconcile_assigns_stable_statuses(
    inventory: InventoryResult,
    lock: LockSnapshot,
    expected: DifferenceStatus,
) -> None:
    result = reconcile_environment_with_lock(inventory, lock)

    assert len(result) == 1
    assert result[0].status is expected


def test_reconcile_treats_all_locked_versions_as_one_membership_set() -> None:
    inventory = _inventory(("demo", "2.0", True))
    lock = _lock(
        ("demo", "1.0", True),
        ("demo", "2.0", True),
        ("demo", "3.0", True),
    )

    result = reconcile_environment_with_lock(inventory, lock)

    assert len(result) == 1
    assert result[0].status is DifferenceStatus.MATCHED
    assert result[0].installed_versions == ("2.0",)
    assert result[0].locked_versions == ("1.0", "2.0", "3.0")


def test_reconcile_sorts_by_normalized_name_and_deduplicates_versions() -> None:
    inventory = _inventory(("zeta", "1", True), ("alpha", "2", True))
    lock = _lock(
        ("zeta", "1", True),
        ("alpha", "2", True),
        ("alpha", "2", True),
    )

    result = reconcile_environment_with_lock(inventory, lock)

    assert [item.normalized_name for item in result] == ["alpha", "zeta"]
    assert result[0].locked_versions == ("2",)
