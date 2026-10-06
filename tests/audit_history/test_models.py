from dataclasses import FrozenInstanceError

import pytest

from svarog.audit_history.models import FindingStatus, PackageScope, RunStatus


def test_storage_enums_have_stable_values() -> None:
    assert [status.value for status in RunStatus] == [
        "started",
        "completed_computed",
        "completed_reused",
        "failed",
        "interrupted",
    ]
    assert [scope.value for scope in PackageScope] == ["environment", "lock"]
    assert [status.value for status in FindingStatus] == [
        "affected",
        "indeterminate",
    ]


def test_storage_enums_are_immutable_string_values() -> None:
    assert RunStatus.STARTED == "started"
    with pytest.raises((AttributeError, FrozenInstanceError)):
        RunStatus.STARTED.value = "changed"  # type: ignore[misc]
