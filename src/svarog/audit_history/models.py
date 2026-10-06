"""Small storage-stable value types for audit history."""

from enum import Enum


class RunStatus(str, Enum):
    STARTED = "started"
    COMPLETED_COMPUTED = "completed_computed"
    COMPLETED_REUSED = "completed_reused"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class PackageScope(str, Enum):
    ENVIRONMENT = "environment"
    LOCK = "lock"


class FindingStatus(str, Enum):
    AFFECTED = "affected"
    INDETERMINATE = "indeterminate"
