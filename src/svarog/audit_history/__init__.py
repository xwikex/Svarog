"""Versioned SQLite storage foundations for Svarog audit history."""

from .database import DatabaseManager, immediate_transaction
from .errors import HistoryDatabaseError
from .migrations import APPLICATION_ID, CURRENT_SCHEMA_VERSION
from .models import FindingStatus, PackageScope, RunStatus

__all__ = [
    "APPLICATION_ID",
    "CURRENT_SCHEMA_VERSION",
    "DatabaseManager",
    "FindingStatus",
    "HistoryDatabaseError",
    "PackageScope",
    "RunStatus",
    "immediate_transaction",
]
