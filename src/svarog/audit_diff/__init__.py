"""Semantic differences between immutable audit snapshots."""

from .service import DiffService, classify_change

__all__ = ["DiffService", "classify_change"]
