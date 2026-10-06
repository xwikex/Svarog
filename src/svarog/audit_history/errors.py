"""Stable, non-sensitive audit-history errors."""


class HistoryDatabaseError(RuntimeError):
    """A database operation failed with a public, stable error code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
