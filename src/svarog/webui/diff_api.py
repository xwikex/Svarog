"""Web-facing semantic comparison without filesystem or browser-supplied scope."""

from __future__ import annotations

from svarog.audit_diff.reporting import diff_payload
from svarog.audit_diff.service import DiffService
from svarog.audit_history.repository import HistoryRepository

from .history_api import snapshot_kind


def compare_snapshots(
    repository: HistoryRepository, project_id: str, *,
    baseline_snapshot_id: int | None, target_snapshot_id: int,
) -> dict[str, object]:
    kind = snapshot_kind(repository, project_id, target_snapshot_id)
    report = DiffService(repository).compare_snapshots(
        project_id, kind, baseline_snapshot_id, target_snapshot_id,
    )
    return diff_payload(report)
