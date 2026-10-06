"""Small read-only adapter for persisted audit history."""

from __future__ import annotations

from dataclasses import asdict

from svarog.audit_diff.service import DiffService
from svarog.audit_history.errors import HistoryDatabaseError
from svarog.audit_history.repository import HistoryRepository


_KINDS = ("python_project", "python_environment")


def snapshot_kind(repository: HistoryRepository, project_id: str, snapshot_id: int) -> str:
    """Find the audit kind without allowing an out-of-project snapshot to leak."""

    for kind in _KINDS:
        try:
            repository.get_snapshot_summary(snapshot_id, project_id=project_id, audit_kind=kind)
        except HistoryDatabaseError as error:
            if error.code != "snapshot_not_found":
                raise
        else:
            return kind
    raise HistoryDatabaseError("snapshot_not_found")


def list_history(
    repository: HistoryRepository, project_id: str, *,
    audit_kind: str | None = None, run_status: str | None = None,
    reused: bool | None = None, completed_from: str | None = None,
    completed_to: str | None = None, limit: int = 20, offset: int = 0,
) -> dict[str, object]:
    page = repository.list_runs(
        project_id, audit_kind=audit_kind, run_status=run_status, reused=reused,
        completed_from=completed_from, completed_to=completed_to,
        limit=limit, offset=offset,
    )
    classifications = DiffService(repository).classifications_for_runs(
        project_id, tuple(run.run_id for run in page.items),
    )
    items = []
    for run in page.items:
        row = {
            "run_id": run.run_id,
            "snapshot_id": run.snapshot_id,
            "baseline_run_id": run.baseline_run_id,
            "audit_kind": run.audit_kind,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "status": run.status.value,
            "reused": run.reused,
            "failure_code": run.failure_code,
            "classification": classifications.get(run.run_id),
        }
        if run.snapshot_id is not None:
            summary = repository.get_snapshot_summary(
                run.snapshot_id, project_id=project_id, audit_kind=run.audit_kind,
            )
            row["summary"] = {
                "audit_status": summary.audit_status,
                "environment_package_count": summary.environment_package_count,
                "lock_package_count": summary.lock_package_count,
                "affected_finding_count": summary.affected_finding_count,
                "indeterminate_finding_count": summary.indeterminate_finding_count,
                "issue_count": summary.issue_count,
            }
        items.append(row)
    return {
        "project_id": project_id,
        "items": items,
        "total_count": page.total_count,
        "limit": page.limit,
        "offset": page.offset,
    }


def get_snapshot(
    repository: HistoryRepository, project_id: str, snapshot_id: int, *,
    limit: int = 50, offset: int = 0,
) -> dict[str, object]:
    kind = snapshot_kind(repository, project_id, snapshot_id)
    summary = repository.get_snapshot_summary(snapshot_id, project_id=project_id, audit_kind=kind)
    pages = {}
    for label, method in (
        ("packages", repository.list_snapshot_packages),
        ("findings", repository.list_snapshot_findings),
        ("dependencies", repository.list_snapshot_dependencies),
        ("issues", repository.list_snapshot_issues),
    ):
        page = method(snapshot_id, project_id=project_id, audit_kind=kind,
                      limit=limit, offset=offset)
        pages[label] = {
            "items": [asdict(row) for row in page.items],
            "total_count": page.total_count,
            "limit": page.limit,
            "offset": page.offset,
        }
    return {"summary": asdict(summary), **pages}
