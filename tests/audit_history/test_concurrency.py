from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from svarog.audit_history.database import DatabaseManager
from svarog.audit_history.models import RunStatus
from svarog.audit_history.repository import HistoryRepository

from .test_repository import RUN_1, RUN_2, _snapshot


def test_two_connections_racing_identical_snapshot_compute_once(tmp_path: Path) -> None:
    path = tmp_path / "race.sqlite3"
    with DatabaseManager.open(path):
        pass
    barrier = Barrier(2)

    def save(run_id: str):
        with DatabaseManager.open(path) as database:
            repository = HistoryRepository(database.connection)
            barrier.wait()
            return repository.save_run(_snapshot(), run_id=run_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(save, (RUN_1, RUN_2)))

    assert sorted(result.reused for result in results) == [False, True]
    computed = next(result for result in results if not result.reused)
    reused = next(result for result in results if result.reused)
    assert computed.snapshot_id == reused.snapshot_id

    with DatabaseManager.open(path) as database:
        repository = HistoryRepository(database.connection)
        assert database.connection.execute(
            "SELECT COUNT(*) FROM audit_snapshots"
        ).fetchone() == (1,)
        assert repository.get_run(computed.run_id).status is RunStatus.COMPLETED_COMPUTED
        reused_run = repository.get_run(reused.run_id)
        assert reused_run.status is RunStatus.COMPLETED_REUSED
        assert reused_run.baseline_run_id == computed.run_id
