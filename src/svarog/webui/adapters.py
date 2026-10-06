"""Thin Web UI orchestration over Svarog's existing domain services."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from collections.abc import Callable

from svarog import doctor as _doctor
from svarog.dependency_audit.inventory import (
    inventory_python_environment as _inventory_python_environment,
)
from svarog.dependency_audit.models import (
    DependencyAuditReport,
    InventoryResult,
    VulnerabilitySnapshot,
)
from svarog.dependency_audit.remote_repository import (
    load_remote_vulnerability_snapshot as _default_remote_snapshot_loader,
)
from svarog.dependency_audit.repository import (
    load_vulnerability_snapshot as _load_vulnerability_snapshot,
)
from svarog.dependency_audit.reporting import (
    render_dependency_json as _render_dependency_json,
)
from svarog.dependency_audit.service import (
    build_dependency_audit_report as _build_dependency_audit_report,
)
from svarog.parsers.nginx_json import parse_jsonl as _parse_jsonl
from svarog.policy import build_report as _build_web_report
from svarog.project_audit.lockfile import load_lock_snapshot as _load_lock_snapshot
from svarog.project_audit.models import LockSnapshot, ProjectDependencyAuditReport
from svarog.project_audit.reporting import render_project_json as _render_project_json
from svarog.project_audit.service import (
    build_project_audit_report as _build_project_audit_report,
)
from svarog.reporting import render_json as _render_web_json
from svarog.sop.agent import load_advisor as _default_advisor_loader
from svarog.sop.service import run_case as _run_case
from svarog.sop.storage import CaseStore as _CaseStore


_remote_snapshot_loader = _default_remote_snapshot_loader
_doctor_command_runner = _doctor._run_fixed_command
_doctor_database_checker = _doctor._check_database
_doctor_tcp_connector = _doctor.socket.create_connection
_advisor_loader = _default_advisor_loader


@dataclass(frozen=True, slots=True)
class _AuditExecution:
    inventory: InventoryResult
    lock: LockSnapshot | None
    vulnerability: VulnerabilitySnapshot
    report: DependencyAuditReport | ProjectDependencyAuditReport | None = None
    result: dict | None = None


def _prepare_audit(
    environment: Path,
    *,
    lock_file: Path | None,
    vuln_db: Path | None,
    vuln_api: str | None,
    token: str | None,
) -> _AuditExecution:
    vulnerability = _select_snapshot(vuln_db, vuln_api, token)
    inventory = _inventory_python_environment(environment)
    lock = None if lock_file is None else _load_lock_snapshot(lock_file)
    return _AuditExecution(inventory, lock, vulnerability)


def _complete_audit(
    prepared: _AuditExecution, *, now: datetime | None = None
) -> _AuditExecution:
    if prepared.report is not None or prepared.result is not None:
        raise ValueError("audit_already_completed")
    if prepared.lock is None:
        report = _build_dependency_audit_report(
            prepared.inventory, prepared.vulnerability, now=now
        )
        result = {
            "kind": "dependency_audit",
            "report": json.loads(_render_dependency_json(report)),
        }
    else:
        report = _build_project_audit_report(
            prepared.inventory, prepared.lock, prepared.vulnerability, now=now
        )
        result = {
            "kind": "project_audit",
            "report": json.loads(_render_project_json(report)),
        }
    return _AuditExecution(
        prepared.inventory, prepared.lock, prepared.vulnerability, report, result
    )


def analyze_web_log(path: Path) -> dict:
    parsed = _parse_jsonl(path)
    report = _build_web_report(
        parsed.events,
        parsed.issues,
        total_input_issues=parsed.total_issue_count,
    )
    return {"kind": "web_analysis", "report": json.loads(_render_web_json(report))}


def audit_python(
    environment: Path,
    *,
    vuln_db: Path | None,
    vuln_api: str | None,
    token: str | None = None,
) -> dict:
    completed = _complete_audit(
        _prepare_audit(
            environment, lock_file=None, vuln_db=vuln_db, vuln_api=vuln_api,
            token=token,
        )
    )
    if completed.result is None:
        raise RuntimeError("audit_result_missing")
    return completed.result


def audit_project(
    environment: Path,
    lock_file: Path,
    *,
    vuln_db: Path | None,
    vuln_api: str | None,
    token: str | None = None,
) -> dict:
    completed = _complete_audit(
        _prepare_audit(
            environment, lock_file=lock_file, vuln_db=vuln_db, vuln_api=vuln_api,
            token=token,
        )
    )
    if completed.result is None:
        raise RuntimeError("audit_result_missing")
    return completed.result


def audit_with_persistent_history(
    environment: Path,
    *,
    lock_file: Path | None,
    vuln_db: Path | None,
    vuln_api: str | None,
    history_db: Path,
    project_id: str,
    display_name: str,
    retention_days: int,
    token: str | None = None,
    clock: Callable[[], datetime] | None = None,
):
    """Run a UI audit through the immutable history service."""

    from svarog.audit_history.database import DatabaseManager
    from svarog.audit_history.repository import HistoryRepository
    from svarog.audit_history.service import audit_with_history
    from svarog.audit_diff.service import DiffService

    prepared = _prepare_audit(
        environment, lock_file=lock_file, vuln_db=vuln_db,
        vuln_api=vuln_api, token=token,
    )
    with DatabaseManager.open(history_db) as database:
        repository = HistoryRepository(database.connection)
        outcome = audit_with_history(
            prepared, environment=environment, project_id=project_id,
            display_name=display_name, repository=repository,
            retention_days=retention_days,
            clock=clock or (lambda: datetime.now(UTC)),
        )
        DiffService(repository).compare_run(outcome.run_id)
        return outcome


def run_doctor_check(
    environment: Path,
    lock_file: Path,
    output_directory: Path,
    *,
    vuln_db: Path | None,
    vuln_api: str | None,
) -> dict:
    _require_one_source(vuln_db, vuln_api)
    report = _doctor.run_doctor(
        environment=environment,
        lock_file=lock_file,
        output_directory=output_directory,
        vuln_db=vuln_db,
        vuln_api=vuln_api,
        command_runner=_doctor_command_runner,
        database_checker=_doctor_database_checker,
        tcp_connector=_doctor_tcp_connector,
    )
    return {"kind": "doctor", "report": _doctor_json(report)}


def run_sop_case(
    alert: Path,
    logs: Path,
    *,
    case_db: Path,
    log_format: str,
    log_host: str | None,
    window_minutes: int,
    limit: int,
    agent_config: Path | None,
    persist: bool = True,
) -> dict:
    if type(persist) is not bool:
        raise TypeError("persist 必须是布尔值")
    advisor = None if agent_config is None else _advisor_loader(agent_config)
    case = _run_case(
        alert,
        logs,
        window_minutes=window_minutes,
        limit=limit,
        log_format=log_format,
        log_host=log_host,
        advisor=advisor,
    )
    if persist:
        with _CaseStore(case_db) as store:
            store.save(case)
            case = store.get(case["case_id"])
    return {"kind": "sop_case", "report": case}


def _require_one_source(vuln_db: Path | None, vuln_api: str | None) -> None:
    if (vuln_db is None) == (vuln_api is None):
        raise ValueError("必须且只能选择一个漏洞来源")


def _select_snapshot(
    vuln_db: Path | None,
    vuln_api: str | None,
    token: str | None,
):
    _require_one_source(vuln_db, vuln_api)
    if vuln_db is not None:
        return _load_vulnerability_snapshot(vuln_db)
    effective_token = token
    if effective_token is None or (
        isinstance(effective_token, str) and not effective_token.strip()
    ):
        effective_token = os.environ.get("SVAROG_VULN_API_TOKEN", "")
    return _remote_snapshot_loader(vuln_api, effective_token)


def _doctor_json(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _doctor_json(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _doctor_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_doctor_json(item) for item in value]
    return value


__all__ = [
    "analyze_web_log",
    "audit_python",
    "audit_project",
    "run_doctor_check",
    "run_sop_case",
]
