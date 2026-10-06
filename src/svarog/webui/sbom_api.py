"""Web-facing CycloneDX export, scoped to the current local project."""

from __future__ import annotations

import hashlib

from svarog.audit_history.repository import HistoryRepository
from svarog.sbom.cyclonedx import export_snapshot_sbom


SBOM_MIME = "application/vnd.cyclonedx+json"


def download_sbom(
    repository: HistoryRepository, project_id: str, snapshot_id: int,
) -> tuple[bytes, str]:
    payload = export_snapshot_sbom(repository, project_id, snapshot_id)
    return payload, hashlib.sha256(payload).hexdigest()
