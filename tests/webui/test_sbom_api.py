"""SBOM download is generated, scoped, and protected."""

import json

from test_history_api import _request, history_app


def test_sbom_download_is_valid_and_has_safe_headers(history_app):
    app, _, snapshot_id = history_app
    response, parsed = _request(
        app, "GET", f"/api/audit-history/snapshots/{snapshot_id}/sbom",
    )
    assert response.status == 200
    assert response.content_type == "application/vnd.cyclonedx+json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Disposition"] == 'attachment; filename="svarog-sbom.json"'
    bom = json.loads(response.body)
    assert bom["specVersion"] == "1.7"
    assert bom["components"][0]["name"] == "demo"
    assert _request(app, "POST", f"/api/audit-history/snapshots/{snapshot_id}/sbom")[0].status == 405
    assert _request(app, "GET", "/api/audit-history/snapshots/999999/sbom")[0].status == 404
