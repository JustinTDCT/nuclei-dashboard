"""S3D: high-risk staff collection GETs are HistoryPage-bounded."""

from __future__ import annotations

import inspect
from pathlib import Path

from tests.conftest import page_items, requires_postgres
from tests.test_phase1d import _client, _headers, _login, _world

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PAGED = (
    ("app.routers.assets", "list_assets", "limit(1000)"),
    ("app.routers.devices", "list_devices", "limit(1000)"),
    ("app.routers.findings", "list_findings", "limit(2000)"),
    ("app.routers.findings", "list_asset_findings", "limit(2000)"),
    ("app.routers.alerts", "list_alerts", "limit(500)"),
    ("app.routers.scans", "list_jobs", "limit(100)"),
    ("app.routers.scans", "list_all_jobs", "limit(50)"),
)


def test_s3d_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_agent_pin_unchanged():
    from app.agent_source import PINNED_AGENT_GIT_COMMIT

    assert PINNED_AGENT_GIT_COMMIT == "3cdb52c42a87552db98e609e9ec7c1c01e86b23b"


def test_high_risk_list_sources_are_offset_pages():
    for module_path, func_name, old_cap in PAGED:
        mod = __import__(module_path, fromlist=[func_name])
        src = inspect.getsource(getattr(mod, func_name))
        assert old_cap not in src.replace(" ", "")
        assert "paginate_query" in src
        assert "LIST_PAGE_MAX" in src


def test_scheduler_catalog_unchanged():
    from app.scheduler import scheduler_job_catalog

    assert [row["id"] for row in scheduler_job_catalog()] == [
        "schedules",
        "stale",
        "asset-inactive",
        "discovery-metadata",
        "policy-reconcile",
        "stuck-jobs",
        "vuln-intel",
        "finding-age-priority",
        "treatment-expiration",
        "alert-routing",
        "alert-delivery",
        "raw-artifact-retention",
    ]


def test_agent_job_poll_stays_a_list():
    from app.routers import agent_api, scanner_api

    assert "HistoryPage" not in inspect.getsource(agent_api.poll_jobs)
    assert "HistoryPage" not in inspect.getsource(scanner_api.poll_jobs)


@requires_postgres
def test_asset_pages_are_disjoint_and_capped(reset_db):
    from app.migrate import apply_schema

    apply_schema()
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        site_id = world["site"]["id"]
        created = []
        for index in range(3):
            row = client.post(
                f"/api/tenants/{tenant_id}/assets",
                headers=_headers(token),
                json={
                    "site_id": site_id,
                    "display_name": f"paged-{index}",
                    "hostname": f"paged-{index}.example",
                },
            )
            assert row.status_code == 200, row.text
            created.append(row.json()["id"])
        too_big = client.get(
            f"/api/tenants/{tenant_id}/assets?limit=201",
            headers=_headers(token),
        )
        assert too_big.status_code == 422
        first = client.get(
            f"/api/tenants/{tenant_id}/assets?limit=1&offset=0",
            headers=_headers(token),
        )
        assert first.status_code == 200
        body = first.json()
        assert set(body) >= {"items", "total", "limit", "offset"}
        assert body["limit"] == 1
        assert body["offset"] == 0
        assert body["total"] >= 3
        assert len(body["items"]) == 1
        second = client.get(
            f"/api/tenants/{tenant_id}/assets?limit=1&offset=1",
            headers=_headers(token),
        )
        assert second.status_code == 200
        assert page_items(first.json())[0]["id"] != page_items(second.json())[0]["id"]
        default = client.get(f"/api/tenants/{tenant_id}/assets", headers=_headers(token))
        assert default.json()["limit"] == 50
        assert len(page_items(default.json())) <= 50


@requires_postgres
def test_asset_finding_filters_apply_before_page(reset_db):
    from app.migrate import apply_schema

    apply_schema()
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        unfiltered = client.get(
            f"/api/tenants/{world['tenant']['id']}/asset-findings",
            headers=_headers(token),
        )
        assert unfiltered.status_code == 200
        assert "items" in unfiltered.json()
        filtered = client.get(
            f"/api/tenants/{world['tenant']['id']}/asset-findings?technical_state=open&limit=50",
            headers=_headers(token),
        )
        assert filtered.status_code == 200
        for row in page_items(filtered.json()):
            assert row["technical_state"] == "open"


@requires_postgres
def test_alerts_and_jobs_use_history_page(reset_db):
    from app.migrate import apply_schema

    apply_schema()
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        alerts = client.get("/api/alerts?limit=10", headers=_headers(token))
        assert alerts.status_code == 200
        assert set(alerts.json()) >= {"items", "total", "limit", "offset"}
        jobs = client.get(
            f"/api/tenants/{world['tenant']['id']}/jobs?limit=10",
            headers=_headers(token),
        )
        assert jobs.status_code == 200
        assert set(jobs.json()) >= {"items", "total", "limit", "offset"}
        devices = client.get(
            f"/api/tenants/{world['tenant']['id']}/devices?limit=10",
            headers=_headers(token),
        )
        assert devices.status_code == 200
        assert set(devices.json()) >= {"items", "total", "limit", "offset"}
        findings = client.get(
            f"/api/tenants/{world['tenant']['id']}/findings?limit=10",
            headers=_headers(token),
        )
        assert findings.status_code == 200
        assert set(findings.json()) >= {"items", "total", "limit", "offset"}
