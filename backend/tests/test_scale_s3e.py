"""S3E: report and compatibility CSV exports iterate by keyset, not OFFSET/.all()."""

from __future__ import annotations

import inspect
import math
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.conftest import requires_postgres
from tests.test_phase1d import _client, _headers, _login, _world

BACKEND_ROOT = Path(__file__).resolve().parents[1]
FROZEN_JOB_IDS = [
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


def test_s3e_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_agent_pin_unchanged():
    from app.agent_source import PINNED_AGENT_GIT_COMMIT

    assert PINNED_AGENT_GIT_COMMIT == "3cdb52c42a87552db98e609e9ec7c1c01e86b23b"


def test_s3d_staff_lists_still_use_offset_pages():
    from app.routers.assets import list_assets
    from app.routers.alerts import list_alerts
    from app.reporting.service import preview_report

    assert "paginate_query" in inspect.getsource(list_assets)
    assert "paginate_query" in inspect.getsource(list_alerts)
    preview_src = inspect.getsource(preview_report)
    assert "offset" in preview_src
    assert "page_size" in preview_src


def test_export_iters_are_keyset_not_offset():
    from app.reporting import queries, service
    from app.routers import assets, devices, findings

    for fn in (
        queries.asset_inventory_iter,
        queries.finding_iter,
        queries.executive_iter,
        queries.asset_change_iter,
        queries.treatment_iter,
        queries.scan_history_iter,
        queries.agent_health_iter,
        queries.control_evidence_iter,
        service._iter_rows,
        assets.iter_asset_export_rows,
        devices.iter_device_export_rows,
        findings.iter_finding_export_rows,
    ):
        src = inspect.getsource(fn)
        assert ".offset(" not in src.replace(" ", "")
        assert "query.all()" not in src.replace(" ", "")

    assert "map_keyset" in inspect.getsource(queries.asset_inventory_iter)
    assert "map_keyset" in inspect.getsource(assets.iter_asset_export_rows)
    assert "Finding.id.desc()" in inspect.getsource(findings.finding_export_query)
    assert "Device.id" in inspect.getsource(devices.device_export_query)


def test_scheduler_catalog_unchanged():
    from app.scheduler import scheduler_job_catalog

    assert [row["id"] for row in scheduler_job_catalog()] == FROZEN_JOB_IDS


def test_seek_clause_matches_composite_order():
    from sqlalchemy import column

    from app.reporting.keyset import KeyCol, seek_clause

    name = column("display_name")
    ident = column("id")
    clause = seek_clause((KeyCol(name), KeyCol(ident)), ("host-10", 4))
    compiled = str(clause.compile(compile_kwargs={"literal_binds": True}))
    assert "display_name" in compiled
    assert ">" in compiled
    assert "id" in compiled


def _seed_assets(db, *, count: int, label: str):
    from app.models import Asset, Site, Tenant

    tenant = Tenant(name=f"s3e-{label}", notes="")
    db.add(tenant)
    db.flush()
    site = Site(tenant_id=tenant.id, name="HQ", timezone="UTC")
    db.add(site)
    db.flush()
    rows = []
    for index in range(count):
        rows.append(
            Asset(
                tenant_id=tenant.id,
                site_id=site.id,
                display_name=f"asset-{index % 17:02d}-{index:04d}",
                classification="Unknown",
                first_seen=datetime.now(timezone.utc) - timedelta(minutes=index),
                last_seen=datetime.now(timezone.utc),
            )
        )
    db.add_all(rows)
    db.commit()
    return tenant


def _seed_devices(db, tenant_id: int, count: int):
    from app.models import Device

    rows = [
        Device(
            tenant_id=tenant_id,
            ip=f"10.{index // 250}.{index % 250}.10",
            hostname=f"host-{index % 9:02d}-{index:04d}",
            scope="wan",
            status="known",
        )
        for index in range(count)
    ]
    db.add_all(rows)
    db.commit()


def _seed_findings(db, tenant_id: int, count: int):
    from app.models import Finding

    now = datetime.now(timezone.utc)
    rows = [
        Finding(
            tenant_id=tenant_id,
            template_id=f"t-{index}",
            name="exposure",
            severity="low",
            hostname=f"host-{index}",
            evidence_key=f"s3e-finding-{tenant_id}-{index}",
            found_at=now - timedelta(seconds=index),
            raw_json={"template-id": f"t-{index}", "host": "h"},
        )
        for index in range(count)
    ]
    db.add_all(rows)
    db.commit()


def _assert_first_last_total(streamed, legacy):
    assert len(streamed) == len(legacy)
    assert len(streamed) > 1
    assert streamed[0] == legacy[0]
    assert streamed[-1] == legacy[-1]
    assert streamed == legacy


@requires_postgres
def test_compat_and_report_exports_match_full_load(reset_db, monkeypatch):
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.reporting.queries import asset_inventory_iter, asset_inventory_rows
    from app.reporting.scope import build_context
    from app.routers.assets import asset_export_query, iter_asset_export_rows, serialize_asset_export_row
    from app.routers.devices import device_export_query, iter_device_export_rows, serialize_device_export_row
    from app.routers.findings import finding_export_query, iter_finding_export_rows, serialize_finding_export_row
    from app.models import User
    from app.seed import seed

    monkeypatch.setenv("REPORT_EXPORT_BATCH_SIZE", "7")
    apply_schema()
    db = SessionLocal()
    try:
        seed(db)
        tenant = _seed_assets(db, count=40, label="equiv")
        _seed_devices(db, tenant.id, 40)
        _seed_findings(db, tenant.id, 40)

        legacy_assets = [serialize_asset_export_row(row) for row in asset_export_query(db, tenant.id).all()]
        db.expunge_all()
        streamed_assets = list(iter_asset_export_rows(db, tenant.id))
        _assert_first_last_total(streamed_assets, legacy_assets)

        legacy_devices = [serialize_device_export_row(row) for row in device_export_query(db, tenant.id).all()]
        db.expunge_all()
        streamed_devices = list(iter_device_export_rows(db, tenant.id))
        _assert_first_last_total(streamed_devices, legacy_devices)

        legacy_findings = [serialize_finding_export_row(row) for row in finding_export_query(db, tenant.id).all()]
        db.expunge_all()
        streamed_findings = list(iter_finding_export_rows(db, tenant.id))
        _assert_first_last_total(streamed_findings, legacy_findings)

        admin = db.query(User).filter(User.username == "admin").one()
        ctx = build_context(db, admin, tenant_id=tenant.id)
        legacy_report = asset_inventory_rows(ctx)
        db.expunge_all()
        ctx = build_context(db, admin, tenant_id=tenant.id)
        streamed_report = list(asset_inventory_iter(ctx))
        _assert_first_last_total(streamed_report, legacy_report)
    finally:
        db.close()


@requires_postgres
def test_http_export_and_preview_contracts(reset_db, monkeypatch):
    from app.migrate import apply_schema

    monkeypatch.setenv("REPORT_EXPORT_BATCH_SIZE", "8")
    apply_schema()
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        site_id = world["site"]["id"]
        for index in range(12):
            created = client.post(
                f"/api/tenants/{tenant_id}/assets",
                headers=_headers(token),
                json={
                    "site_id": site_id,
                    "display_name": f"http-{index:02d}",
                    "hostname": f"http-{index:02d}.example",
                },
            )
            assert created.status_code == 200, created.text
        page = client.get(
            f"/api/tenants/{tenant_id}/assets?limit=5&offset=0",
            headers=_headers(token),
        )
        assert page.status_code == 200
        body = page.json()
        assert set(body) >= {"items", "total", "limit", "offset"}
        assert body["limit"] == 5
        csv_resp = client.get(f"/api/tenants/{tenant_id}/assets/export", headers=_headers(token))
        assert csv_resp.status_code == 200
        lines = [line for line in csv_resp.text.splitlines() if line]
        assert lines[0].startswith("id,")
        assert len(lines) == 13
        report = client.get(
            f"/api/reports/asset_inventory/export?format=csv&tenant_id={tenant_id}",
            headers=_headers(token),
        )
        assert report.status_code == 200
        preview = client.get(
            f"/api/reports/asset_inventory/preview?tenant_id={tenant_id}&page=1&page_size=5",
            headers=_headers(token),
        )
        assert preview.status_code == 200
        preview_body = preview.json()
        assert preview_body["page"] == 1
        assert preview_body["page_size"] == 5
        assert "total" in preview_body
        assert len(preview_body["rows"]) <= 5


@requires_postgres
def test_export_select_count_grows_with_batches_not_rows(reset_db, monkeypatch):
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.routers.assets import iter_asset_export_rows
    from app.seed import seed
    from tests.scale_s2.metrics import SqlProbe

    monkeypatch.setenv("REPORT_EXPORT_BATCH_SIZE", "10")
    apply_schema()
    db = SessionLocal()
    try:
        seed(db)

        def consume(count: int) -> tuple[int, int]:
            tenant = _seed_assets(db, count=count, label=f"sql-{count}")
            probe = SqlProbe(db)
            probe.attach()
            try:
                n = sum(1 for _ in iter_asset_export_rows(db, tenant.id))
            finally:
                probe.detach()
            return n, probe.selects

        small_n, small_selects = consume(30)
        large_n, large_selects = consume(90)
        assert small_n == 30
        assert large_n == 90
        small_pages = math.ceil(small_n / 10)
        large_pages = math.ceil(large_n / 10)
        assert small_selects <= small_pages * 12 + 8
        assert large_selects <= large_pages * 12 + 8
        assert large_selects / large_n <= (small_selects / small_n) * 2 + 0.25
    finally:
        db.close()


def _rss_bytes_for_asset_export(count: int) -> int:
    script = r"""
import os
import resource
import sys
from datetime import datetime, timezone

count = int(sys.argv[1])
os.environ["REPORT_EXPORT_BATCH_SIZE"] = "25"
from app.database import SessionLocal
from app.models import Asset, Site, Tenant
from app.routers.assets import iter_asset_export_rows

db = SessionLocal()
tenant = Tenant(name="s3e-rss-%s" % count, notes="")
db.add(tenant)
db.flush()
site = Site(tenant_id=tenant.id, name="HQ", timezone="UTC")
db.add(site)
db.flush()
db.add_all(
    [
        Asset(
            tenant_id=tenant.id,
            site_id=site.id,
            display_name="rss-%04d" % index,
            classification="Unknown",
            first_seen=datetime.now(timezone.utc),
        )
        for index in range(count)
    ]
)
db.commit()
seen = 0
for _row in iter_asset_export_rows(db, tenant.id):
    seen += 1
assert seen == count
db.close()
usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(usage if sys.platform == "darwin" else int(usage) * 1024)
"""
    env = os.environ.copy()
    proc = subprocess.run(
        [sys.executable, "-c", script, str(count)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(BACKEND_ROOT),
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return int(proc.stdout.strip().splitlines()[-1])


@requires_postgres
def test_export_peak_rss_is_bounded_not_linear_with_row_count(reset_db):
    from app.migrate import apply_schema

    apply_schema()
    small = _rss_bytes_for_asset_export(80)
    large = _rss_bytes_for_asset_export(800)
    assert small > 0
    assert large > 0
    assert large <= max(small * 25 // 10, small + 24 * 1024 * 1024)
