"""S3C: EventAlertQueue processing rows must be reclaimable after the lease.

A recently claimed row is not stolen. Max-attempt rules still apply.
Reclaim uses existing updated_at; no 0018 lease column.
"""

from __future__ import annotations

import inspect
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.conftest import requires_postgres

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


def test_s3c_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_agent_pin_unchanged():
    from app.agent_source import PINNED_AGENT_GIT_COMMIT

    assert PINNED_AGENT_GIT_COMMIT == "3cdb52c42a87552db98e609e9ec7c1c01e86b23b"


def test_claim_source_reclaims_stale_processing_without_unbounded_scan():
    from app import alert_engine

    src = inspect.getsource(alert_engine._claim_queue)
    assert "ALERT_QUEUE_PROCESSING" in src
    assert "ALERT_QUEUE_LEASE_SECONDS" in src
    assert "updated_at" in src
    assert "skip_locked" in src
    assert ".limit(" in src
    assert "query(EventAlertQueue).all()" not in src
    route_src = inspect.getsource(alert_engine.route_pending_events)
    assert "MAX_DELIVERY_ATTEMPTS" in route_src


def test_alert_routing_catalog_unchanged():
    from app.scheduler import scheduler_job_catalog

    catalog = scheduler_job_catalog()
    assert [row["id"] for row in catalog] == FROZEN_JOB_IDS
    routing = next(row for row in catalog if row["id"] == "alert-routing")
    assert routing == {"id": "alert-routing", "seconds": 15}


def _asset(db, tenant_id: int, site_id: int, name: str):
    from app.models import Asset

    row = Asset(
        tenant_id=tenant_id,
        site_id=site_id,
        display_name=name,
        classification="Unknown",
        first_seen=datetime.now(timezone.utc),
    )
    db.add(row)
    db.flush()
    return row


def _queue_for(db, asset):
    from app.events import emit_new_asset
    from app.models import EventAlertQueue

    event = emit_new_asset(db, asset)
    db.flush()
    return db.query(EventAlertQueue).filter(EventAlertQueue.domain_event_id == event.id).one()


@requires_postgres
def test_stale_processing_queue_is_reclaimed_recent_is_not(reset_db):
    from app.alert_engine import route_pending_events
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import (
        ALERT_QUEUE_LEASE_SECONDS,
        MAX_DELIVERY_ATTEMPTS,
        Alert,
        EventAlertQueue,
        Site,
        Tenant,
    )

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="s3c-lease", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        recent_asset = _asset(db, tenant.id, site.id, "recent")
        stale_asset = _asset(db, tenant.id, site.id, "stale")
        exhausted_asset = _asset(db, tenant.id, site.id, "exhausted")
        pending_asset = _asset(db, tenant.id, site.id, "pending")
        recent = _queue_for(db, recent_asset)
        stale = _queue_for(db, stale_asset)
        exhausted = _queue_for(db, exhausted_asset)
        pending = _queue_for(db, pending_asset)
        now = datetime.now(timezone.utc)
        recent.status = "processing"
        recent.updated_at = now
        recent.attempts = 1
        stale.status = "processing"
        stale.updated_at = now - timedelta(seconds=ALERT_QUEUE_LEASE_SECONDS + 5)
        stale.attempts = 1
        exhausted.status = "processing"
        exhausted.updated_at = now - timedelta(seconds=ALERT_QUEUE_LEASE_SECONDS + 5)
        exhausted.attempts = MAX_DELIVERY_ATTEMPTS
        db.commit()
        route_pending_events(db)
        db.commit()
        verify = SessionLocal()
        try:
            recent2 = verify.get(EventAlertQueue, recent.id)
            stale2 = verify.get(EventAlertQueue, stale.id)
            exhausted2 = verify.get(EventAlertQueue, exhausted.id)
            pending2 = verify.get(EventAlertQueue, pending.id)
            assert recent2.status == "processing"
            assert recent2.attempts == 1
            assert stale2.status == "processed"
            assert stale2.attempts == 2
            assert exhausted2.status == "failed"
            assert exhausted2.attempts == MAX_DELIVERY_ATTEMPTS + 1
            assert exhausted2.last_error == "max routing attempts exceeded"
            assert pending2.status == "processed"
            alerts = {row.asset_id: row for row in verify.query(Alert).all()}
            assert stale_asset.id in alerts
            assert pending_asset.id in alerts
            assert recent_asset.id not in alerts
            assert exhausted_asset.id not in alerts
        finally:
            verify.close()
    finally:
        db.close()


@requires_postgres
def test_locked_stale_queue_row_is_skipped_not_stolen(reset_db):
    from sqlalchemy import text

    from app.alert_engine import route_pending_events
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import ALERT_QUEUE_LEASE_SECONDS, EventAlertQueue, Site, Tenant

    apply_schema()
    setup = SessionLocal()
    try:
        tenant = Tenant(name="s3c-skip", notes="")
        setup.add(tenant)
        setup.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        setup.add(site)
        setup.flush()
        held_asset = _asset(setup, tenant.id, site.id, "held")
        free_asset = _asset(setup, tenant.id, site.id, "free")
        held = _queue_for(setup, held_asset)
        free = _queue_for(setup, free_asset)
        stale_at = datetime.now(timezone.utc) - timedelta(seconds=ALERT_QUEUE_LEASE_SECONDS + 5)
        held.status = "processing"
        held.updated_at = stale_at
        held.attempts = 1
        free.status = "processing"
        free.updated_at = stale_at
        free.attempts = 1
        setup.commit()
        held_id, free_id = held.id, free.id
    finally:
        setup.close()

    holder = SessionLocal()
    router = SessionLocal()
    try:
        locked = holder.query(EventAlertQueue).filter(EventAlertQueue.id == held_id).with_for_update().one()
        assert locked.status == "processing"
        router.execute(text("SET LOCAL lock_timeout = '1s'"))
        started = time.monotonic()
        processed = route_pending_events(router)
        elapsed = time.monotonic() - started
        router.commit()
        assert elapsed < 2.0
        assert processed == 1
        holder.expire_all()
        router.expire_all()
        assert holder.get(EventAlertQueue, held_id).status == "processing"
        assert router.get(EventAlertQueue, free_id).status == "processed"
        assert router.get(EventAlertQueue, held_id).status == "processing"
    finally:
        router.close()
        holder.close()
