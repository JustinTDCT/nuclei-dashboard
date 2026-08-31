"""S3A: API startup must not scan the whole Device table.

Device classification / auto_label / tech semantics stay the former
startup-refresh rules. Catch-up is one keyset page per scheduler tick.
"""

from __future__ import annotations

import inspect
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SMALL_INVENTORY = 50
LARGE_INVENTORY = 400
PAGE_SIZE = 50


def _legacy_refreshed_fields(hostname, ports, title, tech, classification, auto_label):
    """Contract of the former whole-table startup refresh. Keep in lockstep."""
    from app.classify import clean_tech, infer_class, infer_label

    classification_out = classification or ""
    if classification_out in ("", "Unknown"):
        guessed = infer_class(hostname or "", ports, title or "", tech or "")
        if guessed not in ("", "Unknown", "Other"):
            classification_out = guessed
    label = infer_label(hostname or "", ports, title or "", tech or "")
    cleaned = clean_tech(tech or "")
    return classification_out, label, cleaned


def _device_sql_counts(probe) -> dict[str, int]:
    return {
        "selects": probe.by_table.get(("SELECT", "devices"), 0),
        "inserts": probe.by_table.get(("INSERT", "devices"), 0),
        "updates": probe.by_table.get(("UPDATE", "devices"), 0),
        "deletes": probe.by_table.get(("DELETE", "devices"), 0),
    }


def _seed_devices(db, count: int, *, dirty: bool = True):
    from app.models import Device, Tenant

    tenant = Tenant(name="s3a-inventory", notes="")
    db.add(tenant)
    db.flush()
    rows = []
    for index in range(count):
        if index % 7 == 0:
            hostname = f"idrac-{index}"
            ports = [443]
            classification = "Unknown"
            auto_label = ""
            tech = "jQuery, iDRAC/9, bootstrap" if dirty else "idrac"
        elif index % 7 == 1:
            hostname = f"printer-{index}"
            ports = [9100]
            classification = "Unknown"
            auto_label = "stale-label"
            tech = "jQuery, CUPS" if dirty else "cups"
        else:
            hostname = f"host-{index}.example"
            ports = [22, 80]
            classification = "Desktop"
            auto_label = "custom-kept-until-infer"
            tech = "nginx"
        rows.append(
            Device(
                tenant_id=tenant.id,
                ip=f"10.{index // 250}.{index % 250}.10",
                hostname=hostname,
                scope="wan",
                status="known",
                classification=classification,
                auto_label=auto_label,
                title="",
                tech=tech,
                ports=ports,
            )
        )
    db.add_all(rows)
    db.commit()
    return tenant, rows


def _walk_pages(db, *, batch_size: int = PAGE_SIZE, after_id: int = 0):
    from app.inventory import refresh_discovery_metadata

    pages = []
    cursor = after_id
    while True:
        page = refresh_discovery_metadata(db, batch_size=batch_size, after_id=cursor)
        pages.append(page)
        if page.complete:
            break
        cursor = page.last_id
    return pages


def test_s3a_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_startup_source_does_not_refresh_devices():
    from app import main

    assert "refresh_discovery_metadata" not in inspect.getsource(main.lifespan)
    assert "refresh_discovery_metadata" not in inspect.getsource(main.prepare_control_plane)
    assert "refresh_discovery_metadata" not in (BACKEND_ROOT / "app" / "main.py").read_text()


def test_refresh_source_is_keyset_bounded():
    from app import inventory

    src = inspect.getsource(inventory.refresh_discovery_metadata)
    assert "query(Device).all()" not in src
    assert "Device.id >" in src
    assert ".limit(" in src
    assert "order_by(Device.id" in src
    assert "with_for_update" in src
    assert "skip_locked" in src


def test_scheduler_source_registers_bounded_discovery_job():
    from app import scheduler as sched

    src = inspect.getsource(sched.start_scheduler)
    assert "refresh_discovery_metadata_job" in src
    assert 'id="discovery-metadata"' in src
    job_src = inspect.getsource(sched.refresh_discovery_metadata_job)
    assert "query(Device).all()" not in job_src
    assert "after_id" in job_src


@requires_postgres
def test_lifespan_does_not_call_discovery_refresh(reset_db):
    from fastapi.testclient import TestClient

    from app.migrate import apply_schema

    apply_schema()
    with patch("app.inventory.refresh_discovery_metadata") as refresh:
        with patch("app.main.start_scheduler"):
            from app.main import app

            with TestClient(app):
                pass
    refresh.assert_not_called()


@requires_postgres
def test_startup_device_sql_is_zero_and_independent_of_inventory(reset_db):
    from app.database import SessionLocal
    from app.main import prepare_control_plane
    from tests.scale_s2.metrics import SqlProbe
    from tests.scale_s2.world import reset_schema

    def measure(count: int) -> dict[str, int]:
        reset_schema()
        db = SessionLocal()
        try:
            _seed_devices(db, count, dirty=True)
            probe = SqlProbe(db)
            probe.attach()
            try:
                prepare_control_plane(db)
                device = _device_sql_counts(probe)
                return {
                    **device,
                    "selects_total": probe.selects,
                    "statements": probe.statements,
                }
            finally:
                probe.detach()
        finally:
            db.close()

    small = measure(SMALL_INVENTORY)
    large = measure(LARGE_INVENTORY)
    assert small["selects"] == 0
    assert large["selects"] == 0
    assert small["inserts"] == 0
    assert large["inserts"] == 0
    assert small["updates"] == 0
    assert large["updates"] == 0
    assert small["selects_total"] == large["selects_total"]
    assert small["statements"] == large["statements"]


@requires_postgres
def test_one_page_never_loads_more_than_limit(reset_db):
    from app.database import SessionLocal
    from app.inventory import refresh_discovery_metadata
    from app.migrate import apply_schema
    from tests.scale_s2.metrics import SqlProbe

    apply_schema()
    db = SessionLocal()
    try:
        _seed_devices(db, LARGE_INVENTORY, dirty=True)
        probe = SqlProbe(db)
        probe.attach()
        try:
            page = refresh_discovery_metadata(db, batch_size=PAGE_SIZE, after_id=0)
        finally:
            probe.detach()
        assert page.scanned == PAGE_SIZE
        assert page.complete is False
        assert page.last_id > 0
        device = _device_sql_counts(probe)
        assert device["selects"] == 1
        assert device["selects"] < LARGE_INVENTORY
    finally:
        db.close()


@requires_postgres
def test_keyset_pages_cover_all_ids_and_match_legacy_semantics(reset_db):
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import Device

    apply_schema()
    db = SessionLocal()
    try:
        _seed_devices(db, LARGE_INVENTORY, dirty=True)
        expected = {
            row.id: _legacy_refreshed_fields(
                row.hostname,
                row.ports,
                row.title,
                row.tech,
                row.classification,
                row.auto_label,
            )
            for row in db.query(Device).order_by(Device.id).all()
        }
        pages = _walk_pages(db, batch_size=PAGE_SIZE)
        assert pages[-1].complete is True
        assert sum(page.scanned for page in pages) == LARGE_INVENTORY
        assert all(page.scanned <= PAGE_SIZE for page in pages)
        assert pages[0].scanned == PAGE_SIZE
        observed = db.query(Device).order_by(Device.id).all()
        assert len(observed) == LARGE_INVENTORY
        for row in observed:
            classification, label, tech = expected[row.id]
            assert row.classification == classification
            assert row.auto_label == label
            assert row.tech == tech
    finally:
        db.close()


@requires_postgres
def test_scheduler_job_advances_one_page_and_rewinds(reset_db, monkeypatch):
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.scheduler import refresh_discovery_metadata_job, reset_discovery_metadata_cursor

    apply_schema()
    monkeypatch.setattr("app.inventory.DISCOVERY_METADATA_BATCH_SIZE", PAGE_SIZE)
    reset_discovery_metadata_cursor()
    db = SessionLocal()
    try:
        _seed_devices(db, 120, dirty=True)
    finally:
        db.close()

    try:
        first = refresh_discovery_metadata_job()
        second = refresh_discovery_metadata_job()
        third = refresh_discovery_metadata_job()
        assert first is not None and second is not None and third is not None
        assert first.scanned == PAGE_SIZE
        assert first.complete is False
        assert second.scanned == PAGE_SIZE
        assert second.complete is False
        assert third.scanned == 20
        assert third.complete is True
        fourth = refresh_discovery_metadata_job()
        assert fourth is not None
        assert fourth.scanned == PAGE_SIZE
        assert fourth.complete is False
    finally:
        reset_discovery_metadata_cursor()


@requires_postgres
def test_ingest_still_writes_classification_label_tech(reset_db):
    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import Scan, ScanJob, Tenant
    from app.schemas import DeviceReport

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="s3a-ingest", notes="")
        db.add(tenant)
        db.flush()
        scan = Scan(tenant_id=tenant.id, name="wan", scope="wan", profile="discovery")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        db.add(job)
        db.flush()
        created, devices = upsert_devices(
            db,
            tenant.id,
            job.id,
            [
                DeviceReport(
                    ip="203.0.113.10",
                    scope="wan",
                    hostname="idrac-lab",
                    ports=[443],
                    tech="jQuery, iDRAC/9, bootstrap",
                )
            ],
        )
        assert created == 1
        device = devices[0]
        assert device.classification == "Server Management"
        assert device.tech == "idrac"
        assert device.auto_label == "iDRAC · HTTPS"
    finally:
        db.close()


def _newer_proxmox_report():
    from app.schemas import DeviceReport

    return DeviceReport(
        ip="203.0.113.10",
        scope="wan",
        hostname="lab-host",
        ports=[8006],
        title="Proxmox VE",
        tech="Proxmox, jQuery",
    )


def _dirty_idrac_device(db):
    """One Device whose stored fields catch-up would rewrite to iDRAC, ingest to Proxmox."""
    from app.inventory import upsert_devices
    from app.models import Device, Scan, ScanJob, Tenant
    from app.schemas import DeviceReport

    tenant = Tenant(name="s3a-race", notes="")
    db.add(tenant)
    db.flush()
    scan = Scan(tenant_id=tenant.id, name="wan", scope="wan", profile="discovery")
    db.add(scan)
    db.flush()
    job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
    db.add(job)
    db.flush()
    _, devices = upsert_devices(
        db,
        tenant.id,
        job.id,
        [
            DeviceReport(
                ip="203.0.113.10",
                scope="wan",
                hostname="lab-host",
                ports=[443],
                tech="jQuery, iDRAC/9, bootstrap",
            )
        ],
    )
    device = devices[0]
    device.classification = "Unknown"
    device.auto_label = ""
    device.title = ""
    device.tech = "jQuery, iDRAC/9, bootstrap"
    device.ports = [443]
    db.commit()
    return tenant.id, scan.id, device.id


def _assert_ingest_won(db, device_id: int) -> None:
    from app.models import Device

    db.expire_all()
    row = db.get(Device, device_id)
    assert row is not None
    assert row.classification == "Virtual Host"
    assert row.tech == "proxmox"
    assert row.auto_label == "Proxmox"
    assert row.classification != "Server Management"
    assert row.tech != "idrac"
    assert row.auto_label != "iDRAC · HTTPS"


def _wait_for_backend_lock_wait(*, timeout: float = 15.0) -> None:
    from sqlalchemy import text

    from app.database import engine

    deadline = time.time() + timeout
    while time.time() < deadline:
        with engine.connect() as conn:
            waiting = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE wait_event_type = 'Lock' AND state = 'active'"
                )
            ).scalar()
        if waiting:
            return
        time.sleep(0.05)
    raise AssertionError("ingest session did not block on the catch-up Device lock")


@requires_postgres
def test_catchup_skips_ingest_locked_device_and_ingest_wins(reset_db):
    from app.database import SessionLocal
    from app.inventory import refresh_discovery_metadata, upsert_devices
    from app.migrate import apply_schema
    from app.models import Device, ScanJob

    apply_schema()
    setup = SessionLocal()
    try:
        tenant_id, scan_id, device_id = _dirty_idrac_device(setup)
    finally:
        setup.close()

    ingest_db = SessionLocal()
    catchup_db = SessionLocal()
    try:
        locked = ingest_db.query(Device).filter(Device.id == device_id).with_for_update().one()
        assert locked.tech == "jQuery, iDRAC/9, bootstrap"
        page = refresh_discovery_metadata(catchup_db, batch_size=10, after_id=0)
        assert page.scanned == 0
        assert page.updated == 0
        job = ScanJob(scan_id=scan_id, tenant_id=tenant_id, status="running")
        ingest_db.add(job)
        ingest_db.flush()
        upsert_devices(ingest_db, tenant_id, job.id, [_newer_proxmox_report()])
        ingest_db.commit()
    finally:
        catchup_db.close()
        ingest_db.close()

    verify = SessionLocal()
    try:
        _assert_ingest_won(verify, device_id)
    finally:
        verify.close()


@requires_postgres
def test_catchup_lock_first_then_newer_ingest_wins(reset_db):
    from app import inventory as inventory_mod
    from app.database import SessionLocal
    from app.inventory import apply_stored_discovery_metadata, refresh_discovery_metadata, upsert_devices
    from app.migrate import apply_schema
    from app.models import ScanJob

    apply_schema()
    setup = SessionLocal()
    try:
        tenant_id, scan_id, device_id = _dirty_idrac_device(setup)
    finally:
        setup.close()

    lock_held = threading.Event()
    ingest_waiting = threading.Event()
    errors: list[BaseException] = []

    def catchup() -> None:
        db = SessionLocal()
        try:

            def wrapped(device):
                lock_held.set()
                if not ingest_waiting.wait(timeout=15):
                    raise AssertionError("ingest did not block on the catch-up Device lock")
                return apply_stored_discovery_metadata(device)

            inventory_mod.apply_stored_discovery_metadata = wrapped
            try:
                refresh_discovery_metadata(db, batch_size=10, after_id=0)
            finally:
                inventory_mod.apply_stored_discovery_metadata = apply_stored_discovery_metadata
        except BaseException as exc:  # noqa: BLE001 — surface thread failures after join
            errors.append(exc)
            lock_held.set()
            raise
        finally:
            db.close()

    def ingest() -> None:
        if not lock_held.wait(timeout=15):
            raise AssertionError("catch-up never locked the Device row")
        db = SessionLocal()
        try:
            job = ScanJob(scan_id=scan_id, tenant_id=tenant_id, status="running")
            db.add(job)
            db.flush()
            upsert_devices(db, tenant_id, job.id, [_newer_proxmox_report()])
            db.commit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            raise
        finally:
            db.close()

    def watch() -> None:
        if not lock_held.wait(timeout=15):
            return
        _wait_for_backend_lock_wait()
        ingest_waiting.set()

    with ThreadPoolExecutor(max_workers=3) as pool:
        catchup_f = pool.submit(catchup)
        assert lock_held.wait(timeout=15)
        watch_f = pool.submit(watch)
        ingest_f = pool.submit(ingest)
        catchup_f.result(timeout=20)
        ingest_f.result(timeout=20)
        watch_f.result(timeout=20)

    assert not errors
    verify = SessionLocal()
    try:
        _assert_ingest_won(verify, device_id)
    finally:
        verify.close()
