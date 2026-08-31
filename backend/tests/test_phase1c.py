from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, inspect, text
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE1B_HEAD = "0004_asset_observation_integrity"
PHASE1C_HEAD = "0005_asset_correlation_lifecycle"
PHASE1D_HEAD = "0006_scan_definition_execution"
PHASE2A_HEAD = "0009_phase2a_detector_identity_partition"
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
PHASE3A_HEAD = "0017_security_h6_h8"
PHASE1C_TABLES = {"asset_correlation_decisions", "domain_events"}
FROZEN = (
    "0001_baseline_current_schema.py",
    "0002_sites_networks.py",
    "0003_assets_observations.py",
    "0004_asset_observation_integrity.py",
)


@contextmanager
def _client() -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app) as client:
        yield client


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_staff(client: TestClient, admin_token: str, username: str, role: str) -> str:
    response = client.post(
        "/api/users",
        headers=_headers(admin_token),
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": f"{username}-password",
            "role": role,
            **({"viewer_all_tenants": True} if role == "viewer" else {}),
        },
    )
    assert response.status_code == 200, response.text
    return _login(client, username, f"{username}-password")


def _tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _columns(engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def _job(db: Session, tenant_id: int, *, scope: str = "wan", agent=None) -> int:
    from app.models import Scan, ScanJob

    scan = Scan(
        tenant_id=tenant_id,
        name=f"{scope}-{datetime.now(timezone.utc).timestamp()}",
        scope=scope,
        profile="discovery",
        agent_id=agent.id if agent is not None else None,
    )
    db.add(scan)
    db.flush()
    job = ScanJob(scan_id=scan.id, tenant_id=tenant_id, status="running")
    db.add(job)
    db.flush()
    return job.id


def _lan_world(db: Session, tenant, site_name: str):
    from app.models import Agent, Site

    site = Site(tenant_id=tenant.id, name=site_name)
    db.add(site)
    db.flush()
    agent = Agent(
        tenant_id=tenant.id,
        site_id=site.id,
        name=f"{site_name} agent",
        uuid=f"{site_name.lower()}-agent-uuid-000000000000"[:36],
        status="approved",
    )
    db.add(agent)
    db.flush()
    return site, agent


@requires_postgres
def test_fresh_db_reaches_phase1c_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3A_HEAD
    assert PHASE1C_TABLES.issubset(_tables(engine))
    assert "site_id" in _columns(engine, "devices")
    assert "merged_into_asset_id" in _columns(engine, "assets")
    assert "validity" in _columns(engine, "asset_identifiers")


def test_0001_through_0004_remain_frozen():
    for name in FROZEN:
        source = (BACKEND_ROOT / "alembic" / "versions" / name).read_text()
        assert "from app.database import Base" not in source
        assert "import app.models" not in source
        assert "0005_asset_correlation" not in source or name.startswith("0004") is False
    phase1c = (BACKEND_ROOT / "alembic" / "versions" / "0005_asset_correlation_lifecycle.py").read_text()
    assert 'down_revision: str | None = "0004_asset_observation_integrity"' in phase1c


@requires_postgres
def test_upgrade_0004_to_0005_preserves_assets_and_does_not_merge(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision, head_revision
    from app.models import Asset, AssetAddress, Device

    command.upgrade(alembic_config(), PHASE1B_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 1C', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        a1 = conn.execute(
            text(
                """
                INSERT INTO assets (
                    tenant_id, site_id, display_name, classification, description,
                    lifecycle_state, disposition, criticality, is_expected, first_seen, last_seen, updated_at
                ) VALUES (
                    :t, :s, 'alpha', 'Unknown', '', 'active', 'unreviewed', 'normal', false, :n, :n, :n
                ) RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        a2 = conn.execute(
            text(
                """
                INSERT INTO assets (
                    tenant_id, site_id, display_name, classification, description,
                    lifecycle_state, disposition, criticality, is_expected, first_seen, last_seen, updated_at
                ) VALUES (
                    :t, :s, 'beta', 'Unknown', '', 'active', 'approved', 'normal', false, :n, :n, :n
                ) RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        for asset_id, host, ip in ((a1, "alpha", "10.1.1.10"), (a2, "beta", "10.1.1.10")):
            conn.execute(
                text(
                    """
                    INSERT INTO asset_identifiers (
                        asset_id, tenant_id, identifier_type, value, normalized_value, source
                    ) VALUES (:a, :t, 'hostname', :h, :h, 'scanner')
                    """
                ),
                {"a": asset_id, "t": tenant_id, "h": host},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO asset_addresses (
                        asset_id, tenant_id, site_id, ip, address_family, source
                    ) VALUES (:a, :t, :s, :ip, 'ipv4', 'scanner')
                    """
                ),
                {"a": asset_id, "t": tenant_id, "s": site_id, "ip": ip},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO devices (
                        tenant_id, ip, hostname, scope, status, classification, description,
                        auto_label, title, tech, ports, first_seen, last_seen, asset_id
                    ) VALUES (
                        :t, :ip, :h, 'lan', 'known', 'Unknown', '', '', '', '', '[]'::jsonb, :n, :n, :a
                    )
                    """
                ),
                {"t": tenant_id, "ip": ip, "h": host, "n": now, "a": asset_id},
            )

    command.upgrade(alembic_config(), "head")
    assert current_revision() == head_revision() == PHASE3A_HEAD
    db = SessionLocal()
    try:
        assets = db.query(Asset).filter(Asset.tenant_id == tenant_id).all()
        assert {row.display_name for row in assets} == {"alpha", "beta"}
        assert all(row.merged_into_asset_id is None for row in assets)
        assert db.query(AssetAddress).filter(AssetAddress.ip == "10.1.1.10").count() == 2
        devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
        assert {row.hostname for row in devices} == {"alpha", "beta"}
        assert {row.site_id for row in devices} == {site_id}
        assert {row.asset_id for row in devices} == {a1, a2}
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0005_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE1C_HEAD)
    try:
        command.downgrade(alembic_config(), PHASE1B_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0005_asset_correlation_lifecycle" in str(exc)
        return
    raise AssertionError("0005 downgrade must refuse")


@requires_postgres
def test_unversioned_phase1c_tables_fail_closed(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    apply_schema()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()


@requires_postgres
def test_unversioned_phase1c_marker_columns_fail_closed(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE1B_HEAD)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS site_id INTEGER"))
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()


@requires_postgres
def test_correlation_safety_cases(reset_db):
    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.lifecycle import mark_inactive_assets
    from app.migrate import apply_schema
    from app.models import (
        EVENT_ASSET_BECAME_INACTIVE,
        EVENT_NEW_ASSET,
        EVENT_PREVIOUSLY_INACTIVE_RETURNED,
        LIFECYCLE_INACTIVE,
        Asset,
        AssetAddress,
        AssetCorrelationDecision,
        AssetIdentifier,
        AssetObservation,
        Device,
        DomainEvent,
        Finding,
        Tenant,
    )
    from app.schemas import DeviceReport
    from app.settings_store import save_settings

    apply_schema()
    db: Session = SessionLocal()
    try:
        tenant = Tenant(name="Corr Tenant", notes="")
        db.add(tenant)
        db.flush()
        site_a, agent_a = _lan_world(db, tenant, "Boston")
        site_b, agent_b = _lan_world(db, tenant, "Hartford")

        job_a = _job(db, tenant.id, scope="lan", agent=agent_a)
        job_b = _job(db, tenant.id, scope="lan", agent=agent_b)
        created_a, devices_a = upsert_devices(
            db,
            tenant.id,
            job_a,
            [DeviceReport(ip="192.168.1.25", scope="lan", hostname="printer01")],
        )
        created_b, devices_b = upsert_devices(
            db,
            tenant.id,
            job_b,
            [DeviceReport(ip="192.168.1.25", scope="lan", hostname="printer01")],
        )
        assert created_a == created_b == 1
        assert devices_a[0].asset_id != devices_b[0].asset_id
        assert devices_a[0].site_id == site_a.id
        assert devices_b[0].site_id == site_b.id
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == 2

        wan_job = _job(db, tenant.id, scope="wan")
        _, laptop_devs = upsert_devices(
            db,
            tenant.id,
            wan_job,
            [DeviceReport(ip="10.1.1.50", scope="wan", hostname="laptop01", mac="aa:bb:cc:dd:ee:99")],
        )
        laptop = db.get(Asset, laptop_devs[0].asset_id)
        later_job = _job(db, tenant.id, scope="wan")
        _, camera_devs = upsert_devices(
            db, tenant.id, later_job, [DeviceReport(ip="10.1.1.50", scope="wan", hostname="camera01")]
        )
        assert camera_devs[0].asset_id != laptop.id
        assert db.query(AssetAddress).filter(AssetAddress.ip == "10.1.1.50").count() == 2

        multi_job = _job(db, tenant.id, scope="wan")
        _, multi = upsert_devices(
            db,
            tenant.id,
            multi_job,
            [DeviceReport(ip="10.1.1.10", scope="wan", hostname="dual", mac="aa:bb:cc:dd:ee:01")],
        )
        multi_asset = db.get(Asset, multi[0].asset_id)
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.1.1.11", scope="wan", hostname="dual", mac="aa:bb:cc:dd:ee:01")],
        )
        db.refresh(multi_asset)
        addrs = {row.ip for row in db.query(AssetAddress).filter(AssetAddress.asset_id == multi_asset.id)}
        assert addrs == {"10.1.1.10", "10.1.1.11"}

        ip_only_job = _job(db, tenant.id, scope="wan")
        before_assets = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        upsert_devices(db, tenant.id, ip_only_job, [DeviceReport(ip="203.0.113.9", scope="wan", hostname="203.0.113.9")])
        upsert_devices(
            db, tenant.id, _job(db, tenant.id, scope="wan"), [DeviceReport(ip="203.0.113.9", scope="wan", hostname="")]
        )
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == before_assets + 2

        placeholder = db.query(AssetIdentifier).filter(AssetIdentifier.normalized_value == "203.0.113.9").all()
        assert placeholder == []

        mac_job = _job(db, tenant.id, scope="wan")
        _, strong = upsert_devices(
            db,
            tenant.id,
            mac_job,
            [DeviceReport(ip="10.8.1.1", scope="wan", hostname="n1", mac="11:22:33:44:55:66")],
        )
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.8.1.8", scope="wan", hostname="n1b", mac="11:22:33:44:55:66")],
        )
        decision = (
            db.query(AssetCorrelationDecision)
            .filter(AssetCorrelationDecision.selected_asset_id == strong[0].asset_id)
            .order_by(AssetCorrelationDecision.id.desc())
            .first()
        )
        assert decision.decision == "linked_existing"
        assert decision.confidence == "high"
        assert any("mac" in str(item.get("label", "")).lower() for item in decision.evidence)

        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.8.1.2", scope="wan", hostname="serial-box", serial="SER-1")],
        )
        conflict_before = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [
                DeviceReport(
                    ip="10.8.1.3",
                    scope="wan",
                    hostname="conflict",
                    mac="11:22:33:44:55:66",
                    serial="SER-1",
                )
            ],
        )
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == conflict_before + 1

        hq, hq_agent = _lan_world(db, tenant, "HQ")
        from app.assets import SOURCE_MANUAL, upsert_address, upsert_identifier
        from app.models import IDENTIFIER_HOSTNAME

        expected = Asset(
            tenant_id=tenant.id,
            site_id=hq.id,
            display_name="DC01",
            classification="Server",
            description="",
            lifecycle_state=None,
            disposition="approved",
            criticality="high",
            is_expected=True,
            first_seen=None,
            last_seen=None,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(expected)
        db.flush()
        upsert_identifier(db, expected, IDENTIFIER_HOSTNAME, "dc01.example.local", source=SOURCE_MANUAL, seen_at=None)
        upsert_address(db, expected, "10.1.1.10", site_id=hq.id, network_id=None, source=SOURCE_MANUAL, seen_at=datetime.now(timezone.utc))
        addr = db.query(AssetAddress).filter(AssetAddress.asset_id == expected.id).one()
        addr.first_seen = None
        addr.last_seen = None
        db.flush()
        expected_id = expected.id
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hq_agent),
            [DeviceReport(ip="10.1.1.10", scope="lan", hostname="dc01.example.local")],
        )
        db.refresh(expected)
        assert expected.id == expected_id
        assert expected.first_seen is not None
        assert expected.lifecycle_state == "active"
        assert expected.disposition == "approved"
        assert expected.is_expected is True
        assert db.query(DomainEvent).filter(DomainEvent.asset_id == expected.id, DomainEvent.event_type == EVENT_NEW_ASSET).count() == 1

        expected_ip = Asset(
            tenant_id=tenant.id,
            site_id=hq.id,
            display_name="IP only",
            classification="Unknown",
            description="",
            lifecycle_state=None,
            disposition="unreviewed",
            criticality="normal",
            is_expected=True,
            first_seen=None,
            last_seen=None,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(expected_ip)
        db.flush()
        upsert_address(db, expected_ip, "10.9.9.9", site_id=hq.id, network_id=None, source=SOURCE_MANUAL, seen_at=datetime.now(timezone.utc))
        only = db.query(AssetAddress).filter(AssetAddress.asset_id == expected_ip.id).one()
        only.first_seen = None
        only.last_seen = None
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hq_agent),
            [DeviceReport(ip="10.9.9.9", scope="lan", hostname="")],
        )
        db.refresh(expected_ip)
        discovered_ip = (
            db.query(Device)
            .filter(Device.tenant_id == tenant.id, Device.ip == "10.9.9.9", Device.asset_id != expected_ip.id)
            .first()
        )
        assert expected_ip.first_seen is None
        assert discovered_ip is not None
        assert discovered_ip.asset_id != expected_ip.id

        twin = Asset(
            tenant_id=tenant.id,
            site_id=hq.id,
            display_name="twin-a",
            classification="Unknown",
            description="",
            lifecycle_state="active",
            disposition="unreviewed",
            criticality="normal",
            is_expected=False,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        twin2 = Asset(
            tenant_id=tenant.id,
            site_id=hq.id,
            display_name="twin-b",
            classification="Unknown",
            description="",
            lifecycle_state="active",
            disposition="unreviewed",
            criticality="normal",
            is_expected=False,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add_all([twin, twin2])
        db.flush()
        upsert_identifier(db, twin, IDENTIFIER_HOSTNAME, "sharedhost", source=SOURCE_MANUAL, seen_at=datetime.now(timezone.utc))
        upsert_identifier(db, twin2, IDENTIFIER_HOSTNAME, "sharedhost", source=SOURCE_MANUAL, seen_at=datetime.now(timezone.utc))
        before_amb = {twin.id, twin2.id}
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hq_agent),
            [DeviceReport(ip="10.4.4.4", scope="lan", hostname="sharedhost")],
        )
        amb_decision = (
            db.query(AssetCorrelationDecision)
            .filter(AssetCorrelationDecision.decision == "ambiguous")
            .order_by(AssetCorrelationDecision.id.desc())
            .first()
        )
        assert amb_decision is not None
        assert amb_decision.selected_asset_id not in before_amb

        inactive = db.get(Asset, laptop.id)
        inactive.lifecycle_state = LIFECYCLE_INACTIVE
        inactive.last_seen = datetime.now(timezone.utc) - timedelta(days=40)
        original_first = inactive.first_seen
        original_disp = inactive.disposition
        db.flush()
        before_host_only = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.2.2.2", scope="wan", hostname="laptop01")],
        )
        db.refresh(inactive)
        assert inactive.lifecycle_state == LIFECYCLE_INACTIVE
        assert inactive.first_seen == original_first
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == before_host_only + 1
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.2.2.2", scope="wan", hostname="laptop01", mac="aa:bb:cc:dd:ee:99")],
        )
        db.refresh(inactive)
        assert inactive.lifecycle_state == "active"
        assert inactive.first_seen == original_first
        assert inactive.disposition == original_disp
        assert (
            db.query(DomainEvent)
            .filter(
                DomainEvent.asset_id == inactive.id,
                DomainEvent.event_type == EVENT_PREVIOUSLY_INACTIVE_RETURNED,
            )
            .count()
            == 1
        )

        stale = Asset(
            tenant_id=tenant.id,
            site_id=None,
            display_name="old-ip",
            classification="Unknown",
            description="",
            lifecycle_state=LIFECYCLE_INACTIVE,
            disposition="unreviewed",
            criticality="normal",
            is_expected=False,
            first_seen=datetime.now(timezone.utc) - timedelta(days=90),
            last_seen=datetime.now(timezone.utc) - timedelta(days=40),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(stale)
        db.flush()
        upsert_address(db, stale, "10.1.1.20", site_id=None, network_id=None, source="scanner", seen_at=stale.last_seen)
        upsert_devices(
            db, tenant.id, _job(db, tenant.id, scope="wan"), [DeviceReport(ip="10.1.1.20", scope="wan", hostname="newbox")]
        )
        db.refresh(stale)
        assert stale.lifecycle_state == LIFECYCLE_INACTIVE

        bad = (
            db.query(AssetIdentifier)
            .filter(AssetIdentifier.asset_id == multi_asset.id, AssetIdentifier.identifier_type == "mac")
            .first()
        )
        bad.validity = "incorrect"
        db.flush()
        before_bad = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.7.7.7", scope="wan", hostname="other", mac="aa:bb:cc:dd:ee:01")],
        )
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == before_bad + 1

        retry_job = _job(db, tenant.id, scope="wan")
        report = DeviceReport(ip="198.51.100.8", scope="wan", hostname="retry-host")
        upsert_devices(db, tenant.id, retry_job, [report])
        asset = db.query(Device).filter(Device.hostname == "retry-host").one().asset
        first_seen = asset.first_seen
        last_seen = asset.last_seen
        obs_count = db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).count()
        dec_count = db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.selected_asset_id == asset.id).count()
        ev_count = db.query(DomainEvent).filter(DomainEvent.asset_id == asset.id).count()
        upsert_devices(db, tenant.id, retry_job, [report])
        db.refresh(asset)
        assert asset.first_seen == first_seen
        assert asset.last_seen == last_seen
        assert db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).count() == obs_count
        assert db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.selected_asset_id == asset.id).count() == dec_count
        assert db.query(DomainEvent).filter(DomainEvent.asset_id == asset.id).count() == ev_count
        assert asset.disposition == "unreviewed"

        finding = Finding(
            tenant_id=tenant.id,
            device_id=devices_a[0].id,
            template_id="keep",
            name="stay",
            severity="high",
            hostname="printer01",
            host="192.168.1.25",
        )
        db.add(finding)
        db.flush()
        upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=agent_b),
            [DeviceReport(ip="192.168.1.25", scope="lan", hostname="printer01")],
        )
        db.refresh(finding)
        assert finding.device_id == devices_a[0].id
        assert db.get(Device, devices_a[0].id).asset_id == devices_a[0].asset_id

        save_settings(db, {"asset_inactive_days": 14})
        aged = db.get(Asset, camera_devs[0].asset_id)
        aged.last_seen = datetime.now(timezone.utc) - timedelta(days=20)
        db.flush()
        first_sweep = mark_inactive_assets(db)
        assert first_sweep >= 1
        db.refresh(aged)
        assert aged.lifecycle_state == LIFECYCLE_INACTIVE
        assert aged.disposition == "unreviewed"
        assert (
            db.query(DomainEvent)
            .filter(DomainEvent.asset_id == aged.id, DomainEvent.event_type == EVENT_ASSET_BECAME_INACTIVE)
            .count()
            == 1
        )
        assert mark_inactive_assets(db) == 0
        expected_unseen = db.get(Asset, expected_ip.id)
        assert expected_unseen.lifecycle_state is None

        queries: list[str] = []

        def _capture(_conn, _cursor, statement, _params, _context, _executemany):
            queries.append(statement)

        event.listen(db.bind, "before_cursor_execute", _capture)
        from app.correlation import generate_candidate_ids, signals_from_report

        signals = signals_from_report(
            tenant.id,
            DeviceReport(ip="192.168.1.25", scope="lan", hostname="printer01"),
            {"site_id": site_a.id, "scope": "lan"},
        )
        generate_candidate_ids(db, signals)
        event.remove(db.bind, "before_cursor_execute", _capture)
        full_scans = [
            sql
            for sql in queries
            if "from assets" in sql.lower()
            and "tenant_id" in sql.lower()
            and " assets.id in" not in sql.lower()
            and " assets.id =" not in sql.lower()
            and "asset_identifiers" not in sql.lower()
        ]
        assert full_scans == []
        assert any("asset_identifiers" in sql.lower() or "asset_addresses" in sql.lower() for sql in queries)
        assert len(queries) < 20
        for row in db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.decision == "linked_existing"):
            assert row.score >= 50
            assert row.confidence != "low"
    finally:
        db.close()


@requires_postgres
def test_manual_identity_ops_and_rbac(reset_db):
    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import (
        Asset,
        AssetIdentifier,
        AssetObservation,
        AuditLog,
        Device,
        Tenant,
    )
    from app.schemas import DeviceReport

    apply_schema()
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        operator = _create_staff(client, admin, "operator1c", "user")
        viewer = _create_staff(client, admin, "viewer1c", "viewer")
        tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Ops Tenant", "notes": ""}).json()
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other Tenant", "notes": ""}).json()
        site = client.post(f"/api/tenants/{tenant['id']}/sites", headers=_headers(admin), json={"name": "Main"}).json()
        other_site = client.post(f"/api/tenants/{other['id']}/sites", headers=_headers(admin), json={"name": "Foreign"}).json()
        dest_site = client.post(f"/api/tenants/{tenant['id']}/sites", headers=_headers(admin), json={"name": "DR"}).json()

        db = SessionLocal()
        try:
            t = db.get(Tenant, tenant["id"])
            upsert_devices(db, t.id, _job(db, t.id), [DeviceReport(ip="10.0.0.1", scope="wan", hostname="host-one")])
            upsert_devices(db, t.id, _job(db, t.id), [DeviceReport(ip="10.0.0.2", scope="wan", hostname="host-two")])
            one = db.query(Asset).filter(Asset.display_name == "host-one").one()
            two = db.query(Asset).filter(Asset.display_name == "host-two").one()
            foreign = Asset(
                tenant_id=other["id"],
                site_id=other_site["id"],
                display_name="foreign",
                classification="Unknown",
                description="",
                lifecycle_state="active",
                disposition="unreviewed",
                criticality="normal",
                is_expected=False,
                updated_at=datetime.now(timezone.utc),
            )
            db.add(foreign)
            db.flush()
            obs = db.query(AssetObservation).filter(AssetObservation.asset_id == two.id).all()
            ident = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == one.id).first()
            db.commit()
            one_id, two_id, foreign_id, obs_id, ident_id = one.id, two.id, foreign.id, obs[0].id, ident.id
        finally:
            db.close()

        denied = client.post(
            f"/api/assets/{one_id}/merge",
            headers=_headers(viewer),
            json={"source_asset_ids": [two_id], "reason": "no"},
        )
        assert denied.status_code == 403
        for path, body in (
            (f"/api/assets/{one_id}/split", {"observation_ids": [obs_id]}),
            (f"/api/assets/{one_id}/identifiers/{ident_id}/correct", {"reason": "bad"}),
            (f"/api/assets/{one_id}/move-site", {"site_id": dest_site["id"]}),
            (f"/api/assets/{two_id}/observations/{obs_id}/reassociate", {"target_asset_id": one_id}),
        ):
            assert client.post(path, headers=_headers(viewer), json=body).status_code == 403

        cross = client.post(
            f"/api/assets/{one_id}/merge",
            headers=_headers(operator),
            json={"source_asset_ids": [foreign_id], "reason": "cross"},
        )
        assert cross.status_code == 400
        cross_move = client.post(
            f"/api/assets/{one_id}/move-site",
            headers=_headers(operator),
            json={"site_id": other_site["id"], "reason": "cross"},
        )
        assert cross_move.status_code in {400, 404}
        cross_re = client.post(
            f"/api/assets/{two_id}/observations/{obs_id}/reassociate",
            headers=_headers(operator),
            json={"target_asset_id": foreign_id, "reason": "cross"},
        )
        assert cross_re.status_code == 400

        merged = client.post(
            f"/api/assets/{one_id}/merge",
            headers=_headers(operator),
            json={"source_asset_ids": [two_id], "reason": "duplicates"},
        )
        assert merged.status_code == 200, merged.text
        assert merged.json()["id"] == one_id
        source = client.get(f"/api/assets/{two_id}", headers=_headers(operator))
        assert source.status_code == 200
        assert source.json()["merged_into_asset_id"] == one_id

        db = SessionLocal()
        try:
            kept = db.get(Asset, two_id)
            assert kept is not None
            assert db.query(AssetObservation).filter(AssetObservation.asset_id.in_([one_id, two_id])).count() >= 2
            upsert_devices(db, tenant["id"], _job(db, tenant["id"]), [DeviceReport(ip="10.0.0.2", scope="wan", hostname="host-two")])
            device = db.query(Device).filter(Device.hostname == "host-two").order_by(Device.id.desc()).first()
            assert device is not None
            assert device.asset_id == one_id
            db.commit()
            split_obs = (
                db.query(AssetObservation)
                .filter(AssetObservation.asset_id == one_id, AssetObservation.hostname == "host-two")
                .first()
            )
            split_id = split_obs.id
            original_ts = split_obs.observed_at
        finally:
            db.close()

        split = client.post(
            f"/api/assets/{one_id}/split",
            headers=_headers(operator),
            json={"observation_ids": [split_id], "reason": "not the same"},
        )
        assert split.status_code == 200, split.text
        new_id = split.json()["id"]
        assert new_id != one_id
        moved = client.post(
            f"/api/assets/{new_id}/move-site",
            headers=_headers(operator),
            json={"site_id": dest_site["id"], "reason": "relocate"},
        )
        assert moved.status_code == 200
        assert moved.json()["site_id"] == dest_site["id"]

        db = SessionLocal()
        try:
            observation = db.get(AssetObservation, split_id)
            assert observation.observed_at == original_ts
            assert observation.asset_id == new_id
            ident = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == new_id).first()
            ident_id = ident.id if ident else ident_id
        finally:
            db.close()

        correct = client.post(
            f"/api/assets/{new_id}/identifiers/{ident_id}/correct",
            headers=_headers(operator),
            json={"reason": "typo", "replacement_value": "two-fixed"},
        )
        assert correct.status_code == 200, correct.text
        assert any(row["validity"] == "incorrect" for row in correct.json()["identifiers"])
        assert any(row["value"] == "two-fixed" for row in correct.json()["identifiers"])

        detail = client.get(f"/api/assets/{one_id}", headers=_headers(viewer))
        assert detail.status_code == 200
        corr = detail.json().get("latest_correlation")
        assert corr is not None
        assert corr["decision"] in {"created_new", "linked_existing", "ambiguous"}
        assert corr["confidence"] in {"high", "medium", "low"}
        assert isinstance(corr.get("evidence"), list)
        assert isinstance(corr.get("candidates"), list)
        assert corr.get("algorithm_version")

        db = SessionLocal()
        try:
            actions = {row.action for row in db.query(AuditLog).all()}
            assert {
                "asset.merge",
                "asset.split",
                "asset.identifier_correct",
                "asset.move_site",
            }.issubset(actions)
        finally:
            db.close()


@requires_postgres
def test_phase1c_corrective_regressions(reset_db):
    from app.assets import observation_fingerprint
    from app.auth import hash_password
    from app.correlation import observation_key_for_report
    from app.database import SessionLocal
    from app.identity_ops import merge_assets, split_observations_to_new_asset
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import (
        Asset,
        AssetCorrelationDecision,
        AssetIdentifier,
        AssetObservation,
        AssetService,
        Device,
        Finding,
        Tenant,
        User,
    )
    from app.schemas import DeviceReport

    apply_schema()
    db: Session = SessionLocal()
    try:
        tenant = Tenant(name="Corrective Tenant", notes="")
        db.add(tenant)
        db.flush()
        actor = (
            db.query(User).filter(User.username == "admin").first()
            or User(
                username="admin",
                email="admin@localhost",
                password_hash=hash_password("test-admin-pass"),
                role="admin",
                is_active=True,
            )
        )
        if actor.id is None:
            db.add(actor)
            db.flush()
        hq, hq_agent = _lan_world(db, tenant, "HQ")

        same = observation_fingerprint("srv01", "10.1.1.10", "wan", [443])
        assert same == observation_fingerprint("srv01", "10.1.1.10", "wan", [443])
        assert observation_fingerprint(
            "srv01", "10.1.1.10", "wan", [443], tls_name="old.example.com"
        ) != observation_fingerprint("srv01", "10.1.1.10", "wan", [443], tls_name="new.example.com")
        assert observation_key_for_report(
            DeviceReport(ip="10.1.1.10", scope="wan", hostname="srv01", ports=[443], tls_name="old.example.com"),
            "wan",
        ) != observation_key_for_report(
            DeviceReport(ip="10.1.1.10", scope="wan", hostname="srv01", ports=[443], tls_name="new.example.com"),
            "wan",
        )

        retry_job = _job(db, tenant.id, scope="wan")
        old_tls = DeviceReport(
            ip="10.1.1.10", scope="wan", hostname="srv01", ports=[443], tls_name="old.example.com"
        )
        new_tls = DeviceReport(
            ip="10.1.1.10", scope="wan", hostname="srv01", ports=[443], tls_name="new.example.com"
        )
        upsert_devices(db, tenant.id, retry_job, [old_tls])
        upsert_devices(db, tenant.id, retry_job, [new_tls])
        upsert_devices(db, tenant.id, retry_job, [new_tls])
        tls_asset = db.query(Device).filter(Device.hostname == "srv01").one().asset
        tls_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == tls_asset.id).all()
        assert len(tls_obs) == 2
        assert {row.snapshot.get("tls_name") for row in tls_obs} == {"old.example.com", "new.example.com"}
        assert (
            db.query(AssetCorrelationDecision)
            .filter(AssetCorrelationDecision.scan_job_id == retry_job)
            .count()
            == 2
        )

        _, old_pc = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.1.1.20", scope="wan", hostname="accounting-pc")],
        )
        before_pc = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        _, new_pc = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.1.1.87", scope="wan", hostname="accounting-pc")],
        )
        assert new_pc[0].asset_id != old_pc[0].asset_id
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == before_pc + 1

        _, created_a = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hq_agent),
            [DeviceReport(ip="192.168.1.10", scope="lan", hostname="server01", ports=[443])],
        )
        _, created_b = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hq_agent),
            [DeviceReport(ip="192.168.1.20", scope="lan", hostname="server01", ports=[443])],
        )
        asset_a = db.get(Asset, created_a[0].asset_id)
        asset_b = db.get(Asset, created_b[0].asset_id)
        assert asset_a.id != asset_b.id
        finding_a = Finding(
            tenant_id=tenant.id,
            device_id=created_a[0].id,
            template_id="keep-a",
            name="finding-a",
            severity="high",
            hostname="server01",
            host="192.168.1.10",
        )
        finding_b = Finding(
            tenant_id=tenant.id,
            device_id=created_b[0].id,
            template_id="keep-b",
            name="finding-b",
            severity="medium",
            hostname="server01",
            host="192.168.1.20",
        )
        db.add_all([finding_a, finding_b])
        db.flush()
        merge_assets(db, target=asset_a, source_ids=[asset_b.id], actor=actor, reason="same host")
        db.refresh(asset_b)
        assert asset_b.merged_into_asset_id == asset_a.id
        devices = (
            db.query(Device)
            .filter(Device.hostname == "server01", Device.site_id == hq.id, Device.asset_id == asset_a.id)
            .all()
        )
        assert len(devices) == 1
        db.refresh(finding_a)
        db.refresh(finding_b)
        assert finding_a.device_id == devices[0].id
        assert finding_b.device_id == devices[0].id
        merged_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset_a.id).all()
        assert len(merged_obs) == 2
        host_ident = (
            db.query(AssetIdentifier)
            .filter(
                AssetIdentifier.asset_id == asset_a.id,
                AssetIdentifier.identifier_type == "hostname",
                AssetIdentifier.normalized_value == "server01",
                AssetIdentifier.validity == "active",
            )
            .one()
        )
        obs_times = [row.observed_at for row in merged_obs]
        assert host_ident.first_seen == min(obs_times)
        assert host_ident.last_seen == max(obs_times)
        merged_services = (
            db.query(AssetService)
            .filter(AssetService.asset_id == asset_a.id, AssetService.port == 443)
            .all()
        )
        assert {row.ip for row in merged_services} == {"192.168.1.10", "192.168.1.20"}
        for service in merged_services:
            match = next(row for row in merged_obs if row.ip == service.ip)
            assert service.first_seen == match.observed_at
            assert service.last_seen == match.observed_at

        _, rich = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [
                DeviceReport(
                    ip="10.9.9.9",
                    scope="wan",
                    hostname="split-host",
                    ports=[443],
                    mac="aa:bb:cc:dd:ee:ff",
                    fqdn="split-host.example.local",
                    tls_name="split-host.example.local",
                    dns_name="split-host.example.local",
                    serial="SN-SPLIT-1",
                    device_identifier="det-1",
                )
            ],
        )
        source = db.get(Asset, rich[0].asset_id)
        observation = db.query(AssetObservation).filter(AssetObservation.asset_id == source.id).one()
        original_ts = observation.observed_at
        original_site = observation.site_id
        split_into = split_observations_to_new_asset(
            db,
            source=source,
            observation_ids=[observation.id],
            actor=actor,
            reason="different machine",
        )
        db.refresh(source)
        db.refresh(split_into)
        db.refresh(observation)
        assert observation.observed_at == original_ts
        assert observation.site_id == original_site
        assert observation.asset_id == split_into.id
        types = {
            row.identifier_type
            for row in db.query(AssetIdentifier).filter(
                AssetIdentifier.asset_id == split_into.id,
                AssetIdentifier.validity == "active",
            )
        }
        assert {
            "hostname",
            "mac",
            "fqdn",
            "tls_name",
            "dns_name",
            "serial",
            "device_id",
        }.issubset(types)
        assert source.first_seen is None
        assert source.last_seen is None
        assert source.lifecycle_state is None
        assert (
            db.query(AssetIdentifier)
            .filter(
                AssetIdentifier.asset_id == source.id,
                AssetIdentifier.identifier_type == "mac",
                AssetIdentifier.validity == "active",
            )
            .count()
            == 0
        )
    finally:
        db.close()


@requires_postgres
def test_low_confidence_and_cross_site_move(reset_db):
    from app.auth import hash_password
    from app.database import SessionLocal
    from app.identity_ops import merge_assets, move_asset_site
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import (
        Asset,
        AssetCorrelationDecision,
        AssetObservation,
        Device,
        Finding,
        Tenant,
        User,
    )
    from app.schemas import DeviceReport

    apply_schema()
    db: Session = SessionLocal()
    try:
        tenant = Tenant(name="Threshold Tenant", notes="")
        db.add(tenant)
        db.flush()
        actor = User(
            username="threshold-admin",
            email="threshold-admin@example.com",
            password_hash=hash_password("threshold-admin-pass"),
            role="admin",
            is_active=True,
        )
        db.add(actor)
        db.flush()

        _, created_a = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [
                DeviceReport(
                    ip="10.50.0.1",
                    scope="wan",
                    hostname="sharedhost",
                    tech="nginx",
                    ports=[{"port": 443, "product": "nginx"}],
                )
            ],
        )
        _, created_b = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="10.50.0.2", scope="wan", hostname="sharedhost")],
        )
        assert created_a[0].asset_id != created_b[0].asset_id
        probe_job = _job(db, tenant.id, scope="wan")
        upsert_devices(
            db,
            tenant.id,
            probe_job,
            [
                DeviceReport(
                    ip="10.50.0.9",
                    scope="wan",
                    hostname="sharedhost",
                    tech="nginx",
                    ports=[{"port": 80, "product": "nginx"}],
                )
            ],
        )
        decision = (
            db.query(AssetCorrelationDecision)
            .filter(AssetCorrelationDecision.scan_job_id == probe_job)
            .order_by(AssetCorrelationDecision.id.desc())
            .first()
        )
        assert decision is not None
        assert decision.decision != "linked_existing"
        assert decision.decision in {"ambiguous", "created_new"}
        for row in db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.decision == "linked_existing"):
            assert row.score >= 50
            assert row.confidence != "low"

        boston, boston_agent = _lan_world(db, tenant, "Boston")
        hartford, hartford_agent = _lan_world(db, tenant, "Hartford")
        _, boston_devs = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=boston_agent),
            [DeviceReport(ip="192.168.10.10", scope="lan", hostname="server01")],
        )
        _, hartford_devs = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="lan", agent=hartford_agent),
            [DeviceReport(ip="192.168.20.10", scope="lan", hostname="server01")],
        )
        asset_a = db.get(Asset, boston_devs[0].asset_id)
        asset_b = db.get(Asset, hartford_devs[0].asset_id)
        assert asset_a.site_id == boston.id
        assert asset_b.site_id == hartford.id
        boston_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset_a.id).one()
        hartford_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset_b.id).one()
        finding_a = Finding(
            tenant_id=tenant.id,
            device_id=boston_devs[0].id,
            template_id="keep-boston",
            name="finding-boston",
            severity="high",
            hostname="server01",
            host="192.168.10.10",
        )
        finding_b = Finding(
            tenant_id=tenant.id,
            device_id=hartford_devs[0].id,
            template_id="keep-hartford",
            name="finding-hartford",
            severity="medium",
            hostname="server01",
            host="192.168.20.10",
        )
        db.add_all([finding_a, finding_b])
        db.flush()
        merge_assets(db, target=asset_a, source_ids=[asset_b.id], actor=actor, reason="same host")
        db.refresh(asset_a)
        move_asset_site(db, asset=asset_a, site_id=hartford.id, actor=actor, reason="correct location")
        db.refresh(asset_a)
        db.refresh(finding_a)
        db.refresh(finding_b)
        db.refresh(boston_obs)
        db.refresh(hartford_obs)
        assert asset_a.site_id == hartford.id
        devices = (
            db.query(Device)
            .filter(
                Device.asset_id == asset_a.id,
                Device.hostname == "server01",
                Device.scope == "lan",
            )
            .all()
        )
        assert len(devices) == 1
        assert devices[0].site_id == hartford.id
        assert finding_a.device_id == devices[0].id
        assert finding_b.device_id == devices[0].id
        assert db.get(Device, finding_a.device_id) is not None
        assert db.get(Device, finding_b.device_id) is not None
        assert boston_obs.site_id == boston.id
        assert hartford_obs.site_id == hartford.id
    finally:
        db.close()


@requires_postgres
def test_phase_boundary_no_later_engines(reset_db):
    from app.database import engine
    from app.migrate import apply_schema

    apply_schema()
    tables = _tables(engine)
    assert "asset_findings" in tables
    assert "vulnerabilities" in tables
    assert "scan_run_detector_coverage" in tables
    assert "policies" not in tables
    assert "alert_policies" not in tables
    assert "scan_definitions" not in tables
    assert "mitigations" not in tables
    assert "risk_acceptances" not in tables
    assert "cvss_scores" not in tables
    assert "epss_scores" not in tables
    from app import correlation

    assert hasattr(correlation, "post_correlation_asset_policy_hook")
    from app.models import Scan

    assert hasattr(Scan, "interval_minutes")
    assert not hasattr(Scan, "cron_expression")
