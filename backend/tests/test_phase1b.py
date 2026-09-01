from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from tests.conftest import page_items, requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE1A_REVISION = "0002_sites_networks"
PHASE1B_HEAD = "0004_asset_observation_integrity"
PHASE1C_HEAD = "0005_asset_correlation_lifecycle"
PHASE1D_HEAD = "0006_scan_definition_execution"
PHASE2A_HEAD = "0009_phase2a_detector_identity_partition"
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
PHASE3A_HEAD = "0017_security_h6_h8"
PHASE1B_TABLES = {
    "assets",
    "asset_identifiers",
    "asset_addresses",
    "asset_services",
    "asset_observations",
    "tags",
}


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


def _insert_phase1a_representative(engine) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(
            text("INSERT INTO tenants (name, notes) VALUES ('Phase1A Tenant', '1b upgrade') RETURNING id")
        ).scalar_one()
        boston_id = conn.execute(
            text(
                "INSERT INTO sites (tenant_id, name, created_at) VALUES (:tid, 'Boston', :now) RETURNING id"
            ),
            {"tid": tenant_id, "now": now},
        ).scalar_one()
        imported_id = conn.execute(
            text(
                "INSERT INTO sites (tenant_id, name, created_at) VALUES (:tid, 'Imported Site', :now) RETURNING id"
            ),
            {"tid": tenant_id, "now": now},
        ).scalar_one()
        network_id = conn.execute(
            text(
                """
                INSERT INTO networks (tenant_id, site_id, name, cidr, dispatch_mode, created_at)
                VALUES (:tid, :sid, 'HQ LAN', '10.10.0.0/24', 'any_available', :now)
                RETURNING id
                """
            ),
            {"tid": tenant_id, "sid": boston_id, "now": now},
        ).scalar_one()
        agent_id = conn.execute(
            text(
                """
                INSERT INTO agents (tenant_id, site_id, name, uuid, status, created_at)
                VALUES (:tid, :sid, 'Boston Agent', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'approved', :now)
                RETURNING id
                """
            ),
            {"tid": tenant_id, "sid": boston_id, "now": now},
        ).scalar_one()
        lan_scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (
                    tenant_id, agent_id, name, scope, profile, nuclei_severities, nuclei_tags,
                    subnet_ids, is_enabled
                )
                VALUES (:tid, :aid, 'LAN Scan', 'lan', 'discovery', 'high', '', '[]'::jsonb, true)
                RETURNING id
                """
            ),
            {"tid": tenant_id, "aid": agent_id},
        ).scalar_one()
        wan_scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (
                    tenant_id, agent_id, name, scope, profile, nuclei_severities, nuclei_tags,
                    subnet_ids, is_enabled
                )
                VALUES (:tid, NULL, 'WAN Scan', 'wan', 'discovery', 'high', '', '[]'::jsonb, true)
                RETURNING id
                """
            ),
            {"tid": tenant_id},
        ).scalar_one()
        job_id = conn.execute(
            text(
                """
                INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count)
                VALUES (:sid, :tid, 'done', 1, 1)
                RETURNING id
                """
            ),
            {"sid": lan_scan_id, "tid": tenant_id},
        ).scalar_one()
        lan_device_id = conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports, first_seen, last_seen, last_scan_job_id
                )
                VALUES (
                    :tid, '10.10.0.8', 'lan-host', 'lan', 'known', 'Server', 'lan keep',
                    'Web Server', 'Example', 'nginx', CAST(:ports AS jsonb), :seen, :seen, :jid
                )
                RETURNING id
                """
            ),
            {
                "tid": tenant_id,
                "jid": job_id,
                "seen": now,
                "ports": '[{"port": 443, "protocol": "tcp"}]',
            },
        ).scalar_one()
        unresolved_lan_id = conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports, first_seen, last_seen
                )
                VALUES (
                    :tid, '10.20.0.9', 'orphan-lan', 'lan', 'new', 'Unknown', 'no job',
                    '', '', '', '[]'::jsonb, :seen, :seen
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "seen": now},
        ).scalar_one()
        wan_device_id = conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports, first_seen, last_seen
                )
                VALUES (
                    :tid, '203.0.113.10', 'wan-host', 'wan', 'new', 'Unknown', 'wan keep',
                    '', '', '', '[80]'::jsonb, :seen, :seen
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "seen": now},
        ).scalar_one()
        finding_id = conn.execute(
            text(
                """
                INSERT INTO findings (
                    tenant_id, scan_job_id, device_id, template_id, name, severity,
                    hostname, host, matched_at, tags, found_at, raw_json
                )
                VALUES (
                    :tid, :jid, :did, 'cve-keep', 'Keep finding', 'high',
                    'lan-host', '10.10.0.8', 'https://10.10.0.8', '', :found, '{}'::jsonb
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "jid": job_id, "did": lan_device_id, "found": now},
        ).scalar_one()
    return {
        "tenant": tenant_id,
        "boston": boston_id,
        "imported": imported_id,
        "network": network_id,
        "agent": agent_id,
        "lan_scan": lan_scan_id,
        "wan_scan": wan_scan_id,
        "job": job_id,
        "lan_device": lan_device_id,
        "unresolved_lan": unresolved_lan_id,
        "wan_device": wan_device_id,
        "finding": finding_id,
    }


@requires_postgres
def test_upgrade_0002_to_0003_preserves_phase1a_data(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision, head_revision
    from app.models import (
        SOURCE_LEGACY_MIGRATION,
        Asset,
        AssetAddress,
        AssetIdentifier,
        AssetObservation,
        AssetService,
        Device,
        Finding,
    )

    command.upgrade(alembic_config(), PHASE1A_REVISION)
    ids = _insert_phase1a_representative(engine)
    command.upgrade(alembic_config(), "head")
    assert current_revision() == head_revision() == PHASE3A_HEAD
    assert PHASE1B_TABLES.issubset(_tables(engine))

    db = SessionLocal()
    try:
        lan = db.get(Device, ids["lan_device"])
        wan = db.get(Device, ids["wan_device"])
        unresolved = db.get(Device, ids["unresolved_lan"])
        finding = db.get(Finding, ids["finding"])
        assert lan is not None and wan is not None and unresolved is not None
        assert lan.id == ids["lan_device"]
        assert wan.id == ids["wan_device"]
        assert finding is not None and finding.device_id == ids["lan_device"]
        assert lan.asset_id and wan.asset_id and unresolved.asset_id
        assert lan.asset_id != wan.asset_id != unresolved.asset_id
        lan_asset = db.get(Asset, lan.asset_id)
        wan_asset = db.get(Asset, wan.asset_id)
        unresolved_asset = db.get(Asset, unresolved.asset_id)
        assert lan_asset is not None and wan_asset is not None and unresolved_asset is not None
        assert lan_asset.site_id == ids["boston"]
        assert wan_asset.site_id is None
        assert unresolved_asset.site_id == ids["imported"]
        assert lan_asset.classification == "Server"
        assert lan_asset.description == "lan keep"
        assert lan_asset.disposition == "unreviewed"
        assert lan_asset.first_seen is not None and lan_asset.last_seen is not None
        host = (
            db.query(AssetIdentifier)
            .filter(AssetIdentifier.asset_id == lan_asset.id, AssetIdentifier.identifier_type == "hostname")
            .one()
        )
        assert host.value == "lan-host"
        assert host.source == SOURCE_LEGACY_MIGRATION
        addr = db.query(AssetAddress).filter(AssetAddress.asset_id == lan_asset.id).one()
        assert addr.ip == "10.10.0.8"
        service = db.query(AssetService).filter(AssetService.asset_id == lan_asset.id).one()
        assert service.port == 443
        obs = db.query(AssetObservation).filter(AssetObservation.asset_id == lan_asset.id).one()
        assert obs.source == SOURCE_LEGACY_MIGRATION
        assert obs.provenance == SOURCE_LEGACY_MIGRATION
        assert obs.snapshot.get("legacy_device_id") == lan.id
        assert db.query(AssetObservation).count() == 3
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0003_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config

    command.upgrade(alembic_config(), "0003_assets_observations")
    try:
        command.downgrade(alembic_config(), PHASE1A_REVISION)
    except (NotImplementedError, CommandError) as exc:
        assert "Refusing to downgrade 0003_assets_observations" in str(exc)
    else:
        raise AssertionError("0003 downgrade must refuse instead of dropping Asset history")


@requires_postgres
def test_downgrade_from_0004_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config

    command.upgrade(alembic_config(), PHASE1B_HEAD)
    try:
        command.downgrade(alembic_config(), "0003_assets_observations")
    except (NotImplementedError, CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0004_asset_observation_integrity" in str(exc)
    else:
        raise AssertionError("0004 downgrade must refuse instead of reversing observation integrity")


@requires_postgres
def test_identity_history_and_no_automatic_correlation(reset_db):
    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import Asset, AssetAddress, AssetIdentifier, AssetObservation, Device, Scan, ScanJob
    from app.schemas import DeviceReport

    apply_schema()
    db: Session = SessionLocal()
    try:
        from app.models import Tenant

        tenant = Tenant(name="Identity Tenant", notes="")
        db.add(tenant)
        db.flush()

        def _job() -> int:
            scan = Scan(tenant_id=tenant.id, name="wan", scope="wan", profile="discovery")
            db.add(scan)
            db.flush()
            job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
            db.add(job)
            db.flush()
            return job.id

        job_a = _job()
        created, devices = upsert_devices(
            db,
            tenant.id,
            job_a,
            [
                DeviceReport(ip="10.1.1.10", scope="wan", hostname="alpha"),
                DeviceReport(ip="10.1.1.10", scope="wan", hostname="beta"),
            ],
        )
        assert created == 2
        assert devices[0].asset_id != devices[1].asset_id
        same_ip = (
            db.query(AssetAddress)
            .filter(AssetAddress.tenant_id == tenant.id, AssetAddress.ip == "10.1.1.10")
            .all()
        )
        assert len({row.asset_id for row in same_ip}) == 2

        first = db.get(Asset, devices[0].asset_id)
        before = db.query(AssetObservation).filter(AssetObservation.asset_id == first.id).count()
        job_repeat = _job()
        upsert_devices(db, tenant.id, job_repeat, [DeviceReport(ip="10.1.1.10", scope="wan", hostname="alpha")])
        upsert_devices(db, tenant.id, job_repeat, [DeviceReport(ip="10.1.1.10", scope="wan", hostname="alpha")])
        after = db.query(AssetObservation).filter(AssetObservation.asset_id == first.id).all()
        assert len(after) == before + 1
        db.refresh(first)
        assert first.disposition == "unreviewed"
        same_device = db.query(Device).filter(Device.id == devices[0].id).one()
        assert same_device.asset_id == first.id

        before_change = db.query(Asset).filter(Asset.tenant_id == tenant.id).count()
        upsert_devices(db, tenant.id, _job(), [DeviceReport(ip="10.1.1.11", scope="wan", hostname="alpha")])
        db.refresh(first)
        addrs = db.query(AssetAddress).filter(AssetAddress.asset_id == first.id).all()
        assert {row.ip for row in addrs} == {"10.1.1.10"}
        assert db.query(Asset).filter(Asset.tenant_id == tenant.id).count() == before_change + 1

        from app.models import Site

        site_a = Site(tenant_id=tenant.id, name="Site A")
        site_b = Site(tenant_id=tenant.id, name="Site B")
        db.add_all([site_a, site_b])
        db.flush()
        db.add_all(
            [
                AssetAddress(
                    asset_id=first.id,
                    tenant_id=tenant.id,
                    site_id=site_a.id,
                    ip="10.9.9.9",
                    address_family="ipv4",
                    source="manual",
                ),
                AssetAddress(
                    asset_id=devices[1].asset_id,
                    tenant_id=tenant.id,
                    site_id=site_b.id,
                    ip="10.9.9.9",
                    address_family="ipv4",
                    source="manual",
                ),
            ]
        )
        db.flush()
        shared = db.query(AssetAddress).filter(AssetAddress.ip == "10.9.9.9").all()
        assert {row.site_id for row in shared} == {site_a.id, site_b.id}

        from app.assets import upsert_identifier

        upsert_identifier(db, first, "hostname", "shared.example", source="manual", seen_at=None)
        upsert_identifier(db, db.get(Asset, devices[1].asset_id), "hostname", "shared.example", source="manual", seen_at=None)
        upsert_identifier(db, first, "hostname", "shared.example", source="manual", seen_at=None)
        names = (
            db.query(AssetIdentifier)
            .filter(AssetIdentifier.normalized_value == "shared.example")
            .all()
        )
        assert len(names) == 2
        assert {row.asset_id for row in names} == {first.id, devices[1].asset_id}

        indexes = inspect(db.bind).get_indexes("devices")
        unique = inspect(db.bind).get_unique_constraints("devices")
        assert any("asset_id" in (idx.get("column_names") or []) for idx in indexes)
        assert not any(uc.get("column_names") == ["asset_id"] for uc in unique)
    finally:
        db.close()


@requires_postgres
def test_scanner_lan_wan_observations_and_service_history(reset_db):
    from app.auth import create_agent_token
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import Asset, AssetObservation, AssetService, Device

    apply_schema()
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Scan Tenant", "notes": ""}).json()
        site = client.post(
            f"/api/tenants/{tenant['id']}/sites",
            headers=_headers(admin),
            json={"name": "HQ"},
        ).json()
        network = client.post(
            f"/api/sites/{site['id']}/networks",
            headers=_headers(admin),
            json={"name": "Servers", "cidr": "10.1.0.0/24"},
        ).json()
        agent = client.post(
            f"/api/tenants/{tenant['id']}/agents",
            headers=_headers(admin),
            json={"name": "Agent HQ", "site_id": site["id"]},
        ).json()
        client.put(
            f"/api/networks/{network['id']}/authorized-agents",
            headers=_headers(admin),
            json={"agent_ids": [agent["id"]]},
        )
        lan_scan = client.post(
            f"/api/tenants/{tenant['id']}/scans",
            headers=_headers(admin),
            json={
                "name": "LAN",
                "scope": "lan",
                "agent_id": agent["id"],
                "subnet_ids": [network["subnet_id"]],
                "profile": "discovery",
            },
        ).json()
        wan_target = client.post(
            f"/api/tenants/{tenant['id']}/wan-targets",
            headers=_headers(admin),
            json={"name": "Edge", "target_type": "cidr", "value": "203.0.113.0/24"},
        )
        assert wan_target.status_code == 200, wan_target.text
        wan_scan = client.post(
            f"/api/tenants/{tenant['id']}/scans",
            headers=_headers(admin),
            json={"name": "WAN", "scope": "wan", "profile": "discovery", "wan_target_ids": [wan_target.json()["id"]]},
        ).json()
        lan_job = client.post(f"/api/scans/{lan_scan['id']}/run", headers=_headers(admin)).json()
        wan_job = client.post(f"/api/scans/{wan_scan['id']}/run", headers=_headers(admin)).json()

        db = SessionLocal()
        try:
            from app.models import Agent, ScanJob

            row = db.get(Agent, agent["id"])
            row.status = "approved"
            job = db.get(ScanJob, lan_job["id"])
            job.claimed_by = agent["uuid"]
            job.status = "running"
            wan = db.get(ScanJob, wan_job["id"])
            wan.claimed_by = "central"
            wan.status = "running"
            db.commit()
        finally:
            db.close()

        agent_headers = {"Authorization": f"Bearer {create_agent_token(agent['uuid'], agent['id'], tenant['id'])}"}
        posted = client.post(
            f"/api/agent/jobs/{lan_job['id']}/devices",
            headers=agent_headers,
            json=[{"ip": "10.1.0.20", "scope": "lan", "hostname": "srv01", "ports": [22, 443], "title": "panel"}],
        )
        assert posted.status_code == 200, posted.text
        posted_again = client.post(
            f"/api/agent/jobs/{lan_job['id']}/devices",
            headers=agent_headers,
            json=[{"ip": "10.1.0.20", "scope": "lan", "hostname": "srv01", "ports": [22, 443], "title": "panel"}],
        )
        assert posted_again.status_code == 200

        from app.config import settings

        wan_post = client.post(
            f"/api/internal/scanner/jobs/{wan_job['id']}/devices",
            headers={"x-scanner-token": settings.scanner_token},
            json=[{"ip": "203.0.113.5", "scope": "wan", "hostname": "edge01", "ports": [443]}],
        )
        assert wan_post.status_code == 200, wan_post.text

        db = SessionLocal()
        try:
            lan_device = db.query(Device).filter(Device.hostname == "srv01").one()
            wan_device = db.query(Device).filter(Device.hostname == "edge01").one()
            lan_asset = db.get(Asset, lan_device.asset_id)
            wan_asset = db.get(Asset, wan_device.asset_id)
            assert lan_asset.site_id == site["id"]
            assert wan_asset.site_id is None
            lan_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == lan_asset.id).all()
            assert len(lan_obs) == 1
            assert lan_obs[0].agent_id == agent["id"]
            assert lan_obs[0].site_id == site["id"]
            assert lan_obs[0].network_id == network["id"]
            assert lan_obs[0].scan_job_id == lan_job["id"]
            assert lan_obs[0].scope == "lan"
            assert lan_obs[0].observed_at.tzinfo is not None
            wan_obs = db.query(AssetObservation).filter(AssetObservation.asset_id == wan_asset.id).one()
            assert wan_obs.agent_id is None
            assert wan_obs.site_id is None
            assert wan_obs.scope == "wan"
            services = db.query(AssetService).filter(AssetService.asset_id == lan_asset.id).all()
            assert {row.port for row in services} == {22, 443}
            assert lan_asset.disposition == "unreviewed"
            devices = client.get(f"/api/tenants/{tenant['id']}/devices", headers=_headers(admin))
            assert devices.status_code == 200
            assert {row["hostname"] for row in page_items(devices.json())} >= {"srv01", "edge01"}
        finally:
            db.close()


@requires_postgres
def test_expected_assets_tags_rbac_and_audit(reset_db):
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import Asset, AuditLog, Device

    apply_schema()
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        operator = _create_staff(client, admin, "operator", "user")
        viewer = _create_staff(client, admin, "auditor", "viewer")
        tenant_a = client.post("/api/tenants", headers=_headers(admin), json={"name": "Tenant A", "notes": ""}).json()
        tenant_b = client.post("/api/tenants", headers=_headers(admin), json={"name": "Tenant B", "notes": ""}).json()
        site_a = client.post(
            f"/api/tenants/{tenant_a['id']}/sites",
            headers=_headers(operator),
            json={"name": "HQ"},
        ).json()
        site_b = client.post(
            f"/api/tenants/{tenant_b['id']}/sites",
            headers=_headers(admin),
            json={"name": "Other"},
        ).json()
        created = client.post(
            f"/api/tenants/{tenant_a['id']}/assets",
            headers=_headers(operator),
            json={
                "site_id": site_a["id"],
                "display_name": "DC01",
                "hostname": "dc01.example.local",
                "ip": "10.1.1.10",
                "classification": "Server",
                "criticality": "high",
                "tags": ["Domain Controller"],
            },
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["is_expected"] is True
        assert body["is_not_yet_observed"] is True
        assert body["lifecycle_state"] is None
        assert body["first_seen"] is None
        assert body["last_seen"] is None
        assert body["disposition"] == "unreviewed"
        assert body["hostname"] == "dc01.example.local"
        asset_id = body["id"]

        placeholder_expected = client.post(
            f"/api/tenants/{tenant_a['id']}/assets",
            headers=_headers(operator),
            json={
                "site_id": site_a["id"],
                "display_name": "IP Only Expected",
                "hostname": "10.9.9.9",
                "ip": "10.9.9.9",
                "classification": "Unknown",
            },
        )
        assert placeholder_expected.status_code == 200, placeholder_expected.text
        placeholder_body = placeholder_expected.json()
        assert placeholder_body["lifecycle_state"] is None
        assert placeholder_body["is_not_yet_observed"] is True
        assert placeholder_body["current_addresses"] == ["10.9.9.9"]
        placeholder_detail = client.get(
            f"/api/assets/{placeholder_body['id']}",
            headers=_headers(operator),
        )
        assert placeholder_detail.status_code == 200
        assert placeholder_detail.json()["identifiers"] == []

        cross = client.post(
            f"/api/tenants/{tenant_a['id']}/assets",
            headers=_headers(admin),
            json={"site_id": site_b["id"], "display_name": "Bad"},
        )
        assert cross.status_code == 404

        viewer_create = client.post(
            f"/api/tenants/{tenant_a['id']}/assets",
            headers=_headers(viewer),
            json={"site_id": site_a["id"], "display_name": "Nope"},
        )
        assert viewer_create.status_code == 403
        viewer_patch = client.patch(
            f"/api/assets/{asset_id}",
            headers=_headers(viewer),
            json={"disposition": "approved"},
        )
        assert viewer_patch.status_code == 403
        viewer_tag = client.post(
            f"/api/assets/{asset_id}/tags",
            headers=_headers(viewer),
            json={"name": "CUI"},
        )
        assert viewer_tag.status_code == 403
        listed = client.get(f"/api/tenants/{tenant_a['id']}/assets", headers=_headers(viewer))
        assert listed.status_code == 200
        assert {row["display_name"] for row in page_items(listed.json())} == {"DC01", "IP Only Expected"}

        bad_crit = client.patch(f"/api/assets/{asset_id}", headers=_headers(operator), json={"criticality": "urgent"})
        assert bad_crit.status_code == 400
        bad_disp = client.patch(f"/api/assets/{asset_id}", headers=_headers(operator), json={"disposition": "trusted"})
        assert bad_disp.status_code == 400
        bad_life = client.patch(f"/api/assets/{asset_id}", headers=_headers(operator), json={"lifecycle_state": "approved"})
        assert bad_life.status_code == 400
        ok = client.patch(
            f"/api/assets/{asset_id}",
            headers=_headers(operator),
            json={"disposition": "approved", "criticality": "critical", "lifecycle_state": "inactive"},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["disposition"] == "approved"
        assert ok.json()["criticality"] == "critical"
        assert ok.json()["lifecycle_state"] == "inactive"

        site_tag = client.post(f"/api/sites/{site_a['id']}/tags", headers=_headers(operator), json={"name": "Production"})
        assert site_tag.status_code == 200
        network = client.post(
            f"/api/sites/{site_a['id']}/networks",
            headers=_headers(operator),
            json={"name": "VLAN", "cidr": "10.1.1.0/24"},
        ).json()
        net_tag = client.post(
            f"/api/networks/{network['id']}/tags",
            headers=_headers(operator),
            json={"name": "Production"},
        )
        assert net_tag.status_code == 200
        dup = client.post(f"/api/assets/{asset_id}/tags", headers=_headers(operator), json={"name": "Domain Controller"})
        assert dup.status_code == 200
        other_tag = client.post(f"/api/tenants/{tenant_b['id']}/tags", headers=_headers(admin), json={"name": "Foreign"})
        assert other_tag.status_code == 200
        cross_tag = client.post(
            f"/api/assets/{asset_id}/tags",
            headers=_headers(admin),
            json={"tag_id": other_tag.json()["id"]},
        )
        assert cross_tag.status_code == 400

        from app.inventory import upsert_devices
        from app.models import Scan, ScanJob
        from app.schemas import DeviceReport

        db = SessionLocal()
        try:
            scan = Scan(tenant_id=tenant_a["id"], name="discover", scope="wan", profile="discovery")
            db.add(scan)
            db.flush()
            job = ScanJob(scan_id=scan.id, tenant_id=tenant_a["id"], status="running")
            db.add(job)
            db.flush()
            upsert_devices(
                db,
                tenant_a["id"],
                job.id,
                [DeviceReport(ip="10.1.1.10", scope="wan", hostname="dc01.example.local")],
            )
            db.commit()
            expected = db.get(Asset, asset_id)
            discovered = db.query(Device).filter(Device.hostname == "dc01.example.local").first()
            assert expected.first_seen is None
            assert discovered is not None
            assert discovered.asset_id != expected.id
            actions = {row.action for row in db.query(AuditLog).all()}
            assert "asset.manual_create" in actions
            assert "asset.disposition_change" in actions
            assert "asset.criticality_change" in actions
            assert "asset.tag_change" in actions
            assert "site.tag_change" in actions
            assert "network.tag_change" in actions
        finally:
            db.close()

        history = client.get(f"/api/assets/{asset_id}/observations?limit=10&offset=0", headers=_headers(viewer))
        assert history.status_code == 200
        assert history.json()["limit"] == 10
        assert history.json()["total"] == 0
        findings = client.get(f"/api/tenants/{tenant_a['id']}/findings", headers=_headers(viewer))
        assert findings.status_code == 200


@requires_postgres
def test_asset_list_avoids_nplus_one_and_no_phase1c(reset_db):
    from sqlalchemy import event

    from app.database import engine
    from app.migrate import apply_schema
    from app.models import Asset, Site, Tenant

    apply_schema()
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        tenant = Tenant(name="Perf Tenant", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        for i in range(15):
            db.add(
                Asset(
                    tenant_id=tenant.id,
                    site_id=site.id,
                    display_name=f"host-{i}",
                    classification="Unknown",
                    description="",
                    lifecycle_state="active",
                    disposition="unreviewed",
                    criticality="normal",
                )
            )
        db.commit()
        tenant_id = tenant.id
    finally:
        db.close()

    statements: list[str] = []

    def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        statements.append(statement)

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        event.listen(engine, "before_cursor_execute", before_cursor)
        try:
            listed = client.get(f"/api/tenants/{tenant_id}/assets", headers=_headers(admin))
            assert listed.status_code == 200
            assert len(page_items(listed.json())) == 15
        finally:
            event.remove(engine, "before_cursor_execute", before_cursor)
    assert len(statements) < 20

    inventory = (BACKEND_ROOT / "app" / "inventory.py").read_text()
    assert "search all Assets" not in inventory


@requires_postgres
def test_upgrade_0003_to_0004_fixes_lifecycle_and_placeholder_hostnames(reset_db):
    from alembic import command
    from datetime import datetime, timezone

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision, head_revision
    from app.models import Asset, AssetAddress, AssetIdentifier, AssetObservation

    command.upgrade(alembic_config(), "0003_assets_observations")
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(
            text("INSERT INTO tenants (name, notes) VALUES ('Integrity Tenant', '') RETURNING id")
        ).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:tid, 'HQ', :now) RETURNING id"),
            {"tid": tenant_id, "now": now},
        ).scalar_one()
        expected_id = conn.execute(
            text(
                """
                INSERT INTO assets (
                    tenant_id, site_id, display_name, classification, description,
                    lifecycle_state, disposition, criticality, is_expected,
                    first_seen, last_seen, created_at, updated_at
                )
                VALUES (
                    :tid, :sid, 'Expected Box', 'Server', '',
                    'active', 'unreviewed', 'normal', true,
                    NULL, NULL, :now, :now
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "sid": site_id, "now": now},
        ).scalar_one()
        observed_id = conn.execute(
            text(
                """
                INSERT INTO assets (
                    tenant_id, site_id, display_name, classification, description,
                    lifecycle_state, disposition, criticality, is_expected,
                    first_seen, last_seen, created_at, updated_at
                )
                VALUES (
                    :tid, :sid, '10.1.1.20', 'Unknown', '',
                    'active', 'unreviewed', 'normal', false,
                    :now, :now, :now, :now
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "sid": site_id, "now": now},
        ).scalar_one()
        conn.execute(
            text(
                """
                INSERT INTO asset_identifiers (
                    asset_id, tenant_id, identifier_type, value, normalized_value, source, created_at
                )
                VALUES
                    (:eid, :tid, 'hostname', 'dc01.example.local', 'dc01.example.local', 'manual', :now),
                    (:oid, :tid, 'hostname', '10.1.1.20', '10.1.1.20', 'legacy_migration', :now),
                    (:oid, :tid, 'hostname', 'dev-abc123', 'dev-abc123', 'legacy_migration', :now)
                """
            ),
            {"eid": expected_id, "oid": observed_id, "tid": tenant_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO asset_addresses (
                    asset_id, tenant_id, site_id, ip, address_family, source, first_seen, last_seen, created_at
                )
                VALUES (:oid, :tid, :sid, '10.1.1.20', 'ipv4', 'legacy_migration', :now, :now, :now)
                """
            ),
            {"oid": observed_id, "tid": tenant_id, "sid": site_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO asset_observations (
                    asset_id, tenant_id, site_id, scope, source, observed_at, hostname, ip,
                    snapshot, provenance, created_at
                )
                VALUES (
                    :oid, :tid, :sid, 'wan', 'legacy_migration', :now, '10.1.1.20', '10.1.1.20',
                    CAST(:snap AS jsonb), 'legacy_migration', :now
                )
                """
            ),
            {
                "oid": observed_id,
                "tid": tenant_id,
                "sid": site_id,
                "now": now,
                "snap": '{"hostname": "10.1.1.20", "ip": "10.1.1.20", "ports": [443], "scope": "wan"}',
            },
        )

    command.upgrade(alembic_config(), "head")
    assert current_revision() == head_revision() == PHASE3A_HEAD

    db = SessionLocal()
    try:
        expected = db.get(Asset, expected_id)
        observed = db.get(Asset, observed_id)
        assert expected is not None and expected.lifecycle_state is None
        assert observed is not None and observed.lifecycle_state == "active"
        names = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id.in_([expected_id, observed_id])).all()
        assert {row.value for row in names} == {"dc01.example.local"}
        assert db.query(AssetAddress).filter(AssetAddress.asset_id == observed_id, AssetAddress.ip == "10.1.1.20").one()
        obs = db.query(AssetObservation).filter(AssetObservation.asset_id == observed_id).one()
        assert obs.observation_key
        assert len(obs.observation_key) == 64
        uniques = inspect(engine).get_unique_constraints("asset_observations")
        unique_names = {row["name"] for row in uniques}
        assert "uq_asset_observations_job_asset_key" in unique_names
        assert "uq_asset_observations_scan_job_id_asset_id" not in unique_names
        lifecycle = {col["name"]: col for col in inspect(engine).get_columns("assets")}["lifecycle_state"]
        assert lifecycle["nullable"] is True
    finally:
        db.close()


@requires_postgres
def test_observation_uses_report_facts_and_per_report_keys(reset_db):
    from datetime import timedelta

    import importlib.util

    from app.assets import observation_fingerprint
    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import Asset, AssetAddress, AssetIdentifier, AssetObservation, AssetService, Device, Scan, ScanJob, Tenant
    from app.schemas import DeviceReport

    spec = importlib.util.spec_from_file_location(
        "phase1b_0004",
        BACKEND_ROOT / "alembic" / "versions" / "0004_asset_observation_integrity.py",
    )
    assert spec is not None and spec.loader is not None
    migrated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migrated)
    assert migrated.observation_fingerprint("srv01", "10.1.1.10", "wan", [443]) == migrated.observation_fingerprint(
        "srv01", "10.1.1.10", "wan", [443]
    )
    assert migrated.observation_fingerprint("10.1.1.20", "10.1.1.20", "wan", []) == migrated.observation_fingerprint(
        "10.1.1.20", "10.1.1.20", "wan", []
    )
    assert observation_fingerprint("srv01", "10.1.1.10", "wan", [443]) != migrated.observation_fingerprint(
        "srv01", "10.1.1.10", "wan", [443]
    )
    assert observation_fingerprint(
        "srv01", "10.1.1.10", "wan", [443], tls_name="old.example.com"
    ) != observation_fingerprint("srv01", "10.1.1.10", "wan", [443], tls_name="new.example.com")
    assert observation_fingerprint("srv01", "10.1.1.10", "wan", [443]) == observation_fingerprint(
        "srv01", "10.1.1.10", "wan", [443]
    )

    apply_schema()
    db: Session = SessionLocal()
    try:
        tenant = Tenant(name="Report Facts Tenant", notes="")
        db.add(tenant)
        db.flush()
        scan = Scan(tenant_id=tenant.id, name="wan", scope="wan", profile="discovery")
        db.add(scan)
        db.flush()
        job1 = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        job2 = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        job3 = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        db.add_all([job1, job2, job3])
        db.flush()

        upsert_devices(
            db,
            tenant.id,
            job1.id,
            [
                DeviceReport(
                    ip="10.8.8.8",
                    scope="wan",
                    hostname="srv01",
                    ports=[443],
                    title="panel",
                    tech="nginx",
                    mac="aa:bb:cc:dd:ee:02",
                )
            ],
        )
        device = db.query(Device).filter(Device.hostname == "srv01").one()
        asset = db.get(Asset, device.asset_id)
        service = db.query(AssetService).filter(AssetService.asset_id == asset.id, AssetService.port == 443).one()
        first_seen = service.last_seen
        assert first_seen is not None

        service.last_seen = first_seen - timedelta(days=1)
        db.flush()
        stale_last_seen = service.last_seen

        upsert_devices(
            db,
            tenant.id,
            job2.id,
            [
                DeviceReport(
                    ip="10.8.8.8",
                    scope="wan",
                    hostname="srv01",
                    ports=[],
                    title="",
                    tech="",
                    mac="aa:bb:cc:dd:ee:02",
                )
            ],
        )
        db.refresh(service)
        assert service.port == 443
        assert service.last_seen == stale_last_seen
        empty_obs = (
            db.query(AssetObservation)
            .filter(AssetObservation.asset_id == asset.id, AssetObservation.scan_job_id == job2.id)
            .one()
        )
        assert empty_obs.snapshot["ports"] == []
        assert empty_obs.snapshot["title"] == ""
        assert empty_obs.snapshot["tech"] == ""

        upsert_devices(
            db,
            tenant.id,
            job3.id,
            [
                DeviceReport(ip="10.1.1.10", scope="wan", hostname="srv01", ports=[443], mac="aa:bb:cc:dd:ee:02"),
                DeviceReport(ip="10.1.1.11", scope="wan", hostname="srv01", ports=[22], mac="aa:bb:cc:dd:ee:02"),
                DeviceReport(ip="10.1.1.11", scope="wan", hostname="srv01", ports=[22], mac="aa:bb:cc:dd:ee:02"),
            ],
        )
        same_job = (
            db.query(AssetObservation)
            .filter(AssetObservation.asset_id == asset.id, AssetObservation.scan_job_id == job3.id)
            .all()
        )
        assert len(same_job) == 2
        assert {row.ip for row in same_job} == {"10.1.1.10", "10.1.1.11"}
        assert len({row.observation_key for row in same_job}) == 2
        assert {row.ip for row in db.query(AssetAddress).filter(AssetAddress.asset_id == asset.id).all()} >= {
            "10.8.8.8",
            "10.1.1.10",
            "10.1.1.11",
        }
        assert {row.port for row in db.query(AssetService).filter(AssetService.asset_id == asset.id).all()} == {22, 443}

        ip_only = upsert_devices(
            db,
            tenant.id,
            job3.id,
            [DeviceReport(ip="203.0.113.9", scope="wan", hostname="203.0.113.9", ports=[80])],
        )
        created_count, created_devices = ip_only
        assert created_count == 1
        placeholder_asset = db.get(Asset, created_devices[0].asset_id)
        host_ids = (
            db.query(AssetIdentifier)
            .filter(
                AssetIdentifier.asset_id == placeholder_asset.id,
                AssetIdentifier.identifier_type == "hostname",
            )
            .all()
        )
        assert host_ids == []
        assert db.query(AssetAddress).filter(AssetAddress.asset_id == placeholder_asset.id, AssetAddress.ip == "203.0.113.9").one()
    finally:
        db.close()


@requires_postgres
def test_exact_retry_does_not_advance_asset_evidence(reset_db):
    from datetime import timedelta
    from unittest.mock import patch

    from app.database import SessionLocal
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import Asset, AssetAddress, AssetIdentifier, AssetObservation, AssetService, Device, Scan, ScanJob, Tenant
    from app.schemas import DeviceReport

    apply_schema()
    db: Session = SessionLocal()
    try:
        tenant = Tenant(name="Retry Evidence Tenant", notes="")
        db.add(tenant)
        db.flush()
        scan = Scan(tenant_id=tenant.id, name="wan", scope="wan", profile="discovery")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        db.add(job)
        db.flush()
        report = DeviceReport(
            ip="10.4.4.4",
            scope="wan",
            hostname="retry01",
            ports=[443],
            title="panel",
            tech="nginx",
        )
        upsert_devices(db, tenant.id, job.id, [report])
        device = db.query(Device).filter(Device.hostname == "retry01").one()
        asset = db.get(Asset, device.asset_id)
        identifier = (
            db.query(AssetIdentifier)
            .filter(AssetIdentifier.asset_id == asset.id, AssetIdentifier.identifier_type == "hostname")
            .one()
        )
        address = db.query(AssetAddress).filter(AssetAddress.asset_id == asset.id, AssetAddress.ip == "10.4.4.4").one()
        service = db.query(AssetService).filter(AssetService.asset_id == asset.id, AssetService.port == 443).one()
        observation = db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).one()
        recorded = {
            "asset": asset.last_seen,
            "identifier": identifier.last_seen,
            "address": address.last_seen,
            "service": service.last_seen,
            "observed_at": observation.observed_at,
            "obs_id": observation.id,
            "snapshot": dict(observation.snapshot),
        }
        assert all(value is not None for key, value in recorded.items() if key not in {"obs_id", "snapshot"})

        later = recorded["asset"] + timedelta(seconds=30)
        with patch("app.assets.utcnow", return_value=later):
            upsert_devices(db, tenant.id, job.id, [report])

        db.refresh(asset)
        db.refresh(identifier)
        db.refresh(address)
        db.refresh(service)
        db.refresh(observation)
        observations = db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).all()
        assert len(observations) == 1
        assert observations[0].id == recorded["obs_id"]
        assert asset.last_seen == recorded["asset"]
        assert identifier.last_seen == recorded["identifier"]
        assert address.last_seen == recorded["address"]
        assert service.last_seen == recorded["service"]
        assert observation.observed_at == recorded["observed_at"]
        assert observation.snapshot == recorded["snapshot"]
        assert later != recorded["asset"]
    finally:
        db.close()
