from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = BACKEND_ROOT / "alembic" / "versions" / "0001_baseline_current_schema.py"
PHASE1A_REVISION = "0002_sites_networks"
PHASE1B_HEAD = "0003_assets_observations"
PHASE1B_TABLES = {
    "assets",
    "asset_identifiers",
    "asset_addresses",
    "asset_services",
    "asset_observations",
}


@contextmanager
def _client() -> Iterator[TestClient]:
    with patch("app.main.start_scheduler"):
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
        },
    )
    assert response.status_code == 200, response.text
    return _login(client, username, f"{username}-password")


def _tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _insert_phase0_representative(engine) -> dict[str, int]:
    with engine.begin() as conn:
        user_id = conn.execute(
            text(
                """
                INSERT INTO users (username, email, password_hash, role, is_active)
                VALUES ('phase0-admin', 'phase0@localhost', 'not-a-real-hash', 'admin', true)
                RETURNING id
                """
            )
        ).scalar_one()
        tenant_id = conn.execute(
            text("INSERT INTO tenants (name, notes) VALUES ('Phase0 Tenant', 'upgrade fixture') RETURNING id")
        ).scalar_one()
        lan_id = conn.execute(
            text(
                """
                INSERT INTO subnets (tenant_id, name, cidr, scope)
                VALUES (:tid, 'HQ LAN', '10.10.0.0/24', 'lan')
                RETURNING id
                """
            ),
            {"tid": tenant_id},
        ).scalar_one()
        wan_id = conn.execute(
            text(
                """
                INSERT INTO subnets (tenant_id, name, cidr, scope)
                VALUES (:tid, 'Edge WAN', '203.0.113.0/24', 'wan')
                RETURNING id
                """
            ),
            {"tid": tenant_id},
        ).scalar_one()
        agent_id = conn.execute(
            text(
                """
                INSERT INTO agents (tenant_id, name, uuid, enrollment_secret, status)
                VALUES (
                    :tid, 'Phase0 Agent', '11111111-2222-3333-4444-555555555555',
                    'phase0-enrollment-secret', 'approved'
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id},
        ).scalar_one()
        lan_scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (
                    tenant_id, agent_id, name, scope, profile, nuclei_severities, nuclei_tags,
                    subnet_ids, interval_minutes, is_enabled
                )
                VALUES (
                    :tid, :aid, 'LAN Discovery', 'lan', 'discovery', 'critical,high', '',
                    CAST(:subnets AS jsonb), 60, true
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "aid": agent_id, "subnets": f"[{lan_id}]"},
        ).scalar_one()
        wan_scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (
                    tenant_id, agent_id, name, scope, profile, nuclei_severities, nuclei_tags,
                    subnet_ids, interval_minutes, is_enabled
                )
                VALUES (
                    :tid, NULL, 'WAN Discovery', 'wan', 'discovery', 'critical,high', '',
                    CAST(:subnets AS jsonb), NULL, true
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "subnets": f"[{wan_id}]"},
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
        device_id = conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports, last_scan_job_id
                )
                VALUES (
                    :tid, '10.10.0.8', 'phase0-host', 'lan', 'known', 'Server', 'keep',
                    '', '', '', '[]'::jsonb, :jid
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "jid": job_id},
        ).scalar_one()
        finding_id = conn.execute(
            text(
                """
                INSERT INTO findings (
                    tenant_id, scan_job_id, device_id, template_id, name, severity,
                    hostname, host, matched_at, tags, found_at, raw_json
                )
                VALUES (
                    :tid, :jid, :did, 'phase0-template', 'Phase0 finding', 'high',
                    'phase0-host', '10.10.0.8', 'https://10.10.0.8', '', :found, '{}'::jsonb
                )
                RETURNING id
                """
            ),
            {
                "tid": tenant_id,
                "jid": job_id,
                "did": device_id,
                "found": datetime.now(timezone.utc),
            },
        ).scalar_one()
    return {
        "user": user_id,
        "tenant": tenant_id,
        "lan_subnet": lan_id,
        "wan_subnet": wan_id,
        "agent": agent_id,
        "lan_scan": lan_scan_id,
        "wan_scan": wan_scan_id,
        "job": job_id,
        "device": device_id,
        "finding": finding_id,
    }


@requires_postgres
def test_upgrade_from_0001_preserves_representative_phase0_data(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, apply_schema, current_revision, head_revision
    from app.models import COMPATIBILITY_SITE_NAME, Agent, Device, Finding, Network, NetworkAgent, Scan, Site, Subnet

    command.upgrade(alembic_config(), "0001_baseline")
    ids = _insert_phase0_representative(engine)
    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE1B_HEAD
    assert PHASE1B_TABLES.issubset(_tables(engine))

    db = SessionLocal()
    try:
        site = db.query(Site).filter(Site.tenant_id == ids["tenant"]).one()
        assert site.name == COMPATIBILITY_SITE_NAME
        assert site.timezone is None
        network = db.query(Network).filter(Network.tenant_id == ids["tenant"]).one()
        assert network.site_id == site.id
        assert network.cidr == "10.10.0.0/24"
        lan = db.get(Subnet, ids["lan_subnet"])
        wan = db.get(Subnet, ids["wan_subnet"])
        assert lan is not None and lan.scope == "lan" and lan.network_id == network.id
        assert wan is not None and wan.scope == "wan" and wan.network_id is None and wan.site_id is None
        agent = db.get(Agent, ids["agent"])
        assert agent is not None
        assert agent.site_id == site.id
        assert agent.uuid == "11111111-2222-3333-4444-555555555555"
        assert agent.enrollment_secret == "phase0-enrollment-secret"
        assert (
            db.query(NetworkAgent)
            .filter(NetworkAgent.network_id == network.id, NetworkAgent.agent_id == agent.id)
            .one()
        )
        lan_scan = db.get(Scan, ids["lan_scan"])
        wan_scan = db.get(Scan, ids["wan_scan"])
        assert lan_scan is not None
        assert lan_scan.agent_id == ids["agent"]
        assert lan_scan.subnet_ids == [ids["lan_subnet"]]
        assert wan_scan is not None
        assert wan_scan.subnet_ids == [ids["wan_subnet"]]
        assert wan_scan.agent_id is None
        assert db.get(Device, ids["device"]).hostname == "phase0-host"
        assert db.get(Finding, ids["finding"]).template_id == "phase0-template"
        assert db.query(Network).filter(Network.cidr == "203.0.113.0/24").count() == 0
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0002_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE1A_REVISION)
    try:
        command.downgrade(alembic_config(), "0001_baseline")
    except (NotImplementedError, CommandError) as exc:
        assert "Refusing to downgrade 0002_sites_networks" in str(exc)
    else:
        raise AssertionError("0002 downgrade must refuse instead of dropping Phase 1A data")


@requires_postgres
def test_overlapping_cidrs_across_sites_and_authorization_rules(reset_db):
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        operator = _create_staff(client, admin, "operator", "user")
        viewer = _create_staff(client, admin, "auditor", "viewer")

        tenant_a = client.post("/api/tenants", headers=_headers(admin), json={"name": "Tenant A", "notes": ""}).json()
        tenant_b = client.post("/api/tenants", headers=_headers(admin), json={"name": "Tenant B", "notes": ""}).json()

        site_a = client.post(
            f"/api/tenants/{tenant_a['id']}/sites",
            headers=_headers(operator),
            json={"name": "Boston", "timezone": "America/New_York"},
        )
        site_b = client.post(
            f"/api/tenants/{tenant_a['id']}/sites",
            headers=_headers(operator),
            json={"name": "Hartford"},
        )
        site_other = client.post(
            f"/api/tenants/{tenant_b['id']}/sites",
            headers=_headers(admin),
            json={"name": "Other HQ"},
        )
        assert site_a.status_code == 200, site_a.text
        assert site_a.json()["timezone"] == "America/New_York"
        assert site_a.json()["effective_timezone"] == "America/New_York"

        net_a = client.post(
            f"/api/sites/{site_a.json()['id']}/networks",
            headers=_headers(operator),
            json={"name": "Server VLAN", "cidr": "192.168.1.0/24"},
        )
        net_b = client.post(
            f"/api/sites/{site_b.json()['id']}/networks",
            headers=_headers(operator),
            json={"name": "Server VLAN", "cidr": "192.168.1.0/24"},
        )
        assert net_a.status_code == 200, net_a.text
        assert net_b.status_code == 200, net_b.text
        assert net_a.json()["cidr"] == net_b.json()["cidr"] == "192.168.1.0/24"
        assert net_a.json()["id"] != net_b.json()["id"]

        agent_a1 = client.post(
            f"/api/tenants/{tenant_a['id']}/agents",
            headers=_headers(operator),
            json={"name": "Agent-HQ-01", "site_id": site_a.json()["id"]},
        )
        agent_a2 = client.post(
            f"/api/tenants/{tenant_a['id']}/agents",
            headers=_headers(operator),
            json={"name": "Agent-HQ-02", "site_id": site_a.json()["id"]},
        )
        agent_b = client.post(
            f"/api/tenants/{tenant_a['id']}/agents",
            headers=_headers(operator),
            json={"name": "Hartford Agent", "site_id": site_b.json()["id"]},
        )
        agent_other = client.post(
            f"/api/tenants/{tenant_b['id']}/agents",
            headers=_headers(admin),
            json={"name": "Other Agent", "site_id": site_other.json()["id"]},
        )
        assert agent_a1.status_code == 200
        auth = client.put(
            f"/api/networks/{net_a.json()['id']}/authorized-agents",
            headers=_headers(operator),
            json={"agent_ids": [agent_a1.json()["id"], agent_a2.json()["id"]]},
        )
        assert auth.status_code == 200, auth.text
        assert sorted(auth.json()["authorized_agent_ids"]) == sorted(
            [agent_a1.json()["id"], agent_a2.json()["id"]]
        )

        cross_site = client.put(
            f"/api/networks/{net_a.json()['id']}/authorized-agents",
            headers=_headers(operator),
            json={"agent_ids": [agent_a1.json()["id"], agent_b.json()["id"]]},
        )
        assert cross_site.status_code == 400
        assert "another site" in cross_site.json()["detail"]

        cross_tenant = client.put(
            f"/api/networks/{net_a.json()['id']}/authorized-agents",
            headers=_headers(admin),
            json={"agent_ids": [agent_other.json()["id"]]},
        )
        assert cross_tenant.status_code == 400
        assert "another tenant" in cross_tenant.json()["detail"]

        from app.database import SessionLocal
        from app.locality import authorize_agent
        from app.models import Agent, Network
        from fastapi import HTTPException

        db = SessionLocal()
        try:
            network = db.get(Network, net_a.json()["id"])
            already = db.get(Agent, agent_a1.json()["id"])
            try:
                authorize_agent(db, network, already)
            except HTTPException as exc:
                assert exc.status_code == 400
                assert "already authorized" in exc.detail
            else:
                raise AssertionError("duplicate authorization must fail")
        finally:
            db.close()

        preferred_bad = client.patch(
            f"/api/networks/{net_a.json()['id']}",
            headers=_headers(operator),
            json={
                "name": "Server VLAN",
                "cidr": "192.168.1.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": agent_b.json()["id"],
            },
        )
        assert preferred_bad.status_code == 400

        preferred_ok = client.patch(
            f"/api/networks/{net_a.json()['id']}",
            headers=_headers(operator),
            json={
                "name": "Server VLAN",
                "cidr": "192.168.1.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": agent_a2.json()["id"],
            },
        )
        assert preferred_ok.status_code == 200, preferred_ok.text
        assert preferred_ok.json()["dispatch_mode"] == "preferred_failover"
        assert preferred_ok.json()["preferred_agent_id"] == agent_a2.json()["id"]

        bad_tz_site = client.post(
            f"/api/tenants/{tenant_a['id']}/sites",
            headers=_headers(operator),
            json={"name": "Bad TZ", "timezone": "Not/AZone"},
        )
        assert bad_tz_site.status_code == 400

        settings = client.get("/api/admin/settings", headers=_headers(admin))
        assert settings.status_code == 200
        payload = settings.json()
        payload["default_timezone"] = "Not/AZone"
        bad_global = client.put("/api/admin/settings", headers=_headers(admin), json=payload)
        assert bad_global.status_code == 400

        payload["default_timezone"] = "America/Chicago"
        good_global = client.put("/api/admin/settings", headers=_headers(admin), json=payload)
        assert good_global.status_code == 200, good_global.text
        assert good_global.json()["default_timezone"] == "America/Chicago"

        display = client.get("/api/display-settings", headers=_headers(viewer))
        assert display.status_code == 200
        assert display.json()["default_timezone"] == "America/Chicago"

        viewer_create = client.post(
            f"/api/tenants/{tenant_a['id']}/sites",
            headers=_headers(viewer),
            json={"name": "Viewer Site"},
        )
        assert viewer_create.status_code == 403
        viewer_auth = client.put(
            f"/api/networks/{net_a.json()['id']}/authorized-agents",
            headers=_headers(viewer),
            json={"agent_ids": []},
        )
        assert viewer_auth.status_code == 403
        listed = client.get(f"/api/tenants/{tenant_a['id']}/sites", headers=_headers(viewer))
        assert listed.status_code == 200
        assert {row["name"] for row in listed.json()} >= {"Boston", "Hartford"}

        hart_auth = client.put(
            f"/api/networks/{net_b.json()['id']}/authorized-agents",
            headers=_headers(operator),
            json={"agent_ids": [agent_b.json()["id"]]},
        )
        assert hart_auth.status_code == 200, hart_auth.text
        archive = client.post(
            f"/api/networks/{net_b.json()['id']}/archive",
            headers=_headers(operator),
        )
        assert archive.status_code == 200
        assert archive.json()["is_archived"] is True

        lan_scan = client.post(
            f"/api/tenants/{tenant_a['id']}/scans",
            headers=_headers(operator),
            json={
                "name": "Boston LAN",
                "scope": "lan",
                "agent_id": agent_a1.json()["id"],
                "subnet_ids": [net_a.json()["subnet_id"]],
                "profile": "discovery",
                "is_enabled": True,
            },
        )
        assert lan_scan.status_code == 200, lan_scan.text

        archived_scan = client.post(
            f"/api/tenants/{tenant_a['id']}/scans",
            headers=_headers(operator),
            json={
                "name": "Archived net",
                "scope": "lan",
                "agent_id": agent_b.json()["id"],
                "subnet_ids": [net_b.json()["subnet_id"]],
                "profile": "discovery",
            },
        )
        assert archived_scan.status_code == 400

        from app.database import SessionLocal
        from app.models import AuditLog

        db = SessionLocal()
        try:
            actions = {row.action for row in db.query(AuditLog).all()}
            assert "site.create" in actions
            assert "network.create" in actions
            assert "network.authorization" in actions
            assert "network.update" in actions
            assert "settings.timezone_change" in actions
            assert "agent.create" in actions
            assert "network.archive" in actions
        finally:
            db.close()


@requires_postgres
def test_migrated_lan_and_wan_scans_remain_valid_through_api(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import alembic_config

    command.upgrade(alembic_config(), "0001_baseline")
    ids = _insert_phase0_representative(engine)
    command.upgrade(alembic_config(), "head")

    from app.auth import hash_password
    from app.database import SessionLocal
    from app.models import User

    db = SessionLocal()
    try:
        db.add(
            User(
                username="admin",
                email="admin@localhost",
                password_hash=hash_password("test-admin-pass"),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
    finally:
        db.close()

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        scans = client.get(f"/api/tenants/{ids['tenant']}/scans", headers=_headers(admin))
        assert scans.status_code == 200, scans.text
        names = {row["name"] for row in scans.json()}
        assert names == {"LAN Discovery", "WAN Discovery"}
        lan = next(row for row in scans.json() if row["name"] == "LAN Discovery")
        wan = next(row for row in scans.json() if row["name"] == "WAN Discovery")
        assert lan["agent_id"] == ids["agent"]
        assert lan["subnet_ids"] == [ids["lan_subnet"]]
        assert wan["subnet_ids"] == [ids["wan_subnet"]]

        update_lan = client.patch(
            f"/api/scans/{lan['id']}",
            headers=_headers(admin),
            json={
                "name": "LAN Discovery",
                "scope": "lan",
                "agent_id": ids["agent"],
                "subnet_ids": [ids["lan_subnet"]],
                "profile": "discovery",
                "is_enabled": True,
            },
        )
        assert update_lan.status_code == 200, update_lan.text

        update_wan = client.patch(
            f"/api/scans/{wan['id']}",
            headers=_headers(admin),
            json={
                "name": "WAN Discovery",
                "scope": "wan",
                "agent_id": None,
                "subnet_ids": [ids["wan_subnet"]],
                "profile": "discovery",
                "is_enabled": True,
            },
        )
        assert update_wan.status_code == 200, update_wan.text

        wan_create = client.post(
            f"/api/tenants/{ids['tenant']}/subnets",
            headers=_headers(admin),
            json={"name": "Another WAN", "cidr": "198.51.100.0/24", "scope": "wan"},
        )
        assert wan_create.status_code == 200, wan_create.text
        assert wan_create.json()["network_id"] is None


@requires_postgres
def test_baseline_revision_file_still_frozen():
    source = BASELINE_PATH.read_text()
    assert source.startswith('"""Frozen Phase 0 application schema.')
    assert "0002" not in source
    assert "sites" not in source
    assert "networks" not in source
    assert "audit_logs" not in source
    assert "from app.database import Base" not in source
