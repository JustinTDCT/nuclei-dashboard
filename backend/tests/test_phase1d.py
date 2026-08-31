from __future__ import annotations

import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE1C_HEAD = "0005_asset_correlation_lifecycle"
PHASE1D_HEAD = "0006_scan_definition_execution"
PHASE2A_HEAD = "0009_phase2a_detector_identity_partition"
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
PHASE3A_HEAD = "0017_security_h6_h8"
RUNTIME_ROOT = BACKEND_ROOT.parent / "scan_runtime"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


@contextmanager
def _client() -> Iterator[TestClient]:
    with patch("app.main.start_scheduler"):
        from app.main import app

        with TestClient(app) as client:
            yield client


def _login(client: TestClient, username: str = "admin", password: str = "test-admin-pass") -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_staff(client: TestClient, admin: str, username: str, role: str) -> str:
    response = client.post(
        "/api/users",
        headers=_headers(admin),
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


def _heartbeat(agent_id: int, when: datetime | None = None) -> None:
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        assert agent is not None
        agent.status = "approved"
        agent.last_heartbeat = when or datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def _finish_job(job_id: int, status: str = "done") -> None:
    from app.database import SessionLocal
    from app.models import ScanJob

    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        assert job is not None
        job.status = status
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def _world(client: TestClient, token: str) -> dict:
    tenant = client.post("/api/tenants", headers=_headers(token), json={"name": "1D Tenant", "notes": ""}).json()
    site = client.post(
        f"/api/tenants/{tenant['id']}/sites",
        headers=_headers(token),
        json={"name": "HQ", "timezone": "America/New_York"},
    ).json()
    net1 = client.post(
        f"/api/sites/{site['id']}/networks",
        headers=_headers(token),
        json={"name": "Net One", "cidr": "10.1.0.0/24"},
    ).json()
    net2 = client.post(
        f"/api/sites/{site['id']}/networks",
        headers=_headers(token),
        json={"name": "Net Two", "cidr": "10.2.0.0/24"},
    ).json()
    agent1 = client.post(
        f"/api/tenants/{tenant['id']}/agents",
        headers=_headers(token),
        json={"name": "Agent A", "site_id": site["id"]},
    ).json()
    agent2 = client.post(
        f"/api/tenants/{tenant['id']}/agents",
        headers=_headers(token),
        json={"name": "Agent B", "site_id": site["id"]},
    ).json()
    for network in (net1, net2):
        client.put(
            f"/api/networks/{network['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": [agent1["id"], agent2["id"]]},
        )
    wan = client.post(
        f"/api/tenants/{tenant['id']}/wan-targets",
        headers=_headers(token),
        json={"name": "Edge", "target_type": "cidr", "value": "203.0.113.0/24"},
    ).json()
    return {
        "tenant": tenant,
        "site": site,
        "net1": net1,
        "net2": net2,
        "agent1": agent1,
        "agent2": agent2,
        "wan": wan,
    }


def _lan_scan(client: TestClient, token: str, world: dict, **extra) -> dict:
    body = {
        "name": extra.pop("name", "LAN Scan"),
        "scope": "lan",
        "site_id": world["site"]["id"],
        "network_ids": extra.pop("network_ids", [world["net1"]["id"], world["net2"]["id"]]),
        "is_enabled": True,
        "stage_config": extra.pop("stage_config", {"discovery": True, "port_mode": "common", "fingerprint": True, "vulnerability": False}),
        "intensity_config": extra.pop("intensity_config", {"preset": "normal"}),
        "schedule_config": extra.pop("schedule_config", {"type": "manual"}),
    }
    body.update(extra)
    response = client.post(f"/api/tenants/{world['tenant']['id']}/scans", headers=_headers(token), json=body)
    assert response.status_code == 200, response.text
    return response.json()


@requires_postgres
def test_fresh_db_reaches_phase1d_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3A_HEAD
    tables = set(inspect(engine).get_table_names())
    assert {"authorized_wan_targets", "scan_network_targets", "scan_wan_targets", "scan_exclusions"}.issubset(tables)
    assert "execution_snapshot" in {c["name"] for c in inspect(engine).get_columns("scan_jobs")}


@requires_postgres
def test_0005_to_0006_preserves_ids_and_does_not_fabricate_snapshots(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision, head_revision
    from app.models import AuthorizedWanTarget, Scan, ScanNetworkTarget, ScanWanTarget

    command.upgrade(alembic_config(), PHASE1C_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 1D', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        net_id = conn.execute(
            text(
                """
                INSERT INTO networks (tenant_id, site_id, name, cidr, dispatch_mode, created_at)
                VALUES (:t, :s, 'LAN', '10.9.0.0/24', 'any_available', :n) RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        subnet_id = conn.execute(
            text(
                """
                INSERT INTO subnets (tenant_id, name, cidr, scope, site_id, network_id)
                VALUES (:t, 'LAN', '10.9.0.0/24', 'lan', :s, :n) RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": net_id},
        ).scalar_one()
        wan_id = conn.execute(
            text("INSERT INTO subnets (tenant_id, name, cidr, scope) VALUES (:t, 'WAN', '198.51.100.0/24', 'wan') RETURNING id"),
            {"t": tenant_id},
        ).scalar_one()
        agent_id = conn.execute(
            text(
                """
                INSERT INTO agents (tenant_id, site_id, name, uuid, status)
                VALUES (:t, :s, 'A', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'approved') RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id},
        ).scalar_one()
        conn.execute(text("INSERT INTO network_agents (network_id, agent_id) VALUES (:n, :a)"), {"n": net_id, "a": agent_id})
        lan_scan = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, agent_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, interval_minutes, is_enabled)
                VALUES (:t, :a, 'Old LAN', 'lan', 'discovery', 'high', '', CAST(:ids AS jsonb), 60, true)
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": agent_id, "ids": f"[{subnet_id}]"},
        ).scalar_one()
        wan_scan = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old WAN', 'wan', 'discovery_nuclei', 'critical,high', 'cve', CAST(:ids AS jsonb), true)
                RETURNING id
                """
            ),
            {"t": tenant_id, "ids": f"[{wan_id}]"},
        ).scalar_one()
        job_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'done', 3, 2) RETURNING id"),
            {"s": lan_scan, "t": tenant_id},
        ).scalar_one()

    command.upgrade(alembic_config(), PHASE1D_HEAD)
    assert current_revision() == PHASE1D_HEAD
    db = SessionLocal()
    try:
        assert db.get(Scan, lan_scan) is not None
        assert db.get(Scan, wan_scan) is not None
        job = db.execute(
            text(
                """
                SELECT execution_snapshot, snapshot_version, hosts_found
                FROM scan_jobs WHERE id = :id
                """
            ),
            {"id": job_id},
        ).mappings().one()
        assert job["execution_snapshot"] is None
        assert job["snapshot_version"] == "legacy_pre_1d"
        assert job["hosts_found"] == 3
        lan = db.get(Scan, lan_scan)
        assert lan.site_id == site_id
        assert lan.definition_revision == 1
        assert db.query(ScanNetworkTarget).filter(ScanNetworkTarget.scan_id == lan_scan).count() == 1
        wan = db.get(Scan, wan_scan)
        assert wan.stage_config["vulnerability"] is True
        assert db.query(AuthorizedWanTarget).filter(AuthorizedWanTarget.tenant_id == tenant_id).count() == 1
        assert db.query(ScanWanTarget).filter(ScanWanTarget.scan_id == wan_scan).count() == 1
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0006_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE1D_HEAD)
    try:
        command.downgrade(alembic_config(), PHASE1C_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0006_scan_definition_execution" in str(exc)
        return
    raise AssertionError("0006 downgrade must refuse")


@requires_postgres
def test_unversioned_phase1d_markers_fail_closed(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    apply_schema()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()


@requires_postgres
def test_definition_edit_does_not_change_old_run_and_future_uses_revision(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        first = client.get(f"/api/jobs/{run.json()['id']}", headers=_headers(token)).json()
        assert first["execution_snapshot"]
        assert first["definition_revision"] == 1
        patched = client.patch(
            f"/api/scans/{scan['id']}",
            headers=_headers(token),
            json={
                "name": "LAN Scan edited",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"]],
                "stage_config": {"discovery": True, "port_mode": "deep", "fingerprint": True, "vulnerability": True, "nuclei_severities": "critical"},
                "intensity_config": {"preset": "low"},
                "schedule_config": {"type": "manual"},
                "is_enabled": True,
            },
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["definition_revision"] == 2
        old = client.get(f"/api/jobs/{first['id']}", headers=_headers(token)).json()
        assert old["execution_snapshot"]["stages"]["port_mode"] == "common"
        assert old["definition_revision"] == 1
        _finish_job(first["id"])
        second = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert second.status_code == 200, second.text
        nxt = client.get(f"/api/jobs/{second.json()['id']}", headers=_headers(token)).json()
        assert nxt["definition_revision"] == 2
        assert nxt["execution_snapshot"]["stages"]["port_mode"] == "deep"


@requires_postgres
def test_archived_definition_cannot_run_but_history_remains(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        job_id = run.json()["id"]
        archived = client.post(f"/api/scans/{scan['id']}/archive", headers=_headers(token))
        assert archived.status_code == 200
        blocked = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert blocked.status_code == 400
        history = client.get(f"/api/jobs/{job_id}", headers=_headers(token))
        assert history.status_code == 200


@requires_postgres
def test_wan_authorization_and_audit(reset_db):
    with _client() as client:
        admin = _login(client)
        viewer = _create_staff(client, admin, "auditor", "viewer")
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        ok_ip = client.post(
            f"/api/tenants/{tenant_id}/wan-targets",
            headers=_headers(admin),
            json={"name": "Host", "target_type": "ip", "value": "203.0.113.10"},
        )
        assert ok_ip.status_code == 200
        ok_fqdn = client.post(
            f"/api/tenants/{tenant_id}/wan-targets",
            headers=_headers(admin),
            json={"name": "Web", "target_type": "fqdn", "value": "Edge.Example.COM."},
        )
        assert ok_fqdn.status_code == 200, ok_fqdn.text
        assert ok_fqdn.json()["normalized_value"] == "edge.example.com"
        for bad in (
            {"target_type": "fqdn", "value": "https://evil.example"},
            {"target_type": "fqdn", "value": "host.example.com:443"},
            {"target_type": "fqdn", "value": "*.example.com"},
            {"target_type": "ip", "value": "192.168.1.1"},
            {"target_type": "ip", "value": "127.0.0.1"},
            {"target_type": "ip", "value": "169.254.169.254"},
            {"target_type": "cidr", "value": "0.0.0.0/0"},
            {"target_type": "cidr", "value": "10.0.0.0/8"},
            {"target_type": "cidr", "value": "8.8.0.0/8"},
            {"target_type": "ip", "value": "::ffff:127.0.0.1"},
            {"target_type": "ip", "value": "::ffff:10.0.0.1"},
            {"target_type": "ip", "value": "::8.8.8.8"},
            {"target_type": "cidr", "value": "::ffff:0:0/96"},
            {"target_type": "cidr", "value": "2001:db8::/32"},
            {"target_type": "fqdn", "value": "metadata.google.internal"},
        ):
            resp = client.post(f"/api/tenants/{tenant_id}/wan-targets", headers=_headers(admin), json={"name": "x", **bad})
            assert resp.status_code == 400
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other", "notes": ""}).json()
        foreign = client.post(
            f"/api/tenants/{other['id']}/wan-targets",
            headers=_headers(admin),
            json={"name": "Foreign", "target_type": "ip", "value": "198.51.100.8"},
        ).json()
        rejected = client.post(
            f"/api/tenants/{tenant_id}/scans",
            headers=_headers(admin),
            json={
                "name": "Cross",
                "scope": "wan",
                "wan_target_ids": [foreign["id"]],
                "schedule_config": {"type": "manual"},
            },
        )
        assert rejected.status_code == 400
        viewer_create = client.post(
            f"/api/tenants/{tenant_id}/wan-targets",
            headers=_headers(viewer),
            json={"name": "Nope", "target_type": "ip", "value": "203.0.113.20"},
        )
        assert viewer_create.status_code == 403
        from app.database import SessionLocal
        from app.models import AuditLog

        db = SessionLocal()
        try:
            actions = {row.action for row in db.query(AuditLog).all()}
            assert "wan_target.create" in actions
        finally:
            db.close()


@requires_postgres
def test_new_wan_target_does_not_join_old_definition_and_revoke_blocks_run(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(token),
            json={
                "name": "WAN",
                "scope": "wan",
                "wan_target_ids": [world["wan"]["id"]],
                "schedule_config": {"type": "manual"},
            },
        )
        assert scan.status_code == 200, scan.text
        added = client.post(
            f"/api/tenants/{world['tenant']['id']}/wan-targets",
            headers=_headers(token),
            json={"name": "Later", "target_type": "ip", "value": "203.0.113.55"},
        )
        assert added.status_code == 200
        run = client.post(f"/api/scans/{scan.json()['id']}/run", headers=_headers(token))
        job = client.get(f"/api/jobs/{run.json()['id']}", headers=_headers(token)).json()
        ids = [row["id"] for row in job["execution_snapshot"]["targets"]["wan_targets"]]
        assert ids == [world["wan"]["id"]]
        client.post(f"/api/wan-targets/{world['wan']['id']}/archive", headers=_headers(token))
        from app.config import settings

        start = client.post(
            f"/api/internal/scanner/jobs/{job['id']}/start",
            headers={"X-Scanner-Token": settings.scanner_token},
        )
        assert start.status_code == 409


@requires_postgres
def test_lan_site_and_intersection_rules(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        other_site = client.post(
            f"/api/tenants/{world['tenant']['id']}/sites",
            headers=_headers(token),
            json={"name": "Other"},
        ).json()
        other_net = client.post(
            f"/api/sites/{other_site['id']}/networks",
            headers=_headers(token),
            json={"name": "Elsewhere", "cidr": "10.8.0.0/24"},
        ).json()
        spanning = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(token),
            json={
                "name": "Span",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"], other_net["id"]],
            },
        )
        assert spanning.status_code == 400
        client.put(
            f"/api/networks/{world['net2']['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": [world["agent1"]["id"]]},
        )
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        job = client.get(f"/api/jobs/{run.json()['id']}", headers=_headers(token)).json()
        assert set(job["execution_snapshot"]["dispatch"]["eligible_agent_ids"]) == {world["agent1"]["id"]}
        _heartbeat(world["agent2"]["id"])
        polled = client.get("/api/agent/jobs", headers=_agent_headers(world["agent2"]))
        assert polled.status_code == 200
        assert polled.json() == []


def _agent_headers(agent: dict) -> dict[str, str]:
    from app.auth import create_agent_token

    return {"Authorization": f"Bearer {create_agent_token(agent['uuid'], agent['id'], agent['tenant_id'])}"}


def _post_required_versions(client: TestClient, job_id: int, headers: dict[str, str], url_prefix: str) -> dict:
    from app.database import SessionLocal
    from app.models import ScanJob
    from app.scanner_versions import required_run_version_keys

    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        keys = required_run_version_keys(job) if job is not None else []
    finally:
        db.close()
    if not keys:
        return {}
    payload = {key: f"test-{key}" for key in keys}
    posted = client.post(f"{url_prefix}/{job_id}/provenance", headers=headers, json=payload)
    assert posted.status_code == 200, posted.text
    return payload


@requires_postgres
def test_atomic_claim_and_new_agent_does_not_join_old_pool(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        job_id = run.json()["id"]
        _heartbeat(world["agent1"]["id"])
        _heartbeat(world["agent2"]["id"])
        agent3 = client.post(
            f"/api/tenants/{world['tenant']['id']}/agents",
            headers=_headers(token),
            json={"name": "Late", "site_id": world["site"]["id"]},
        ).json()
        for network in (world["net1"], world["net2"]):
            current = network["authorized_agent_ids"] + [agent3["id"]]
            client.put(
                f"/api/networks/{network['id']}/authorized-agents",
                headers=_headers(token),
                json={"agent_ids": [world["agent1"]["id"], world["agent2"]["id"], agent3["id"]]},
            )
        _heartbeat(agent3["id"])
        late = client.get("/api/agent/jobs", headers=_agent_headers(agent3))
        assert late.json() == []

        def _start(agent):
            return client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(agent))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(_start, (world["agent1"], world["agent2"])))
        codes = sorted(r.status_code for r in results)
        assert 200 in codes
        assert codes.count(200) == 1
        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job.claimed_agent_id in {world["agent1"]["id"], world["agent2"]["id"]}
            assert job.status == "running"
        finally:
            db.close()


@requires_postgres
def test_waiting_missed_and_preferred_failover(reset_db):
    from app.database import SessionLocal
    from app.events import emit_scan_missed_unavailable_agent
    from app.models import DomainEvent, ScanJob
    from app.scheduler import expire_waiting_jobs

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        client.patch(
            f"/api/networks/{world['net1']['id']}",
            headers=_headers(token),
            json={
                "name": "Net One",
                "cidr": "10.1.0.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": world["agent1"]["id"],
            },
        )
        client.patch(
            f"/api/networks/{world['net2']['id']}",
            headers=_headers(token),
            json={
                "name": "Net Two",
                "cidr": "10.2.0.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": world["agent1"]["id"],
            },
        )
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        job = run.json()
        assert job["status"] == "waiting_for_agent"
        _heartbeat(world["agent2"]["id"])
        start_secondary = client.post(f"/api/agent/jobs/{job['id']}/start", headers=_agent_headers(world["agent2"]))
        assert start_secondary.status_code == 200, start_secondary.text
        _finish_job(job["id"])

        run2 = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run2.status_code == 200, run2.text
        job2 = run2.json()
        _heartbeat(world["agent1"]["id"])
        start_pref = client.post(f"/api/agent/jobs/{job2['id']}/start", headers=_agent_headers(world["agent1"]))
        assert start_pref.status_code == 200, start_pref.text

        settings = client.get("/api/admin/settings", headers=_headers(token)).json()
        settings["agent_job_wait_minutes"] = 1
        client.put("/api/admin/settings", headers=_headers(token), json=settings)
        from app.models import Agent

        db_agents = SessionLocal()
        try:
            for row in db_agents.query(Agent).all():
                row.last_heartbeat = None
            db_agents.commit()
        finally:
            db_agents.close()
        waiting = _lan_scan(client, token, world, name="Waiter")
        queued = client.post(f"/api/scans/{waiting['id']}/run", headers=_headers(token)).json()
        assert queued["status"] == "waiting_for_agent"
        db = SessionLocal()
        try:
            row = db.get(ScanJob, queued["id"])
            row.wait_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.commit()
            expire_waiting_jobs(db)
            row = db.get(ScanJob, queued["id"])
            assert row.status == "missed"
            events = db.query(DomainEvent).filter(DomainEvent.event_type == "scan_missed_unavailable_agent").all()
            assert len(events) == 1
            emit_scan_missed_unavailable_agent(db, row)
            db.commit()
            assert db.query(DomainEvent).filter(DomainEvent.event_type == "scan_missed_unavailable_agent").count() == 1
        finally:
            db.close()


@requires_postgres
def test_conflicting_preferred_agents_rejected(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        client.patch(
            f"/api/networks/{world['net1']['id']}",
            headers=_headers(token),
            json={
                "name": "Net One",
                "cidr": "10.1.0.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": world["agent1"]["id"],
            },
        )
        client.patch(
            f"/api/networks/{world['net2']['id']}",
            headers=_headers(token),
            json={
                "name": "Net Two",
                "cidr": "10.2.0.0/24",
                "dispatch_mode": "preferred_failover",
                "preferred_agent_id": world["agent2"]["id"],
            },
        )
        resp = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(token),
            json={
                "name": "Conflict",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"], world["net2"]["id"]],
            },
        )
        assert resp.status_code == 400
        assert "preferred" in resp.json()["detail"].lower()


@requires_postgres
def test_intensity_caps_exclusions_and_viewer(reset_db):
    with _client() as client:
        admin = _login(client)
        viewer = _create_staff(client, admin, "look", "viewer")
        world = _world(client, admin)
        settings = client.get("/api/admin/settings", headers=_headers(admin)).json()
        settings["scan_cap_naabu_rate"] = 100
        saved = client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        assert saved.status_code == 200
        over = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={
                "name": "Hot",
                "scope": "wan",
                "wan_target_ids": [world["wan"]["id"]],
                "intensity_config": {"preset": "custom", "naabu_rate": 5000},
            },
        )
        assert over.status_code == 400
        settings["scan_cap_naabu_rate"] = 5000
        restored = client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        assert restored.status_code == 200
        queued_scan = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={
                "name": "QueuedHot",
                "scope": "wan",
                "wan_target_ids": [world["wan"]["id"]],
                "intensity_config": {"preset": "custom", "naabu_rate": 2000},
            },
        )
        assert queued_scan.status_code == 200, queued_scan.text
        queued_run = client.post(f"/api/scans/{queued_scan.json()['id']}/run", headers=_headers(admin))
        assert queued_run.status_code == 200, queued_run.text
        settings["scan_cap_naabu_rate"] = 100
        tightened = client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        assert tightened.status_code == 200
        from app.config import settings as app_settings

        blocked = client.post(
            f"/api/internal/scanner/jobs/{queued_run.json()['id']}/start",
            headers={"X-Scanner-Token": app_settings.scanner_token},
        )
        assert blocked.status_code == 409
        settings["scan_cap_naabu_rate"] = 5000
        client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        excl = client.post(
            "/api/scan-exclusions",
            headers=_headers(admin),
            json={"scope": "tenant", "tenant_id": world["tenant"]["id"], "exclusion_type": "cidr", "value": "203.0.113.0/24"},
        )
        assert excl.status_code == 200, excl.text
        scan = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={"name": "Empty", "scope": "wan", "wan_target_ids": [world["wan"]["id"]]},
        )
        assert scan.status_code == 200
        run = client.post(f"/api/scans/{scan.json()['id']}/run", headers=_headers(admin))
        assert run.status_code == 400
        viewer_run = client.post(f"/api/scans/{scan.json()['id']}/run", headers=_headers(viewer))
        assert viewer_run.status_code == 403
        viewer_mut = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(viewer),
            json={"name": "Nope", "scope": "wan", "wan_target_ids": [world["wan"]["id"]]},
        )
        assert viewer_mut.status_code == 403


@requires_postgres
def test_schedule_dst_and_idempotence(reset_db):
    from datetime import datetime
    from zoneinfo import ZoneInfo

    from app.scan_schedule import next_occurrence

    tz = "America/New_York"
    before_fall = datetime(2026, 10, 31, 6, 0, tzinfo=timezone.utc)
    first = next_occurrence({"type": "daily", "hour": 1, "minute": 30}, tz_name=tz, after=before_fall)
    second = next_occurrence({"type": "daily", "hour": 1, "minute": 30}, tz_name=tz, after=first)
    assert first.astimezone(ZoneInfo(tz)).hour == 1
    assert second > first
    assert (second - first).total_seconds() >= 23 * 3600
    with pytest.raises(Exception):
        next_occurrence({"type": "cron", "expression": "not a cron"}, tz_name="UTC", after=datetime.now(timezone.utc))

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(
            client,
            token,
            world,
            name="Daily",
            schedule_config={"type": "daily", "hour": 3, "minute": 15},
        )
        assert scan["next_run_at"]
        from app.database import SessionLocal
        from app.jobs import queue_scheduled_run
        from app.models import Scan, ScanJob

        db = SessionLocal()
        try:
            row = db.get(Scan, scan["id"])
            row.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            db.commit()
            first_job = queue_scheduled_run(db, row)
            db.commit()
            assert first_job is not None
            row = db.get(Scan, scan["id"])
            row.next_run_at = datetime.now(timezone.utc) - timedelta(days=3)
            db.commit()
            second_job = queue_scheduled_run(db, row)
            db.commit()
            assert db.query(ScanJob).filter(ScanJob.scan_id == scan["id"], ScanJob.trigger_type == "scheduled").count() <= 2
            assert second_job is None or second_job.id != first_job.id
        finally:
            db.close()


def test_command_builders_honor_stages_and_do_not_invent_flags():
    from commands import build_httpx_command, build_naabu_command, build_nuclei_command

    none = build_naabu_command("naabu", ["10.0.0.0/24"], port_mode="none")
    assert none is None
    from commands import build_naabu_host_discovery_command

    host_disc = build_naabu_host_discovery_command("naabu", ["10.0.0.0/24"], intensity={"naabu_rate": 200})
    assert host_disc is not None
    assert "-sn" not in host_disc
    assert "-top-ports" not in host_disc
    assert "-p" in host_disc
    assert "22,80" in host_disc[host_disc.index("-p") + 1]
    common = build_naabu_command("naabu", ["10.0.0.0/24"], port_mode="common", intensity={"naabu_rate": 200})
    assert "-top-ports" in common and "100" in common
    assert "-rate" in common
    deep = build_naabu_command("naabu", ["10.0.0.0/24"], port_mode="deep")
    assert "1000" in deep
    custom = build_naabu_command("naabu", ["10.0.0.0/24"], port_mode="custom", custom_ports=["80", "443-445"])
    assert "-p" in custom and "80,443-445" in custom
    httpx = build_httpx_command("httpx", "/tmp/t", intensity={"httpx_rate": 50})
    assert "-rl" in httpx
    nuclei = build_nuclei_command("nuclei", "/tmp/t", severities="critical", tags="cve", intensity={"nuclei_concurrency": 10})
    assert "-severity" in nuclei and "critical" in nuclei
    assert "-tags" in nuclei
    assert "-c" in nuclei
    assert "-duc" in nuclei
    assert "-tl" not in nuclei


def test_port_scope_defaults_and_requires_discovery_for_detected():
    from app.scan_intensity import PRESETS
    from app.scan_stages import StageConfigError, normalize_stage_config

    detected = normalize_stage_config({"discovery": True, "port_mode": "common"})
    assert detected["port_scope"] == "detected"
    with pytest.raises(StageConfigError, match="detected hosts"):
        normalize_stage_config({"discovery": False, "port_mode": "common", "port_scope": "detected"})
    everything = normalize_stage_config(
        {"discovery": False, "port_mode": "common", "port_scope": "all", "fingerprint": False, "vulnerability": False}
    )
    assert everything["port_scope"] == "all"
    assert PRESETS["normal"]["naabu_retries"] == 1
    assert PRESETS["normal"]["naabu_timeout_ms"] <= 400
    assert PRESETS["high"]["naabu_retries"] == 0


def test_pipeline_detected_hosts_do_not_port_scan_cidrs():
    import runner as runtime_runner

    captured: dict[str, list] = {}

    def fake_discovery(*_args, **_kwargs):
        return ([{"ip": "10.1.0.9"}], None)

    def fake_naabu(targets, **_kwargs):
        captured["naabu"] = list(targets)
        return ([{"ip": "10.1.0.9", "port": 80}], None)

    with (
        patch.object(runtime_runner, "run_host_discovery", side_effect=fake_discovery) as discovery,
        patch.object(runtime_runner, "run_naabu", side_effect=fake_naabu),
        patch.object(runtime_runner, "run_httpx", return_value=([], None)),
        patch.object(runtime_runner, "collect_run_provenance", return_value={"runtime_version": "t"}),
    ):
        runtime_runner.run_pipeline(
            {
                "scope": "lan",
                "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
                "stages": {
                    "discovery": True,
                    "port_mode": "common",
                    "port_scope": "detected",
                    "fingerprint": False,
                    "vulnerability": False,
                },
                "intensity": {"naabu_rate": 2500, "naabu_retries": 3, "naabu_timeout_ms": 1000},
                "exclusions": [],
            }
        )
    discovery.assert_called_once()
    assert discovery.call_args.kwargs["intensity"]["naabu_retries"] == 1
    assert discovery.call_args.kwargs["intensity"]["naabu_timeout_ms"] == 500
    assert captured["naabu"] == ["10.1.0.9"]


def test_pipeline_all_addresses_port_scans_cidrs_without_ping_first():
    import runner as runtime_runner

    captured: dict[str, list] = {}

    def fake_naabu(targets, **_kwargs):
        captured["naabu"] = list(targets)
        return ([{"ip": "10.1.0.9", "port": 80}], None)

    with (
        patch.object(runtime_runner, "run_host_discovery") as discovery,
        patch.object(runtime_runner, "run_naabu", side_effect=fake_naabu),
        patch.object(runtime_runner, "run_httpx", return_value=([], None)),
        patch.object(runtime_runner, "collect_run_provenance", return_value={"runtime_version": "t"}),
    ):
        runtime_runner.run_pipeline(
            {
                "scope": "lan",
                "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
                "stages": {
                    "discovery": True,
                    "port_mode": "common",
                    "port_scope": "all",
                    "fingerprint": False,
                    "vulnerability": False,
                },
                "intensity": {},
                "exclusions": [],
            }
        )
    discovery.assert_not_called()
    assert captured["naabu"] == ["10.1.0.0/24"]


def test_custom_ports_and_fqdn_normalization():
    from app.scan_stages import StageConfigError, parse_custom_ports
    from app.wan_targets import WanTargetInvalidError, normalize_wan_target

    assert parse_custom_ports("80,443,8000-8010") == ["80", "443", "8000-8010"]
    with pytest.raises(StageConfigError):
        parse_custom_ports("0")
    with pytest.raises(StageConfigError):
        parse_custom_ports("8000-80")
    assert normalize_wan_target("ip", "192.168.0.1") == ("ip", "192.168.0.1")
    with pytest.raises(WanTargetInvalidError):
        normalize_wan_target("fqdn", "https://x.example")


def test_exclusion_subtraction_and_mocked_fqdn():
    import ipaddress
    from unittest.mock import patch

    from app.scan_exclusions import apply_exclusions_to_cidrs, exclusion_networks

    remaining = apply_exclusions_to_cidrs(
        ["10.0.0.0/24"],
        exclusion_networks("ip", "10.0.0.1"),
    )
    assert "10.0.0.1/32" not in remaining
    assert any(item.startswith("10.0.0.") for item in remaining)

    import runner as runtime_runner

    with patch("runner.socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.1", 0))]):
        kept = runtime_runner._keep_fqdn("evil.example", [ipaddress.ip_network("10.0.0.1/32")])
        assert kept is False
    with patch("runner.socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.9", 0))]):
        kept = runtime_runner._keep_fqdn("ok.example", [ipaddress.ip_network("10.0.0.1/32")])
        assert kept is True
        pinned = runtime_runner._pin_fqdn_ips("ok.example", [ipaddress.ip_network("10.0.0.1/32")])
        assert pinned == ["10.0.0.9"]


@requires_postgres
def test_unversioned_phase1d_column_marker_fail_closed(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, alembic_config, apply_schema

    command.upgrade(alembic_config(), "0001_baseline")
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS execution_snapshot JSONB"))
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()


def test_preferred_idle_grace_and_offline_failover():
    from types import SimpleNamespace

    from app.scan_dispatch import agent_may_claim_now

    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    preferred = SimpleNamespace(id=1, status="approved", last_heartbeat=now)
    secondary = SimpleNamespace(id=2, status="approved", last_heartbeat=now)
    snapshot = {
        "created_at": now.isoformat(),
        "dispatch": {
            "mode": "preferred_failover",
            "preferred_agent_id": 1,
            "eligible_agent_ids": [1, 2],
            "grace_seconds": 60,
        },
    }
    agents = {1: preferred, 2: secondary}
    assert agent_may_claim_now(preferred, snapshot, agents, now=now)
    assert not agent_may_claim_now(secondary, snapshot, agents, now=now)
    assert agent_may_claim_now(secondary, snapshot, agents, now=now + timedelta(seconds=61))
    offline = SimpleNamespace(id=1, status="approved", last_heartbeat=None)
    assert agent_may_claim_now(secondary, snapshot, {1: offline, 2: secondary}, now=now)


def test_schedule_weekly_monthly_legacy_and_timezones():
    from zoneinfo import ZoneInfo

    from app.scan_schedule import effective_scan_timezone, next_occurrence, normalize_schedule_config

    after = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
    weekly = next_occurrence({"type": "weekly", "weekday": 2, "hour": 9, "minute": 0}, tz_name="America/New_York", after=after)
    assert weekly.astimezone(ZoneInfo("America/New_York")).weekday() == 2
    monthly = next_occurrence({"type": "monthly", "day": 1, "hour": 4, "minute": 0}, tz_name="UTC", after=after)
    assert monthly.day == 1
    legacy = next_occurrence({"type": "legacy_interval", "interval_minutes": 60}, tz_name="UTC", after=after)
    assert (legacy - after).total_seconds() == 3600
    assert effective_scan_timezone("America/New_York", "UTC", "lan") == "America/New_York"
    assert effective_scan_timezone(None, "UTC", "wan") == "UTC"
    assert normalize_schedule_config(None, interval_minutes=30, allow_legacy=True)["type"] == "legacy_interval"
    with pytest.raises(Exception):
        normalize_schedule_config({"type": "legacy_interval", "interval_minutes": 30}, allow_legacy=False)


def test_snapshot_has_no_secrets_and_provenance_is_not_fabricated():
    from app.scan_snapshot import SnapshotError, assert_no_secrets
    import runner as runtime_runner

    assert_no_secrets({"targets": [{"type": "cidr", "value": "10.0.0.0/24"}], "intensity": {"preset": "low"}})
    with pytest.raises(SnapshotError):
        assert_no_secrets({"smtp_password": "x"})
    versions = runtime_runner.collect_tool_versions()
    assert "naabu_version" not in versions or versions["naabu_version"]
    assert versions.get("nuclei_version") != "unknown"


def test_fingerprint_and_vulnerability_off_skip_commands():
    import os
    from unittest.mock import patch

    import runner as runtime_runner

    job = {
        "scope": "wan",
        "targets": [{"type": "cidr", "value": "203.0.113.0/24"}],
        "stages": {"discovery": True, "port_mode": "none", "fingerprint": False, "vulnerability": False},
        "intensity": {},
        "exclusions": [],
    }
    env = {key: value for key, value in os.environ.items() if key != "SCAN_DRY_RUN"}
    with patch.dict(os.environ, env, clear=True):
        with (
            patch.object(runtime_runner, "run_naabu") as naabu,
            patch.object(runtime_runner, "run_host_discovery", return_value=[{"ip": "203.0.113.10"}]) as discovery,
            patch.object(runtime_runner, "run_httpx") as httpx,
            patch.object(runtime_runner, "run_nuclei") as nuclei,
        ):
            result = runtime_runner.run_pipeline(job)
    naabu.assert_not_called()
    discovery.assert_called_once()
    httpx.assert_not_called()
    nuclei.assert_not_called()
    assert result["devices"]


@requires_postgres
def test_manual_legacy_interval_viewer_caps_and_timezone_snapshot(reset_db):
    with _client() as client:
        admin = _login(client)
        viewer = _create_staff(client, admin, "watch", "viewer")
        world = _world(client, admin)
        manual = _lan_scan(client, admin, world, name="ManualOnly")
        assert manual["next_run_at"] is None
        assert manual["schedule_config"]["type"] == "manual"
        rejected_legacy = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={
                "name": "LegacyUI",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"]],
                "schedule_config": {"type": "legacy_interval", "interval_minutes": 45},
            },
        )
        assert rejected_legacy.status_code == 400
        compat = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={
                "name": "LegacyCompat",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"]],
                "interval_minutes": 45,
            },
        )
        assert compat.status_code == 200, compat.text
        assert compat.json()["schedule_config"]["type"] == "legacy_interval"
        wan = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(admin),
            json={"name": "WAN TZ", "scope": "wan", "wan_target_ids": [world["wan"]["id"]]},
        )
        assert wan.status_code == 200
        run = client.post(f"/api/scans/{wan.json()['id']}/run", headers=_headers(admin))
        job = client.get(f"/api/jobs/{run.json()['id']}", headers=_headers(admin)).json()
        assert job["execution_snapshot"]["schedule"]["timezone"] == "UTC"
        assert "password" not in str(job["execution_snapshot"]).lower()
        _finish_job(run.json()["id"])
        lan_run = client.post(f"/api/scans/{manual['id']}/run", headers=_headers(admin))
        lan_job = client.get(f"/api/jobs/{lan_run.json()['id']}", headers=_headers(admin)).json()
        assert lan_job["execution_snapshot"]["schedule"]["timezone"] == "America/New_York"
        viewer_excl = client.post(
            "/api/scan-exclusions",
            headers=_headers(viewer),
            json={"scope": "global", "exclusion_type": "ip", "value": "10.0.0.1"},
        )
        assert viewer_excl.status_code == 403
        settings = client.get("/api/admin/settings", headers=_headers(admin)).json()
        viewer_caps = client.put("/api/admin/settings", headers=_headers(viewer), json=settings)
        assert viewer_caps.status_code == 403


@requires_postgres
def test_pending_legacy_pre_1d_jobs_cannot_execute_mutable_scan(reset_db):
    from alembic import command

    from app.config import settings
    from app.database import SessionLocal, engine
    from app.jobs import fail_pending_legacy_pre_1d_jobs
    from app.migrate import alembic_config, apply_schema
    from app.models import LEGACY_PRE_1D_REQUEUE_ERROR, ScanJob

    command.upgrade(alembic_config(), PHASE1C_HEAD)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Legacy queue', '') RETURNING id")).scalar_one()
        wan_id = conn.execute(
            text("INSERT INTO subnets (tenant_id, name, cidr, scope) VALUES (:t, 'WAN', '198.51.100.0/24', 'wan') RETURNING id"),
            {"t": tenant_id},
        ).scalar_one()
        scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old WAN', 'wan', 'discovery', 'high', '', CAST(:ids AS jsonb), true)
                RETURNING id
                """
            ),
            {"t": tenant_id, "ids": f"[{wan_id}]"},
        ).scalar_one()
        queued_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'queued', 0, 0) RETURNING id"),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()
        done_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'done', 4, 1) RETURNING id"),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()
    apply_schema()
    db = SessionLocal()
    try:
        queued = db.get(ScanJob, queued_id)
        done = db.get(ScanJob, done_id)
        assert queued is not None and done is not None
        assert queued.execution_snapshot is None
        assert queued.snapshot_version == "legacy_pre_1d"
        if queued.status != "failed":
            fail_pending_legacy_pre_1d_jobs(db)
            db.commit()
            queued = db.get(ScanJob, queued_id)
        assert queued.status == "failed"
        assert LEGACY_PRE_1D_REQUEUE_ERROR in (queued.error or "")
        assert done.status == "done"
        assert done.execution_snapshot is None
        assert done.hosts_found == 4
    finally:
        db.close()

    with _client() as client:
        start = client.post(
            f"/api/internal/scanner/jobs/{queued_id}/start",
            headers={"X-Scanner-Token": settings.scanner_token},
        )
        assert start.status_code in {404, 409}


@requires_postgres
def test_new_wan_definition_rejects_empty_target_list(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        empty = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(token),
            json={"name": "Silent all", "scope": "wan", "wan_target_ids": []},
        )
        assert empty.status_code == 400
        assert "authorized target" in empty.json()["detail"].lower()


@requires_postgres
def test_queued_fqdn_is_blocked_by_new_ip_exclusion(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        fqdn = client.post(
            f"/api/tenants/{world['tenant']['id']}/wan-targets",
            headers=_headers(token),
            json={"name": "Edge", "target_type": "fqdn", "value": "edge.example.com"},
        )
        assert fqdn.status_code == 200, fqdn.text
        scan = client.post(
            f"/api/tenants/{world['tenant']['id']}/scans",
            headers=_headers(token),
            json={"name": "FQDN", "scope": "wan", "wan_target_ids": [fqdn.json()["id"]]},
        )
        assert scan.status_code == 200, scan.text
        run = client.post(f"/api/scans/{scan.json()['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        excl = client.post(
            "/api/scan-exclusions",
            headers=_headers(token),
            json={"scope": "tenant", "tenant_id": world["tenant"]["id"], "exclusion_type": "ip", "value": "203.0.113.50"},
        )
        assert excl.status_code == 200, excl.text
        from app.config import settings
        from app.scan_security import resolve_fqdn_addresses

        with patch("app.scan_security.socket.getaddrinfo", return_value=[(None, None, None, None, ("203.0.113.50", 0))]):
            addrs = resolve_fqdn_addresses("edge.example.com")
            assert str(addrs[0]) == "203.0.113.50"
            blocked = client.post(
                f"/api/internal/scanner/jobs/{run.json()['id']}/start",
                headers={"X-Scanner-Token": settings.scanner_token},
            )
        assert blocked.status_code == 409
        assert "exclusion" in blocked.json()["detail"].lower()


@requires_postgres
def test_wan_subnet_rename_and_cidr_change_archives_old_authorization(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        created = client.post(
            f"/api/tenants/{world['tenant']['id']}/subnets",
            headers=_headers(token),
            json={"name": "Old Edge", "cidr": "198.51.100.0/24", "scope": "wan"},
        )
        assert created.status_code == 200, created.text
        updated = client.patch(
            f"/api/subnets/{created.json()['id']}",
            headers=_headers(token),
            json={"name": "New Edge", "cidr": "192.0.2.0/24", "scope": "wan"},
        )
        assert updated.status_code == 200, updated.text
        rows = client.get(
            f"/api/tenants/{world['tenant']['id']}/wan-targets?include_archived=true",
            headers=_headers(token),
        ).json()
        by_value = {row["normalized_value"]: row for row in rows}
        assert "198.51.100.0/24" in by_value
        assert by_value["198.51.100.0/24"]["archived_at"] is not None
        assert "192.0.2.0/24" in by_value
        assert by_value["192.0.2.0/24"]["archived_at"] is None


def _scanner_headers() -> dict[str, str]:
    from app.config import settings

    return {"X-Scanner-Token": settings.scanner_token}


def _wan_scan(client: TestClient, token: str, world: dict, **extra) -> dict:
    body = {
        "name": extra.pop("name", "WAN Scan"),
        "scope": "wan",
        "wan_target_ids": extra.pop("wan_target_ids", [world["wan"]["id"]]),
        "is_enabled": True,
        "stage_config": extra.pop("stage_config", {"discovery": True, "port_mode": "common", "fingerprint": True, "vulnerability": False}),
        "intensity_config": extra.pop("intensity_config", {"preset": "normal"}),
        "schedule_config": extra.pop("schedule_config", {"type": "manual"}),
    }
    body.update(extra)
    response = client.post(f"/api/tenants/{world['tenant']['id']}/scans", headers=_headers(token), json=body)
    assert response.status_code == 200, response.text
    return response.json()


@requires_postgres
def test_queued_lan_run_stays_agent_only_after_definition_edited_to_wan(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        edited = client.patch(
            f"/api/scans/{scan['id']}",
            headers=_headers(token),
            json={
                "name": "Now WAN",
                "scope": "wan",
                "wan_target_ids": [world["wan"]["id"]],
                "is_enabled": True,
            },
        )
        assert edited.status_code == 200, edited.text
        assert edited.json()["scope"] == "wan"
        history = client.get(f"/api/jobs/{job_id}", headers=_headers(token)).json()
        assert history["scope"] == "lan"
        assert history["execution_snapshot"]["scope"] == "lan"
        _heartbeat(world["agent1"]["id"])
        agent_poll = client.get("/api/agent/jobs", headers=_agent_headers(world["agent1"]))
        assert agent_poll.status_code == 200, agent_poll.text
        assert any(row["job_id"] == job_id for row in agent_poll.json())
        scanner_poll = client.get("/api/internal/scanner/jobs", headers=_scanner_headers())
        assert scanner_poll.status_code == 200, scanner_poll.text
        assert scanner_poll.json() == []
        scanner_start = client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())
        assert scanner_start.status_code == 404
        agent_start = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
        assert agent_start.status_code == 200, agent_start.text
        assert agent_start.json()["scope"] == "lan"


@requires_postgres
def test_queued_wan_run_stays_central_only_after_definition_edited_to_lan(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _wan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        edited = client.patch(
            f"/api/scans/{scan['id']}",
            headers=_headers(token),
            json={
                "name": "Now LAN",
                "scope": "lan",
                "site_id": world["site"]["id"],
                "network_ids": [world["net1"]["id"], world["net2"]["id"]],
                "is_enabled": True,
            },
        )
        assert edited.status_code == 200, edited.text
        assert edited.json()["scope"] == "lan"
        history = client.get(f"/api/jobs/{job_id}", headers=_headers(token)).json()
        assert history["scope"] == "wan"
        _heartbeat(world["agent1"]["id"])
        agent_poll = client.get("/api/agent/jobs", headers=_agent_headers(world["agent1"]))
        assert agent_poll.json() == []
        agent_start = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
        assert agent_start.status_code == 404
        scanner_poll = client.get("/api/internal/scanner/jobs", headers=_scanner_headers())
        assert any(row["job_id"] == job_id for row in scanner_poll.json())
        scanner_start = client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())
        assert scanner_start.status_code == 200, scanner_start.text
        assert scanner_start.json()["scope"] == "wan"


@requires_postgres
def test_phase1d_lan_device_lands_on_snapshot_site_network_and_claimed_agent(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world, network_ids=[world["net1"]["id"]])
        assert scan["agent_id"] is None
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        _heartbeat(world["agent1"]["id"])
        started = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
        assert started.status_code == 200, started.text
        posted = client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(world["agent1"]),
            json=[{"ip": "10.1.0.20", "scope": "lan", "hostname": "hq-srv01", "ports": [22]}],
        )
        assert posted.status_code == 200, posted.text
        from app.database import SessionLocal
        from app.models import Asset, AssetObservation, Device, ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job.claimed_agent_id == world["agent1"]["id"]
            device = db.query(Device).filter(Device.hostname == "hq-srv01").one()
            asset = db.get(Asset, device.asset_id)
            assert device.scope == "lan"
            assert device.site_id == world["site"]["id"]
            assert asset.site_id == world["site"]["id"]
            obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).one()
            assert obs.site_id == world["site"]["id"]
            assert obs.network_id == world["net1"]["id"]
            assert obs.agent_id == world["agent1"]["id"]
            assert obs.scope == "lan"
            assert obs.scan_job_id == job_id
        finally:
            db.close()


@requires_postgres
def test_findings_retain_run_scope_after_definition_scope_changes(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world, network_ids=[world["net1"]["id"]])
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        job_id = run.json()["id"]
        _heartbeat(world["agent1"]["id"])
        assert client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"])).status_code == 200
        assert client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(world["agent1"]),
            json=[{"ip": "10.1.0.21", "scope": "wan", "hostname": "hq-panel"}],
        ).status_code == 200
        edited = client.patch(
            f"/api/scans/{scan['id']}",
            headers=_headers(token),
            json={
                "name": "Edited WAN",
                "scope": "wan",
                "wan_target_ids": [world["wan"]["id"]],
                "is_enabled": True,
            },
        )
        assert edited.status_code == 200, edited.text
        findings = client.post(
            f"/api/agent/jobs/{job_id}/findings",
            headers=_agent_headers(world["agent1"]),
            json=[
                {
                    "template_id": "exposed-panel",
                    "name": "Panel",
                    "severity": "high",
                    "host": "https://10.1.0.21",
                    "matched_at": "https://10.1.0.21/",
                    "tags": "panel",
                }
            ],
        )
        assert findings.status_code == 200, findings.text
        history = client.get(f"/api/jobs/{job_id}", headers=_headers(token)).json()
        assert history["scope"] == "lan"
        from app.database import SessionLocal
        from app.models import Device, Finding

        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.hostname == "hq-panel").one()
            assert device.scope == "lan"
            assert device.site_id == world["site"]["id"]
            finding = db.query(Finding).filter(Finding.scan_job_id == job_id).one()
            assert finding.device_id == device.id
        finally:
            db.close()


@requires_postgres
def test_already_running_legacy_pre_1d_job_cannot_unquarantine(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, apply_schema
    from app.models import LEGACY_PRE_1D_REQUEUE_ERROR, ScanJob

    command.upgrade(alembic_config(), PHASE1C_HEAD)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Legacy running', '') RETURNING id")).scalar_one()
        wan_id = conn.execute(
            text("INSERT INTO subnets (tenant_id, name, cidr, scope) VALUES (:t, 'WAN', '198.51.100.0/24', 'wan') RETURNING id"),
            {"t": tenant_id},
        ).scalar_one()
        scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old running WAN', 'wan', 'discovery', 'high', '', CAST(:ids AS jsonb), true)
                RETURNING id
                """
            ),
            {"t": tenant_id, "ids": f"[{wan_id}]"},
        ).scalar_one()
        running_id = conn.execute(
            text(
                """
                INSERT INTO scan_jobs (scan_id, tenant_id, status, claimed_by, hosts_found, findings_count)
                VALUES (:s, :t, 'running', 'central', 0, 0)
                RETURNING id
                """
            ),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()
    apply_schema()
    db = SessionLocal()
    try:
        job = db.get(ScanJob, running_id)
        assert job is not None
        assert job.execution_snapshot is None
        assert job.snapshot_version == "legacy_pre_1d"
        assert job.status == "failed"
        assert LEGACY_PRE_1D_REQUEUE_ERROR in (job.error or "")
        assert job.claimed_by is None
        assert job.claimed_agent_id is None
    finally:
        db.close()

    with _client() as client:
        devices = client.post(
            f"/api/internal/scanner/jobs/{running_id}/devices",
            headers=_scanner_headers(),
            json=[{"ip": "198.51.100.8", "scope": "wan", "hostname": "legacy-box"}],
        )
        assert devices.status_code == 409
        findings = client.post(
            f"/api/internal/scanner/jobs/{running_id}/findings",
            headers=_scanner_headers(),
            json=[{"template_id": "x", "host": "198.51.100.8"}],
        )
        assert findings.status_code == 409
        provenance = client.post(
            f"/api/internal/scanner/jobs/{running_id}/provenance",
            headers=_scanner_headers(),
            json={"tool": "naabu"},
        )
        assert provenance.status_code == 409
        complete = client.post(
            f"/api/internal/scanner/jobs/{running_id}/complete",
            headers=_scanner_headers(),
            params={"ok": "true"},
        )
        assert complete.status_code == 409

    db = SessionLocal()
    try:
        job = db.get(ScanJob, running_id)
        assert job.status == "failed"
        assert job.claimed_by is None
    finally:
        db.close()


@requires_postgres
def test_fqdn_is_pinned_at_start_and_runtime_fail_closes_on_later_exclusion(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        fqdn = client.post(
            f"/api/tenants/{world['tenant']['id']}/wan-targets",
            headers=_headers(token),
            json={"name": "Edge host", "target_type": "fqdn", "value": "edge.example.com"},
        )
        assert fqdn.status_code == 200, fqdn.text
        scan = _wan_scan(client, token, world, name="FQDN pin", wan_target_ids=[fqdn.json()["id"]])
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        with patch("app.scan_security.socket.getaddrinfo", return_value=[(None, None, None, None, ("203.0.113.51", 0))]):
            started = client.post(
                f"/api/internal/scanner/jobs/{run.json()['id']}/start",
                headers=_scanner_headers(),
            )
        assert started.status_code == 200, started.text
        payload = started.json()
        assert payload["scope"] == "wan"
        assert all(row["type"] != "fqdn" for row in payload["targets"])
        assert any(
            row["type"] == "ip" and row["value"] == "203.0.113.51" and row.get("source_fqdn") == "edge.example.com"
            for row in payload["targets"]
        )

        import runner as runtime_runner

        with patch("runner.socket.getaddrinfo") as dns:
            pinned = runtime_runner.resolve_execution_targets(payload)
            dns.assert_not_called()
        assert pinned == [{"type": "ip", "value": "203.0.113.51", "source_fqdn": "edge.example.com"}] or all(
            row["type"] == "ip" and row["value"] == "203.0.113.51" and row.get("source_fqdn") == "edge.example.com"
            for row in pinned
        )

        leftover = {
            "targets": [{"type": "fqdn", "value": "edge.example.com"}],
            "exclusions": [{"type": "ip", "value": "203.0.113.50"}],
        }
        with patch("runner.socket.getaddrinfo", return_value=[(None, None, None, None, ("203.0.113.50", 0))]):
            with pytest.raises(RuntimeError, match="Exclusions remove all targets"):
                runtime_runner.resolve_execution_targets(leftover)


def test_fingerprint_only_cidr_invokes_httpx():
    import runner as runtime_runner

    captured = {}

    def _fake_httpx(hosts, log=None, intensity=None, **_kwargs):
        captured["hosts"] = hosts
        return []

    with patch.object(runtime_runner, "run_httpx", side_effect=_fake_httpx):
        result = runtime_runner.run_pipeline(
            {
                "scope": "lan",
                "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
                "stages": {
                    "discovery": False,
                    "port_mode": "none",
                    "fingerprint": True,
                    "vulnerability": False,
                },
                "intensity": {},
                "exclusions": [],
            }
        )
    assert any(row.get("ip") == "10.1.0.0/24" for row in captured.get("hosts") or [])
    assert result["devices"] == []


@requires_postgres
def test_wan_fqdn_dns_failure_fails_the_run_closed(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        fqdn = client.post(
            f"/api/tenants/{world['tenant']['id']}/wan-targets",
            headers=_headers(token),
            json={"name": "Unresolved", "target_type": "fqdn", "value": "down.example.com"},
        )
        assert fqdn.status_code == 200, fqdn.text
        scan = _wan_scan(client, token, world, name="FQDN DNS down", wan_target_ids=[fqdn.json()["id"]])
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        with patch("app.scan_security.socket.getaddrinfo", side_effect=OSError("name resolution failed")):
            poll = client.get("/api/internal/scanner/jobs", headers=_scanner_headers())
            assert poll.status_code == 200, poll.text
            assert poll.json() == []
        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job.status == "failed"
            assert "resolve" in (job.error or "").lower()
        finally:
            db.close()

        scan2 = _wan_scan(client, token, world, name="FQDN DNS start", wan_target_ids=[fqdn.json()["id"]])
        run2 = client.post(f"/api/scans/{scan2['id']}/run", headers=_headers(token))
        assert run2.status_code == 200, run2.text
        with patch("app.scan_security.socket.getaddrinfo", side_effect=OSError("name resolution failed")):
            started = client.post(
                f"/api/internal/scanner/jobs/{run2.json()['id']}/start",
                headers=_scanner_headers(),
            )
        assert started.status_code == 409, started.text
        assert "resolve" in started.json()["detail"].lower()
        db = SessionLocal()
        try:
            job = db.get(ScanJob, run2.json()["id"])
            assert job.status == "failed"
            assert job.claimed_by is None
        finally:
            db.close()


@requires_postgres
def test_lan_observation_uses_snapshotted_cidr_after_network_edit(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world, network_ids=[world["net1"]["id"]])
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        history = client.get(f"/api/jobs/{job_id}", headers=_headers(token)).json()
        snap_nets = history["execution_snapshot"]["targets"]["networks"]
        assert any(row["id"] == world["net1"]["id"] and row["cidr"] == "10.1.0.0/24" for row in snap_nets)
        _heartbeat(world["agent1"]["id"])
        started = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
        assert started.status_code == 200, started.text
        edited = client.patch(
            f"/api/networks/{world['net1']['id']}",
            headers=_headers(token),
            json={"name": "Net One", "cidr": "10.2.0.0/24"},
        )
        assert edited.status_code == 200, edited.text
        assert edited.json()["cidr"] == "10.2.0.0/24"
        posted = client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(world["agent1"]),
            json=[{"ip": "10.1.0.20", "scope": "lan", "hostname": "snap-net-host", "ports": [22]}],
        )
        assert posted.status_code == 200, posted.text
        from app.database import SessionLocal
        from app.models import Asset, AssetObservation, Device

        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.hostname == "snap-net-host").one()
            asset = db.get(Asset, device.asset_id)
            obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id).one()
            assert obs.network_id == world["net1"]["id"]
            assert obs.site_id == world["site"]["id"]
            assert obs.agent_id == world["agent1"]["id"]
        finally:
            db.close()
