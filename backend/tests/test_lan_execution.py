from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.conftest import requires_postgres


@contextmanager
def _client() -> Iterator[TestClient]:
    with patch("app.main.start_scheduler"):
        from app.main import app

        with TestClient(app) as client:
            yield client


def _login(client: TestClient) -> str:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "test-admin-pass"})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _setup_two_network_scan(client: TestClient, token: str) -> dict:
    tenant = client.post("/api/tenants", headers=_headers(token), json={"name": "Exec Tenant", "notes": ""})
    assert tenant.status_code == 200, tenant.text
    tenant_id = tenant.json()["id"]
    site = client.post(
        f"/api/tenants/{tenant_id}/sites",
        headers=_headers(token),
        json={"name": "HQ"},
    )
    site_id = site.json()["id"]
    net1 = client.post(
        f"/api/sites/{site_id}/networks",
        headers=_headers(token),
        json={"name": "Net One", "cidr": "10.1.0.0/24"},
    )
    net2 = client.post(
        f"/api/sites/{site_id}/networks",
        headers=_headers(token),
        json={"name": "Net Two", "cidr": "10.2.0.0/24"},
    )
    agent = client.post(
        f"/api/tenants/{tenant_id}/agents",
        headers=_headers(token),
        json={"name": "Agent A", "site_id": site_id},
    )
    agent_id = agent.json()["id"]
    for network in (net1, net2):
        auth = client.put(
            f"/api/networks/{network.json()['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": [agent_id]},
        )
        assert auth.status_code == 200, auth.text
    scan = client.post(
        f"/api/tenants/{tenant_id}/scans",
        headers=_headers(token),
        json={
            "name": "Both networks",
            "scope": "lan",
            "agent_id": agent_id,
            "subnet_ids": [net1.json()["subnet_id"], net2.json()["subnet_id"]],
            "profile": "discovery",
            "interval_minutes": 15,
            "is_enabled": True,
        },
    )
    assert scan.status_code == 200, scan.text
    return {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "network_1": net1.json(),
        "network_2": net2.json(),
        "agent": agent.json(),
        "scan": scan.json(),
    }


def _job_count(client: TestClient, token: str, tenant_id: int) -> int:
    jobs = client.get(f"/api/tenants/{tenant_id}/jobs", headers=_headers(token))
    assert jobs.status_code == 200, jobs.text
    return len(jobs.json())


def _approve_agent(agent_id: int) -> None:
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        assert agent is not None
        agent.status = "approved"
        db.commit()
    finally:
        db.close()


def _agent_headers(agent: dict) -> dict[str, str]:
    from app.auth import create_agent_token

    return {"Authorization": f"Bearer {create_agent_token(agent['uuid'], agent['id'], agent['tenant_id'])}"}


@requires_postgres
def test_run_now_fails_after_deauthorizing_one_selected_network(reset_db):
    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        revoke = client.put(
            f"/api/networks/{fixture['network_2']['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": []},
        )
        assert revoke.status_code == 200, revoke.text
        run = client.post(f"/api/scans/{fixture['scan']['id']}/run", headers=_headers(token))
        assert run.status_code == 400, run.text
        assert "not authorized" in run.json()["detail"]
        assert _job_count(client, token, fixture["tenant_id"]) == 0


@requires_postgres
def test_run_now_fails_after_archiving_selected_network(reset_db):
    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        archived = client.post(
            f"/api/networks/{fixture['network_2']['id']}/archive",
            headers=_headers(token),
        )
        assert archived.status_code == 200, archived.text
        run = client.post(f"/api/scans/{fixture['scan']['id']}/run", headers=_headers(token))
        assert run.status_code == 400, run.text
        assert "archived" in run.json()["detail"]
        assert _job_count(client, token, fixture["tenant_id"]) == 0


@requires_postgres
def test_run_now_fails_after_moving_agent_off_site(reset_db):
    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        other = client.post(
            f"/api/tenants/{fixture['tenant_id']}/sites",
            headers=_headers(token),
            json={"name": "Other Site"},
        )
        moved = client.patch(
            f"/api/agents/{fixture['agent']['id']}",
            headers=_headers(token),
            json={"site_id": other.json()["id"]},
        )
        assert moved.status_code == 200, moved.text
        run = client.post(f"/api/scans/{fixture['scan']['id']}/run", headers=_headers(token))
        assert run.status_code == 400, run.text
        assert _job_count(client, token, fixture["tenant_id"]) == 0


@requires_postgres
def test_queued_job_does_not_execute_after_authorization_removed(reset_db):
    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        queued = client.post(f"/api/scans/{fixture['scan']['id']}/run", headers=_headers(token))
        assert queued.status_code == 200, queued.text
        job_id = queued.json()["id"]
        revoke = client.put(
            f"/api/networks/{fixture['network_2']['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": []},
        )
        assert revoke.status_code == 200, revoke.text
        _approve_agent(fixture["agent"]["id"])

        polled = client.get("/api/agent/jobs", headers=_agent_headers(fixture["agent"]))
        assert polled.status_code == 200, polled.text
        assert polled.json() == []

        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "failed"
            assert job.error and "not authorized" in job.error
        finally:
            db.close()


@requires_postgres
def test_claim_fails_closed_when_authorization_changes_after_queue(reset_db):
    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        queued = client.post(f"/api/scans/{fixture['scan']['id']}/run", headers=_headers(token))
        job_id = queued.json()["id"]
        client.put(
            f"/api/networks/{fixture['network_1']['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": []},
        )
        _approve_agent(fixture["agent"]["id"])
        started = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(fixture["agent"]))
        assert started.status_code == 409, started.text
        assert "not authorized" in started.json()["detail"]

        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "failed"
            assert job.claimed_by is None
        finally:
            db.close()


@requires_postgres
def test_scheduler_does_not_queue_invalid_lan_scan(reset_db):
    from app.scheduler import tick_schedules

    with _client() as client:
        token = _login(client)
        fixture = _setup_two_network_scan(client, token)
        client.put(
            f"/api/networks/{fixture['network_2']['id']}/authorized-agents",
            headers=_headers(token),
            json={"agent_ids": []},
        )
        tick_schedules()
        assert _job_count(client, token, fixture["tenant_id"]) == 0
