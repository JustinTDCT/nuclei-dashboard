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


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_staff(client: TestClient, admin_token: str, username: str, role: str) -> None:
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


@requires_postgres
def test_admin_and_user_can_download_deployment_material(reset_db):
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        _create_staff(client, admin, "operator", "user")
        user = _login(client, "operator", "operator-password")

        tenant = client.post(
            "/api/tenants",
            headers=_headers(admin),
            json={"name": "RBAC Tenant", "notes": ""},
        )
        assert tenant.status_code == 200, tenant.text
        tenant_id = tenant.json()["id"]

        created = client.post(
            f"/api/tenants/{tenant_id}/agents",
            headers=_headers(user),
            json={"name": "Site A"},
        )
        assert created.status_code == 200, created.text
        agent = created.json()
        assert agent["enrollment_secret"]
        secret = agent["enrollment_secret"]
        agent_id = agent["id"]

        for token in (admin, user):
            compose = client.get(f"/api/agents/{agent_id}/compose", headers=_headers(token))
            env = client.get(f"/api/agents/{agent_id}/env", headers=_headers(token))
            assert compose.status_code == 200, compose.text
            assert env.status_code == 200, env.text
            assert secret in compose.text
            assert f"ENROLLMENT_SECRET={secret}" in env.text
            assert "${TLS_VERIFY:-1}" in compose.text
            assert "TLS_VERIFY=1" in env.text
            assert "TLS_CA_FILE" in compose.text
            assert "${TLS_CA_HOST_DIR:-./agent-certs}:/certs:ro" in compose.text


@requires_postgres
def test_viewer_cannot_retrieve_enrollment_secret_or_deployment_material(reset_db):
    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        _create_staff(client, admin, "auditor", "viewer")
        viewer = _login(client, "auditor", "auditor-password")

        tenant = client.post(
            "/api/tenants",
            headers=_headers(admin),
            json={"name": "Viewer Tenant", "notes": ""},
        )
        tenant_id = tenant.json()["id"]
        created = client.post(
            f"/api/tenants/{tenant_id}/agents",
            headers=_headers(admin),
            json={"name": "Site B"},
        )
        agent = created.json()
        secret = agent["enrollment_secret"]
        agent_id = agent["id"]

        compose = client.get(f"/api/agents/{agent_id}/compose", headers=_headers(viewer))
        env = client.get(f"/api/agents/{agent_id}/env", headers=_headers(viewer))
        assert compose.status_code == 403
        assert env.status_code == 403
        assert secret not in compose.text
        assert secret not in env.text

        listed = client.get(f"/api/tenants/{tenant_id}/agents", headers=_headers(viewer))
        assert listed.status_code == 200, listed.text
        body = listed.json()
        assert len(body) == 1
        assert body[0]["id"] == agent_id
        assert body[0]["name"] == "Site B"
        assert body[0]["status"] == "pending_enrollment"
        assert body[0]["enrollment_secret"] is None
        assert secret not in listed.text

        dashboard = client.get("/api/dashboard", headers=_headers(viewer))
        assert dashboard.status_code == 200, dashboard.text
        assert dashboard.json()["tenants"] >= 1
        assert secret not in dashboard.text

        create_as_viewer = client.post(
            f"/api/tenants/{tenant_id}/agents",
            headers=_headers(viewer),
            json={"name": "Should Fail"},
        )
        assert create_as_viewer.status_code == 403
