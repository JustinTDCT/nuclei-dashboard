from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from tests.conftest import requires_postgres
from tests.test_migrations import FROZEN_MIGRATION_HASHES
from tests.test_phase1d import _client, _create_staff, _headers, _heartbeat, _lan_scan, _login, _world
from tests.test_phase3c import PHASE3C_GIT_BLOB, PHASE3C_HEAD, PHASE3C_SHA256, _create_viewer, _open_critical, _site_asset

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
MIGRATION_0014 = BACKEND_ROOT / "alembic" / "versions" / "0014_reports_auditor_access.py"
FORBIDDEN_DETAIL_KEYS = {
    "enrollment_secret",
    "password",
    "password_hash",
    "access_token",
    "Authorization",
    "authorization",
    "private_key",
    "smtp_password",
}


def _audits(db, *, action: str | None = None, object_id: int | None = None):
    from app.models import AuditLog

    query = db.query(AuditLog)
    if action is not None:
        query = query.filter(AuditLog.action == action)
    if object_id is not None:
        query = query.filter(AuditLog.object_id == object_id)
    return query.order_by(AuditLog.id.asc()).all()


def _detail_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _detail_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _detail_keys(child)


def _assert_no_secrets(details: dict, *secrets: str) -> None:
    leaked = FORBIDDEN_DETAIL_KEYS.intersection(_detail_keys(details))
    assert not leaked
    blob = str(details)
    for secret in secrets:
        if secret:
            assert secret not in blob


def _pubkey() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _enroll(client: TestClient, agent: dict, *, secret: str | None = None, public_key: str | None = None, hostname="edge-1"):
    return client.post(
        "/api/agent/enroll",
        json={
            "uuid": agent["uuid"],
            "enrollment_secret": secret if secret is not None else agent["enrollment_secret"],
            "public_key": public_key or _pubkey(),
            "hostname": hostname,
            "container_id": "ctr-1",
        },
        headers={"X-Forwarded-For": "203.0.113.10"},
    )


@requires_postgres
def test_agent_approve_revoke_and_failed_approve_audit(reset_db):
    from app.database import SessionLocal
    from app.models import Agent, AuditLog

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        world = _world(client, admin)
        agent = world["agent1"]
        pending = client.post(f"/api/agents/{agent['id']}/approve", headers=_headers(admin))
        assert pending.status_code == 400
        assert pending.json()["detail"] == "Agent has not connected yet"

        db = SessionLocal()
        try:
            assert _audits(db, action="agent.approve", object_id=agent["id"]) == []
            row = db.get(Agent, agent["id"])
            assert row is not None
            row.public_key = _pubkey()
            db.commit()
        finally:
            db.close()

        approved = client.post(f"/api/agents/{agent['id']}/approve", headers=_headers(admin))
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["enrollment_secret"] is None

        db = SessionLocal()
        try:
            rows = _audits(db, action="agent.approve", object_id=agent["id"])
            assert len(rows) == 1
            row = rows[0]
            assert row.actor_username == "admin"
            assert row.object_type == "agent"
            assert row.object_id == agent["id"]
            assert row.tenant_id == world["tenant"]["id"]
            assert row.site_id == world["site"]["id"]
            assert row.details["before"]["status"] == "pending_enrollment"
            assert row.details["after"]["status"] == "approved"
            assert row.details["approved_at"]
            _assert_no_secrets(row.details, agent["enrollment_secret"])
            stored = db.get(Agent, agent["id"])
            assert stored is not None
            assert stored.enrollment_secret is None
            assert stored.status == "approved"
        finally:
            db.close()

        revoked = client.post(f"/api/agents/{agent['id']}/revoke", headers=_headers(admin))
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["status"] == "revoked"

        db = SessionLocal()
        try:
            rows = _audits(db, action="agent.revoke", object_id=agent["id"])
            assert len(rows) == 1
            row = rows[0]
            assert row.actor_username == "admin"
            assert row.details["before"]["status"] == "approved"
            assert row.details["after"]["status"] == "revoked"
            _assert_no_secrets(row.details, agent["enrollment_secret"])
            stored = db.get(Agent, agent["id"])
            assert stored is not None
            assert stored.status == "revoked"
            assert stored.enrollment_secret is None
            assert db.query(AuditLog).filter(AuditLog.action == "agent.approve", AuditLog.object_id == agent["id"]).count() == 1
        finally:
            db.close()


@requires_postgres
def test_agent_enroll_and_denied_audit(reset_db):
    from app.database import SessionLocal
    from app.events import emit_agent_identity_mismatch
    from app.models import Agent, DomainEvent

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        world = _world(client, admin)
        agent = world["agent1"]
        key = _pubkey()

        denied = _enroll(client, agent, secret="wrong-secret", public_key=key)
        assert denied.status_code == 403
        assert denied.json()["detail"] == "Invalid enrollment secret"

        first = _enroll(client, agent, public_key=key)
        assert first.status_code == 200, first.text
        assert first.json() == {"status": "pending_approval", "approved": False}

        repeat = _enroll(client, agent, public_key=key, hostname="edge-1-restart")
        assert repeat.status_code == 200, repeat.text
        assert repeat.json()["status"] == "pending_approval"

        db = SessionLocal()
        try:
            stored = db.get(Agent, agent["id"])
            assert stored is not None
            stored.status = "approved"
            stored.public_key = key
            stored.enrollment_secret = None
            db.commit()
        finally:
            db.close()

        approved_repeat = _enroll(client, agent, secret="", public_key=key)
        assert approved_repeat.status_code == 200, approved_repeat.text
        assert approved_repeat.json()["approved"] is True

        db = SessionLocal()
        try:
            enrolls = _audits(db, action="agent.enroll", object_id=agent["id"])
            denied_rows = _audits(db, action="agent.enroll_denied", object_id=agent["id"])
            assert len(enrolls) == 1
            assert len(denied_rows) == 1
            row = enrolls[0]
            assert row.actor_user_id is None
            assert row.tenant_id == world["tenant"]["id"]
            assert row.site_id == world["site"]["id"]
            assert row.details["previous_status"] == "pending_enrollment"
            assert row.details["new_status"] == "pending_approval"
            assert row.details["hostname"] == "edge-1"
            assert row.details["container_id"] == "ctr-1"
            assert row.details["source_ip"] == "203.0.113.10"
            assert row.details["public_key_fingerprint"] == hashlib.sha256(key.encode("utf-8")).hexdigest()
            _assert_no_secrets(row.details, agent["enrollment_secret"], "wrong-secret")
            denied_row = denied_rows[0]
            assert denied_row.details["reason"] == "invalid_enrollment_secret"
            assert denied_row.details["source_ip"] == "203.0.113.10"
            _assert_no_secrets(denied_row.details, agent["enrollment_secret"], "wrong-secret")

            emit_agent_identity_mismatch(db, db.get(Agent, agent["id"]), reason="key mismatch", source_ip="10.1.1.8")
            db.commit()
            assert db.query(DomainEvent).filter(DomainEvent.event_type == "agent_identity_mismatch").count() == 1
        finally:
            db.close()


@requires_postgres
def test_deployment_material_access_audit_and_viewer_denied(reset_db):
    from app.database import SessionLocal
    from app.models import Agent

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        world = _world(client, admin)
        agent = world["agent1"]
        secret = agent["enrollment_secret"]
        viewer, _ = _create_viewer(client, admin, "material-viewer", tenant_ids=[world["tenant"]["id"]])

        missing = client.get("/api/agents/999999/compose", headers=_headers(admin))
        assert missing.status_code == 404
        viewer_denied = client.get(f"/api/agents/{agent['id']}/compose", headers=_headers(viewer))
        assert viewer_denied.status_code == 403

        compose = client.get(f"/api/agents/{agent['id']}/compose", headers=_headers(admin))
        env = client.get(f"/api/agents/{agent['id']}/env", headers=_headers(admin))
        assert compose.status_code == 200
        assert env.status_code == 200
        assert secret in compose.text
        assert f"ENROLLMENT_SECRET={secret}" in env.text

        db = SessionLocal()
        try:
            rows = _audits(db, action="agent.deployment_material_access", object_id=agent["id"])
            assert len(rows) == 2
            formats = {row.details["format"] for row in rows}
            assert formats == {"compose", "env"}
            for row in rows:
                assert row.actor_username == "admin"
                assert row.tenant_id == world["tenant"]["id"]
                assert row.site_id == world["site"]["id"]
                assert row.details["included_active_enrollment_secret"] is True
                _assert_no_secrets(row.details, secret)
            stored = db.get(Agent, agent["id"])
            assert stored is not None
            stored.status = "approved"
            stored.enrollment_secret = None
            stored.public_key = _pubkey()
            db.commit()
        finally:
            db.close()

        approved = client.get(f"/api/agents/{agent['id']}/compose", headers=_headers(admin))
        assert approved.status_code == 200
        assert "ENROLLMENT_SECRET" not in approved.text

        db = SessionLocal()
        try:
            rows = _audits(db, action="agent.deployment_material_access", object_id=agent["id"])
            assert len(rows) == 3
            last = rows[-1]
            assert last.details["included_active_enrollment_secret"] is False
            _assert_no_secrets(last.details, secret)
            assert _audits(db, action="agent.deployment_material_access", object_id=999999) == []
        finally:
            db.close()


@requires_postgres
def test_login_success_and_denied_audits(reset_db):
    from app.database import SessionLocal
    from app.models import User

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        _create_staff(client, admin, "login-user", "user")
        viewer, viewer_id = _create_viewer(client, admin, "login-viewer", all_tenants=True)
        assert viewer

        bad = client.post("/api/auth/login", json={"username": "login-user", "password": "nope-nope-nope"})
        assert bad.status_code == 401
        assert bad.json()["detail"] == "Invalid credentials"

        unknown = client.post("/api/auth/login", json={"username": "nobody-here", "password": "password12"})
        assert unknown.status_code == 401
        assert unknown.json()["detail"] == "Invalid credentials"

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == "login-user").one()
            user.is_active = False
            db.commit()
        finally:
            db.close()
        inactive = client.post("/api/auth/login", json={"username": "login-user", "password": "login-user-password"})
        assert inactive.status_code == 401
        assert inactive.json()["detail"] == "Invalid credentials"

        client.patch(
            f"/api/users/{viewer_id}",
            headers=_headers(admin),
            json={"viewer_expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
        )
        expired = client.post("/api/auth/login", json={"username": "login-viewer", "password": "login-viewer-password"})
        assert expired.status_code == 401
        assert expired.json()["detail"] == "Viewer access has expired"

        db = SessionLocal()
        try:
            successes = _audits(db, action="auth.login_success")
            denied = _audits(db, action="auth.login_denied")
            assert any(row.actor_username == "admin" and row.object_type == "user" for row in successes)
            assert any(row.actor_username == "login-user" for row in successes)
            assert any(row.actor_username == "login-viewer" for row in successes)
            reasons = {row.details["reason"] for row in denied}
            assert "invalid_credentials" in reasons
            assert "account_inactive" in reasons
            assert "viewer_expired" in reasons
            unknown_row = next(row for row in denied if row.details.get("username") == "nobody-here")
            assert unknown_row.actor_user_id is None
            assert unknown_row.object_type == "auth"
            for row in [*successes, *denied]:
                _assert_no_secrets(
                    row.details,
                    "test-admin-pass",
                    "login-user-password",
                    "login-viewer-password",
                    "nope-nope-nope",
                    "password12",
                )
                assert "access_token" not in row.details
                assert row.tenant_id is None
        finally:
            db.close()


@requires_postgres
def test_tenant_create_update_and_delete_refused(reset_db):
    from app.database import SessionLocal
    from app.events import emit_new_asset
    from app.models import Asset, AssetFinding, AuditLog, DomainEvent, Finding, ScanJob, Site, Tenant

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        created = client.post(
            "/api/tenants",
            headers=_headers(admin),
            json={"name": "Keep History", "notes": "sensitive operator notes"},
        )
        assert created.status_code == 200, created.text
        tenant_id = created.json()["id"]
        updated = client.patch(
            f"/api/tenants/{tenant_id}",
            headers=_headers(admin),
            json={"name": "Keep History Ltd", "notes": "changed notes"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["name"] == "Keep History Ltd"

        site = client.post(f"/api/tenants/{tenant_id}/sites", headers=_headers(admin), json={"name": "HQ"}).json()
        asset = client.post(
            f"/api/tenants/{tenant_id}/assets",
            headers=_headers(admin),
            json={"site_id": site["id"], "display_name": "DC01", "hostname": "dc01"},
        )
        assert asset.status_code == 200, asset.text
        world = {
            "tenant": created.json(),
            "site": site,
            "net1": client.post(
                f"/api/sites/{site['id']}/networks",
                headers=_headers(admin),
                json={"name": "Lan", "cidr": "10.9.0.0/24"},
            ).json(),
            "net2": client.post(
                f"/api/sites/{site['id']}/networks",
                headers=_headers(admin),
                json={"name": "Lan Two", "cidr": "10.10.0.0/24"},
            ).json(),
            "agent1": client.post(
                f"/api/tenants/{tenant_id}/agents",
                headers=_headers(admin),
                json={"name": "Edge", "site_id": site["id"]},
            ).json(),
        }
        client.put(
            f"/api/networks/{world['net1']['id']}/authorized-agents",
            headers=_headers(admin),
            json={"agent_ids": [world["agent1"]["id"]]},
        )
        _heartbeat(world["agent1"]["id"])
        scan = _lan_scan(client, admin, world, network_ids=[world["net1"]["id"]])
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]

        db = SessionLocal()
        try:
            site_asset = _site_asset(db, tenant_id, site["id"], "Hist Host")
            finding = _open_critical(db, tenant_id, site_asset, "nuclei:keep-history")
            emit_new_asset(db, site_asset)
            db.commit()
            site_count = db.query(Site).filter(Site.tenant_id == tenant_id).count()
            asset_count = db.query(Asset).filter(Asset.tenant_id == tenant_id).count()
            job_count = db.query(ScanJob).filter(ScanJob.tenant_id == tenant_id).count()
            finding_count = db.query(Finding).filter(Finding.tenant_id == tenant_id).count()
            asset_finding_count = db.query(AssetFinding).filter(AssetFinding.tenant_id == tenant_id).count()
            event_count = db.query(DomainEvent).filter(DomainEvent.tenant_id == tenant_id).count()
            audit_count = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).count()
            assert site_count >= 1
            assert asset_count >= 1
            assert job_count >= 1
            assert finding_count >= 1
            assert asset_finding_count >= 1
            assert event_count >= 1
            assert audit_count >= 1
            existing_audit_ids = {row.id for row in db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).all()}
        finally:
            db.close()

        refused = client.delete(f"/api/tenants/{tenant_id}", headers=_headers(admin))
        assert refused.status_code == 409, refused.text
        assert "historical evidence" in refused.json()["detail"]

        missing = client.delete("/api/tenants/999999", headers=_headers(admin))
        assert missing.status_code == 404

        db = SessionLocal()
        try:
            assert db.get(Tenant, tenant_id) is not None
            assert db.query(Site).filter(Site.tenant_id == tenant_id).count() == site_count
            assert db.query(Asset).filter(Asset.tenant_id == tenant_id).count() == asset_count
            assert db.query(ScanJob).filter(ScanJob.id == job_id).count() == 1
            assert db.query(Finding).filter(Finding.tenant_id == tenant_id).count() == finding_count
            assert db.query(AssetFinding).filter(AssetFinding.tenant_id == tenant_id).count() == asset_finding_count
            assert db.query(DomainEvent).filter(DomainEvent.tenant_id == tenant_id).count() == event_count
            leftover = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id, AuditLog.id.in_(existing_audit_ids)).count()
            assert leftover == len(existing_audit_ids)
            create_rows = _audits(db, action="tenant.create", object_id=tenant_id)
            update_rows = _audits(db, action="tenant.update", object_id=tenant_id)
            refused_rows = _audits(db, action="tenant.delete_refused", object_id=tenant_id)
            assert len(create_rows) == 1
            assert create_rows[0].actor_username == "admin"
            assert create_rows[0].tenant_id == tenant_id
            assert create_rows[0].details["name"] == "Keep History"
            assert create_rows[0].details["notes_present"] is True
            assert "sensitive operator notes" not in str(create_rows[0].details)
            assert len(update_rows) == 1
            assert update_rows[0].details["before"]["name"] == "Keep History"
            assert update_rows[0].details["after"]["name"] == "Keep History Ltd"
            assert update_rows[0].details["notes_changed"] is True
            assert "changed notes" not in str(update_rows[0].details)
            assert len(refused_rows) == 1
            assert refused_rows[0].actor_username == "admin"
            assert refused_rows[0].details["reason"] == "historical_integrity"
            _assert_no_secrets(create_rows[0].details)
            _assert_no_secrets(update_rows[0].details)
            _assert_no_secrets(refused_rows[0].details)
        finally:
            db.close()


@requires_postgres
def test_audit_history_scope_for_new_actions(reset_db):
    from app.database import SessionLocal

    with _client() as client:
        admin = _login(client, "admin", "test-admin-pass")
        a = client.post("/api/tenants", headers=_headers(admin), json={"name": "Alpha-A", "notes": ""}).json()
        b = client.post("/api/tenants", headers=_headers(admin), json={"name": "Beta-A", "notes": ""}).json()
        site_a = client.post(f"/api/tenants/{a['id']}/sites", headers=_headers(admin), json={"name": "A-HQ"}).json()
        agent_a = client.post(
            f"/api/tenants/{a['id']}/agents",
            headers=_headers(admin),
            json={"name": "A-Edge", "site_id": site_a["id"]},
        ).json()
        viewer, _ = _create_viewer(client, admin, "hist-a", tenant_ids=[a["id"]])

        own = client.get(f"/api/audit-history?tenant_id={a['id']}&action=tenant.create", headers=_headers(viewer))
        assert own.status_code == 200, own.text
        assert any(item["object_id"] == a["id"] for item in own.json()["items"])
        other = client.get(f"/api/audit-history?tenant_id={b['id']}", headers=_headers(viewer))
        assert other.status_code == 404
        scoped = client.get("/api/audit-history", headers=_headers(viewer)).json()
        assert scoped["items"]
        assert all(item["tenant_id"] == a["id"] for item in scoped["items"])
        assert all(item["action"] not in {"auth.login_success", "auth.login_denied"} for item in scoped["items"])
        assert all(item["tenant_id"] is not None for item in scoped["items"])

        db = SessionLocal()
        try:
            assert any(row.action == "agent.create" and row.object_id == agent_a["id"] for row in _audits(db))
        finally:
            db.close()


@requires_postgres
def test_tranche_a_does_not_change_migrations(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    from tests.test_migrations import SECURITY_H_HEAD

    assert revision == head_revision() == current_revision() == SECURITY_H_HEAD
    assert hashlib.sha256(MIGRATION_0014.read_bytes()).hexdigest() == PHASE3C_SHA256
    assert FROZEN_MIGRATION_HASHES["0014_reports_auditor_access.py"] == PHASE3C_SHA256
    blob = subprocess.check_output(["git", "hash-object", str(MIGRATION_0014)], cwd=REPO_ROOT, text=True).strip()
    assert blob == PHASE3C_GIT_BLOB
    assert (BACKEND_ROOT / "alembic" / "versions" / "0015_raw_scan_evidence.py").is_file()
    assert "viewer_tenant_grants" in inspect(engine).get_table_names()
