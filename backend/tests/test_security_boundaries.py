from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Request

from tests.conftest import requires_postgres
from tests.test_phase1d import _client, _create_staff, _headers, _login, _scanner_headers, _wan_scan, _world


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_placeholder_secrets_are_rejected():
    from app.startup_security import InsecureConfigurationError, validate_runtime_secrets

    insecure = SimpleNamespace(
        database_url="postgresql://nuclei:changeme@localhost:5432/nuclei",
        secret_key="change-this-to-a-long-random-string",
        scanner_token="change-this-scanner-token",
        admin_password="changeme",
    )
    with pytest.raises(InsecureConfigurationError, match="insecure default credentials"):
        validate_runtime_secrets(insecure)


def test_runtime_test_secrets_are_accepted():
    from app.config import settings
    from app.startup_security import validate_runtime_secrets

    validate_runtime_secrets(settings)


def test_caddyfile_does_not_publish_internal_scanner_api():
    text = (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "handle /api/internal*" in text
    assert 'respond "Not Found" 404' in text
    assert "handle /api*" in text


def test_wan_target_policy_rejects_unsafe_scope():
    from app.wan_targets import WanTargetInvalidError, assert_wan_target_policy, normalize_wan_target

    target_type, normalized = normalize_wan_target("ip", "192.168.0.1")
    assert (target_type, normalized) == ("ip", "192.168.0.1")
    with pytest.raises(WanTargetInvalidError, match="private"):
        assert_wan_target_policy(target_type, normalized)
    with pytest.raises(WanTargetInvalidError, match="prefix"):
        assert_wan_target_policy("cidr", "0.0.0.0/0")
    with pytest.raises(WanTargetInvalidError, match="metadata"):
        assert_wan_target_policy("fqdn", "metadata.google.internal")
    assert_wan_target_policy("cidr", "203.0.113.0/24")


def test_request_source_ip_uses_rightmost_forwarded_hop():
    from app.audit import request_source_ip

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4, 203.0.113.10")],
            "client": ("172.18.0.5", 12345),
        }
    )
    assert request_source_ip(request) == "203.0.113.10"


@requires_postgres
def test_smtp_password_is_masked_on_settings_read(reset_db):
    with _client() as client:
        token = _login(client)
        current = client.get("/api/admin/settings", headers=_headers(token)).json()
        current["smtp_password"] = "smtp-super-secret"
        saved = client.put("/api/admin/settings", headers=_headers(token), json=current)
        assert saved.status_code == 200, saved.text
        assert saved.json()["smtp_password"] == "********"
        assert saved.json()["smtp_password_configured"] is True
        again = client.get("/api/admin/settings", headers=_headers(token)).json()
        assert again["smtp_password"] == "********"
        assert "smtp-super-secret" not in str(again)
        keep = dict(again)
        keep["smtp_host"] = "mail.example.com"
        keep["smtp_password"] = ""
        kept = client.put("/api/admin/settings", headers=_headers(token), json=keep)
        assert kept.status_code == 200, kept.text
        assert kept.json()["smtp_host"] == "mail.example.com"
        assert kept.json()["smtp_password_configured"] is True
        from app.database import SessionLocal
        from app.settings_store import get_settings

        db = SessionLocal()
        try:
            stored = get_settings(db)
            assert stored["smtp_password"] == "smtp-super-secret"
            assert "smtp_password_configured" not in stored
        finally:
            db.close()


@requires_postgres
def test_password_reset_invalidates_staff_token_and_is_audited(reset_db):
    with _client() as client:
        admin = _login(client)
        staff_token = _create_staff(client, admin, "operator", "user")
        users = client.get("/api/users", headers=_headers(admin)).json()
        operator = next(row for row in users if row["username"] == "operator")
        before = client.get("/api/auth/me", headers=_headers(staff_token))
        assert before.status_code == 200
        reset = client.patch(
            f"/api/users/{operator['id']}",
            headers=_headers(admin),
            json={"password": "replacement-password-1"},
        )
        assert reset.status_code == 200, reset.text
        after = client.get("/api/auth/me", headers=_headers(staff_token))
        assert after.status_code == 401
        from app.database import SessionLocal
        from app.models import AuditLog

        db = SessionLocal()
        try:
            rows = db.query(AuditLog).filter(AuditLog.action == "user.password_reset").all()
            assert len(rows) == 1
            assert rows[0].details["username"] == "operator"
            assert "replacement-password-1" not in str(rows[0].details)
        finally:
            db.close()


@requires_postgres
def test_wan_claim_is_atomic_across_concurrent_starts(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _wan_scan(client, token, world)
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]

        def _start(_index: int):
            return client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(_start, (1, 2)))
        codes = sorted(result.status_code for result in results)
        assert codes.count(200) == 1
        assert 404 in codes
        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "running"
            assert job.claimed_by == "central"
        finally:
            db.close()
