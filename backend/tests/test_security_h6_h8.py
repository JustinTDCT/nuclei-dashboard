from __future__ import annotations

import gzip
import hashlib
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import TEST_SETTINGS_ENCRYPTION_KEY, requires_postgres
from tests.test_phase1d import _agent_headers, _client, _headers, _lan_scan, _login, _world
from tests.test_security_boundaries import REPO_ROOT

RUNTIME_ROOT = REPO_ROOT / "scan_runtime"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


def test_mutable_agent_git_context_is_rejected():
    from app.agent_source import AgentSourceError, assert_immutable_agent_git_context

    with pytest.raises(AgentSourceError, match="mutable"):
        assert_immutable_agent_git_context(
            "https://github.com/JustinTDCT/nuclei-dashboard.git#refs/heads/main:scan_runtime"
        )
    with pytest.raises(AgentSourceError, match="branch"):
        assert_immutable_agent_git_context(
            "https://github.com/JustinTDCT/nuclei-dashboard.git#main:scan_runtime"
        )
    pinned = assert_immutable_agent_git_context(
        "https://github.com/JustinTDCT/nuclei-dashboard.git#9211fc9f4100f5fbd3b4a42f0c817e83a0103c21:scan_runtime"
    )
    assert "9211fc9f4100f5fbd3b4a42f0c817e83a0103c21" in pinned
    with pytest.raises(AgentSourceError, match="not a tag"):
        assert_immutable_agent_git_context(
            "https://github.com/JustinTDCT/nuclei-dashboard.git#refs/tags/v1.0.0:scan_runtime"
        )
    source = (REPO_ROOT / "backend" / "app" / "agent_source.py").read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "ls-remote" not in source
    assert "resolve_tag_to_commit" not in source


def test_generated_agent_compose_is_immutably_pinned(monkeypatch):
    from app import compose_gen
    from app.agent_source import DEFAULT_AGENT_GIT_CONTEXT
    from app.models import Agent

    monkeypatch.setattr(compose_gen.settings, "agent_git_context", DEFAULT_AGENT_GIT_CONTEXT)
    monkeypatch.setattr(compose_gen.settings, "agent_image", "nuclei-dashboard-agent:latest")
    agent = Agent(
        id=1,
        tenant_id=1,
        name="Edge",
        uuid="11111111-2222-3333-4444-555555555555",
        enrollment_secret="secret-value",
        status="pending_enrollment",
    )
    compose = compose_gen.agent_compose(agent, "https://dashboard.example.com:8118")
    assert "refs/heads/main" not in compose
    assert "104054936b71faefac2da29d300ef3c9360e8343" in compose
    assert "no-new-privileges:true" in compose
    assert "network_mode: host" in compose
    assert 'user: "1000:1000"' in compose
    assert "cap_drop:" in compose
    assert "NET_RAW" in compose
    assert "\n    privileged:" not in compose
    assert "refs/tags/" not in compose
    root = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    agent_file = (REPO_ROOT / "agent" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "refs/heads/main" not in root
    assert "refs/heads/main" not in agent_file
    assert "104054936b71faefac2da29d300ef3c9360e8343" in root
    assert "104054936b71faefac2da29d300ef3c9360e8343" in agent_file
    dockerfile = (RUNTIME_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 1000:1000" in dockerfile
    assert "user: \"1000:1000\"" in root
    assert "NET_RAW" in root
    assert "user: \"1000:1000\"" in agent_file
    assert "NET_RAW" in agent_file


def test_checksum_mismatch_fails_closed(tmp_path):
    from pinned_download import checksum_for

    expected = checksum_for("zip", binary="nuclei", arch="amd64")
    archive = tmp_path / "nuclei.zip"
    archive.write_bytes(b"not-the-official-nuclei-zip")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert actual != expected


def test_append_gzipped_jsonl_is_bounded(tmp_path):
    from runner import _append_gzipped_jsonl

    src = tmp_path / "part.jsonl.gz"
    dest = tmp_path / "combined.jsonl"
    with gzip.open(src, "wb") as handle:
        handle.write(b'{"template-id":"a","host":"https://example.test"}\n')
    _append_gzipped_jsonl(src, dest)
    _append_gzipped_jsonl(src, dest)
    text = dest.read_text(encoding="utf-8")
    assert text.count("template-id") == 2
    source = (RUNTIME_ROOT / "runner.py").read_text(encoding="utf-8")
    fn = source.split("def _append_gzipped_jsonl")[1].split("def ")[0]
    assert "incoming.read()" not in fn
    assert "copyfileobj" in fn


def test_run_command_kills_process_group_on_cancel(tmp_path):
    from artifact_io import JobControl, ScanCancelled, run_command_to_file, use_job_control

    dest = tmp_path / "out.bin"
    cancel = threading.Event()
    started = threading.Event()

    def _run() -> None:
        started.set()
        try:
            with use_job_control(JobControl(cancel_event=cancel, kill_grace=1.0)):
                run_command_to_file(["/bin/sleep", "30"], dest)
        except ScanCancelled:
            return

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    assert started.wait(2)
    time.sleep(0.2)
    cancel.set()
    worker.join(timeout=8)
    assert not worker.is_alive()
    with pytest.raises(ScanCancelled):
        with use_job_control(JobControl(cancel_event=cancel, kill_grace=0.5)):
            run_command_to_file(["/bin/sleep", "30"], dest)


def test_security_headers_are_present_on_health():
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from app.security_headers import SecurityHeadersMiddleware

    async def health(_request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/api/health", health)])
    app.add_middleware(SecurityHeadersMiddleware)
    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    caddy = (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "Strict-Transport-Security" in caddy
    assert "X-Frame-Options DENY" in caddy
    assert "frame-ancestors 'none'" in caddy


@requires_postgres
def test_login_lockout_after_repeated_failures(reset_db, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "login_failure_limit", 2)
    monkeypatch.setattr(settings, "login_lockout_seconds", 600)
    monkeypatch.setattr(settings, "login_ip_limit", 50)
    with _client() as client:
        first = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        second = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        third = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert first.status_code == 401
        assert second.status_code == 401
        assert third.status_code == 429
        blocked = client.post("/api/auth/login", json={"username": "admin", "password": "test-admin-pass"})
        assert blocked.status_code == 429


@requires_postgres
def test_login_ip_throttle_is_atomic_under_concurrency(reset_db, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import HTTPException

    from app.auth_throttle import assert_login_allowed
    from app.config import settings
    from app.database import SessionLocal
    from app.models import AuthThrottle

    monkeypatch.setattr(settings, "login_ip_limit", 5)
    monkeypatch.setattr(settings, "login_ip_window_seconds", 900)
    monkeypatch.setattr(settings, "login_lockout_seconds", 600)
    monkeypatch.setattr(settings, "login_failure_limit", 100)
    with _client():
        pass

    def _attempt() -> str:
        db = SessionLocal()
        try:
            assert_login_allowed(db, username="admin", source_ip="203.0.113.88")
            return "ok"
        except HTTPException as exc:
            return str(exc.status_code)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: _attempt(), range(20)))
    assert results.count("ok") <= 5
    assert results.count("429") >= 15
    db = SessionLocal()
    try:
        row = (
            db.query(AuthThrottle)
            .filter(AuthThrottle.scope == "login_ip", AuthThrottle.subject == "203.0.113.88")
            .one()
        )
        assert row.attempt_count >= 6
        assert row.locked_until is not None
    finally:
        db.close()


@requires_postgres
def test_agent_challenges_are_durable_and_single_use(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw().hex()
        from app.database import SessionLocal
        from app.models import Agent, AgentChallenge

        db = SessionLocal()
        try:
            agent = db.get(Agent, world["agent1"]["id"])
            assert agent is not None
            agent.public_key = public
            agent.status = "approved"
            db.commit()
            uuid = agent.uuid
        finally:
            db.close()

        first = client.get("/api/agent/challenge", params={"uuid": uuid})
        second = client.get("/api/agent/challenge", params={"uuid": uuid})
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        nonce_a = first.json()["nonce"]
        nonce_b = second.json()["nonce"]
        assert nonce_a != nonce_b

        db = SessionLocal()
        try:
            rows = db.query(AgentChallenge).filter(AgentChallenge.agent_id == world["agent1"]["id"]).all()
            assert {row.nonce for row in rows} == {nonce_a, nonce_b}
        finally:
            db.close()

        def _sign(nonce: str) -> str:
            return private.sign(nonce.encode()).hex()

        used = client.post(
            "/api/agent/token",
            json={"uuid": uuid, "nonce": nonce_a, "signature": _sign(nonce_a)},
        )
        assert used.status_code == 200, used.text
        assert used.json()["approved"] is True
        replay = client.post(
            "/api/agent/token",
            json={"uuid": uuid, "nonce": nonce_a, "signature": _sign(nonce_a)},
        )
        assert replay.status_code == 401
        other = client.post(
            "/api/agent/token",
            json={"uuid": uuid, "nonce": nonce_b, "signature": _sign(nonce_b)},
        )
        assert other.status_code == 200, other.text


@requires_postgres
def test_expired_job_requests_cancel_and_rejects_clean_success(reset_db):
    from app.database import SessionLocal
    from app.finding_lifecycle import FindingLifecycleError, complete_scan_run
    from app.job_control import mark_cancel_requested
    from app.models import EVALUATION_CLEAN, JOB_CANCELLED, JOB_RUNNING, AssetFindingRunEvaluation, ScanJob
    from app.scheduler import expire_stuck_jobs

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world, name="Deadline")
        run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
        assert run.status_code == 200, run.text
        job_id = run.json()["id"]
        headers = _agent_headers(world["agent1"])
        from app.models import Agent

        db = SessionLocal()
        try:
            agent = db.get(Agent, world["agent1"]["id"])
            assert agent is not None
            agent.status = "approved"
            agent.last_heartbeat = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()
        started = client.post(f"/api/agent/jobs/{job_id}/start", headers=headers)
        assert started.status_code == 200, started.text
        assert started.json().get("deadline_at")

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            job.deadline_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        finally:
            db.close()

        expire_stuck_jobs()
        beat = client.post("/api/agent/heartbeat", headers=headers, json={"job_id": job_id, "activity": "scanning"})
        assert beat.status_code == 200, beat.text
        assert beat.json()["cancel_requested"] is True

        success = client.post(
            f"/api/agent/jobs/{job_id}/complete",
            headers=headers,
            params={"ok": "true"},
            json={"status": "none_executed", "artifact_keys": []},
        )
        assert success.status_code == 409
        failed = client.post(
            f"/api/agent/jobs/{job_id}/complete",
            headers=headers,
            params={"ok": "false", "error": "scan cancelled"},
        )
        assert failed.status_code == 200, failed.text
        assert failed.json()["status"] == JOB_CANCELLED

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == JOB_CANCELLED
            assert (
                db.query(AssetFindingRunEvaluation)
                .filter(AssetFindingRunEvaluation.outcome == EVALUATION_CLEAN)
                .count()
                == 0
            )
            with pytest.raises(FindingLifecycleError, match="cannot complete successfully"):
                job.status = JOB_RUNNING
                mark_cancel_requested(job)
                complete_scan_run(db, job, ok=True)
        finally:
            db.close()


@requires_postgres
def test_smtp_password_requires_encryption_key(reset_db, monkeypatch):
    from app.config import settings
    from app.settings_crypto import SettingsCryptoError
    from app.settings_store import save_settings

    monkeypatch.setattr(settings, "settings_encryption_key", "")
    with _client() as client:
        token = _login(client)
        current = client.get("/api/admin/settings", headers=_headers(token)).json()
        current["smtp_password"] = "new-smtp-secret"
        saved = client.put("/api/admin/settings", headers=_headers(token), json=current)
        assert saved.status_code == 400
        assert "SETTINGS_ENCRYPTION_KEY" in saved.text
        from app.database import SessionLocal

        db = SessionLocal()
        try:
            with pytest.raises(SettingsCryptoError, match="SETTINGS_ENCRYPTION_KEY"):
                save_settings(db, {"smtp_password": "another-secret"})
        finally:
            db.close()


def test_settings_encryption_key_must_be_fernet_and_distinct():
    from app.settings_crypto import SettingsCryptoError, encrypt_secret, is_valid_fernet_key
    from app.startup_security import InsecureConfigurationError, validate_runtime_secrets

    assert is_valid_fernet_key(TEST_SETTINGS_ENCRYPTION_KEY)
    assert not is_valid_fernet_key("password1")
    with pytest.raises(SettingsCryptoError, match="Fernet"):
        encrypt_secret("smtp-secret", key="password1")
    reused = TEST_SETTINGS_ENCRYPTION_KEY
    cfg = type("Cfg", (), {})()
    cfg.database_url = "postgresql://nuclei:other-db-pass@localhost:5432/nuclei"
    cfg.secret_key = reused
    cfg.scanner_token = "phase0-test-scanner-token-not-for-production"
    cfg.admin_password = "bootstrap-admin-1"
    cfg.settings_encryption_key = reused
    with pytest.raises(InsecureConfigurationError, match="must be distinct"):
        validate_runtime_secrets(cfg)
    cfg.secret_key = "phase0-test-secret-not-for-production"
    cfg.settings_encryption_key = "password1"
    with pytest.raises(InsecureConfigurationError, match="Fernet"):
        validate_runtime_secrets(cfg)


@requires_postgres
def test_smtp_password_startup_migrates_plaintext_and_refuses_wrong_key(reset_db, monkeypatch):
    from cryptography.fernet import Fernet

    from app.config import settings
    from app.database import SessionLocal
    from app.models import Setting
    from app.settings_crypto import encrypt_secret, is_encrypted_secret
    from app.settings_store import validate_and_migrate_smtp_password
    from app.startup_security import InsecureConfigurationError

    with _client():
        pass
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "system").first()
        if row is None:
            db.add(Setting(key="system", value={"smtp_password": "legacy-plaintext"}))
        else:
            value = dict(row.value or {})
            value["smtp_password"] = "legacy-plaintext"
            row.value = value
        db.commit()
        monkeypatch.setattr(settings, "settings_encryption_key", "")
        with pytest.raises(InsecureConfigurationError, match="SMTP password is stored"):
            validate_and_migrate_smtp_password(db)
        monkeypatch.setattr(
            settings, "settings_encryption_key", TEST_SETTINGS_ENCRYPTION_KEY
        )
        validate_and_migrate_smtp_password(db)
        stored = db.query(Setting).filter(Setting.key == "system").one().value["smtp_password"]
        assert is_encrypted_secret(stored)
        assert "legacy-plaintext" not in stored
        other = Fernet.generate_key().decode()
        monkeypatch.setattr(settings, "settings_encryption_key", other)
        with pytest.raises(InsecureConfigurationError, match="could not be decrypted"):
            validate_and_migrate_smtp_password(db)
        monkeypatch.setattr(settings, "settings_encryption_key", "")
        with pytest.raises(InsecureConfigurationError, match="SMTP password is stored"):
            validate_and_migrate_smtp_password(db)
    finally:
        db.close()
