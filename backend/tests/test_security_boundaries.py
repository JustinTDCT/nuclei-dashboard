from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Request

from tests.conftest import requires_postgres
from tests.test_phase1d import (
    _agent_headers,
    _client,
    _create_staff,
    _headers,
    _login,
    _scanner_headers,
    _wan_scan,
    _world,
)


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


def test_secret_key_must_differ_from_scanner_token():
    from app.startup_security import InsecureConfigurationError, validate_runtime_secrets

    reused = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    cfg = SimpleNamespace(
        database_url="postgresql://nuclei:other-db-pass@localhost:5432/nuclei",
        secret_key=reused,
        scanner_token=reused,
        admin_password="bootstrap-admin-1",
    )
    with pytest.raises(InsecureConfigurationError, match="must be distinct"):
        validate_runtime_secrets(cfg)


def test_admin_password_required_only_during_bootstrap():
    from app.startup_security import InsecureConfigurationError, validate_runtime_secrets

    cfg = SimpleNamespace(
        database_url="postgresql://nuclei:other-db-pass@localhost:5432/nuclei",
        secret_key="phase0-test-secret-not-for-production",
        scanner_token="phase0-test-scanner-token-not-for-production",
        admin_password="",
    )
    with pytest.raises(InsecureConfigurationError, match="ADMIN_PASSWORD"):
        validate_runtime_secrets(cfg, require_admin_password=True)
    validate_runtime_secrets(cfg, require_admin_password=False)


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
    with pytest.raises(WanTargetInvalidError, match="65536"):
        assert_wan_target_policy("cidr", "0.0.0.0/0")
    with pytest.raises(WanTargetInvalidError, match="65536"):
        assert_wan_target_policy("cidr", "2001:db8::/32")
    with pytest.raises(WanTargetInvalidError, match="65536"):
        assert_wan_target_policy("cidr", "1.2.0.0/15")
    with pytest.raises(WanTargetInvalidError, match="65536"):
        assert_wan_target_policy("cidr", "2001:db8::/111")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("ip", "::ffff:127.0.0.1")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("cidr", "::ffff:0:0/96")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("ip", "::ffff:8.8.8.8")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("ip", "::ffff:10.0.0.1")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("ip", "::ffff:169.254.169.254")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("ip", "::8.8.8.8")
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_target_policy("cidr", "::/96")
    with pytest.raises(WanTargetInvalidError, match="metadata"):
        assert_wan_target_policy("fqdn", "metadata.google.internal")
    assert_wan_target_policy("cidr", "203.0.113.0/24")
    assert_wan_target_policy("cidr", "1.2.0.0/16")
    assert_wan_target_policy("cidr", "2001:db8::/112")


def test_resolved_ipv4_compatible_address_is_rejected():
    import ipaddress

    from app.wan_targets import WanTargetInvalidError, assert_wan_address_policy

    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_address_policy(ipaddress.ip_address("::8.8.8.8"))
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_address_policy(ipaddress.ip_address("::ffff:8.8.8.8"))
    with pytest.raises(WanTargetInvalidError, match="IPv4-mapped"):
        assert_wan_address_policy(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert_wan_address_policy(ipaddress.ip_address("203.0.113.25"))
    assert_wan_address_policy(ipaddress.ip_address("2001:db8::1"))


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
def test_malformed_nuclei_jsonl_cannot_count_clean(reset_db, monkeypatch):
    import sys

    runtime_root = REPO_ROOT / "scan_runtime"
    if str(runtime_root) not in sys.path:
        sys.path.insert(0, str(runtime_root))
    import runner as runtime_runner
    from job_finish import finish_pipeline_run
    from tests.test_phase2a import _run_detected, _start_lan

    def fake_run(cmd, dest, log=None):
        dest.write_text('{not-json "template-id":"exposed-panel"\n', encoding="utf-8")

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei" if name == "nuclei" else None)
    monkeypatch.setattr(runtime_runner, "_pd_httpx", lambda: None)
    monkeypatch.setattr(runtime_runner, "collect_run_provenance", lambda **kwargs: {"runtime_version": "test"})
    monkeypatch.setattr(runtime_runner, "collect_runtime_inventory", lambda **kwargs: {"runtime_version": "test"})

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan, _first, _ = _run_detected(client, token, world, hostname="edge-1", ip="203.0.113.10")
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        with pytest.raises(runtime_runner.PipelineError) as exc:
            runtime_runner.run_pipeline(
                {
                    "scope": "lan",
                    "targets": [{"type": "ip", "value": "203.0.113.10"}],
                    "stages": {
                        "discovery": False,
                        "port_mode": "none",
                        "fingerprint": True,
                        "vulnerability": True,
                        "nuclei_severities": "critical,high,medium",
                        "nuclei_tags": "",
                    },
                    "intensity": {},
                    "exclusions": [],
                }
            )
        result = exc.value.as_result()
        assert result["detector_coverage"] == []
        assert result["findings"] == []
        assert "malformed JSONL" in str(exc.value)

        headers = _agent_headers(world["agent1"])
        posted_coverage: list[dict] = []
        completes: list[tuple] = []

        def coverage_fn(payload):
            posted_coverage.append(payload)
            return client.post(
                f"/api/agent/jobs/{job_id}/detector-coverage",
                headers=headers,
                json=payload,
            )

        def complete(ok, error=None, raw_evidence=None):
            posted = client.post(
                f"/api/agent/jobs/{job_id}/complete",
                headers=headers,
                params={"ok": "true" if ok else "false", "error": error or ""},
                json=raw_evidence,
            )
            completes.append((ok, posted.status_code, posted.text))
            assert posted.status_code == 200, posted.text

        finish_pipeline_run(
            result=result,
            upload=lambda _artifact: None,
            complete=complete,
            coverage_fn=coverage_fn,
            findings_fn=lambda findings: client.post(
                f"/api/agent/jobs/{job_id}/findings",
                headers=headers,
                json=findings,
            ),
            pipeline_error=str(exc.value),
        )
        assert posted_coverage == []
        assert completes and completes[0][0] is False

        from app.database import SessionLocal
        from app.models import (
            EVALUATION_CLEAN,
            AssetFinding,
            AssetFindingRunEvaluation,
            ScanJob,
            ScanRunDetectorCoverage,
        )

        db = SessionLocal()
        try:
            finding = db.query(AssetFinding).one()
            assert finding.technical_state == "open"
            assert finding.consecutive_clean_scans == 0
            assert (
                db.query(AssetFindingRunEvaluation)
                .filter(AssetFindingRunEvaluation.outcome == EVALUATION_CLEAN)
                .count()
                == 0
            )
            assert (
                db.query(ScanRunDetectorCoverage)
                .filter(ScanRunDetectorCoverage.scan_job_id == job_id)
                .count()
                == 0
            )
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "failed"
        finally:
            db.close()


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
        from app.models import Setting
        from app.settings_crypto import is_encrypted_secret
        from app.settings_store import get_settings

        db = SessionLocal()
        try:
            stored = get_settings(db)
            assert stored["smtp_password"] == "smtp-super-secret"
            assert "smtp_password_configured" not in stored
            raw = db.query(Setting).filter(Setting.key == "system").one().value
            assert is_encrypted_secret(raw["smtp_password"])
            assert "smtp-super-secret" not in raw["smtp_password"]
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
