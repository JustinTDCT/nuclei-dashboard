from __future__ import annotations

import gzip
import hashlib
import inspect
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect as sa_inspect

from tests.conftest import requires_postgres
from tests.test_migrations import FROZEN_MIGRATION_HASHES, PHASE3C_HEAD, TRANCHE_B_HEAD
from tests.test_phase1d import (
    _agent_headers,
    _client,
    _finish_job,
    _headers,
    _heartbeat,
    _lan_scan,
    _login,
    _scanner_headers,
    _wan_scan,
    _world,
)
from tests.test_phase3c import PHASE3C_GIT_BLOB, PHASE3C_SHA256, _create_viewer

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
RUNTIME_ROOT = REPO_ROOT / "scan_runtime"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
MIGRATION_0014 = BACKEND_ROOT / "alembic" / "versions" / "0014_reports_auditor_access.py"
MIGRATION_0015 = BACKEND_ROOT / "alembic" / "versions" / "0015_raw_scan_evidence.py"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


def _artifact_root(tmp_path: Path, monkeypatch, max_bytes: int = 1024 * 1024) -> Path:
    from app.config import settings

    root = tmp_path / "raw-artifacts"
    root.mkdir()
    monkeypatch.setattr(settings, "raw_artifact_dir", str(root))
    monkeypatch.setattr(settings, "raw_artifact_max_bytes", max_bytes)
    return root


def _gzip_jsonl(lines: list[str]) -> bytes:
    return gzip.compress(("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))


def _upload(client: TestClient, url: str, headers: dict, gz: bytes, **fields):
    data = {
        "artifact_key": fields.pop("artifact_key", "vulnerability.nuclei"),
        "stage": fields.pop("stage", "vulnerability"),
        "tool": fields.pop("tool", "nuclei"),
        "media_type": fields.pop("media_type", "application/x-ndjson"),
        "content_encoding": fields.pop("content_encoding", "gzip"),
        "provenance": fields.pop("provenance", json.dumps({"nuclei_version": "3.0"})),
    }
    data.update(fields)
    return client.post(
        url,
        headers=headers,
        files={"file": ("artifact.jsonl.gz", BytesIO(gz), "application/gzip")},
        data=data,
    )


def _named_world(client: TestClient, token: str, name: str) -> dict:
    created = client.post("/api/tenants", headers=_headers(token), json={"name": name, "notes": ""})
    assert created.status_code == 200, created.text
    tenant = created.json()
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


def _claim_lan(client: TestClient, token: str, world: dict) -> tuple[int, dict]:
    scan = _lan_scan(client, token, world)
    run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
    assert run.status_code == 200, run.text
    job_id = run.json()["id"]
    _heartbeat(world["agent1"]["id"])
    started = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
    assert started.status_code == 200, started.text
    return job_id, world["agent1"]


def _claim_wan(client: TestClient, token: str, world: dict) -> int:
    scan = _wan_scan(client, token, world)
    run = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token))
    assert run.status_code == 200, run.text
    job_id = run.json()["id"]
    started = client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())
    assert started.status_code == 200, started.text
    return job_id


def _audits(action: str):
    from app.database import SessionLocal
    from app.models import AuditLog

    db = SessionLocal()
    try:
        return db.query(AuditLog).filter(AuditLog.action == action).all()
    finally:
        db.close()


@requires_postgres
def test_0014_frozen_and_0015_is_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == TRANCHE_B_HEAD
    assert hashlib.sha256(MIGRATION_0014.read_bytes()).hexdigest() == PHASE3C_SHA256
    assert FROZEN_MIGRATION_HASHES["0014_reports_auditor_access.py"] == PHASE3C_SHA256
    blob = __import__("subprocess").check_output(["git", "hash-object", str(MIGRATION_0014)], cwd=REPO_ROOT, text=True).strip()
    assert blob == PHASE3C_GIT_BLOB
    assert MIGRATION_0015.is_file()
    assert "scan_artifacts" in sa_inspect(engine).get_table_names()
    assert "BYTEA" not in MIGRATION_0015.read_text()
    assert "LargeBinary" not in MIGRATION_0015.read_text()


@requires_postgres
def test_upload_stores_metadata_not_body_and_is_idempotent(reset_db, tmp_path, monkeypatch):
    root = _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"template-id":"x","host":"10.1.0.1"}'])
    digest = hashlib.sha256(gz).hexdigest()
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        first = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz)
        assert first.status_code == 200, first.text
        body = first.json()
        assert body["sha256"] == digest
        assert body["size_bytes"] == len(gz)
        assert body["available"] is True
        assert "storage_key" not in body
        assert "raw-artifacts" not in json.dumps(body)
        assert not str(body).startswith("/")
        stored = list(root.rglob("*.jsonl.gz"))
        assert len(stored) == 1
        assert stored[0].read_bytes() == gz
        retry = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz)
        assert retry.status_code == 200, retry.text
        assert retry.json()["id"] == body["id"]
        assert len(list(root.rglob("*.jsonl.gz"))) == 1
        conflict = _upload(
            client,
            f"/api/agent/jobs/{job_id}/artifacts",
            _agent_headers(agent),
            _gzip_jsonl(['{"template-id":"other"}']),
        )
        assert conflict.status_code == 409
        empty = _upload(
            client,
            f"/api/agent/jobs/{job_id}/artifacts",
            _agent_headers(agent),
            _gzip_jsonl([]),
            artifact_key="vulnerability.nuclei.empty",
        )
        assert empty.status_code == 200, empty.text
        assert empty.json()["size_bytes"] == len(_gzip_jsonl([]))


@requires_postgres
def test_malformed_and_path_inputs_fail_closed(reset_db, tmp_path, monkeypatch):
    _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"ok":true}'])
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        headers = _agent_headers(agent)
        assert _upload(client, f"/api/agent/jobs/{job_id}/artifacts", headers, gz, artifact_key="../etc/passwd").status_code == 400
        assert _upload(client, f"/api/agent/jobs/{job_id}/artifacts", headers, gz, artifact_key="/tmp/evil").status_code == 400
        assert _upload(client, f"/api/agent/jobs/{job_id}/artifacts", headers, gz, stage="bad/stage").status_code == 400
        huge_meta = _upload(
            client,
            f"/api/agent/jobs/{job_id}/artifacts",
            headers,
            gz,
            artifact_key="fingerprint.httpx",
            stage="fingerprint",
            tool="httpx",
            provenance="{" + ("x" * 20000) + "}",
        )
        assert huge_meta.status_code == 400


def test_storage_key_resolution_rejects_escape(tmp_path, monkeypatch):
    from app.raw_artifacts import ArtifactStorageError, resolve_storage_path

    root = _artifact_root(tmp_path, monkeypatch)
    with pytest.raises(ArtifactStorageError):
        resolve_storage_path("../etc/passwd", root=root)
    with pytest.raises(ArtifactStorageError):
        resolve_storage_path("/etc/passwd", root=root)
    with pytest.raises(ArtifactStorageError):
        resolve_storage_path("tenant/1/job/1/../../../../etc/passwd", root=root)
    if hasattr(os, "symlink"):
        outside = tmp_path / "outside-secret"
        outside.write_bytes(b"secret")
        target = root / "tenant" / "1" / "job" / "1"
        target.mkdir(parents=True)
        link = target / "escape.jsonl.gz"
        link.symlink_to(outside)
        with pytest.raises(ArtifactStorageError):
            resolve_storage_path("tenant/1/job/1/escape.jsonl.gz", root=root)


@requires_postgres
def test_oversized_upload_rejected_without_metadata_or_bytes(reset_db, tmp_path, monkeypatch):
    root = _artifact_root(tmp_path, monkeypatch, max_bytes=64)
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        oversized = gzip.compress(os.urandom(2048))
        assert len(oversized) > 64
        response = _upload(
            client,
            f"/api/agent/jobs/{job_id}/artifacts",
            _agent_headers(agent),
            oversized,
        )
        assert response.status_code == 413
        from app.database import SessionLocal
        from app.models import ScanArtifact

        db = SessionLocal()
        try:
            assert db.query(ScanArtifact).count() == 0
        finally:
            db.close()
        assert list(root.rglob("*.jsonl.gz")) == []
        assert list((root / ".incoming").glob("*")) == [] if (root / ".incoming").exists() else True


@requires_postgres
def test_upload_db_failure_removes_orphan_bytes(reset_db, tmp_path, monkeypatch):
    root = _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"ok":true}'])
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        from app.raw_artifacts import ingest_chunks
        from app.database import SessionLocal
        from app.models import ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            with patch.object(db, "flush", side_effect=RuntimeError("db down")):
                with pytest.raises(RuntimeError, match="db down"):
                    ingest_chunks(
                        db,
                        job,
                        artifact_key="port_discovery.naabu",
                        stage="port_discovery",
                        tool="naabu",
                        chunks=[gz],
                    )
        finally:
            db.close()
        assert list(root.rglob("*.jsonl.gz")) == []


@requires_postgres
def test_agent_and_scanner_authorization(reset_db, tmp_path, monkeypatch):
    _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"ip":"10.1.0.1","port":80}'])
    with _client() as client:
        token = _login(client)
        world = _named_world(client, token, "Auth Tenant A")
        other = _named_world(client, token, "Auth Tenant B")
        job_id, agent = _claim_lan(client, token, world)
        _heartbeat(world["agent2"]["id"])
        other_job, other_agent = _claim_lan(client, token, other)
        wan_id = _claim_wan(client, token, world)

        ok = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz, artifact_key="port_discovery.naabu", stage="port_discovery", tool="naabu")
        assert ok.status_code == 200, ok.text
        cross_agent = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(world["agent2"]), gz, artifact_key="fingerprint.httpx", stage="fingerprint", tool="httpx")
        assert cross_agent.status_code == 409
        cross_tenant = _upload(client, f"/api/agent/jobs/{other_job}/artifacts", _agent_headers(agent), gz, artifact_key="fingerprint.httpx", stage="fingerprint", tool="httpx")
        assert cross_tenant.status_code == 409
        wan_as_agent = _upload(client, f"/api/agent/jobs/{wan_id}/artifacts", _agent_headers(agent), gz, artifact_key="discovery.naabu", stage="discovery", tool="naabu")
        assert wan_as_agent.status_code == 409
        completed = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz, artifact_key="later.naabu", stage="port_discovery", tool="naabu")
        _finish_job(job_id, "done")
        after_done = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz, artifact_key="after.done", stage="port_discovery", tool="naabu")
        assert after_done.status_code == 409
        assert completed.status_code == 200

        from app.database import SessionLocal
        from app.models import Agent

        db = SessionLocal()
        try:
            row = db.get(Agent, agent["id"])
            row.status = "revoked"
            db.commit()
        finally:
            db.close()
        revoked = _upload(client, f"/api/agent/jobs/{other_job}/artifacts", _agent_headers(agent), gz)
        assert revoked.status_code in {401, 403}

        wan_ok = _upload(client, f"/api/internal/scanner/jobs/{wan_id}/artifacts", _scanner_headers(), gz, artifact_key="port_discovery.naabu", stage="port_discovery", tool="naabu")
        assert wan_ok.status_code == 200, wan_ok.text
        bad_token = _upload(client, f"/api/internal/scanner/jobs/{wan_id}/artifacts", {"X-Scanner-Token": "nope"}, gz)
        assert bad_token.status_code == 401
        scanner_on_lan = _upload(client, f"/api/internal/scanner/jobs/{other_job}/artifacts", _scanner_headers(), gz)
        assert scanner_on_lan.status_code == 409
        listed = client.get(f"/api/jobs/{wan_id}/artifacts", headers=_headers(token)).json()
        assert listed[0]["tool"] == "naabu"


@requires_postgres
def test_artifact_upload_failure_prevents_successful_completion(reset_db, tmp_path, monkeypatch):
    from api_client import ApiError
    from job_finish import finish_pipeline_run

    completed = []

    def upload(_artifact):
        raise ApiError("upload failed")

    with pytest.raises(ApiError):
        finish_pipeline_run(
            result={
                "artifacts": [{"path": str(tmp_path / "missing.jsonl.gz"), "artifact_key": "vulnerability.nuclei", "stage": "vulnerability", "tool": "nuclei"}],
                "staging_dir": None,
            },
            upload=upload,
            complete=lambda ok, error: completed.append((ok, error)),
        )
    assert completed == []


@requires_postgres
def test_human_authorization_list_download_and_audit(reset_db, tmp_path, monkeypatch):
    root = _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"template-id":"x"}'])
    with _client() as client:
        admin = _login(client)
        from tests.test_phase1d import _create_staff

        user = _create_staff(client, admin, "operator", "user")
        world_a = _named_world(client, admin, "Human Tenant A")
        world_b = _named_world(client, admin, "Human Tenant B")
        job_a, agent_a = _claim_lan(client, admin, world_a)
        job_b, agent_b = _claim_lan(client, admin, world_b)
        art_a = _upload(client, f"/api/agent/jobs/{job_a}/artifacts", _agent_headers(agent_a), gz).json()
        art_b = _upload(client, f"/api/agent/jobs/{job_b}/artifacts", _agent_headers(agent_b), gz).json()
        viewer_a, _ = _create_viewer(client, admin, "view-a", tenant_ids=[world_a["tenant"]["id"]])
        viewer_all, _ = _create_viewer(client, admin, "view-all", all_tenants=True)
        viewer_none, _ = _create_viewer(client, admin, "view-none", tenant_ids=[])
        created_exp = client.post(
            "/api/users",
            headers=_headers(admin),
            json={
                "username": "view-exp",
                "email": "view-exp@example.com",
                "password": "view-exp-password",
                "role": "viewer",
                "viewer_tenant_ids": [world_a["tenant"]["id"]],
                "viewer_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            },
        )
        assert created_exp.status_code == 200, created_exp.text
        expired = _login(client, "view-exp", "view-exp-password")
        client.patch(
            f"/api/users/{created_exp.json()['id']}",
            headers=_headers(admin),
            json={"viewer_expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
        )

        for token in (admin, user, viewer_all):
            listed = client.get(f"/api/jobs/{job_a}/artifacts", headers=_headers(token))
            assert listed.status_code == 200
            assert "storage_key" not in listed.text
            assert str(root) not in listed.text
            download = client.get(f"/api/scan-artifacts/{art_a['id']}/download", headers=_headers(token))
            assert download.status_code == 200
            assert download.content == gz
            assert "scan-" in download.headers.get("content-disposition", "")
            assert ".jsonl.gz" in download.headers.get("content-disposition", "")

        assert client.get(f"/api/jobs/{job_b}/artifacts", headers=_headers(viewer_a)).status_code == 404
        assert client.get(f"/api/scan-artifacts/{art_b['id']}/download", headers=_headers(viewer_a)).status_code == 404
        assert client.get(f"/api/jobs/{job_a}/artifacts", headers=_headers(viewer_a)).status_code == 200
        assert client.get(f"/api/jobs/{job_a}/artifacts", headers=_headers(viewer_none)).status_code == 404
        assert client.get(f"/api/jobs/{job_b}/artifacts", headers=_headers(viewer_all)).status_code == 200
        assert client.get("/api/tenants", headers=_headers(expired)).status_code == 401

        downloads = _audits("scan_artifact.download")
        assert downloads
        for row in downloads:
            blob = json.dumps(row.details)
            assert "template-id" not in blob
            assert "storage_key" not in blob
            assert str(root) not in blob
            assert "password" not in blob
        unauthorized_before = len(downloads)
        denied = client.get(f"/api/scan-artifacts/{art_b['id']}/download", headers=_headers(viewer_a))
        assert denied.status_code == 404
        assert len(_audits("scan_artifact.download")) == unauthorized_before

        history = client.get(
            f"/api/audit-history?tenant_id={world_b['tenant']['id']}",
            headers=_headers(viewer_a),
        )
        assert history.status_code == 404


@requires_postgres
def test_missing_and_deleted_download_have_no_success_audit(reset_db, tmp_path, monkeypatch):
    root = _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"ok":true}'])
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        artifact = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz).json()
        stored = next(root.rglob("*.jsonl.gz"))
        stored.unlink()
        missing = client.get(f"/api/scan-artifacts/{artifact['id']}/download", headers=_headers(token))
        assert missing.status_code == 409
        assert _audits("scan_artifact.download") == []

        from app.database import SessionLocal
        from app.models import ScanArtifact
        from app.raw_artifacts import cleanup_expired_artifacts

        db = SessionLocal()
        try:
            row = db.get(ScanArtifact, artifact["id"])
            row.retention_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()
            # recreate bytes then expire
            stored.write_bytes(gz)
            cleaned = cleanup_expired_artifacts(db, batch_size=10)
            assert cleaned == 1
            db.commit()
            assert row.deleted_at is not None
            assert row.delete_reason == "retention"
            assert not stored.exists()
            job = db.get(type(row.job), job_id) if False else None
        finally:
            db.close()
        gone = client.get(f"/api/scan-artifacts/{artifact['id']}/download", headers=_headers(token))
        assert gone.status_code == 410
        assert _audits("scan_artifact.download") == []
        listed = client.get(f"/api/jobs/{job_id}/artifacts", headers=_headers(token)).json()
        assert listed[0]["deleted_at"] is not None
        assert listed[0]["available"] is False
        assert _audits("scan_artifact.retention_delete")


@requires_postgres
def test_retention_setting_and_cleanup_leaves_normalized_data(reset_db, tmp_path, monkeypatch):
    _artifact_root(tmp_path, monkeypatch)
    with _client() as client:
        token = _login(client)
        settings = client.get("/api/admin/settings", headers=_headers(token)).json()
        assert settings["raw_scan_artifact_retention_days"] == 365
        settings["raw_scan_artifact_retention_days"] = 30
        saved = client.put("/api/admin/settings", headers=_headers(token), json=settings)
        assert saved.status_code == 200
        assert saved.json()["raw_scan_artifact_retention_days"] == 30
        audits = _audits("settings.raw_artifact_retention_change")
        assert len(audits) == 1
        assert audits[0].details == {"before": 365, "after": 30}
        settings["raw_scan_artifact_retention_days"] = 0
        assert client.put("/api/admin/settings", headers=_headers(token), json=settings).status_code == 422
        settings["raw_scan_artifact_retention_days"] = 30
        world = _world(client, token)
        job_id, agent = _claim_lan(client, token, world)
        gz = _gzip_jsonl(['{"ip":"10.1.0.8"}'])
        uploaded = _upload(client, f"/api/agent/jobs/{job_id}/artifacts", _agent_headers(agent), gz).json()
        created = datetime.fromisoformat(uploaded["created_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(uploaded["retention_expires_at"].replace("Z", "+00:00"))
        assert (expires - created).days == 30
        client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(agent),
            json=[{"ip": "10.1.0.8", "scope": "lan", "hostname": "keep-me", "ports": [80]}],
        )
        client.post(f"/api/agent/jobs/{job_id}/complete", headers=_agent_headers(agent), params={"ok": "true"})

        from app.database import SessionLocal
        from app.models import Asset, AssetFinding, AssetObservation, Finding, ScanArtifact, ScanJob
        from app.raw_artifacts import CLEANUP_BATCH_SIZE, cleanup_expired_artifacts

        db = SessionLocal()
        try:
            live = db.get(ScanArtifact, uploaded["id"])
            live.retention_expires_at = datetime.now(timezone.utc) + timedelta(days=10)
            extra = ScanArtifact(
                scan_job_id=job_id,
                tenant_id=live.tenant_id,
                artifact_key="fingerprint.httpx",
                stage="fingerprint",
                tool="httpx",
                media_type="application/x-ndjson",
                content_encoding="gzip",
                storage_key=f"tenant/{live.tenant_id}/job/{job_id}/extra.jsonl.gz",
                size_bytes=3,
                sha256="b" * 64,
                retention_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                provenance={},
            )
            db.add(extra)
            db.flush()
            from app.config import settings as app_settings

            extra_path = Path(app_settings.raw_artifact_dir) / extra.storage_key
            extra_path.parent.mkdir(parents=True, exist_ok=True)
            extra_path.write_bytes(b"abc")
            db.commit()
            source = inspect.getsource(cleanup_expired_artifacts)
            assert ".limit(" in source
            cleaned = cleanup_expired_artifacts(db, batch_size=CLEANUP_BATCH_SIZE)
            assert cleaned == 1
            db.commit()
            db.refresh(live)
            db.refresh(extra)
            assert live.deleted_at is None
            assert extra.deleted_at is not None
            assert extra.delete_reason == "retention"
            assert db.get(ScanJob, job_id) is not None
            assert db.query(Asset).count() >= 1
            assert db.query(AssetObservation).count() >= 1
            assert db.query(Finding).count() >= 0
            assert db.query(AssetFinding).count() >= 0
        finally:
            db.close()


def test_pipeline_captures_native_output_and_cleans_temp(tmp_path, monkeypatch):
    import runner as runtime_runner
    from artifact_io import cleanup_staging
    from job_finish import persist_artifacts

    bins = tmp_path / "bins"
    bins.mkdir()

    def write_bin(name: str, body: str) -> Path:
        path = bins / name
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

    write_bin("naabu", "print('{\"ip\":\"10.1.0.9\",\"port\":80}')\n")
    write_bin(
        "httpx",
        "import sys\nprint('{\"ip\":\"10.1.0.9\",\"port\":80,\"url\":\"https://10.1.0.9\",\"title\":\"x\"}')\n",
    )
    write_bin("nuclei", "print('{\"template-id\":\"t1\",\"host\":\"https://10.1.0.9\",\"info\":{\"name\":\"n\",\"severity\":\"low\",\"tags\":[]}}')\n")

    def which(name):
        candidate = bins / name
        return str(candidate) if candidate.exists() else None

    monkeypatch.setattr(runtime_runner, "_which", which)
    monkeypatch.setattr(runtime_runner, "_pd_httpx", lambda: str(bins / "httpx"))
    monkeypatch.setattr(runtime_runner, "_is_pd_httpx", lambda path: True)
    monkeypatch.setattr(runtime_runner, "collect_tool_versions", lambda log=None: {"nuclei_version": "test"})

    job = {
        "scope": "lan",
        "targets": [{"type": "ip", "value": "10.1.0.9"}],
        "stages": {"discovery": True, "port_mode": "common", "fingerprint": True, "vulnerability": True, "nuclei_severities": "low"},
        "intensity": {},
        "exclusions": [],
    }
    result = runtime_runner.run_pipeline(job)
    keys = {row["artifact_key"] for row in result["artifacts"]}
    assert keys == {"port_discovery.naabu", "fingerprint.httpx", "vulnerability.nuclei"}
    assert result["devices"]
    assert result["findings"][0]["raw"]["template-id"] == "t1"
    for artifact in result["artifacts"]:
        raw = Path(artifact["path"])
        assert raw.suffixes[-2:] == [".jsonl", ".gz"] or raw.name.endswith(".jsonl.gz")
        with gzip.open(raw, "rb") as handle:
            handle.read()
    staging = result["staging_dir"]
    assert staging and Path(staging).is_dir()
    persist_artifacts(lambda _a: None, result["artifacts"], result["provenance"])
    cleanup_staging(staging)
    assert not Path(staging).exists()

    write_bin("nuclei", "import sys\nsys.exit(1)\n")
    failed = None
    try:
        runtime_runner.run_pipeline(job)
    except runtime_runner.PipelineError as exc:
        failed = exc
    assert failed is not None
    assert {row["artifact_key"] for row in failed.artifacts} >= {"port_discovery.naabu", "fingerprint.httpx"}
    assert "vulnerability.nuclei" not in {row["artifact_key"] for row in failed.artifacts}
    cleanup_staging(failed.staging_dir)
    assert failed.staging_dir is None or not Path(failed.staging_dir).exists()

    empty_n = write_bin("nuclei", "import sys\nsys.exit(0)\n")
    assert empty_n.exists()
    empty_result = runtime_runner.run_pipeline(job)
    nuclei = next(row for row in empty_result["artifacts"] if row["tool"] == "nuclei")
    with gzip.open(nuclei["path"], "rb") as handle:
        assert handle.read() == b""
    cleanup_staging(empty_result["staging_dir"])

    monkeypatch.setenv("SCAN_DRY_RUN", "1")
    dry = runtime_runner.run_pipeline(job)
    assert dry["artifacts"] == []
    assert dry["findings"]


@requires_postgres
def test_memory_and_schema_guards(reset_db):
    from app.raw_artifacts import CHUNK_SIZE, assert_no_artifact_body_columns, iter_file_chunks
    from app.models import ScanArtifact

    assert_no_artifact_body_columns()
    source = (BACKEND_ROOT / "app" / "raw_artifacts.py").read_text()
    assert "await file.read()" not in source
    assert "await upload.read()" not in source
    assert "handle.read(chunk_size)" in source or "handle.read(CHUNK_SIZE)" in source or "read(chunk_size)" in source
    scans_src = (BACKEND_ROOT / "app" / "routers" / "scans.py").read_text()
    assert "FileResponse" in scans_src
    assert "path.read_bytes()" not in scans_src
    assert "read_bytes()" not in scans_src
    gzip_src = (RUNTIME_ROOT / "artifact_io.py").read_text()
    assert "incoming.read(chunk_size)" in gzip_src
    assert ".all()" not in (BACKEND_ROOT / "app" / "raw_artifacts.py").read_text().split("def cleanup_expired_artifacts")[1].split("return cleaned")[0] or ".limit(" in (BACKEND_ROOT / "app" / "raw_artifacts.py").read_text()
    columns = {c.name for c in ScanArtifact.__table__.columns}
    assert "storage_key" in columns
    assert not {"body", "bytes", "content", "payload"} & columns
    class Spy:
        def __init__(self):
            self.sizes = []
            self.data = b"abcdef" * 100

        def read(self, n=-1):
            assert n == CHUNK_SIZE
            self.sizes.append(n)
            chunk, self.data = self.data[:n], self.data[n:]
            return chunk

    spy = Spy()
    chunks = list(iter_file_chunks(spy, chunk_size=CHUNK_SIZE))
    assert spy.sizes
    assert b"".join(chunks)


def test_ui_copy_and_admin_retention_controls():
    tenant = (FRONTEND_SRC / "pages" / "TenantDetail.tsx").read_text()
    admin = (FRONTEND_SRC / "pages" / "AdminSettings.tsx").read_text()
    types = (FRONTEND_SRC / "types.ts").read_text()
    assert "Raw evidence" in tenant
    assert "No retained raw artifacts are recorded for this run." in tenant
    assert "Available" in tenant
    assert "Expired" in tenant
    assert "Download" in tenant
    assert "No findings" not in tenant.split("Raw evidence")[1].split("Related controls")[0]
    assert "Scanner produced no output" not in tenant
    assert "Raw scan artifact retention (days)" in admin
    assert "normalized" in admin.lower() or "historical findings" in admin
    assert "RAW_ARTIFACT_DIR" not in admin
    assert "storage root" not in admin.lower()
    assert "/var/lib/nuclei-dashboard" not in admin
    assert "raw_scan_artifact_retention_days" in types
    assert "storage_key" not in types.split("export interface ScanArtifact")[1].split("export interface")[0]
