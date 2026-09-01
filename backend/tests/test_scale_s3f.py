"""S3F: replica-readiness inventory and two-API process gate."""

from __future__ import annotations

import inspect
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import requires_postgres
from tests.test_phase1d import _agent_headers, _headers, _heartbeat, _login, _scanner_headers, _world
from tests.test_tranche_b import _claim_lan, _claim_wan, _gzip_jsonl, _upload

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
PINNED_AGENT = "3cdb52c42a87552db98e609e9ec7c1c01e86b23b"


def test_s3f_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_agent_pin_unchanged():
    from app.agent_source import PINNED_AGENT_GIT_COMMIT

    assert PINNED_AGENT_GIT_COMMIT == PINNED_AGENT
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    assert PINNED_AGENT in compose


def test_auth_and_challenges_are_postgresql_not_process_local():
    from app import agent_challenges, auth_throttle

    throttle_src = inspect.getsource(auth_throttle)
    assert "AuthThrottle" in throttle_src
    assert ".with_for_update()" in throttle_src
    assert "insert(" in throttle_src
    challenge_src = inspect.getsource(agent_challenges)
    assert "AgentChallenge" in challenge_src
    assert ".with_for_update()" in challenge_src
    assert "consumed_at" in challenge_src


def test_discovery_catchup_cursor_is_scheduler_process_local():
    scheduler = (BACKEND_ROOT / "app" / "scheduler.py").read_text()
    assert "_discovery_metadata_after_id" in scheduler
    assert "_discovery_metadata_after_id" not in (BACKEND_ROOT / "app" / "main.py").read_text()
    assert "_discovery_metadata_after_id" not in (BACKEND_ROOT / "app" / "bootstrap.py").read_text()


def test_policy_and_ingest_caches_are_request_scoped():
    from app import finding_ingest, scan_ingest
    from app.policy import PolicyResolver

    assert "Do not reuse across requests" in inspect.getsource(PolicyResolver)
    assert "Per-scan-job write-through cache" in (inspect.getdoc(scan_ingest) or "")
    assert "Per-run write-through index" in (inspect.getdoc(finding_ingest) or "")


def test_export_spool_is_not_artifact_storage():
    from app.reporting import csv_export, pdf_export

    csv_src = inspect.getsource(csv_export)
    pdf_src = inspect.getsource(pdf_export)
    assert "SpooledTemporaryFile" in csv_src
    assert "SpooledTemporaryFile" in pdf_src
    assert "raw_artifact" not in csv_src
    assert "raw_artifact" not in pdf_src


def test_api_bootstrap_lock_is_not_scheduler_lock():
    from app.bootstrap import API_BOOTSTRAP_LOCK_KEY, run_api_bootstrap
    from app.main import lifespan
    from app.scheduler import SCHEDULER_LEADER_LOCK_KEY

    assert API_BOOTSTRAP_LOCK_KEY != SCHEDULER_LEADER_LOCK_KEY
    src = inspect.getsource(run_api_bootstrap)
    assert "pg_advisory_lock" in src
    assert "create_engine" in src
    assert "prepare_control_plane" in src
    lifespan_src = inspect.getsource(lifespan)
    assert "run_api_bootstrap" in lifespan_src
    assert "apply_schema()" not in lifespan_src


def test_compose_shares_artifacts_and_keeps_one_scheduler():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    artifact_mount = "scan-artifacts:/var/lib/nuclei-dashboard/raw-artifacts"
    assert compose.count(artifact_mount) >= 2
    assert "agent-keys:" in compose
    assert "scan-artifacts:/data" not in compose
    assert 'command: ["python", "-m", "app.scheduler_process"]' in compose
    assert compose.count("app.scheduler_process") == 1
    assert "Do not `docker compose up --scale scheduler=2`" in compose
    assert "--scale api=2" in compose
    assert "CENTRAL_URL: http://api:8000" in compose
    dockerfile = (BACKEND_ROOT / "Dockerfile").read_text()
    assert "uvicorn" in dockerfile
    assert "scheduler_process" not in dockerfile


def test_caddy_resolves_api_replicas_and_hides_internal():
    caddy = (REPO_ROOT / "Caddyfile").read_text()
    assert "handle /api/internal*" in caddy
    assert 'respond "Not Found" 404' in caddy
    assert "dynamic a api 8000" in caddy
    assert "lb_policy round_robin" in caddy
    assert "lb_try_duration" in caddy
    assert "health_uri /api/health" in caddy
    assert "fail_duration" in caddy
    assert "reverse_proxy api:8000" not in caddy


def test_settings_are_read_from_postgres():
    from app.settings_store import get_settings

    src = inspect.getsource(get_settings)
    assert "Setting" in src
    assert "lru_cache" not in src


@requires_postgres
def test_concurrent_bootstrap_creates_one_admin(reset_db):
    from app.bootstrap import run_api_bootstrap
    from app.database import SessionLocal
    from app.models import User

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_api_bootstrap)
        second = pool.submit(run_api_bootstrap)
        first.result()
        second.result()

    db = SessionLocal()
    try:
        assert db.query(User).filter(User.username == "admin").count() == 1
    finally:
        db.close()


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _wait_health(port: int, proc: subprocess.Popen, log_path: Path, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    url = f"http://127.0.0.1:{port}/api/health"
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"API replica on {port} exited {proc.returncode}: {log_path.read_text(errors='replace')[-4000:]}"
            )
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = exc
            time.sleep(0.2)
    raise RuntimeError(
        f"API replica on {port} not healthy ({last}): {log_path.read_text(errors='replace')[-4000:]}"
    )


@contextmanager
def two_api_replicas() -> Iterator[tuple[httpx.Client, httpx.Client]]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUNBUFFERED"] = "1"
    procs: list[tuple[subprocess.Popen, Path, object, int]] = []
    clients: list[httpx.Client] = []
    try:
        for _ in range(2):
            fd, name = tempfile.mkstemp(prefix="s3f-api-", suffix=".log")
            log_path = Path(name)
            handle = os.fdopen(fd, "wb")
            port = _free_port()
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                cwd=str(BACKEND_ROOT),
                env=env,
                stdout=handle,
                stderr=subprocess.STDOUT,
            )
            procs.append((proc, log_path, handle, port))
        for proc, log_path, _handle, port in procs:
            _wait_health(port, proc, log_path)
        clients = [
            httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30.0) for _proc, _log, _handle, port in procs
        ]
        yield clients[0], clients[1]
    finally:
        for client in clients:
            client.close()
        for proc, log_path, handle, _port in procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            handle.close()
            log_path.unlink(missing_ok=True)


@requires_postgres
def test_two_api_processes_share_auth_writes_and_artifacts(reset_db):
    from app.database import SessionLocal
    from app.models import Agent

    gz = _gzip_jsonl(['{"ip":"10.1.0.1","port":80}'])
    with two_api_replicas() as (replica_a, replica_b):
        token = _login(replica_a)
        me = replica_b.get("/api/auth/me", headers=_headers(token))
        assert me.status_code == 200, me.text
        assert me.json()["username"] == "admin"

        created = replica_a.post(
            "/api/tenants",
            headers=_headers(token),
            json={"name": "S3F Replica Write", "notes": "from-a"},
        )
        assert created.status_code == 200, created.text
        tenant_id = created.json()["id"]
        seen = replica_b.get(f"/api/tenants/{tenant_id}", headers=_headers(token))
        assert seen.status_code == 200, seen.text
        assert seen.json()["notes"] == "from-a"
        patched = replica_b.patch(
            f"/api/tenants/{tenant_id}",
            headers=_headers(token),
            json={"name": "S3F Replica Write", "notes": "from-b"},
        )
        assert patched.status_code == 200, patched.text
        reread = replica_a.get(f"/api/tenants/{tenant_id}", headers=_headers(token))
        assert reread.json()["notes"] == "from-b"

        poll_a = replica_a.get("/api/internal/scanner/jobs", headers=_scanner_headers())
        poll_b = replica_b.get("/api/internal/scanner/jobs", headers=_scanner_headers())
        assert poll_a.status_code == 200, poll_a.text
        assert poll_b.status_code == 200, poll_b.text

        world = _world(replica_a, token)
        job_id, agent = _claim_lan(replica_a, token, world)
        uploaded = _upload(
            replica_a,
            f"/api/agent/jobs/{job_id}/artifacts",
            _agent_headers(agent),
            gz,
            artifact_key="port_discovery.naabu",
            stage="port_discovery",
            tool="naabu",
        )
        assert uploaded.status_code == 200, uploaded.text
        artifact_id = uploaded.json()["id"]
        downloaded = replica_b.get(
            f"/api/scan-artifacts/{artifact_id}/download",
            headers=_headers(token),
        )
        assert downloaded.status_code == 200, downloaded.text
        assert downloaded.content == gz

        wan_id = _claim_wan(replica_a, token, world)
        scanner_upload = _upload(
            replica_b,
            f"/api/internal/scanner/jobs/{wan_id}/artifacts",
            _scanner_headers(),
            gz,
            artifact_key="port_discovery.naabu",
            stage="port_discovery",
            tool="naabu",
        )
        assert scanner_upload.status_code == 200, scanner_upload.text
        wan_download = replica_a.get(
            f"/api/scan-artifacts/{scanner_upload.json()['id']}/download",
            headers=_headers(token),
        )
        assert wan_download.status_code == 200, wan_download.text
        assert wan_download.content == gz

        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw().hex()
        db = SessionLocal()
        try:
            row = db.get(Agent, world["agent1"]["id"])
            assert row is not None
            row.public_key = public
            row.status = "approved"
            db.commit()
            agent_uuid = row.uuid
        finally:
            db.close()
        challenge = replica_a.get("/api/agent/challenge", params={"uuid": agent_uuid})
        assert challenge.status_code == 200, challenge.text
        nonce = challenge.json()["nonce"]
        signature = private.sign(nonce.encode()).hex()
        issued = replica_b.post(
            "/api/agent/token",
            json={"uuid": agent_uuid, "nonce": nonce, "signature": signature},
        )
        assert issued.status_code == 200, issued.text
        assert issued.json()["approved"] is True
        agent_token = issued.json()["access_token"]
        beat = replica_a.post(
            "/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {agent_token}"},
            json={},
        )
        assert beat.status_code == 200, beat.text
        replay = replica_a.post(
            "/api/agent/token",
            json={"uuid": agent_uuid, "nonce": nonce, "signature": signature},
        )
        assert replay.status_code == 401
