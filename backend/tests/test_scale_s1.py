from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch

import httpx
import pytest

from tests.conftest import requires_postgres
from tests.test_phase1d import _agent_headers, _client, _headers, _heartbeat, _lan_scan, _login, _world
from tests.test_tranche_b import _named_world

BACKEND_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = BACKEND_ROOT.parent / "scan_runtime"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))


def test_central_and_scanner_clients_reuse_httpx_client():
    from api_client import CentralClient, ScannerClient

    agent = CentralClient("http://api.example:8000")
    scanner = ScannerClient("http://api.example:8000", "scanner-token")
    try:
        assert isinstance(agent._http, httpx.Client)
        assert isinstance(scanner._http, httpx.Client)
        first_agent = agent._http
        first_scanner = scanner._http
        agent._http.request = MagicMock(
            return_value=httpx.Response(200, json={"ok": True, "status": "approved"})
        )
        scanner._http.request = MagicMock(return_value=httpx.Response(200, json=[]))
        agent.heartbeat("tok")
        agent.jobs("tok")
        scanner.jobs()
        assert agent._http is first_agent
        assert scanner._http is first_scanner
        assert agent._http.request.call_count == 2
        assert scanner._http.request.call_count == 1
    finally:
        agent.close()
        scanner.close()


def test_real_client_uses_pooled_request(tmp_path):
    from api_client import ARTIFACT_UPLOAD_TIMEOUT, CentralClient, ScannerClient

    artifact_path = tmp_path / "port_discovery.naabu.jsonl.gz"
    artifact_path.write_bytes(b"gz-bytes")
    artifact = {
        "path": str(artifact_path),
        "artifact_key": "port_discovery.naabu",
        "stage": "port_discovery",
        "tool": "naabu",
        "provenance": {"naabu_version": "2.3.0"},
    }
    calls = []

    class FakeResponse:
        status_code = 200
        text = '{"id":1}'

        def json(self):
            return {"id": 1, "artifact_key": "port_discovery.naabu"}

    def fake_request(self, method, url, **kwargs):
        calls.append({"method": method, "url": str(url), "kwargs": kwargs})
        return FakeResponse()

    with patch.object(httpx.Client, "request", fake_request):
        CentralClient("http://api.example:8000").upload_artifact("agent-token", 9, artifact)
        ScannerClient("http://api.example:8000", "scanner-token").upload_artifact(9, artifact)

    assert len(calls) == 2
    assert str(calls[0]["url"]).endswith("/api/agent/jobs/9/artifacts")
    assert str(calls[1]["url"]).endswith("/api/internal/scanner/jobs/9/artifacts")
    for call in calls:
        assert call["kwargs"]["timeout"] == ARTIFACT_UPLOAD_TIMEOUT
        assert "files" in call["kwargs"]


def test_inventory_sent_on_startup_change_and_period_only(monkeypatch):
    import agent_main

    monkeypatch.setattr(agent_main, "_inventory_cache", {"nuclei_version": "v1"})
    monkeypatch.setattr(agent_main, "_inventory_cached_at", time.time())
    monkeypatch.setattr(agent_main, "_last_sent_inventory", None)
    monkeypatch.setattr(agent_main, "_last_inventory_sent_at", 0.0)
    first = agent_main.inventory_for_heartbeat(now=10.0)
    assert first == {"nuclei_version": "v1"}
    assert agent_main.inventory_for_heartbeat(now=20.0) is None
    monkeypatch.setattr(agent_main, "_inventory_cache", {"nuclei_version": "v2"})
    changed = agent_main.inventory_for_heartbeat(now=30.0)
    assert changed == {"nuclei_version": "v2"}
    assert agent_main.inventory_for_heartbeat(now=40.0) is None
    periodic = agent_main.inventory_for_heartbeat(now=40.0 + agent_main.INVENTORY_REFRESH_SECONDS)
    assert periodic == {"nuclei_version": "v2"}


def test_control_loop_heartbeats_while_one_job_runs():
    import agent_main

    heartbeats: list[dict] = []
    job_polls = []

    class FakeClient:
        def heartbeat(self, token, runtime_inventory=None, job_id=None, activity=None):
            heartbeats.append({"job_id": job_id, "activity": activity, "inventory": runtime_inventory})
            return {"ok": True}

        def jobs(self, token):
            job_polls.append(time.time())
            if len(job_polls) == 1:
                return [{"job_id": 7}]
            return []

    def fake_run_job(client, token, job, refresh_token):
        time.sleep(0.7)

    runtime = agent_main.AgentRuntime(
        FakeClient(),
        "agent-uuid",
        "secret",
        "pub",
        object(),
        interval=0.12,
        jitter=0.0,
        run_job_fn=fake_run_job,
        authenticate_fn=lambda *args, **kwargs: "tok",
        inventory_fn=lambda force=False: None,
    )
    thread = Thread(target=lambda: runtime.run(max_cycles=10), daemon=True)
    thread.start()
    deadline = time.time() + 4.0
    while time.time() < deadline and not any(row.get("job_id") == 7 for row in heartbeats):
        time.sleep(0.05)
    time.sleep(0.45)
    during = [row for row in heartbeats if row.get("job_id") == 7]
    runtime.stop()
    thread.join(timeout=3)
    assert len(during) >= 2
    assert all(row.get("activity") == "scanning" for row in during)


def test_progress_interval_never_goes_silent():
    import artifact_io

    assert artifact_io.progress_interval_for_elapsed(0) == 30.0
    assert artifact_io.progress_interval_for_elapsed(599) == 30.0
    assert artifact_io.progress_interval_for_elapsed(600) == 120.0
    assert artifact_io.progress_interval_for_elapsed(1799) == 120.0
    assert artifact_io.progress_interval_for_elapsed(1800) == 300.0
    assert artifact_io.progress_interval_for_elapsed(10_000) == 300.0


def test_run_command_nonzero_exit_with_output_is_failure(tmp_path):
    import artifact_io

    dest = tmp_path / "partial.jsonl"
    dest.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="exit 3"):
        artifact_io.run_command_to_file(["/bin/sh", "-c", "printf '{\"ok\":true}\\n'; exit 3"], dest)
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == '{"ok":true}\n'


def test_run_command_emits_bounded_progress(tmp_path, monkeypatch):
    import artifact_io

    monkeypatch.setattr(artifact_io, "PROGRESS_POLL_SECONDS", 0.2)
    monkeypatch.setattr(artifact_io, "PROGRESS_FAST_INTERVAL_SECONDS", 0.2)
    monkeypatch.setattr(artifact_io, "PROGRESS_FAST_UNTIL_SECONDS", 10.0)
    logs: list[str] = []
    dest = tmp_path / "out.bin"
    artifact_io.run_command_to_file(["sleep", "0.65"], dest, log=logs.append)
    progress = [line for line in logs if "still running" in line]
    assert 1 <= len(progress) <= 5
    assert any("bytes written" in line for line in progress)


def test_httpx_and_nuclei_commands_pin_sni_for_source_fqdn():
    from commands import build_httpx_command, build_nuclei_command

    httpx = build_httpx_command("httpx", "/tmp/t", sni="portal.customer.com")
    assert httpx[httpx.index("-sni") + 1] == "portal.customer.com"
    assert "Host: portal.customer.com" in httpx
    nuclei = build_nuclei_command("nuclei", "/tmp/t", severities="critical", sni="portal.customer.com")
    assert nuclei[nuclei.index("-sni") + 1] == "portal.customer.com"
    assert "Host: portal.customer.com" in nuclei


def test_malformed_nuclei_jsonl_fails_closed_without_coverage(tmp_path, monkeypatch):
    import runner as runtime_runner

    def fake_run(cmd, dest, log=None):
        dest.write_text("{not-json\n", encoding="utf-8")

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei" if name == "nuclei" else None)
    monkeypatch.setattr(runtime_runner, "_pd_httpx", lambda: None)
    monkeypatch.setattr(
        runtime_runner,
        "run_naabu",
        lambda *args, **kwargs: ([{"ip": "203.0.113.10", "port": 443}], None),
    )
    with pytest.raises(runtime_runner.PipelineError) as exc:
        runtime_runner.run_pipeline(
            {
                "scope": "wan",
                "targets": [{"type": "ip", "value": "203.0.113.10", "source_fqdn": "portal.customer.com"}],
                "stages": {
                    "discovery": False,
                    "port_mode": "none",
                    "fingerprint": True,
                    "vulnerability": True,
                    "nuclei_severities": "critical",
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


def test_schema_invalid_nuclei_row_fails_closed(tmp_path, monkeypatch):
    import runner as runtime_runner

    def fake_run(cmd, dest, log=None):
        dest.write_text('{"info":{"name":"exposed"}}\n', encoding="utf-8")

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei")
    with pytest.raises(runtime_runner.StageExecutionError, match="template-id"):
        runtime_runner.run_nuclei(["https://203.0.113.10"], "critical", "", staging_dir=tmp_path)


def test_coverage_targets_use_source_fqdn_not_pinned_ip():
    import runner as runtime_runner

    assert runtime_runner._coverage_targets(
        [{"value": "https://203.0.113.25", "source_fqdn": "portal.customer.com"}]
    ) == ["https://portal.customer.com"]


def test_nuclei_presents_source_fqdn_as_sni_while_connecting_to_pinned_ip(tmp_path, monkeypatch):
    import runner as runtime_runner

    captured: dict[str, object] = {}

    def fake_run(cmd, dest, log=None):
        captured["cmd"] = list(cmd)
        captured["targets"] = Path(cmd[cmd.index("-l") + 1]).read_text(encoding="utf-8")
        dest.write_text(
            '{"template-id":"cve-1","host":"https://portal.customer.com","info":{"name":"x","severity":"high"}}\n',
            encoding="utf-8",
        )

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei")
    findings, _artifact = runtime_runner.run_nuclei(
        [{"value": "https://203.0.113.25", "source_fqdn": "portal.customer.com"}],
        "critical",
        "",
        staging_dir=tmp_path,
    )
    assert findings[0]["template_id"] == "cve-1"
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert "https://203.0.113.25" in str(captured["targets"])
    assert "portal.customer.com" not in str(captured["targets"])
    assert cmd[cmd.index("-sni") + 1] == "portal.customer.com"
    assert "Host: portal.customer.com" in cmd


def test_shared_ip_fans_out_each_authorized_fqdn():
    import runner as runtime_runner

    hosts = [{"ip": "203.0.113.25", "port": 443}]
    runtime_runner._apply_source_fqdns(
        hosts,
        [
            {"type": "ip", "value": "203.0.113.25", "source_fqdn": "portal.customer.com"},
            {"type": "ip", "value": "203.0.113.25", "source_fqdn": "admin.customer.com"},
        ],
    )
    assert [(row["ip"], row["port"], row["source_fqdn"]) for row in hosts] == [
        ("203.0.113.25", 443, "portal.customer.com"),
        ("203.0.113.25", 443, "admin.customer.com"),
    ]


def test_shared_ip_virtual_hosts_are_scanned_separately(tmp_path, monkeypatch):
    import runner as runtime_runner

    captured: list[dict[str, str]] = []

    def fake_run(cmd, dest, log=None):
        sni = cmd[cmd.index("-sni") + 1]
        captured.append({"sni": sni, "targets": Path(cmd[cmd.index("-l") + 1]).read_text(encoding="utf-8")})
        dest.write_text(
            json.dumps(
                {
                    "template-id": sni,
                    "host": f"https://{sni}",
                    "info": {"name": "x", "severity": "high"},
                }
            )
            + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei")
    findings, artifact = runtime_runner.run_nuclei(
        [
            {"value": "https://203.0.113.25", "source_fqdn": "portal.customer.com"},
            {"value": "https://203.0.113.25", "source_fqdn": "admin.customer.com"},
        ],
        "critical",
        "",
        staging_dir=tmp_path,
    )
    assert {row["sni"] for row in captured} == {"portal.customer.com", "admin.customer.com"}
    assert all("203.0.113.25" in row["targets"] and "customer.com" not in row["targets"] for row in captured)
    assert {row["template_id"] for row in findings} == {"portal.customer.com", "admin.customer.com"}
    assert artifact is not None
    assert artifact["artifact_key"] == "vulnerability.nuclei"
    import gzip

    raw = gzip.open(artifact["path"], "rt", encoding="utf-8").read()
    assert "portal.customer.com" in raw
    assert "admin.customer.com" in raw
    assert raw.count("\n") == 2


def test_nuclei_keeps_every_sni_group_in_combined_artifact_on_partial_failure(tmp_path, monkeypatch):
    import gzip

    import runner as runtime_runner

    def fake_run(cmd, dest, log=None):
        sni = cmd[cmd.index("-sni") + 1]
        dest.write_text(
            json.dumps(
                {
                    "template-id": sni,
                    "host": f"https://{sni}",
                    "info": {"name": "x", "severity": "high"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        if sni == "admin.customer.com":
            raise RuntimeError("nuclei crashed (exit 1)")

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei")
    with pytest.raises(runtime_runner.StageExecutionError) as exc:
        runtime_runner.run_nuclei(
            [
                {"value": "https://203.0.113.25", "source_fqdn": "portal.customer.com"},
                {"value": "https://203.0.113.25", "source_fqdn": "admin.customer.com"},
            ],
            "critical",
            "",
            staging_dir=tmp_path,
        )
    assert {row["template_id"] for row in exc.value.findings} == {
        "portal.customer.com",
        "admin.customer.com",
    }
    assert exc.value.artifact is not None
    assert exc.value.artifact["artifact_key"] == "vulnerability.nuclei"
    raw = gzip.open(exc.value.artifact["path"], "rt", encoding="utf-8").read()
    assert "portal.customer.com" in raw
    assert "admin.customer.com" in raw


def test_pipeline_fans_shared_ip_into_each_virtual_host(monkeypatch):
    import runner as runtime_runner

    captured: dict[str, list] = {}

    def fake_httpx(hosts, **_kwargs):
        captured["httpx"] = [dict(row) for row in hosts]
        return (
            [
                {"url": f"https://{row['ip']}", "source_fqdn": row.get("source_fqdn") or ""}
                for row in hosts
            ],
            None,
        )

    def fake_nuclei(targets, **_kwargs):
        captured["nuclei"] = list(targets)
        return [], None

    monkeypatch.setattr(
        runtime_runner,
        "run_naabu",
        lambda *args, **kwargs: ([{"ip": "203.0.113.25", "port": 443}], None),
    )
    monkeypatch.setattr(runtime_runner, "run_httpx", fake_httpx)
    monkeypatch.setattr(runtime_runner, "run_nuclei", fake_nuclei)
    monkeypatch.setattr(runtime_runner, "collect_run_provenance", lambda **kwargs: {"runtime_version": "test"})
    result = runtime_runner.run_pipeline(
        {
            "scope": "wan",
            "targets": [
                {"type": "ip", "value": "203.0.113.25", "source_fqdn": "portal.customer.com"},
                {"type": "ip", "value": "203.0.113.25", "source_fqdn": "admin.customer.com"},
            ],
            "stages": {
                "discovery": False,
                "port_mode": "common",
                "fingerprint": True,
                "vulnerability": True,
                "nuclei_severities": "critical",
                "nuclei_tags": "",
            },
            "intensity": {},
            "exclusions": [],
        }
    )
    assert {row["source_fqdn"] for row in captured["httpx"]} == {
        "portal.customer.com",
        "admin.customer.com",
    }
    assert {row["source_fqdn"] for row in captured["nuclei"]} == {
        "portal.customer.com",
        "admin.customer.com",
    }
    assert set(result["detector_coverage"][0]["targets"]) == {
        "https://portal.customer.com",
        "https://admin.customer.com",
    }


def test_failed_nuclei_retains_valid_positive_rows_without_coverage(tmp_path, monkeypatch):
    import runner as runtime_runner

    def fake_run(cmd, dest, log=None):
        dest.write_text(
            '{"template-id":"cve-2024-1","host":"https://203.0.113.10","matched-at":"https://203.0.113.10/","info":{"name":"x","severity":"high"}}\n',
            encoding="utf-8",
        )
        raise RuntimeError("nuclei crashed (exit 1)")

    monkeypatch.setattr(runtime_runner, "run_command_to_file", fake_run)
    monkeypatch.setattr(runtime_runner, "_which", lambda name: "/bin/nuclei")
    with pytest.raises(runtime_runner.StageExecutionError) as exc:
        runtime_runner.run_nuclei(["https://203.0.113.10"], "critical", "", staging_dir=tmp_path)
    assert exc.value.findings[0]["template_id"] == "cve-2024-1"
    assert exc.value.artifact is not None


def test_httpx_command_does_not_invent_no_classify_flag():
    from commands import build_httpx_command

    cmd = build_httpx_command("httpx", "/tmp/t", intensity={"httpx_rate": 50})
    assert "-json" in cmd
    assert "-no-classify" not in cmd
    assert "-nc" not in cmd
    install = (RUNTIME_ROOT / "install_tools.sh").read_text(encoding="utf-8")
    assert "/root/.dit/model.json" in install
    assert "DIT page classifier" in install


def test_jittered_interval_stays_within_bounds():
    import agent_main

    samples = {agent_main.jittered_interval(15.0, 5.0) for _ in range(40)}
    assert all(15.0 <= value <= 20.0 for value in samples)
    assert len(samples) > 1


@requires_postgres
def test_agent_job_poll_does_not_starve_behind_ineligible_queue(reset_db):
    with _client() as client:
        token = _login(client)
        world_a = _named_world(client, token, "Starve-A")
        world_b = _named_world(client, token, "Starve-B")
        scan_a = _lan_scan(client, token, world_a, name="A-scan")
        first = client.post(f"/api/scans/{scan_a['id']}/run", headers=_headers(token))
        assert first.status_code == 200, first.text
        scan_b = _lan_scan(client, token, world_b, name="B-scan")
        later = client.post(f"/api/scans/{scan_b['id']}/run", headers=_headers(token))
        assert later.status_code == 200, later.text
        later_id = later.json()["id"]

        from app.database import SessionLocal
        from app.models import JOB_QUEUED, ScanJob

        db = SessionLocal()
        try:
            template = db.get(ScanJob, first.json()["id"])
            assert template is not None
            created = datetime.now(timezone.utc) - timedelta(hours=1)
            for index in range(29):
                clone = ScanJob(
                    scan_id=template.scan_id,
                    tenant_id=template.tenant_id,
                    status=JOB_QUEUED,
                    execution_snapshot=deepcopy(template.execution_snapshot),
                    snapshot_version=template.snapshot_version,
                    definition_revision=template.definition_revision,
                    trigger_type=template.trigger_type,
                    created_at=created + timedelta(seconds=index),
                    runtime_provenance=deepcopy(template.runtime_provenance),
                )
                db.add(clone)
            later_job = db.get(ScanJob, later_id)
            later_job.created_at = datetime.now(timezone.utc)
            db.commit()
            queued_a = (
                db.query(ScanJob)
                .filter(ScanJob.tenant_id == world_a["tenant"]["id"], ScanJob.status == JOB_QUEUED)
                .count()
            )
            assert queued_a >= 26
        finally:
            db.close()

        _heartbeat(world_b["agent1"]["id"])
        polled = client.get("/api/agent/jobs", headers=_agent_headers(world_b["agent1"]))
        assert polled.status_code == 200, polled.text
        ids = [row["job_id"] for row in polled.json()]
        assert ids == [later_id]


@requires_postgres
def test_busy_agent_does_not_receive_additional_jobs(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        first_scan = _lan_scan(client, token, world, name="First")
        first = client.post(f"/api/scans/{first_scan['id']}/run", headers=_headers(token))
        assert first.status_code == 200, first.text
        first_id = first.json()["id"]
        _heartbeat(world["agent1"]["id"])
        started = client.post(f"/api/agent/jobs/{first_id}/start", headers=_agent_headers(world["agent1"]))
        assert started.status_code == 200, started.text

        second_scan = _lan_scan(client, token, world, name="Second")
        second = client.post(f"/api/scans/{second_scan['id']}/run", headers=_headers(token))
        assert second.status_code == 200, second.text
        polled = client.get("/api/agent/jobs", headers=_agent_headers(world["agent1"]))
        assert polled.status_code == 200, polled.text
        assert polled.json() == []
        blocked = client.post(
            f"/api/agent/jobs/{second.json()['id']}/start",
            headers=_agent_headers(world["agent1"]),
        )
        assert blocked.status_code == 409


@requires_postgres
def test_poll_returns_only_the_first_claimable_job(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        first_scan = _lan_scan(client, token, world, name="Poll-1")
        first = client.post(f"/api/scans/{first_scan['id']}/run", headers=_headers(token))
        second_scan = _lan_scan(client, token, world, name="Poll-2")
        second = client.post(f"/api/scans/{second_scan['id']}/run", headers=_headers(token))
        assert first.status_code == 200 and second.status_code == 200
        _heartbeat(world["agent1"]["id"])
        polled = client.get("/api/agent/jobs", headers=_agent_headers(world["agent1"]))
        assert polled.status_code == 200, polled.text
        assert len(polled.json()) == 1
        assert polled.json()[0]["job_id"] == first.json()["id"]


@requires_postgres
def test_concurrent_starts_same_agent_claim_exactly_one_job(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        first_scan = _lan_scan(client, token, world, name="Race-1")
        first = client.post(f"/api/scans/{first_scan['id']}/run", headers=_headers(token))
        second_scan = _lan_scan(client, token, world, name="Race-2")
        second = client.post(f"/api/scans/{second_scan['id']}/run", headers=_headers(token))
        assert first.status_code == 200 and second.status_code == 200
        job_ids = [first.json()["id"], second.json()["id"]]
        _heartbeat(world["agent1"]["id"])
        headers = _agent_headers(world["agent1"])

        def _start(job_id: int):
            return client.post(f"/api/agent/jobs/{job_id}/start", headers=headers)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(_start, job_ids))
        codes = sorted(response.status_code for response in results)
        assert codes.count(200) == 1, [response.text for response in results]
        assert 409 in codes
        from app.database import SessionLocal
        from app.models import JOB_RUNNING, ScanJob

        db = SessionLocal()
        try:
            running = (
                db.query(ScanJob)
                .filter(ScanJob.claimed_agent_id == world["agent1"]["id"], ScanJob.status == JOB_RUNNING)
                .all()
            )
            assert len(running) == 1
            assert running[0].id in job_ids
        finally:
            db.close()


@requires_postgres
def test_eligible_job_sql_explain_analyze_is_bounded(reset_db):
    with _client() as client:
        token = _login(client)
        world_a = _named_world(client, token, "Explain-A")
        world_b = _named_world(client, token, "Explain-B")
        scan_a = _lan_scan(client, token, world_a, name="A-scan")
        first = client.post(f"/api/scans/{scan_a['id']}/run", headers=_headers(token))
        assert first.status_code == 200, first.text
        scan_b = _lan_scan(client, token, world_b, name="B-scan")
        later = client.post(f"/api/scans/{scan_b['id']}/run", headers=_headers(token))
        assert later.status_code == 200, later.text

        from app.database import SessionLocal
        from app.models import JOB_QUEUED, ScanJob
        from sqlalchemy import text

        db = SessionLocal()
        try:
            template = db.get(ScanJob, first.json()["id"])
            created = datetime.now(timezone.utc) - timedelta(hours=1)
            for index in range(80):
                db.add(
                    ScanJob(
                        scan_id=template.scan_id,
                        tenant_id=template.tenant_id,
                        status=JOB_QUEUED,
                        execution_snapshot=deepcopy(template.execution_snapshot),
                        snapshot_version=template.snapshot_version,
                        definition_revision=template.definition_revision,
                        trigger_type=template.trigger_type,
                        created_at=created + timedelta(seconds=index),
                        runtime_provenance=deepcopy(template.runtime_provenance),
                    )
                )
            db.commit()
            payload = json.dumps({"dispatch": {"eligible_agent_ids": [world_b["agent1"]["id"]]}})
            plan = db.execute(
                text(
                    """
                    EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
                    SELECT scan_jobs.id
                    FROM scan_jobs
                    WHERE status IN ('queued', 'waiting_for_agent')
                      AND execution_snapshot IS NOT NULL
                      AND execution_snapshot->>'scope' = 'lan'
                      AND execution_snapshot @> CAST(:payload AS jsonb)
                    ORDER BY created_at ASC, id ASC
                    LIMIT 25
                    """
                ),
                {"payload": payload},
            ).scalar_one()
        finally:
            db.close()

        if isinstance(plan, str):
            plan = json.loads(plan)
        root = plan[0]["Plan"]
        execution_ms = float(plan[0].get("Execution Time") or 0)
        assert execution_ms < 250.0
        assert root.get("Actual Rows", 0) >= 0


@requires_postgres
def test_lightweight_heartbeat_keeps_agent_healthy_without_inventory(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        agent = world["agent1"]
        _heartbeat(agent["id"])
        headers = _agent_headers(agent)
        empty = client.post("/api/agent/heartbeat", headers=headers)
        assert empty.status_code == 200, empty.text
        scanning = client.post(
            "/api/agent/heartbeat",
            headers=headers,
            json={"job_id": 42, "activity": "scanning"},
        )
        assert scanning.status_code == 200, scanning.text
        listed = client.get(f"/api/agents/{agent['id']}", headers=_headers(token)).json()
        assert listed["online"] is True
        assert listed["runtime_inventory"] is None
        assert listed["last_heartbeat"]
