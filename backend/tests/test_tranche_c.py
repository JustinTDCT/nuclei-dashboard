from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import requires_postgres
from tests.test_migrations import FROZEN_MIGRATION_HASHES
from tests.test_phase1d import (
    _agent_headers,
    _client,
    _create_staff,
    _headers,
    _heartbeat,
    _login,
    _world,
)
from tests.test_phase3c import _create_viewer
from tests.test_tranche_b import (
    _ARTIFACT_FIELDS,
    _artifact_root,
    _audits,
    _claim_lan,
    _expected_artifact_keys,
    _gzip_jsonl,
    _named_world,
    _upload,
    _upload_keys,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
RUNTIME_ROOT = REPO_ROOT / "scan_runtime"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
MIGRATION_0015 = BACKEND_ROOT / "alembic" / "versions" / "0015_raw_scan_evidence.py"
MIGRATION_0016 = BACKEND_ROOT / "alembic" / "versions" / "0016_scanner_runtime_inventory.py"
TRANCHE_B_SHA256 = "fb0cac18676e410821b61c9c6182d7ad8bc532a7598f76b58440e5bc998e7428"
TRANCHE_B_GIT_BLOB = "3b650a2efc8cfb9074baf102fa4906aeb5688b03"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

FULL_INVENTORY = {
    "runtime_version": "nd-scan-runtime-1",
    "nuclei_version": "v3.11.1",
    "nuclei_templates_version": "v10.4.7",
    "naabu_version": "v2.6.1",
    "httpx_version": "v1.10.0",
}
PORT_PROVENANCE = {
    "runtime_version": "nd-scan-runtime-1",
    "naabu_version": "v2.6.1",
}
FINGERPRINT_PROVENANCE = {**PORT_PROVENANCE, "httpx_version": "v1.10.0"}
VULN_PROVENANCE = {
    **FINGERPRINT_PROVENANCE,
    "nuclei_version": "v3.11.1",
    "nuclei_templates_version": "v10.4.7",
}


def _post_inventory(client: TestClient, agent: dict, inventory: dict | None, *, json_body=True):
    headers = _agent_headers(agent)
    if not json_body:
        return client.post("/api/agent/heartbeat", headers=headers)
    body = {} if inventory is None else {"runtime_inventory": inventory}
    return client.post("/api/agent/heartbeat", headers=headers, json=body)


def _agent_out(client: TestClient, token: str, agent_id: int) -> dict:
    response = client.get(f"/api/agents/{agent_id}", headers=_headers(token))
    assert response.status_code == 200, response.text
    return response.json()


def _complete_captured(client: TestClient, job_id: int, agent: dict, gz: bytes, versions: dict):
    headers = _agent_headers(agent)
    keys = _expected_artifact_keys(job_id)
    for key in keys:
        stage, tool = _ARTIFACT_FIELDS[key]
        uploaded = _upload(
            client,
            f"/api/agent/jobs/{job_id}/artifacts",
            headers,
            gz,
            artifact_key=key,
            stage=stage,
            tool=tool,
            provenance=json.dumps(versions),
        )
        assert uploaded.status_code == 200, uploaded.text
    posted = client.post(f"/api/agent/jobs/{job_id}/provenance", headers=headers, json=versions)
    assert posted.status_code == 200, posted.text
    complete = client.post(
        f"/api/agent/jobs/{job_id}/complete",
        headers=headers,
        params={"ok": "true"},
        json={"status": "captured", "artifact_keys": keys},
    )
    assert complete.status_code == 200, complete.text
    return complete.json()


def test_pin_files_agree_and_install_path_never_uses_latest():
    runtime_pins = json.loads((RUNTIME_ROOT / "pinned_versions.json").read_text(encoding="utf-8"))
    backend_pins = json.loads((BACKEND_ROOT / "app" / "pinned_scanner_versions.json").read_text(encoding="utf-8"))
    assert runtime_pins == backend_pins == FULL_INVENTORY
    from pinned_download import templates_archive_url, tool_zip_url

    nuclei = tool_zip_url("nuclei", "amd64", runtime_pins)
    naabu = tool_zip_url("naabu", "amd64", runtime_pins)
    httpx = tool_zip_url("httpx", "amd64", runtime_pins)
    templates = templates_archive_url(runtime_pins["nuclei_templates_version"])
    assert nuclei == "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip"
    assert naabu == "https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip"
    assert httpx == "https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_linux_amd64.zip"
    assert templates == "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.7.tar.gz"
    for url in (nuclei, naabu, httpx, templates):
        assert "latest" not in url
        assert "/releases/latest" not in url
    install = (RUNTIME_ROOT / "install_tools.sh").read_text(encoding="utf-8")
    downloader = (RUNTIME_ROOT / "pinned_download.py").read_text(encoding="utf-8")
    dockerfile = (RUNTIME_ROOT / "Dockerfile").read_text(encoding="utf-8")
    for source in (install, downloader, dockerfile):
        assert "releases/latest" not in source
    assert "Refusing to fall back to latest" in install
    assert "curl -fsSL" in install
    missing = dict(runtime_pins)
    missing["nuclei_version"] = "v0.0.0-does-not-exist"
    missing_url = tool_zip_url("nuclei", "amd64", missing)
    assert "v0.0.0-does-not-exist" in missing_url
    assert "latest" not in missing_url


def test_nuclei_scan_command_disables_update_and_collector_uses_tv(tmp_path, monkeypatch):
    from commands import build_nuclei_command
    import tool_versions

    cmd = build_nuclei_command("nuclei", "/tmp/t", severities="critical")
    assert "-duc" in cmd
    assert "-disable-update-check" not in cmd or "-duc" in cmd
    assert "-tl" not in cmd

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    args_log = tmp_path / "nuclei.args"

    def write_bin(name: str, body: str) -> None:
        path = bin_dir / name
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    write_bin(
        "nuclei",
        f"""
import sys
from pathlib import Path
Path({str(args_log)!r}).write_text(" ".join(sys.argv[1:]))
if "-tl" in sys.argv:
    print("cve-2024-0001")
    raise SystemExit(0)
if "-tv" in sys.argv:
    print("[INF] Public nuclei-templates version: v10.4.7 (latest)")
    raise SystemExit(0)
print("Nuclei Engine Version: v3.11.1")
""",
    )
    write_bin("naabu", "print('Current Version: v2.6.1')\n")
    write_bin(
        "httpx",
        "print('Current Version: v1.10.0')\nprint('ProjectDiscovery')\n",
    )
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.delenv("SCAN_RUNTIME_VERSION", raising=False)
    inventory = tool_versions.collect_runtime_inventory()
    recorded = args_log.read_text()
    assert "-tv" in recorded
    assert "-tl" not in recorded
    assert "-disable-update-check" in recorded
    assert inventory["nuclei_version"] in {"v3.11.1", "3.11.1"}
    assert inventory["nuclei_templates_version"] in {"v10.4.7", "10.4.7"}
    assert inventory["naabu_version"] in {"v2.6.1", "2.6.1"}
    assert inventory["httpx_version"] in {"v1.10.0", "1.10.0"}
    assert inventory["runtime_version"] == "nd-scan-runtime-1"
    dry = tool_versions.collect_run_provenance(used_tools={"nuclei", "naabu", "httpx"}, dry_run=True)
    assert dry == {"runtime_version": "nd-scan-runtime-1"}
    real = tool_versions.collect_run_provenance(used_tools={"naabu"}, dry_run=False)
    assert real["runtime_version"] == "nd-scan-runtime-1"
    assert "naabu_version" in real
    assert "nuclei_version" not in real


def test_version_comparison_semantics():
    from app.scanner_versions import compare_inventory

    matching = compare_inventory(FULL_INVENTORY, FULL_INVENTORY)
    assert matching["overall"] == "match"
    assert all(row["status"] == "match" for row in matching["fields"].values())
    cosmetic = dict(FULL_INVENTORY)
    cosmetic["nuclei_version"] = "  V3.11.1 "
    assert compare_inventory(FULL_INVENTORY, cosmetic)["overall"] == "match"
    mismatched = dict(FULL_INVENTORY)
    mismatched["nuclei_version"] = "v3.99.0"
    result = compare_inventory(FULL_INVENTORY, mismatched)
    assert result["overall"] == "mismatch"
    assert result["fields"]["nuclei_version"]["status"] == "mismatch"
    missing = compare_inventory(FULL_INVENTORY, None)
    assert missing["overall"] == "not_reported"
    assert missing["fields"]["nuclei_version"]["status"] == "not_reported"
    blank = compare_inventory({key: "" for key in FULL_INVENTORY}, FULL_INVENTORY)
    assert blank["overall"] == "not_configured"
    assert blank["fields"]["runtime_version"]["status"] == "not_configured"


def test_job_finish_provenance_failure_keeps_artifacts_and_fails_closed(tmp_path):
    from job_finish import finish_pipeline_run

    staging = tmp_path / "stage"
    staging.mkdir()
    artifact_path = staging / "port_discovery.naabu.jsonl.gz"
    artifact_path.write_bytes(gzip.compress(b'{"ip":"10.1.0.8"}\n'))
    uploaded: list[dict] = []
    completes: list[tuple] = []

    def upload(payload):
        uploaded.append(payload)

    def boom(_payload):
        raise RuntimeError("central provenance rejected")

    def complete(ok, error=None, raw_evidence=None):
        completes.append((ok, error, raw_evidence))

    result = {
        "artifacts": [
            {
                "artifact_key": "port_discovery.naabu",
                "tool": "naabu",
                "stage": "port_discovery",
                "path": str(artifact_path),
                "provenance": {"naabu_version": "v2.6.1"},
            }
        ],
        "staging_dir": str(staging),
        "provenance": PORT_PROVENANCE,
        "dry_run": False,
        "devices": [],
        "findings": [],
        "detector_coverage": [],
    }
    finish_pipeline_run(
        result=result,
        upload=upload,
        complete=complete,
        provenance_fn=boom,
    )
    assert uploaded
    assert uploaded[0]["artifact_key"] == "port_discovery.naabu"
    assert completes and completes[0][0] is False
    assert "version provenance persistence failed" in str(completes[0][1])

    completes.clear()
    uploaded.clear()
    staging2 = tmp_path / "stage2"
    staging2.mkdir()
    missing = dict(result)
    missing["staging_dir"] = str(staging2)
    missing["provenance"] = {}
    finish_pipeline_run(
        result=missing,
        upload=upload,
        complete=complete,
        provenance_fn=lambda _p: None,
    )
    assert uploaded
    assert completes[0][0] is False
    assert "required version provenance was not collected" in str(completes[0][1])


def test_job_finish_coverage_failure_keeps_findings_and_fails_closed():
    from api_client import ApiError
    from job_finish import finish_pipeline_run

    completes: list[tuple] = []
    findings: list[list] = []

    def coverage(_payload):
        raise ApiError("coverage rejected")

    def store_findings(payload):
        findings.append(payload)

    def complete(ok, error=None, raw_evidence=None):
        completes.append((ok, error, raw_evidence))

    finish_pipeline_run(
        result={
            "artifacts": [],
            "staging_dir": None,
            "provenance": {"runtime_version": "test"},
            "dry_run": False,
            "devices": [],
            "findings": [{"template_id": "cve-1", "host": "https://203.0.113.10"}],
            "detector_coverage": [{"detector_type": "nuclei", "targets": ["https://203.0.113.10"]}],
        },
        upload=lambda _payload: None,
        complete=complete,
        provenance_fn=lambda _payload: None,
        findings_fn=store_findings,
        coverage_fn=coverage,
    )
    assert findings and findings[0][0]["template_id"] == "cve-1"
    assert completes and completes[0][0] is False
    assert "normalized result persistence failed" in str(completes[0][1])


def test_0015_frozen_and_0016_is_current_head():
    assert hashlib.sha256(MIGRATION_0015.read_bytes()).hexdigest() == TRANCHE_B_SHA256
    assert FROZEN_MIGRATION_HASHES["0015_raw_scan_evidence.py"] == TRANCHE_B_SHA256
    blob = subprocess.check_output(["git", "hash-object", str(MIGRATION_0015)], cwd=REPO_ROOT, text=True).strip()
    assert blob == TRANCHE_B_GIT_BLOB
    assert MIGRATION_0016.is_file()
    text = MIGRATION_0016.read_text(encoding="utf-8")
    assert 'revision: str = "0016_scanner_runtime_inventory"' in text
    assert 'down_revision: str | None = "0015_raw_scan_evidence"' in text
    assert "import app.models" not in text
    assert "subprocess" not in text


@requires_postgres
def test_agent_heartbeat_inventory_validation_and_audit(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        agent = world["agent1"]
        other = world["agent2"]
        _heartbeat(agent["id"])
        _heartbeat(other["id"])

        listed = client.get(f"/api/tenants/{world['tenant']['id']}/agents", headers=_headers(token)).json()
        by_id = {row["id"]: row for row in listed}
        assert by_id[agent["id"]]["runtime_inventory"] is None
        assert by_id[agent["id"]]["runtime_inventory_reported_at"] is None
        assert by_id[agent["id"]]["version_status"] == "not_reported"

        first = _post_inventory(client, agent, FULL_INVENTORY)
        assert first.status_code == 200, first.text
        out = _agent_out(client, token, agent["id"])
        assert out["runtime_inventory"] == FULL_INVENTORY
        assert out["runtime_inventory_reported_at"]
        assert out["version_status"] == "match"
        assert out["version_comparison"]["fields"]["nuclei_version"]["status"] == "match"
        other_out = _agent_out(client, token, other["id"])
        assert other_out["runtime_inventory"] is None
        audits = _audits("agent.runtime_inventory_change")
        assert len(audits) == 1
        assert audits[0].actor_user_id is None
        assert audits[0].tenant_id == world["tenant"]["id"]
        assert audits[0].site_id == world["site"]["id"]
        assert audits[0].details["after"]["nuclei_version"] == "v3.11.1"

        second = _post_inventory(client, agent, FULL_INVENTORY)
        assert second.status_code == 200, second.text
        assert len(_audits("agent.runtime_inventory_change")) == 1

        changed = dict(FULL_INVENTORY)
        changed["nuclei_version"] = "v3.12.0"
        third = _post_inventory(client, agent, changed)
        assert third.status_code == 200, third.text
        changed_out = _agent_out(client, token, agent["id"])
        assert changed_out["runtime_inventory"]["nuclei_version"] == "v3.12.0"
        assert changed_out["version_status"] == "mismatch"
        audits = _audits("agent.runtime_inventory_change")
        assert len(audits) == 2
        assert audits[-1].details["before"]["nuclei_version"] == "v3.11.1"
        assert audits[-1].details["after"]["nuclei_version"] == "v3.12.0"

        empty = _post_inventory(client, agent, None, json_body=False)
        assert empty.status_code == 200, empty.text
        still = _agent_out(client, token, agent["id"])
        assert still["runtime_inventory"]["nuclei_version"] == "v3.12.0"

        nested = _post_inventory(client, agent, {"nuclei_version": {"engine": "3.12"}})
        assert nested.status_code == 400
        secret = _post_inventory(client, agent, {"token": "leak", "nuclei_version": "v3.12.0"})
        assert secret.status_code == 400
        unknown = _post_inventory(client, agent, {"nuclei_version": "v3.12.0", "custom_tool": "1"})
        assert unknown.status_code == 400
        overlong = _post_inventory(client, agent, {"nuclei_version": "v" + ("1" * 200)})
        assert overlong.status_code == 400
        after_rejects = _agent_out(client, token, agent["id"])
        assert after_rejects["runtime_inventory"]["nuclei_version"] == "v3.12.0"

        revoke = client.post(f"/api/agents/{agent['id']}/revoke", headers=_headers(token))
        assert revoke.status_code == 200, revoke.text
        revoked = _post_inventory(client, agent, FULL_INVENTORY)
        assert revoked.status_code == 403


@requires_postgres
def test_approved_settings_change_derived_status_and_audit(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        agent = world["agent1"]
        _heartbeat(agent["id"])
        assert _post_inventory(client, agent, FULL_INVENTORY).status_code == 200
        before = _agent_out(client, token, agent["id"])
        assert before["version_status"] == "match"
        settings = client.get("/api/admin/settings", headers=_headers(token)).json()
        for key, value in {
            "approved_scanner_runtime_version": FULL_INVENTORY["runtime_version"],
            "approved_nuclei_version": FULL_INVENTORY["nuclei_version"],
            "approved_nuclei_templates_version": FULL_INVENTORY["nuclei_templates_version"],
            "approved_naabu_version": FULL_INVENTORY["naabu_version"],
            "approved_httpx_version": FULL_INVENTORY["httpx_version"],
        }.items():
            assert settings[key] == value
        noop = client.put("/api/admin/settings", headers=_headers(token), json=settings)
        assert noop.status_code == 200, noop.text
        assert _audits("settings.scanner_versions_change") == []

        changed = dict(settings)
        changed["approved_nuclei_version"] = "v9.9.9"
        saved = client.put("/api/admin/settings", headers=_headers(token), json=changed)
        assert saved.status_code == 200, saved.text
        audits = _audits("settings.scanner_versions_change")
        assert len(audits) == 1
        assert audits[0].details["approved_nuclei_version"]["before"] == "v3.11.1"
        assert audits[0].details["approved_nuclei_version"]["after"] == "v9.9.9"
        assert "smtp_password" not in json.dumps(audits[0].details)
        after = _agent_out(client, token, agent["id"])
        assert after["runtime_inventory"] == FULL_INVENTORY
        assert after["version_status"] == "mismatch"
        assert after["version_comparison"]["fields"]["nuclei_version"]["status"] == "mismatch"
        from app.database import SessionLocal
        from app.models import Agent

        db = SessionLocal()
        try:
            row = db.get(Agent, agent["id"])
            assert row.runtime_inventory == FULL_INVENTORY
        finally:
            db.close()

        blank = dict(changed)
        for key in (
            "approved_scanner_runtime_version",
            "approved_nuclei_version",
            "approved_nuclei_templates_version",
            "approved_naabu_version",
            "approved_httpx_version",
        ):
            blank[key] = ""
        cleared = client.put("/api/admin/settings", headers=_headers(token), json=blank)
        assert cleared.status_code == 200, cleared.text
        unconfigured = _agent_out(client, token, agent["id"])
        assert unconfigured["version_status"] == "not_configured"


@requires_postgres
def test_scan_run_required_version_provenance(reset_db, tmp_path, monkeypatch):
    _artifact_root(tmp_path, monkeypatch)
    gz = _gzip_jsonl(['{"ok":true}'])
    with _client() as client:
        token = _login(client)
        world = _world(client, token)

        port_job, port_agent = _claim_lan(
            client,
            token,
            world,
            stage_config={"discovery": True, "port_mode": "common", "fingerprint": False, "vulnerability": False},
        )
        _complete_captured(client, port_job, port_agent, gz, PORT_PROVENANCE)
        port = client.get(f"/api/jobs/{port_job}", headers=_headers(token)).json()
        assert port["runtime_provenance"]["runtime_version"] == "nd-scan-runtime-1"
        assert port["runtime_provenance"]["naabu_version"] == "v2.6.1"
        assert "nuclei_version" not in (port["runtime_provenance"] or {})
        version_values = [
            port["runtime_provenance"][key]
            for key in ("runtime_version", "naabu_version")
        ]
        assert all(isinstance(value, str) and len(value) < 64 and "\n" not in value for value in version_values)

        fp_job, fp_agent = _claim_lan(
            client,
            token,
            world,
            stage_config={"discovery": True, "port_mode": "common", "fingerprint": True, "vulnerability": False},
        )
        _complete_captured(client, fp_job, fp_agent, gz, FINGERPRINT_PROVENANCE)
        fp = client.get(f"/api/jobs/{fp_job}", headers=_headers(token)).json()
        assert fp["runtime_provenance"]["httpx_version"] == "v1.10.0"
        assert fp["runtime_provenance"]["naabu_version"] == "v2.6.1"

        vuln_job, vuln_agent = _claim_lan(
            client,
            token,
            world,
            stage_config={
                "discovery": True,
                "port_mode": "common",
                "fingerprint": True,
                "vulnerability": True,
                "nuclei_severities": "critical,high,medium",
            },
        )
        _complete_captured(client, vuln_job, vuln_agent, gz, VULN_PROVENANCE)
        vuln = client.get(f"/api/jobs/{vuln_job}", headers=_headers(token)).json()
        for key, value in VULN_PROVENANCE.items():
            assert vuln["runtime_provenance"][key] == value
        artifacts = client.get(f"/api/jobs/{vuln_job}/artifacts", headers=_headers(token)).json()
        for artifact in artifacts:
            for key, value in VULN_PROVENANCE.items():
                assert artifact["provenance"].get(key) == value

        missing_job, missing_agent = _claim_lan(client, token, world)
        headers = _agent_headers(missing_agent)
        keys = _expected_artifact_keys(missing_job)
        _upload_keys(client, f"/api/agent/jobs/{missing_job}/artifacts", headers, gz, keys)
        stale = client.post(
            f"/api/agent/jobs/{missing_job}/complete",
            headers=headers,
            params={"ok": "true"},
            json={"status": "captured", "artifact_keys": keys},
        )
        assert stale.status_code == 409
        assert "version provenance" in stale.text.lower() or "Required scanner version" in stale.text
        from app.database import SessionLocal
        from app.models import ScanArtifact, ScanJob

        db = SessionLocal()
        try:
            job = db.get(ScanJob, missing_job)
            assert job.status == "running"
            assert db.query(ScanArtifact).filter(ScanArtifact.scan_job_id == missing_job).count() == len(keys)
        finally:
            db.close()

        failed_job, failed_agent = _claim_lan(client, token, world)
        failed_headers = _agent_headers(failed_agent)
        _upload_keys(
            client,
            f"/api/agent/jobs/{failed_job}/artifacts",
            failed_headers,
            gz,
            ["port_discovery.naabu"],
        )
        client.post(
            f"/api/agent/jobs/{failed_job}/provenance",
            headers=failed_headers,
            json={"runtime_version": "nd-scan-runtime-1", "naabu_version": "v2.6.1"},
        )
        failed = client.post(
            f"/api/agent/jobs/{failed_job}/complete",
            headers=failed_headers,
            params={"ok": "false", "error": "nuclei crashed"},
        )
        assert failed.status_code == 200, failed.text
        db = SessionLocal()
        try:
            job = db.get(ScanJob, failed_job)
            assert job.status == "failed"
            assert db.query(ScanArtifact).filter(ScanArtifact.scan_job_id == failed_job).count() == 1
            assert job.runtime_provenance["naabu_version"] == "v2.6.1"
        finally:
            db.close()

        dry_job, dry_agent = _claim_lan(
            client, token, world, intensity_config={"preset": "normal", "dry_run": True}
        )
        dry = client.post(
            f"/api/agent/jobs/{dry_job}/complete",
            headers=_agent_headers(dry_agent),
            params={"ok": "true"},
            json={"status": "dry_run", "artifact_keys": []},
        )
        assert dry.status_code == 200, dry.text
        dry_body = client.get(f"/api/jobs/{dry_job}", headers=_headers(token)).json()
        provenance = dry_body.get("runtime_provenance") or {}
        assert "nuclei_version" not in provenance
        assert "naabu_version" not in provenance
        assert "httpx_version" not in provenance
        assert "nuclei_templates_version" not in provenance

        historical_job, historical_agent = _claim_lan(client, token, world)
        from app.database import SessionLocal as _Session
        from app.models import ScanJob as _ScanJob

        db = _Session()
        try:
            row = db.get(_ScanJob, historical_job)
            row.status = "done"
            row.finished_at = datetime.now(timezone.utc)
            row.runtime_provenance = None
            db.commit()
        finally:
            db.close()
        history = client.get(f"/api/jobs/{historical_job}", headers=_headers(token)).json()
        assert not history.get("runtime_provenance")
        scan_report = client.get(
            f"/api/reports/scan_history/preview?tenant_id={world['tenant']['id']}",
            headers=_headers(token),
        ).json()
        historical_row = next(item for item in scan_report["rows"] if item["job_id"] == historical_job)
        assert historical_row["runtime_version"] == "Not Recorded"
        assert historical_row["nuclei_version"] == "Not Recorded"

        _heartbeat(world["agent1"]["id"])
        assert _post_inventory(client, world["agent1"], FULL_INVENTORY).status_code == 200
        unchanged = client.get(f"/api/jobs/{port_job}", headers=_headers(token)).json()
        assert unchanged["runtime_provenance"]["runtime_version"] == PORT_PROVENANCE["runtime_version"]
        assert unchanged["runtime_provenance"]["naabu_version"] == PORT_PROVENANCE["naabu_version"]
        assert "nuclei_version" not in unchanged["runtime_provenance"]
        assert "httpx_version" not in unchanged["runtime_provenance"]


@requires_postgres
def test_auth_report_and_ui_version_surfaces(reset_db):
    with _client() as client:
        admin = _login(client)
        user = _create_staff(client, admin, "operator-c", "user")
        world_a = _named_world(client, admin, "Tenant-C-A")
        world_b = _named_world(client, admin, "Tenant-C-B")
        _heartbeat(world_a["agent1"]["id"])
        _heartbeat(world_b["agent1"]["id"])
        assert _post_inventory(client, world_a["agent1"], FULL_INVENTORY).status_code == 200
        viewer_a, _ = _create_viewer(client, admin, "viewer-c-a", tenant_ids=[world_a["tenant"]["id"]])

        admin_agents = client.get(f"/api/tenants/{world_a['tenant']['id']}/agents", headers=_headers(admin)).json()
        user_agents = client.get(f"/api/tenants/{world_a['tenant']['id']}/agents", headers=_headers(user)).json()
        viewer_agents = client.get(f"/api/tenants/{world_a['tenant']['id']}/agents", headers=_headers(viewer_a)).json()
        for rows in (admin_agents, user_agents, viewer_agents):
            reported = next(row for row in rows if row["id"] == world_a["agent1"]["id"])
            silent = next(row for row in rows if row["id"] == world_a["agent2"]["id"])
            assert reported["version_status"] == "match"
            assert reported["runtime_inventory"]["nuclei_version"] == "v3.11.1"
            assert silent["version_status"] == "not_reported"
            assert silent["runtime_inventory"] is None
            dumped = json.dumps(rows)
            assert "enrollment_secret" not in dumped or all(not row.get("enrollment_secret") for row in rows)
            assert "private_key" not in dumped
            assert "smtp_password" not in dumped

        denied = client.get(f"/api/agents/{world_b['agent1']['id']}", headers=_headers(viewer_a))
        assert denied.status_code == 404
        allowed = client.get(f"/api/agents/{world_a['agent1']['id']}", headers=_headers(viewer_a))
        assert allowed.status_code == 200
        assert allowed.json()["runtime_inventory"]["httpx_version"] == "v1.10.0"

        health = client.get(
            f"/api/reports/agent_health/preview?tenant_id={world_a['tenant']['id']}",
            headers=_headers(viewer_a),
        ).json()
        reported_row = next(row for row in health["rows"] if row["agent_id"] == world_a["agent1"]["id"])
        silent_row = next(row for row in health["rows"] if row["agent_id"] == world_a["agent2"]["id"])
        assert reported_row["runtime_version"] == "nd-scan-runtime-1"
        assert reported_row["nuclei_version"] == "v3.11.1"
        assert reported_row["version_status"] == "Matches approved"
        assert silent_row["runtime_version"] == "Not Reported"
        assert silent_row["nuclei_version"] == "Not Reported"
        assert silent_row["runtime_inventory_reported_at"] == "Not Reported"
        csv_resp = client.get(
            f"/api/reports/agent_health/export?format=csv&tenant_id={world_a['tenant']['id']}",
            headers=_headers(viewer_a),
        )
        assert csv_resp.status_code == 200, csv_resp.text
        assert "nd-scan-runtime-1" in csv_resp.text
        assert "Not Reported" in csv_resp.text
        assert "enrollment_secret" not in csv_resp.text

        settings = client.get("/api/admin/settings", headers=_headers(admin)).json()
        assert settings["approved_scanner_runtime_version"] == "nd-scan-runtime-1"
        assert settings["approved_nuclei_version"] == "v3.11.1"

    tenant = (FRONTEND_SRC / "pages" / "TenantDetail.tsx").read_text()
    sites = (FRONTEND_SRC / "pages" / "SitesPanel.tsx").read_text()
    admin_ui = (FRONTEND_SRC / "pages" / "AdminSettings.tsx").read_text()
    types = (FRONTEND_SRC / "types.ts").read_text()
    version_status = (FRONTEND_SRC / "versionStatus.ts").read_text()
    assert "Approved scanner versions" in admin_ui
    assert "does not upgrade remote Agents" in admin_ui
    assert "approved_scanner_runtime_version" in types
    assert "Approved version status" in tenant
    assert "Approved version status" in sites
    assert "Matches approved" in version_status
    assert "Not Recorded" in version_status
    assert "recordedVersion(selectedJob.runtime_provenance" in tenant
    assert "update available" not in tenant.lower()
    assert "auto-update" not in admin_ui.lower()
