"""S2A: benchmark + semantic freeze. S2B changed how Device/Asset ingest executes."""

from __future__ import annotations

import json
from tests.conftest import requires_postgres
from tests.scale_s2.constants import CURRENT_INGEST_PATH, S1_BASELINE_SHA, WORKLOADS
from tests.scale_s2.harness import (
    counts_from_state,
    hotspot_flags,
    ingest_current_path,
    prepare_and_ingest,
)
from tests.scale_s2.metrics import classify_sql, encoded_payload_bytes
from tests.scale_s2.snapshot import assert_equivalent, capture_normalized_state, diff_normalized
from tests.scale_s2.workloads import build_workload
from tests.scale_s2.world import reset_schema


def test_s1_baseline_sha_is_frozen():
    assert S1_BASELINE_SHA == "312e0d0"
    assert CURRENT_INGEST_PATH == "s2b_device_asset_cache"


def test_sql_classifier_extracts_hot_tables():
    assert classify_sql("SELECT asset_services.id FROM asset_services WHERE asset_id = 1") == (
        "SELECT",
        "asset_services",
    )
    assert classify_sql("INSERT INTO asset_identifiers (asset_id) VALUES (1)") == ("INSERT", "asset_identifiers")
    assert classify_sql('UPDATE "devices" SET last_seen = now()') == ("UPDATE", "devices")
    assert classify_sql("SELECT findings.raw_json FROM findings WHERE detector_key = 'x'") == ("SELECT", "findings")


def test_snapshot_diff_ignores_equal_normalized_rows():
    left = {"devices": [{"key": "a", "ip": "10.0.0.1"}]}
    right = {"devices": [{"key": "a", "ip": "10.0.0.1"}]}
    assert diff_normalized(left, right) == {}
    right = {"devices": [{"key": "a", "ip": "10.0.0.2"}]}
    assert "devices" in diff_normalized(left, right)


def test_small_workload_shape():
    workload = build_workload(WORKLOADS["small"])
    assert len(workload.devices) == 100
    assert len(workload.findings) == 100
    assert sum(len(row.ports or []) for row in workload.devices) == 500
    assert encoded_payload_bytes(workload.devices) > 0
    assert encoded_payload_bytes(workload.findings) > 0


@requires_postgres
def test_small_current_path_is_replay_safe_and_deterministic(reset_db):
    from app.database import SessionLocal

    reset_schema()
    db = SessionLocal()
    try:
        once = prepare_and_ingest(db, WORKLOADS["small"], replay=False)
        once_state = once["state"]
        ingest_current_path(db, once["world"], once["workload"], collect_metrics=False)
        replay_state = capture_normalized_state(db, once["world"].tenant_id)
        assert_equivalent(once_state, replay_state, label="same-run replay")
        metrics = once["metrics"]
        hotspots = hotspot_flags(metrics)
        counts = counts_from_state(once_state)
        assert counts["assets"] == 100
        assert counts["devices"] == 100
        assert counts["asset_services"] == 500
        assert counts["findings"] == 100
        assert counts["asset_observations"] == 100
        assert counts["asset_correlation_decisions"] == 100
        assert counts["scan_jobs"] == 1
        assert once_state["scan_jobs"][0]["status"] == "done"
        assert once_state["scan_jobs"][0]["hosts_found"] == 100
        assert once_state["scan_jobs"][0]["findings_count"] == 100
        assert metrics.select_count > 0
        assert metrics.insert_count > 0
        assert hotspots["per_finding_population_reload"] is True
        assert hotspots["historical_raw_evidence_scan"] is True
        assert metrics.device_request_bytes > 0
        assert metrics.finding_request_bytes > 0
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        isolated = prepare_and_ingest(db, WORKLOADS["small"], replay=False)
        assert_equivalent(once_state, isolated["state"], label="isolated current-path ingest")
    finally:
        db.close()


@requires_postgres
def test_http_chunk_replay_matches_single_upload(reset_db):
    from app.database import SessionLocal
    from tests.test_phase1d import _agent_headers, _client, _headers, _login, _world
    from tests.test_phase2a import _lan_scan, _post_coverage, _start_lan
    from tests.scale_s2.workloads import build_workload

    workload = build_workload(WORKLOADS["tiny"])
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(
            client,
            token,
            world,
            name="S2A HTTP",
            network_ids=[world["net1"]["id"]],
            stage_config={
                "discovery": True,
                "port_mode": "common",
                "fingerprint": True,
                "vulnerability": True,
                "nuclei_severities": "critical,high,medium",
                "nuclei_tags": "",
            },
        )
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        headers = _agent_headers(world["agent1"])
        devices = []
        findings = []
        coverage = []
        for index, report in enumerate(workload.devices):
            ip = f"10.1.0.{10 + index}"
            hostname = f"s2a-http-{index:02d}"
            devices.append({"ip": ip, "scope": "lan", "hostname": hostname, "ports": report.ports})
            coverage.append(ip)
            finding = workload.findings[index]
            findings.append(
                {
                    "template_id": finding.template_id,
                    "name": finding.name,
                    "severity": finding.severity,
                    "host": f"https://{ip}",
                    "matched_at": f"https://{ip}/",
                    "tags": finding.tags,
                    "raw": {
                        "template-id": finding.template_id,
                        "host": f"https://{ip}",
                        "matched-at": f"https://{ip}/",
                        "info": {"name": finding.name, "severity": finding.severity, "tags": ["s2a"]},
                    },
                }
            )
        device_bytes = len(json.dumps(devices, separators=(",", ":")).encode())
        finding_bytes = len(json.dumps(findings, separators=(",", ":")).encode())
        first_devices = client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=headers,
            json=devices,
        )
        assert first_devices.status_code == 200, first_devices.text
        _post_coverage(client, world, job_id, coverage)
        first_findings = client.post(
            f"/api/agent/jobs/{job_id}/findings",
            headers=headers,
            json=findings,
        )
        assert first_findings.status_code == 200, first_findings.text
        db = SessionLocal()
        try:
            once = capture_normalized_state(db, world["tenant"]["id"])
        finally:
            db.close()
        replay_devices = client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=headers,
            json=devices,
        )
        assert replay_devices.status_code == 200, replay_devices.text
        _post_coverage(client, world, job_id, coverage)
        replay_findings = client.post(
            f"/api/agent/jobs/{job_id}/findings",
            headers=headers,
            json=findings,
        )
        assert replay_findings.status_code == 200, replay_findings.text
        assert replay_devices.json()["new_devices"] == 0
        assert replay_findings.json()["added"] == 0
        db = SessionLocal()
        try:
            twice = capture_normalized_state(db, world["tenant"]["id"])
        finally:
            db.close()
        assert_equivalent(once, twice, label="HTTP endpoint replay")
        assert device_bytes > 0
        assert finding_bytes > 0
        assert once["devices"]
        assert once["findings"]
