"""S2D: bounded, replay-safe Device/Finding/coverage transport."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.ingest_chunks import (
    DEFAULT_INGEST_MAX_BYTES,
    DEFAULT_INGEST_MAX_ROWS,
    IngestLimitError,
    encoded_list_bytes,
    iter_ingest_chunks,
    validate_ingest_batch,
)
from app.models import EVALUATION_CLEAN, AssetFindingRunEvaluation, ScanJob
from tests.conftest import requires_postgres
from tests.scale_s2.constants import CHUNKED_INGEST_PATH, WORKLOADS
from tests.scale_s2.harness import (
    counts_from_state,
    hotspot_flags,
    ingest_chunked_path,
    ingest_current_path,
    prepare_and_ingest,
    prepare_and_ingest_chunked,
)
from tests.scale_s2.snapshot import assert_equivalent, capture_normalized_state
from tests.scale_s2.workloads import build_workload
from tests.scale_s2.world import create_ingest_world, reset_schema, seed_historical_findings

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = REPO_ROOT / "scan_runtime"


def test_s2d_path_label():
    assert CHUNKED_INGEST_PATH == "s2d_chunked_transport"


def test_s2d_has_no_schema_revision():
    versions = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    names = [path.name for path in versions.glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_chunker_rejects_single_record_over_byte_limit():
    rows = [{"raw": "x" * 2000}]
    with pytest.raises(IngestLimitError, match="single device record exceeds"):
        list(iter_ingest_chunks(rows, max_rows=100, max_bytes=500, kind="device"))
    with pytest.raises(IngestLimitError, match="single finding record exceeds"):
        validate_ingest_batch(rows, kind="finding", max_rows=100, max_bytes=500)


def test_chunker_splits_on_rows_and_encoded_bytes():
    rows = [{"n": index, "pad": "a" * 20} for index in range(10)]
    by_rows = list(iter_ingest_chunks(rows, max_rows=3, max_bytes=10_000, kind="device"))
    assert [len(chunk) for chunk in by_rows] == [3, 3, 3, 1]
    for chunk in by_rows:
        assert len(chunk) <= 3
        assert encoded_list_bytes(chunk) <= 10_000
    by_bytes = list(iter_ingest_chunks(rows, max_rows=100, max_bytes=120, kind="device"))
    assert len(by_bytes) > 1
    for chunk in by_bytes:
        assert encoded_list_bytes(chunk) <= 120


def test_default_limits_still_accept_small_whole_list():
    rows = [{"ip": f"10.0.0.{index}", "hostname": f"host-{index}"} for index in range(100)]
    validate_ingest_batch(
        rows,
        kind="device",
        max_rows=DEFAULT_INGEST_MAX_ROWS,
        max_bytes=DEFAULT_INGEST_MAX_BYTES,
    )


def test_validate_rejects_over_row_and_byte_batch():
    with pytest.raises(IngestLimitError, match="device batch exceeds 2-row limit"):
        validate_ingest_batch([{"a": 1}, {"b": 2}, {"c": 3}], kind="device", max_rows=2, max_bytes=10_000)
    rows = [{"pad": "z" * 80}, {"pad": "y" * 80}]
    with pytest.raises(IngestLimitError, match="finding batch exceeds 100-byte limit"):
        validate_ingest_batch(rows, kind="finding", max_rows=10, max_bytes=100)


def test_submit_normalized_preserves_order_and_chunks(monkeypatch):
    monkeypatch.setenv("INGEST_MAX_ROWS", "2")
    monkeypatch.setenv("INGEST_MAX_BYTES", str(DEFAULT_INGEST_MAX_BYTES))
    if str(RUNTIME_ROOT) not in sys.path:
        sys.path.insert(0, str(RUNTIME_ROOT))
    from job_finish import submit_normalized

    devices: list[list] = []
    findings: list[list] = []
    coverage: list[dict] = []
    submit_normalized(
        provenance_fn=None,
        devices_fn=devices.append,
        coverage_fn=coverage.append,
        findings_fn=findings.append,
        result={
            "devices": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}],
            "findings": [{"template_id": "a"}, {"template_id": "b"}, {"template_id": "c"}],
            "detector_coverage": [{"detector_type": "nuclei", "targets": ["h1", "h2", "h3", "h4"]}],
        },
    )
    assert [len(chunk) for chunk in devices] == [2, 1]
    assert [len(chunk) for chunk in findings] == [2, 1]
    assert [row["targets"] for row in coverage] == [["h1", "h2"], ["h3", "h4"]]
    assert devices[0][0]["ip"] == "10.0.0.1"


@requires_postgres
def test_s2d_single_equals_n_chunks_replay_and_isolated(reset_db):
    from app.database import SessionLocal

    reset_schema()
    db = SessionLocal()
    try:
        single = prepare_and_ingest(db, WORKLOADS["small"], replay=False)
        single_state = single["state"]
        assert single_state["scan_jobs"][0]["status"] == "done"
        assert single_state["scan_jobs"][0]["findings_count"] == 100
        assert single_state["scan_jobs"][0]["hosts_found"] == 100
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        chunked = prepare_and_ingest_chunked(db, WORKLOADS["small"], replay=False)
        chunked_state = chunked["state"]
        metrics = chunked["metrics"]
        hotspots = hotspot_flags(metrics)
        counts = counts_from_state(chunked_state)
        assert_equivalent(single_state, chunked_state, label="s2d single vs N chunks")
        assert counts["assets"] == 100
        assert counts["devices"] == 100
        assert counts["findings"] == 100
        assert counts["scan_run_detector_coverage"] == 200
        assert chunked_state["scan_jobs"][0]["findings_count"] == 100
        assert chunked_state["scan_jobs"][0]["hosts_found"] == 100
        assert metrics.path == CHUNKED_INGEST_PATH
        assert metrics.device_chunks > 1
        assert metrics.finding_chunks > 1
        assert metrics.coverage_chunks > 1
        assert metrics.finding_index_preloads == (
            metrics.finding_chunks + metrics.coverage_chunks + 1
        )
        assert metrics.finding_index_preload_selects >= metrics.finding_index_preloads
        assert metrics.finding_index_preload_wall_ms >= 0
        assert metrics.finding_index_preload_peak_rss_bytes > 0
        assert hotspots["device_asset_selects_collapsed"] is True
        ingest_chunked_path(db, chunked["world"], chunked["workload"], collect_metrics=False)
        replay_state = capture_normalized_state(db, chunked["world"].tenant_id)
        assert_equivalent(chunked_state, replay_state, label="s2d same-run chunk replay")
        assert replay_state["scan_jobs"][0]["findings_count"] == 100
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        isolated = prepare_and_ingest_chunked(db, WORKLOADS["small"], replay=False)
        assert_equivalent(single_state, isolated["state"], label="s2d isolated chunked ingest")
    finally:
        db.close()


@requires_postgres
def test_s2d_interrupted_then_retried_chunks_match_single(reset_db):
    from app.database import SessionLocal

    reset_schema()
    db = SessionLocal()
    try:
        single = prepare_and_ingest(db, WORKLOADS["tiny"], replay=False)
        single_state = single["state"]
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        workload = build_workload(WORKLOADS["tiny"])
        world = create_ingest_world(db, label="s2d-interrupt")
        seed_historical_findings(db, world, workload)
        partial = ingest_chunked_path(
            db,
            world,
            workload,
            complete=False,
            max_rows=3,
            max_finding_chunks=1,
        )
        job = db.get(ScanJob, world.job_id)
        assert job is not None
        assert job.status == "running"
        assert job.finished_at is None
        clean = (
            db.query(AssetFindingRunEvaluation)
            .filter(
                AssetFindingRunEvaluation.scan_job_id == world.job_id,
                AssetFindingRunEvaluation.outcome == EVALUATION_CLEAN,
            )
            .count()
        )
        assert clean == 0
        assert job.findings_count == len(partial["finding_chunks"][0])
        ingest_chunked_path(db, world, workload, complete=True, max_rows=3)
        resumed = capture_normalized_state(db, world.tenant_id)
        assert_equivalent(single_state, resumed, label="s2d interrupted then retried chunks")
        assert resumed["scan_jobs"][0]["status"] == "done"
        assert resumed["scan_jobs"][0]["findings_count"] == 8
    finally:
        db.close()


@requires_postgres
def test_s2d_duplicate_records_at_chunk_boundary_keep_counters(reset_db):
    from dataclasses import replace

    from app.database import SessionLocal

    reset_schema()
    db = SessionLocal()
    try:
        workload = build_workload(WORKLOADS["tiny"])
        devices = list(workload.devices)
        findings = list(workload.findings)
        devices.insert(3, devices[2])
        findings.insert(3, findings[2])
        mutated = replace(workload, devices=devices, findings=findings)
        world = create_ingest_world(db, label="s2d-dup")
        seed_historical_findings(db, world, mutated)
        ingest_chunked_path(db, world, mutated, complete=True, max_rows=3)
        state = capture_normalized_state(db, world.tenant_id)
        counts = counts_from_state(state)
        assert counts["devices"] == 8
        assert counts["assets"] == 8
        assert counts["findings"] == 8
        assert counts["asset_observations"] == 8
        assert counts["asset_correlation_decisions"] == 8
        assert state["scan_jobs"][0]["hosts_found"] == 8
        assert state["scan_jobs"][0]["findings_count"] == 8
    finally:
        db.close()


@requires_postgres
def test_s2d_cancel_during_chunking_blocks_clean(reset_db):
    from app.database import SessionLocal
    from app.finding_lifecycle import FindingLifecycleError, complete_scan_run

    reset_schema()
    db = SessionLocal()
    try:
        workload = build_workload(WORKLOADS["tiny"])
        world = create_ingest_world(db, label="s2d-cancel")
        seed_historical_findings(db, world, workload)
        ingest_chunked_path(db, world, workload, complete=False, max_rows=3, max_finding_chunks=1)
        job = db.get(ScanJob, world.job_id)
        assert job is not None
        job.cancel_requested_at = datetime.now(timezone.utc)
        db.commit()
        job = db.get(ScanJob, world.job_id)
        with pytest.raises(FindingLifecycleError, match="Cancelled or expired"):
            complete_scan_run(db, job, ok=True)
        db.rollback()
        job = db.get(ScanJob, world.job_id)
        complete_scan_run(db, job, ok=False, error="scan cancelled")
        db.commit()
        job = db.get(ScanJob, world.job_id)
        assert job.status == "cancelled"
        clean = (
            db.query(AssetFindingRunEvaluation)
            .filter(
                AssetFindingRunEvaluation.scan_job_id == world.job_id,
                AssetFindingRunEvaluation.outcome == EVALUATION_CLEAN,
            )
            .count()
        )
        assert clean == 0
    finally:
        db.close()


@requires_postgres
def test_s2d_http_rejects_oversize_batch_and_record(reset_db):
    from tests.test_phase1d import _agent_headers, _client, _headers, _login, _world
    from tests.test_phase2a import _lan_scan, _start_lan

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(
            client,
            token,
            world,
            name="S2D limits",
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
        too_many = [
            {"ip": f"10.9.{index // 250}.{index % 250}", "scope": "lan", "hostname": f"over-{index}"}
            for index in range(DEFAULT_INGEST_MAX_ROWS + 1)
        ]
        over_rows = client.post(f"/api/agent/jobs/{job_id}/devices", headers=headers, json=too_many)
        assert over_rows.status_code == 413, over_rows.text
        assert "row limit" in over_rows.json()["detail"]
        huge = {
            "template_id": "huge",
            "name": "huge",
            "severity": "info",
            "host": "https://10.9.0.1",
            "matched_at": "https://10.9.0.1/",
            "raw": {"blob": "x" * (DEFAULT_INGEST_MAX_BYTES + 1)},
        }
        over_record = client.post(
            f"/api/agent/jobs/{job_id}/findings",
            headers=headers,
            json=[huge],
        )
        assert over_record.status_code == 413, over_record.text
        assert "single finding record exceeds" in over_record.json()["detail"]
        ok = client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=headers,
            json=[{"ip": "10.9.0.8", "scope": "lan", "hostname": "s2d-ok"}],
        )
        assert ok.status_code == 200, ok.text
        job = client.get(f"/api/jobs/{job_id}", headers=_headers(token))
        if job.status_code == 200:
            assert job.json().get("status") != "done"
