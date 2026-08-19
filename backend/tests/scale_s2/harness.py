"""Current-path ingest runner for S2A. Does not replace production functions."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.finding_lifecycle import complete_scan_run, store_detector_coverage
from app.inventory import store_findings, upsert_devices
from app.models import Device, ScanJob
from tests.scale_s2.constants import CURRENT_INGEST_PATH, WORKLOADS, WorkloadSpec
from tests.scale_s2.metrics import MetricsCollector, encoded_payload_bytes, rss_bytes
from tests.scale_s2.snapshot import assert_equivalent, capture_normalized_state
from tests.scale_s2.workloads import IngestWorkload, build_workload
from tests.scale_s2.world import IngestWorld, create_ingest_world, seed_historical_findings


def ingest_current_path(
    db: Session,
    world: IngestWorld,
    workload: IngestWorkload,
    *,
    collect_metrics: bool = True,
    complete: bool = True,
) -> dict[str, Any]:
    """Execute the authoritative S1 ingest sequence: devices, coverage, findings, complete."""
    job = db.get(ScanJob, world.job_id)
    if job is None:
        raise RuntimeError("S2A world is missing its ScanJob")
    collector = MetricsCollector(path=CURRENT_INGEST_PATH, workload=workload.spec.name, session=db)
    device_bytes = encoded_payload_bytes(workload.devices)
    finding_bytes = encoded_payload_bytes(workload.findings)
    coverage_bytes = encoded_payload_bytes(workload.coverage_targets)
    collector.metrics.device_request_bytes = device_bytes
    collector.metrics.finding_request_bytes = finding_bytes
    collector.metrics.coverage_request_bytes = coverage_bytes
    collector.metrics.agent_held_row_count = (
        len(workload.devices) + len(workload.findings) + len(workload.coverage_targets)
    )
    collector.metrics.peak_agent_rss_bytes = rss_bytes()
    if collect_metrics:
        collector.start()
    try:
        with collector.stage("devices", request_bytes=device_bytes):
            upsert_devices(db, world.tenant_id, world.job_id, workload.devices)
            job.hosts_found = (
                db.query(Device).filter(Device.last_scan_job_id == world.job_id).count()
            )
            db.commit()
            job = db.get(ScanJob, world.job_id)
        with collector.stage("coverage", request_bytes=coverage_bytes):
            store_detector_coverage(
                db,
                job,
                detector_type="nuclei",
                targets=workload.coverage_targets,
            )
            db.commit()
            job = db.get(ScanJob, world.job_id)
        with collector.stage("findings", request_bytes=finding_bytes):
            added = store_findings(db, world.tenant_id, world.job_id, "wan", workload.findings)
            job.findings_count = (job.findings_count or 0) + added
            db.commit()
            job = db.get(ScanJob, world.job_id)
        if complete:
            with collector.stage("complete"):
                complete_scan_run(db, job, ok=True)
                db.commit()
    finally:
        metrics = collector.finish() if collect_metrics else collector.metrics
    return {"metrics": metrics, "world": world}


def prepare_and_ingest(
    db: Session,
    spec: WorkloadSpec,
    *,
    replay: bool = False,
    collect_metrics: bool = True,
) -> dict[str, Any]:
    workload = build_workload(spec)
    world = create_ingest_world(db, label=f"s2a-{spec.name}")
    seed_historical_findings(db, world, workload)
    first = ingest_current_path(db, world, workload, collect_metrics=collect_metrics)
    second = None
    if replay:
        second = ingest_current_path(db, world, workload, collect_metrics=False)
    state = capture_normalized_state(db, world.tenant_id)
    return {
        "world": world,
        "workload": workload,
        "state": state,
        "first": first,
        "second": second,
        "metrics": first["metrics"],
    }


def counts_from_state(state: dict[str, Any]) -> dict[str, int]:
    return {name: len(rows) if isinstance(rows, list) else 0 for name, rows in state.items()}


def hotspot_flags(metrics) -> dict[str, Any]:
    by_table = {(op, table): count for (op, table), count in metrics.by_table.items()}
    service_selects = by_table.get(("SELECT", "asset_services"), 0)
    observation_selects = by_table.get(("SELECT", "asset_observations"), 0)
    device_selects = by_table.get(("SELECT", "devices"), 0)
    finding_selects = by_table.get(("SELECT", "findings"), 0)
    raw_json_scans = sum(
        1
        for sample in metrics.samples
        if sample["table"] == "findings" and "raw_json" in (sample.get("sql") or "").lower()
    )
    return {
        "asset_service_selects": service_selects,
        "asset_observation_selects": observation_selects,
        "device_selects": device_selects,
        "finding_selects": finding_selects,
        "finding_raw_json_select_samples": raw_json_scans,
        "per_port_service_selects": service_selects > 0,
        "per_finding_population_reload": observation_selects > 0 and device_selects > 0,
        "historical_raw_evidence_scan": finding_selects > 0 or raw_json_scans > 0,
    }


def run_equivalence_pair(db_factory, spec: WorkloadSpec) -> dict[str, Any]:
    """Ingest once, then replay the same chunk. Final state must match once-only."""
    from tests.scale_s2.world import reset_schema

    reset_schema()
    db = db_factory()
    try:
        once = prepare_and_ingest(db, spec, replay=False)
        once_state = once["state"]
        once_metrics = once["metrics"]
    finally:
        db.close()

    reset_schema()
    db = db_factory()
    try:
        twice = prepare_and_ingest(db, spec, replay=True)
        twice_state = twice["state"]
    finally:
        db.close()

    assert_equivalent(once_state, twice_state, label=f"{spec.name} once vs replay")
    return {
        "spec": spec.name,
        "once_counts": counts_from_state(once_state),
        "replay_counts": counts_from_state(twice_state),
        "metrics": once_metrics.as_dict(),
        "hotspots": hotspot_flags(once_metrics),
    }


def workload_spec(name: str) -> WorkloadSpec:
    try:
        return WORKLOADS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown S2A workload {name!r}") from exc
