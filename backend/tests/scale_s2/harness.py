"""Current-path ingest runner for S2A. Does not replace production functions."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.finding_lifecycle import complete_scan_run, store_detector_coverage
from app.ingest_chunks import iter_ingest_chunks
from app.inventory import store_findings, upsert_devices
from app.models import Device, ScanJob
from tests.scale_s2.constants import (
    CHUNKED_INGEST_PATH,
    CURRENT_INGEST_PATH,
    S2D_TEST_MAX_BYTES,
    S2D_TEST_MAX_ROWS,
    WORKLOADS,
    WorkloadSpec,
)
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
            prefetch = db.info.get("s2b_prefetch") or {}
            collector.metrics.prefetch_identifier_rows = int(prefetch.get("identifier_rows") or 0)
            collector.metrics.prefetch_address_rows = int(prefetch.get("address_rows") or 0)
            collector.metrics.prefetch_device_rows = int(prefetch.get("device_rows") or 0)
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
        _copy_finding_index_metrics(collector.metrics, db)
    finally:
        metrics = collector.finish() if collect_metrics else collector.metrics
    return {"metrics": metrics, "world": world}


def _copy_finding_index_metrics(metrics, db: Session) -> None:
    info = db.info.get("s2d_finding_index") or {}
    metrics.finding_index_preloads = int(info.get("preloads") or 0)
    metrics.finding_index_preload_selects = int(info.get("preload_selects") or 0)
    metrics.finding_index_preload_wall_ms = float(info.get("preload_wall_ms") or 0.0)
    metrics.finding_index_preload_peak_rss_bytes = int(info.get("preload_peak_rss_bytes") or 0)


def ingest_chunked_path(
    db: Session,
    world: IngestWorld,
    workload: IngestWorkload,
    *,
    collect_metrics: bool = True,
    complete: bool = True,
    max_rows: int = S2D_TEST_MAX_ROWS,
    max_bytes: int = S2D_TEST_MAX_BYTES,
    max_device_chunks: int | None = None,
    max_coverage_chunks: int | None = None,
    max_finding_chunks: int | None = None,
) -> dict[str, Any]:
    """Same production ingest functions as the current path, one bounded chunk at a time."""
    job = db.get(ScanJob, world.job_id)
    if job is None:
        raise RuntimeError("S2D world is missing its ScanJob")
    collector = MetricsCollector(path=CHUNKED_INGEST_PATH, workload=workload.spec.name, session=db)
    device_chunks = list(
        iter_ingest_chunks(list(workload.devices), max_rows=max_rows, max_bytes=max_bytes, kind="device")
    )
    coverage_chunks = list(
        iter_ingest_chunks(
            list(workload.coverage_targets), max_rows=max_rows, max_bytes=max_bytes, kind="coverage"
        )
    )
    finding_chunks = list(
        iter_ingest_chunks(list(workload.findings), max_rows=max_rows, max_bytes=max_bytes, kind="finding")
    )
    if max_device_chunks is not None:
        device_chunks = device_chunks[:max_device_chunks]
    if max_coverage_chunks is not None:
        coverage_chunks = coverage_chunks[:max_coverage_chunks]
    if max_finding_chunks is not None:
        finding_chunks = finding_chunks[:max_finding_chunks]
    collector.metrics.device_chunks = len(device_chunks)
    collector.metrics.coverage_chunks = len(coverage_chunks)
    collector.metrics.finding_chunks = len(finding_chunks)
    collector.metrics.device_request_bytes = sum(encoded_payload_bytes(chunk) for chunk in device_chunks)
    collector.metrics.coverage_request_bytes = sum(
        encoded_payload_bytes(chunk) for chunk in coverage_chunks
    )
    collector.metrics.finding_request_bytes = sum(encoded_payload_bytes(chunk) for chunk in finding_chunks)
    collector.metrics.agent_held_row_count = (
        len(workload.devices) + len(workload.findings) + len(workload.coverage_targets)
    )
    collector.metrics.peak_agent_rss_bytes = rss_bytes()
    if collect_metrics:
        collector.start()
    try:
        for index, chunk in enumerate(device_chunks):
            with collector.stage(f"devices_{index}", request_bytes=encoded_payload_bytes(chunk)):
                upsert_devices(db, world.tenant_id, world.job_id, chunk)
                prefetch = db.info.get("s2b_prefetch") or {}
                collector.metrics.prefetch_identifier_rows = int(prefetch.get("identifier_rows") or 0)
                collector.metrics.prefetch_address_rows = int(prefetch.get("address_rows") or 0)
                collector.metrics.prefetch_device_rows = int(prefetch.get("device_rows") or 0)
                job.hosts_found = (
                    db.query(Device).filter(Device.last_scan_job_id == world.job_id).count()
                )
                db.commit()
                job = db.get(ScanJob, world.job_id)
        for index, chunk in enumerate(coverage_chunks):
            with collector.stage(f"coverage_{index}", request_bytes=encoded_payload_bytes(chunk)):
                store_detector_coverage(db, job, detector_type="nuclei", targets=chunk)
                db.commit()
                job = db.get(ScanJob, world.job_id)
        for index, chunk in enumerate(finding_chunks):
            with collector.stage(f"findings_{index}", request_bytes=encoded_payload_bytes(chunk)):
                added = store_findings(db, world.tenant_id, world.job_id, "wan", chunk)
                job.findings_count = (job.findings_count or 0) + added
                db.commit()
                job = db.get(ScanJob, world.job_id)
        if complete:
            with collector.stage("complete"):
                complete_scan_run(db, job, ok=True)
                db.commit()
        _copy_finding_index_metrics(collector.metrics, db)
    finally:
        metrics = collector.finish() if collect_metrics else collector.metrics
    return {
        "metrics": metrics,
        "world": world,
        "device_chunks": device_chunks,
        "coverage_chunks": coverage_chunks,
        "finding_chunks": finding_chunks,
    }


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


def _stage_table_count(metrics, stage_name: str, op: str, table: str) -> int:
    stages = [
        row
        for row in metrics.stages
        if row.name == stage_name or row.name.startswith(f"{stage_name}_")
    ]
    return sum(int(stage.by_table.get((op, table), 0)) for stage in stages)


def hotspot_flags(metrics) -> dict[str, Any]:
    by_table = {(op, table): count for (op, table), count in metrics.by_table.items()}
    service_selects = by_table.get(("SELECT", "asset_services"), 0)
    observation_selects = by_table.get(("SELECT", "asset_observations"), 0)
    device_selects = by_table.get(("SELECT", "devices"), 0)
    finding_selects = by_table.get(("SELECT", "findings"), 0)
    device_stage_service_selects = _stage_table_count(metrics, "devices", "SELECT", "asset_services")
    device_stage_observation_selects = _stage_table_count(
        metrics, "devices", "SELECT", "asset_observations"
    )
    finding_stage_observation_selects = _stage_table_count(
        metrics, "findings", "SELECT", "asset_observations"
    )
    finding_stage_device_selects = _stage_table_count(metrics, "findings", "SELECT", "devices")
    coverage_stage_coverage_selects = _stage_table_count(
        metrics, "coverage", "SELECT", "scan_run_detector_coverage"
    )
    finding_stage_finding_selects = _stage_table_count(metrics, "findings", "SELECT", "findings")
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
        "device_stage_service_selects": device_stage_service_selects,
        "device_stage_observation_selects": device_stage_observation_selects,
        "finding_stage_observation_selects": finding_stage_observation_selects,
        "finding_stage_device_selects": finding_stage_device_selects,
        "finding_stage_finding_selects": finding_stage_finding_selects,
        "coverage_stage_coverage_selects": coverage_stage_coverage_selects,
        "finding_raw_json_select_samples": raw_json_scans,
        "prefetch_identifier_rows": getattr(metrics, "prefetch_identifier_rows", 0),
        "prefetch_device_rows": getattr(metrics, "prefetch_device_rows", 0),
        "device_chunks": getattr(metrics, "device_chunks", 0),
        "coverage_chunks": getattr(metrics, "coverage_chunks", 0),
        "finding_chunks": getattr(metrics, "finding_chunks", 0),
        "finding_index_preloads": getattr(metrics, "finding_index_preloads", 0),
        "finding_index_preload_selects": getattr(metrics, "finding_index_preload_selects", 0),
        "finding_index_preload_wall_ms": getattr(metrics, "finding_index_preload_wall_ms", 0.0),
        "finding_index_preload_peak_rss_bytes": getattr(
            metrics, "finding_index_preload_peak_rss_bytes", 0
        ),
        "per_port_service_selects": device_stage_service_selects >= 500,
        "device_asset_selects_collapsed": device_stage_service_selects < 20,
        "per_finding_population_reload": finding_stage_observation_selects >= 50
        or finding_stage_device_selects >= 50,
        "historical_raw_evidence_scan": finding_stage_finding_selects >= 80,
        "finding_coverage_selects_collapsed": finding_stage_observation_selects < 10
        and finding_stage_device_selects < 10
        and coverage_stage_coverage_selects < 10,
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


def prepare_and_ingest_chunked(
    db: Session,
    spec: WorkloadSpec,
    *,
    replay: bool = False,
    collect_metrics: bool = True,
    complete: bool = True,
    max_rows: int = S2D_TEST_MAX_ROWS,
    max_bytes: int = S2D_TEST_MAX_BYTES,
    max_device_chunks: int | None = None,
    max_coverage_chunks: int | None = None,
    max_finding_chunks: int | None = None,
) -> dict[str, Any]:
    workload = build_workload(spec)
    world = create_ingest_world(db, label=f"s2d-{spec.name}")
    seed_historical_findings(db, world, workload)
    first = ingest_chunked_path(
        db,
        world,
        workload,
        collect_metrics=collect_metrics,
        complete=complete,
        max_rows=max_rows,
        max_bytes=max_bytes,
        max_device_chunks=max_device_chunks,
        max_coverage_chunks=max_coverage_chunks,
        max_finding_chunks=max_finding_chunks,
    )
    second = None
    if replay:
        second = ingest_chunked_path(
            db,
            world,
            workload,
            collect_metrics=False,
            complete=complete,
            max_rows=max_rows,
            max_bytes=max_bytes,
        )
    state = capture_normalized_state(db, world.tenant_id)
    return {
        "world": world,
        "workload": workload,
        "state": state,
        "first": first,
        "second": second,
        "metrics": first["metrics"],
    }


def workload_spec(name: str) -> WorkloadSpec:
    try:
        return WORKLOADS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown S2A workload {name!r}") from exc
