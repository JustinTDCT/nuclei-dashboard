from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.finding_lifecycle import FindingLifecycleError, complete_scan_run, store_detector_coverage
from app.inventory import store_findings, upsert_devices
from app.jobs import fail_job, job_payload
from app.locality import LanScanInvalidError
from app.models import JOB_QUEUED, LEGACY_PRE_1D_REQUEUE_ERROR, Device, ScanJob
from app.scan_dispatch import CENTRAL_WORKER
from app.scan_execution import require_active_phase1d_run, run_scope, snapshot_scope_clause
from app.scan_security import ExecutionBlocked, revalidate_wan_start
from app.raw_artifacts import ArtifactError, ingest_upload_file, raise_http, serialize_artifact
from app.scan_snapshot import merge_provenance
from app.schemas import DetectorCoverageIn, DeviceReport, FindingReport, ScanArtifactOut

router = APIRouter(prefix="/internal/scanner", tags=["scanner"])


def require_scanner(x_scanner_token: str | None = Header(default=None)) -> None:
    if not x_scanner_token or x_scanner_token != settings.scanner_token:
        raise HTTPException(status_code=401, detail="Invalid scanner token")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/jobs")
def poll_jobs(_: None = Depends(require_scanner), db: Session = Depends(get_db)):
    jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.status == JOB_QUEUED,
            ScanJob.execution_snapshot.isnot(None),
            snapshot_scope_clause("wan"),
        )
        .order_by(ScanJob.created_at.asc())
        .limit(5)
        .all()
    )
    payloads = []
    for job in jobs:
        try:
            if not job.execution_snapshot:
                fail_job(db, job, LEGACY_PRE_1D_REQUEUE_ERROR)
                continue
            revalidate_wan_start(db, job)
            payloads.append(job_payload(db, job))
        except (ExecutionBlocked, LanScanInvalidError) as exc:
            fail_job(db, job, exc.detail)
    return payloads


@router.post("/jobs/{job_id}/start")
def start_job(job_id: int, _: None = Depends(require_scanner), db: Session = Depends(get_db)):
    job = (
        db.query(ScanJob)
        .filter(
            ScanJob.id == job_id,
            ScanJob.status == JOB_QUEUED,
            ScanJob.execution_snapshot.isnot(None),
            snapshot_scope_clause("wan"),
        )
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Job not available")
    try:
        if run_scope(job) != "wan":
            raise HTTPException(status_code=404, detail="Job not available")
    except ExecutionBlocked:
        raise HTTPException(status_code=404, detail="Job not available") from None
    try:
        if not job.execution_snapshot:
            fail_job(db, job, LEGACY_PRE_1D_REQUEUE_ERROR)
            raise HTTPException(status_code=409, detail=LEGACY_PRE_1D_REQUEUE_ERROR)
        revalidate_wan_start(db, job)
        payload = job_payload(db, job)
    except (ExecutionBlocked, LanScanInvalidError) as exc:
        fail_job(db, job, exc.detail)
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    job.status = "running"
    job.claimed_by = CENTRAL_WORKER
    job.started_at = _now()
    job.runtime_provenance = merge_provenance(job.runtime_provenance, {"worker": CENTRAL_WORKER})
    db.commit()
    return payload


@router.post("/jobs/{job_id}/devices")
def post_devices(
    job_id: int,
    body: list[DeviceReport],
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    created, _ = upsert_devices(db, job.tenant_id, job.id, body)
    job.hosts_found = db.query(Device).filter(Device.last_scan_job_id == job.id).count()
    db.commit()
    return {"ok": True, "new_devices": created, "hosts_found": job.hosts_found}


@router.post("/jobs/{job_id}/detector-coverage")
def post_detector_coverage(
    job_id: int,
    body: DetectorCoverageIn,
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    added = store_detector_coverage(db, job, detector_type=body.detector_type, targets=body.targets)
    db.commit()
    return {"ok": True, "added": added}


@router.post("/jobs/{job_id}/findings")
def post_findings(
    job_id: int,
    body: list[FindingReport],
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    added = store_findings(db, job.tenant_id, job.id, run_scope(job), body)
    job.findings_count = (job.findings_count or 0) + added
    db.commit()
    return {"ok": True, "added": added}


@router.post("/jobs/{job_id}/complete")
def complete_job(
    job_id: int,
    ok: bool = True,
    error: str | None = None,
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    try:
        complete_scan_run(db, job, ok=ok, error=error)
    except FindingLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    db.commit()
    return {"ok": True, "status": job.status}


@router.post("/jobs/{job_id}/provenance")
def post_provenance(
    job_id: int,
    body: dict,
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    job.runtime_provenance = merge_provenance(job.runtime_provenance, body)
    db.commit()
    return {"ok": True}


@router.post("/jobs/{job_id}/artifacts", response_model=ScanArtifactOut)
def post_artifact(
    job_id: int,
    file: UploadFile = File(...),
    artifact_key: str = Form(...),
    stage: str = Form(...),
    tool: str = Form(...),
    media_type: str = Form("application/x-ndjson"),
    content_encoding: str = Form("gzip"),
    provenance: str = Form(""),
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    try:
        artifact = ingest_upload_file(
            db,
            job,
            upload=file,
            artifact_key=artifact_key,
            stage=stage,
            tool=tool,
            media_type=media_type,
            content_encoding=content_encoding,
            provenance=provenance,
        )
    except ArtifactError as exc:
        raise_http(exc)
    db.commit()
    return serialize_artifact(artifact)


def _owned(db: Session, job_id: int) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.claimed_by == "central").first()
    try:
        return require_active_phase1d_run(job, claimed_by="central")
    except ExecutionBlocked:
        raise HTTPException(status_code=409, detail="Job is not an active Phase 1D run") from None
