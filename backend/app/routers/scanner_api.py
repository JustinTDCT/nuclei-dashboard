from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.inventory import store_findings, upsert_devices
from app.jobs import fail_job, job_payload
from app.models import JOB_QUEUED, Device, Scan, ScanJob
from app.scan_dispatch import CENTRAL_WORKER
from app.scan_security import ExecutionBlocked, revalidate_wan_start
from app.scan_snapshot import merge_provenance
from app.schemas import DeviceReport, FindingReport

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
        .join(Scan, Scan.id == ScanJob.scan_id)
        .filter(ScanJob.status == JOB_QUEUED, Scan.scope == "wan")
        .order_by(ScanJob.created_at.asc())
        .limit(5)
        .all()
    )
    payloads = []
    for job in jobs:
        try:
            if job.execution_snapshot:
                revalidate_wan_start(db, job)
            payloads.append(job_payload(db, job))
        except ExecutionBlocked as exc:
            fail_job(db, job, exc.detail)
    return payloads


@router.post("/jobs/{job_id}/start")
def start_job(job_id: int, _: None = Depends(require_scanner), db: Session = Depends(get_db)):
    job = (
        db.query(ScanJob)
        .join(Scan, Scan.id == ScanJob.scan_id)
        .filter(ScanJob.id == job_id, ScanJob.status == JOB_QUEUED, Scan.scope == "wan")
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Job not available")
    try:
        if job.execution_snapshot:
            revalidate_wan_start(db, job)
        payload = job_payload(db, job)
    except ExecutionBlocked as exc:
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


@router.post("/jobs/{job_id}/findings")
def post_findings(
    job_id: int,
    body: list[FindingReport],
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    added = store_findings(db, job.tenant_id, job.id, job.scan.scope, body)
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
    job.status = "done" if ok else "failed"
    job.error = error
    job.finished_at = _now()
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


def _owned(db: Session, job_id: int) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.claimed_by == "central").first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
