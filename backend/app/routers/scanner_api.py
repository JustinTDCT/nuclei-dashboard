from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.finding_lifecycle import FindingLifecycleError, complete_scan_run, store_detector_coverage
from app.ingest_chunks import raise_ingest_limit
from app.inventory import store_findings, upsert_devices
from app.job_progress import apply_worker_progress
from app.jobs import fail_job, job_payload
from app.locality import LanScanInvalidError
from app.models import JOB_QUEUED, JOB_RUNNING, LEGACY_PRE_1D_REQUEUE_ERROR, Device, ScanJob
from app.scan_dispatch import CENTRAL_WORKER, atomic_claim_central_job
from app.job_control import job_control_payload
from app.scan_execution import require_owned_run_for_persist, run_scope, snapshot_scope_clause
from app.scan_security import ExecutionBlocked, revalidate_wan_start
from app.raw_artifacts import (
    ArtifactError,
    apply_raw_evidence_declaration,
    commit_ingested_artifact,
    ingest_upload_file,
    raise_http,
    serialize_artifact,
)
from app.scan_snapshot import merge_provenance
from app.scanner_versions import VersionProvenanceError, apply_version_provenance_requirement, merge_run_provenance
from app.schemas import (
    DetectorCoverageIn,
    DeviceReport,
    FindingReport,
    RawEvidenceDeclaration,
    ScanArtifactOut,
    WorkerProgressIn,
)

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
    claimed = atomic_claim_central_job(db, job.id, now=_now())
    if claimed is None:
        raise HTTPException(status_code=404, detail="Job not available")
    claimed.runtime_provenance = merge_provenance(claimed.runtime_provenance, {"worker": CENTRAL_WORKER})
    db.commit()
    return job_payload(db, claimed)


@router.post("/jobs/{job_id}/devices")
def post_devices(
    job_id: int,
    body: list[DeviceReport],
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    raise_ingest_limit(body, kind="device")
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
    raise_ingest_limit(body.targets, kind="coverage")
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
    raise_ingest_limit(body, kind="finding")
    added = store_findings(db, job.tenant_id, job.id, run_scope(job), body)
    job.findings_count = (job.findings_count or 0) + added
    db.commit()
    return {"ok": True, "added": added}


@router.post("/jobs/{job_id}/complete")
def complete_job(
    job_id: int,
    ok: bool = True,
    error: str | None = None,
    raw_evidence: RawEvidenceDeclaration | None = None,
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id, completing_ok=ok)
    try:
        apply_raw_evidence_declaration(db, job, ok=ok, declaration=raw_evidence)
        apply_version_provenance_requirement(job, ok=ok)
        complete_scan_run(db, job, ok=ok, error=error)
    except FindingLifecycleError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    except ArtifactError as exc:
        db.rollback()
        raise_http(exc)
    except VersionProvenanceError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
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
    job.runtime_provenance = merge_run_provenance(job.runtime_provenance, body)
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
        ingested = ingest_upload_file(
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
    commit_ingested_artifact(db, ingested)
    return serialize_artifact(ingested.artifact)


@router.get("/jobs/{job_id}")
def job_status(job_id: int, _: None = Depends(require_scanner), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.claimed_by == "central").first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not available")
    payload = job_control_payload(job)
    payload["owned_running"] = job.status == JOB_RUNNING
    return payload


@router.post("/jobs/{job_id}/progress")
def post_progress(
    job_id: int,
    body: WorkerProgressIn,
    _: None = Depends(require_scanner),
    db: Session = Depends(get_db),
):
    job = _owned(db, job_id)
    apply_worker_progress(job, body.model_dump(), activity=body.activity or "scanning")
    db.commit()
    return {"ok": True}


def _owned(db: Session, job_id: int, *, completing_ok: bool | None = None) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.claimed_by == "central").first()
    try:
        if completing_ok is None:
            return require_owned_run_for_persist(job, claimed_by="central")
        return require_owned_run_for_persist(job, claimed_by="central", completing_ok=completing_ok)
    except ExecutionBlocked as exc:
        raise HTTPException(status_code=409, detail=exc.detail or "Job is not an active Phase 1D run") from None
