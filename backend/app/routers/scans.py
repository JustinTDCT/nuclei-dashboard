from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import apply_tenant_scope, require_object_tenant, require_visible_tenant
from app.audit import record_audit, utcnow
from app.auth import require_any, require_user
from app.database import get_db
from app.jobs import create_job, has_active_job
from app.locality import LanScanInvalidError, get_tenant
from app.models import TRIGGER_MANUAL, Scan, ScanJob, User
from app.scan_definitions import (
    DEFINITION_ERRORS,
    ScanDefinitionError,
    apply_scan_payload,
    increment_revision,
    validate_definition,
)
from app.scan_dispatch import resolve_dispatch_policy
from app.schemas import ScanIn, ScanJobOut, ScanOut

router = APIRouter(tags=["scans"])


def serialize_scan(db: Session, scan: Scan) -> ScanOut:
    out = ScanOut.model_validate(scan)
    out.network_ids = [link.network_id for link in scan.network_targets]
    out.wan_target_ids = [link.authorized_wan_target_id for link in scan.wan_target_links]
    out.stage_config = scan.stage_config or {}
    out.intensity_config = scan.intensity_config or {}
    out.schedule_config = scan.schedule_config or {}
    try:
        validated = validate_definition(db, scan, for_run=False)
        if scan.scope == "lan":
            out.dispatch_summary = resolve_dispatch_policy(
                validated["networks"], set(validated["eligible_agent_ids"])
            )
            out.dispatch_summary["eligible_agent_ids"] = validated["eligible_agent_ids"]
            out.dispatch_summary["failover_count"] = max(0, len(validated["eligible_agent_ids"]) - 1)
        else:
            out.dispatch_summary = {"mode": "central", "preferred_agent_id": None}
    except Exception:
        out.dispatch_summary = None
    return out


def job_out(job: ScanJob, *, include_snapshot: bool = False) -> ScanJobOut:
    out = ScanJobOut.model_validate(job)
    out.scan_name = job.scan.name if job.scan else None
    snapshot = job.execution_snapshot or {}
    if snapshot:
        out.scope = snapshot.get("scope")
    else:
        out.scope = job.scan.scope if job.scan else None
    if not include_snapshot:
        out.execution_snapshot = None
    return out


@router.get("/tenants/{tenant_id}/scans", response_model=list[ScanOut])
def list_scans(
    tenant_id: int,
    include_archived: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    require_visible_tenant(db, user, tenant_id)
    q = db.query(Scan).filter(Scan.tenant_id == tenant_id)
    if not include_archived:
        q = q.filter(Scan.archived_at.is_(None))
    return [serialize_scan(db, scan) for scan in q.order_by(Scan.name).all()]


@router.post("/tenants/{tenant_id}/scans", response_model=ScanOut)
def create_scan(tenant_id: int, body: ScanIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    get_tenant(db, tenant_id)
    scan = Scan(tenant_id=tenant_id, name=body.name, scope=body.scope, definition_revision=1)
    db.add(scan)
    db.flush()
    try:
        apply_scan_payload(db, scan, body, creating=True)
    except DEFINITION_ERRORS as exc:
        raise HTTPException(status_code=400, detail=getattr(exc, "detail", str(exc))) from exc
    record_audit(
        db,
        actor=user,
        action="scan_definition.create",
        object_type="scan",
        object_id=scan.id,
        tenant_id=tenant_id,
        site_id=scan.site_id,
        details={"name": scan.name, "scope": scan.scope, "revision": scan.definition_revision},
    )
    db.commit()
    db.refresh(scan)
    return serialize_scan(db, scan)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def read_scan(scan_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    require_object_tenant(db, user, scan, tenant_id=scan.tenant_id if scan else None, detail="Scan not found")
    return serialize_scan(db, scan)


@router.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(scan_id: int, body: ScanIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    before = {"name": scan.name, "revision": scan.definition_revision, "scope": scan.scope}
    try:
        apply_scan_payload(db, scan, body, creating=False)
    except DEFINITION_ERRORS as exc:
        raise HTTPException(status_code=400, detail=getattr(exc, "detail", str(exc))) from exc
    increment_revision(scan)
    record_audit(
        db,
        actor=user,
        action="scan_definition.update",
        object_type="scan",
        object_id=scan.id,
        tenant_id=scan.tenant_id,
        site_id=scan.site_id,
        details={"before": before, "after": {"name": scan.name, "revision": scan.definition_revision}},
    )
    db.commit()
    db.refresh(scan)
    return serialize_scan(db, scan)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    return _archive_scan(db, scan_id, user)


@router.post("/scans/{scan_id}/archive", response_model=ScanOut)
def archive_scan(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    _archive_scan(db, scan_id, user)
    scan = db.get(Scan, scan_id)
    return serialize_scan(db, scan)


def _archive_scan(db: Session, scan_id: int, user: User) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.archived_at is None:
        scan.archived_at = utcnow()
        scan.is_enabled = False
        scan.next_run_at = None
        increment_revision(scan)
        record_audit(
            db,
            actor=user,
            action="scan_definition.archive",
            object_type="scan",
            object_id=scan.id,
            tenant_id=scan.tenant_id,
            site_id=scan.site_id,
            details={"name": scan.name},
        )
        db.commit()
    return {"ok": True, "archived": True}


@router.post("/scans/{scan_id}/run", response_model=ScanJobOut)
def run_scan(scan_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.archived_at is not None:
        raise HTTPException(status_code=400, detail="Archived scan definitions cannot run")
    if has_active_job(db, scan.id):
        raise HTTPException(status_code=409, detail="A job is already queued or running")
    try:
        job = create_job(db, scan, trigger_type=TRIGGER_MANUAL)
    except LanScanInvalidError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    record_audit(
        db,
        actor=user,
        action="scan.run_manual",
        object_type="scan_job",
        object_id=job.id,
        tenant_id=scan.tenant_id,
        site_id=scan.site_id,
        details={"scan_id": scan.id, "revision": scan.definition_revision},
        commit=True,
    )
    return job_out(job)


@router.get("/tenants/{tenant_id}/jobs", response_model=list[ScanJobOut])
def list_jobs(tenant_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    require_visible_tenant(db, user, tenant_id)
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(100)
        .all()
    )
    return [job_out(j) for j in jobs]


@router.get("/jobs", response_model=list[ScanJobOut])
def list_all_jobs(user: User = Depends(require_any), db: Session = Depends(get_db)):
    jobs = (
        apply_tenant_scope(db.query(ScanJob), user, ScanJob.tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(50)
        .all()
    )
    return [job_out(j) for j in jobs]


@router.get("/jobs/{job_id}", response_model=ScanJobOut)
def read_job(job_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    require_object_tenant(db, user, job, tenant_id=job.tenant_id if job else None, detail="Job not found")
    return job_out(job, include_snapshot=True)
