from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_any, require_user
from app.database import get_db
from app.jobs import create_job, has_active_job
from app.models import Agent, Scan, ScanJob, Subnet, Tenant, User
from app.schemas import ScanIn, ScanJobOut, ScanOut

router = APIRouter(tags=["scans"])


def _tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _validate_scan(db: Session, tenant_id: int, body: ScanIn) -> None:
    if body.scope == "lan" and not body.agent_id:
        raise HTTPException(status_code=400, detail="LAN scans require an agent")
    if body.agent_id:
        agent = db.query(Agent).filter(Agent.id == body.agent_id, Agent.tenant_id == tenant_id).first()
        if not agent:
            raise HTTPException(status_code=400, detail="Agent not found for tenant")
    if body.subnet_ids:
        count = (
            db.query(Subnet)
            .filter(
                Subnet.tenant_id == tenant_id,
                Subnet.scope == body.scope,
                Subnet.id.in_(body.subnet_ids),
            )
            .count()
        )
        if count != len(body.subnet_ids):
            raise HTTPException(status_code=400, detail="One or more subnets are invalid for this scope")


def job_out(job: ScanJob) -> ScanJobOut:
    out = ScanJobOut.model_validate(job)
    out.scan_name = job.scan.name if job.scan else None
    out.scope = job.scan.scope if job.scan else None
    return out


@router.get("/tenants/{tenant_id}/scans", response_model=list[ScanOut])
def list_scans(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    _tenant(db, tenant_id)
    return db.query(Scan).filter(Scan.tenant_id == tenant_id).order_by(Scan.name).all()


@router.post("/tenants/{tenant_id}/scans", response_model=ScanOut)
def create_scan(tenant_id: int, body: ScanIn, _: User = Depends(require_user), db: Session = Depends(get_db)):
    _tenant(db, tenant_id)
    _validate_scan(db, tenant_id, body)
    scan = Scan(tenant_id=tenant_id, **body.model_dump())
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(scan_id: int, body: ScanIn, _: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _validate_scan(db, scan.tenant_id, body)
    for key, value in body.model_dump().items():
        setattr(scan, key, value)
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"ok": True}


@router.post("/scans/{scan_id}/run", response_model=ScanJobOut)
def run_scan(scan_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if has_active_job(db, scan.id):
        raise HTTPException(status_code=409, detail="A job is already queued or running")
    return job_out(create_job(db, scan))


@router.get("/tenants/{tenant_id}/jobs", response_model=list[ScanJobOut])
def list_jobs(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    _tenant(db, tenant_id)
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.tenant_id == tenant_id)
        .order_by(ScanJob.created_at.desc())
        .limit(100)
        .all()
    )
    return [job_out(j) for j in jobs]


@router.get("/jobs", response_model=list[ScanJobOut])
def list_all_jobs(_: User = Depends(require_any), db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(50).all()
    return [job_out(j) for j in jobs]
