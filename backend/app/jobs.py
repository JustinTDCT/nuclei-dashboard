from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.locality import lan_cidrs_for_scan
from app.models import Scan, ScanJob, Subnet


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_job(db: Session, scan: Scan) -> ScanJob:
    job = ScanJob(scan_id=scan.id, tenant_id=scan.tenant_id, status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def job_payload(db: Session, job: ScanJob) -> dict:
    scan = job.scan
    subnet_ids = scan.subnet_ids or []
    if scan.scope == "lan":
        cidrs = lan_cidrs_for_scan(db, scan.tenant_id, scan.agent, subnet_ids) if scan.agent else []
    else:
        q = db.query(Subnet).filter(Subnet.tenant_id == scan.tenant_id, Subnet.scope == "wan")
        if subnet_ids:
            q = q.filter(Subnet.id.in_(subnet_ids))
        cidrs = [s.cidr for s in q.all()]
    return {
        "job_id": job.id,
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "scope": scan.scope,
        "profile": scan.profile,
        "nuclei_severities": scan.nuclei_severities,
        "nuclei_tags": scan.nuclei_tags,
        "cidrs": cidrs,
    }


def has_active_job(db: Session, scan_id: int) -> bool:
    return (
        db.query(ScanJob)
        .filter(ScanJob.scan_id == scan_id, ScanJob.status.in_(["queued", "running"]))
        .first()
        is not None
    )


def due_scans(db: Session) -> list[Scan]:
    now = _now()
    scans = db.query(Scan).filter(Scan.is_enabled.is_(True), Scan.interval_minutes.isnot(None)).all()
    ready = []
    for scan in scans:
        if scan.interval_minutes is None or scan.interval_minutes <= 0:
            continue
        if has_active_job(db, scan.id):
            continue
        if scan.last_scheduled_at is None:
            ready.append(scan)
            continue
        last = scan.last_scheduled_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed = (now - last).total_seconds() / 60
        if elapsed >= scan.interval_minutes:
            ready.append(scan)
    return ready
