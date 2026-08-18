from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.locality import LanScanInvalidError
from app.models import (
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_WAITING_FOR_AGENT,
    SCHEDULE_MANUAL,
    SNAPSHOT_LEGACY_PRE_1D,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    Scan,
    ScanJob,
    Subnet,
)
from app.scan_definitions import DEFINITION_ERRORS, ScanDefinitionError, create_run, validate_definition
from app.scan_schedule import next_future_after_catchup, next_occurrence
from app.scan_snapshot import SnapshotError, job_payload_from_snapshot
from app.locality import lan_cidrs_for_scan


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_job(
    db: Session,
    scan: Scan,
    *,
    trigger_type: str = TRIGGER_MANUAL,
    scheduled_for: datetime | None = None,
    commit: bool = True,
) -> ScanJob:
    try:
        job = create_run(db, scan, trigger_type=trigger_type, scheduled_for=scheduled_for)
    except DEFINITION_ERRORS as exc:
        raise LanScanInvalidError(getattr(exc, "detail", str(exc))) from exc
    if commit:
        db.commit()
        db.refresh(job)
    else:
        db.flush()
    return job


def fail_job(db: Session, job: ScanJob, detail: str) -> ScanJob:
    already_running = job.status == JOB_RUNNING
    job.status = "failed"
    job.error = detail
    job.finished_at = _now()
    if not already_running:
        job.claimed_agent_id = None
        job.claimed_by = None
    db.commit()
    db.refresh(job)
    return job


def job_payload(db: Session, job: ScanJob) -> dict:
    if job.execution_snapshot:
        return job_payload_from_snapshot(job)
    return _legacy_job_payload(db, job)


def _legacy_job_payload(db: Session, job: ScanJob) -> dict:
    scan = job.scan
    subnet_ids = scan.subnet_ids or []
    if scan.scope == "lan":
        if not scan.agent:
            raise LanScanInvalidError("LAN scans require an agent")
        cidrs = lan_cidrs_for_scan(db, scan.tenant_id, scan.agent, subnet_ids)
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
        "snapshot_version": job.snapshot_version or SNAPSHOT_LEGACY_PRE_1D,
        "targets": [{"type": "cidr", "value": cidr} for cidr in cidrs],
    }


def has_active_job(db: Session, scan_id: int) -> bool:
    return (
        db.query(ScanJob)
        .filter(
            ScanJob.scan_id == scan_id,
            ScanJob.status.in_([JOB_QUEUED, JOB_RUNNING, JOB_WAITING_FOR_AGENT]),
        )
        .first()
        is not None
    )


def due_scans(db: Session) -> list[Scan]:
    now = _now()
    return (
        db.query(Scan)
        .filter(
            Scan.is_enabled.is_(True),
            Scan.archived_at.is_(None),
            Scan.needs_review.is_(False),
            Scan.next_run_at.isnot(None),
            Scan.next_run_at <= now,
        )
        .order_by(Scan.next_run_at, Scan.id)
        .all()
    )


def queue_scheduled_run(db: Session, scan: Scan) -> ScanJob | None:
    if has_active_job(db, scan.id):
        return None
    try:
        validated = validate_definition(db, scan, for_run=True)
    except DEFINITION_ERRORS as exc:
        raise LanScanInvalidError(getattr(exc, "detail", str(exc))) from exc
    schedule = validated["schedule"]
    if schedule.get("type") == SCHEDULE_MANUAL:
        scan.next_run_at = None
        return None
    due = scan.next_run_at
    if due is None:
        return None
    existing = (
        db.query(ScanJob)
        .filter(ScanJob.scan_id == scan.id, ScanJob.scheduled_for == due)
        .first()
    )
    if existing:
        scan.next_run_at = next_future_after_catchup(
            schedule, tz_name=validated["timezone_name"], now=_now(), due=due
        )
        return None
    job = create_job(
        db,
        scan,
        trigger_type=TRIGGER_SCHEDULED,
        scheduled_for=due,
        commit=False,
    )
    scan.last_scheduled_at = _now()
    scan.next_run_at = next_future_after_catchup(
        schedule, tz_name=validated["timezone_name"], now=_now(), due=due
    )
    return job
