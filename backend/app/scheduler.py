import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.events import emit_scan_missed_unavailable_agent
from app.jobs import due_scans, fail_pending_legacy_pre_1d_jobs, queue_scheduled_run
from app.lifecycle import mark_inactive_assets
from app.locality import LanScanInvalidError
from app.models import JOB_WAITING_FOR_AGENT, Device, ScanJob
from app.scan_dispatch import mark_job_missed, utcnow
from app.settings_store import get_settings

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def tick_schedules() -> None:
    db: Session = SessionLocal()
    try:
        expire_waiting_jobs(db)
        if fail_pending_legacy_pre_1d_jobs(db):
            db.commit()
        for scan in due_scans(db):
            try:
                job = queue_scheduled_run(db, scan)
            except LanScanInvalidError as exc:
                db.rollback()
                log.warning("Skipping scheduled scan %s: %s", scan.id, exc.detail)
                continue
            db.commit()
            if job:
                log.info("Queued scheduled job for scan %s", scan.id)
    except Exception:
        log.exception("Schedule tick failed")
        db.rollback()
    finally:
        db.close()


def expire_waiting_jobs(db: Session) -> None:
    now = utcnow()
    waiting = (
        db.query(ScanJob)
        .filter(ScanJob.status == JOB_WAITING_FOR_AGENT, ScanJob.wait_expires_at.isnot(None), ScanJob.wait_expires_at <= now)
        .all()
    )
    for job in waiting:
        mark_job_missed(db, job, "No healthy eligible agent before wait expiry")
        emit_scan_missed_unavailable_agent(db, job)
    if waiting:
        db.commit()


def mark_stale_devices() -> None:
    db: Session = SessionLocal()
    try:
        days = int(get_settings(db).get("stale_days") or 14)
        cutoff = _now() - timedelta(days=days)
        q = db.query(Device).filter(Device.status != "stale", Device.last_seen < cutoff)
        updated = q.update({Device.status: "stale"}, synchronize_session=False)
        db.commit()
        if updated:
            log.info("Marked %s devices stale", updated)
    except Exception:
        log.exception("Stale device pass failed")
        db.rollback()
    finally:
        db.close()


def expire_stuck_jobs() -> None:
    db: Session = SessionLocal()
    try:
        minutes = int(get_settings(db).get("job_timeout_minutes") or 180)
        cutoff = _now() - timedelta(minutes=max(30, minutes))
        q = db.query(ScanJob).filter(ScanJob.status == "running", ScanJob.started_at < cutoff)
        jobs = q.all()
        for job in jobs:
            job.status = "failed"
            job.finished_at = _now()
            job.error = job.error or f"Timed out after {minutes} minutes with no completion"
        if jobs:
            db.commit()
            log.info("Expired %s stuck running jobs", len(jobs))
    except Exception:
        log.exception("Stuck job pass failed")
        db.rollback()
    finally:
        db.close()


def refresh_vulnerability_intelligence() -> None:
    """Single API process owns APScheduler; PostgreSQL advisory locks still gate overlap."""
    db: Session = SessionLocal()
    try:
        from app.intel.sync import refresh_due_sources

        refresh_due_sources(db)
    except Exception:
        log.exception("Vulnerability intelligence refresh failed")
        db.rollback()
    finally:
        db.close()


def recalculate_finding_age_priority() -> None:
    db: Session = SessionLocal()
    try:
        from app.intel.priority import recalculate_age_bucket_changes

        recalculate_age_bucket_changes(db)
        db.commit()
    except Exception:
        log.exception("Finding age priority pass failed")
        db.rollback()
    finally:
        db.close()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(tick_schedules, "interval", seconds=30, id="schedules", replace_existing=True)
    scheduler.add_job(mark_stale_devices, "interval", minutes=30, id="stale", replace_existing=True)
    scheduler.add_job(mark_inactive_assets, "interval", minutes=30, id="asset-inactive", replace_existing=True)
    scheduler.add_job(expire_stuck_jobs, "interval", minutes=5, id="stuck-jobs", replace_existing=True)
    scheduler.add_job(
        refresh_vulnerability_intelligence,
        "interval",
        minutes=15,
        id="vuln-intel",
        replace_existing=True,
    )
    scheduler.add_job(
        recalculate_finding_age_priority,
        "interval",
        hours=12,
        id="finding-age-priority",
        replace_existing=True,
    )
    scheduler.start()
