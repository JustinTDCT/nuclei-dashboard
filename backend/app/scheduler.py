import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.jobs import create_job, due_scans
from app.locality import LanScanInvalidError
from app.models import Device, ScanJob
from app.settings_store import get_settings

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def tick_schedules() -> None:
    db: Session = SessionLocal()
    try:
        for scan in due_scans(db):
            try:
                create_job(db, scan)
            except LanScanInvalidError as exc:
                db.rollback()
                log.warning("Skipping scheduled scan %s: %s", scan.id, exc.detail)
                continue
            scan.last_scheduled_at = _now()
            db.commit()
            log.info("Queued scheduled job for scan %s", scan.id)
    except Exception:
        log.exception("Schedule tick failed")
        db.rollback()
    finally:
        db.close()


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


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(tick_schedules, "interval", seconds=30, id="schedules", replace_existing=True)
    scheduler.add_job(mark_stale_devices, "interval", minutes=30, id="stale", replace_existing=True)
    scheduler.add_job(expire_stuck_jobs, "interval", minutes=5, id="stuck-jobs", replace_existing=True)
    scheduler.start()
