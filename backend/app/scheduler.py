import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import and_, or_
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

# In-process keyset cursor for discovery-metadata catch-up. Reset when a short
# page shows the table walk is complete. Lost on process restart (harmless:
# the next page is idempotent). S3B will relocate this job with the scheduler.
_discovery_metadata_after_id = 0


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
        from app.job_control import cancel_grace, job_timeout_minutes, mark_cancel_requested
        from app.jobs import transition_job_to_cancelled
        from app.models import JOB_RUNNING

        minutes = job_timeout_minutes(db)
        now = _now()
        cutoff = now - timedelta(minutes=minutes)
        grace = cancel_grace()
        jobs = (
            db.query(ScanJob)
            .filter(
                ScanJob.status == JOB_RUNNING,
                or_(
                    and_(ScanJob.deadline_at.isnot(None), ScanJob.deadline_at <= now),
                    and_(ScanJob.deadline_at.is_(None), ScanJob.started_at.isnot(None), ScanJob.started_at < cutoff),
                ),
            )
            .all()
        )
        changed = 0
        for job in jobs:
            reason = job.error or f"Timed out after {minutes} minutes with no completion"
            if job.cancel_requested_at is None:
                mark_cancel_requested(job, now=now, reason=reason)
                changed += 1
                continue
            requested = job.cancel_requested_at
            if requested.tzinfo is None:
                requested = requested.replace(tzinfo=timezone.utc)
            if now - requested >= grace:
                transition_job_to_cancelled(db, job, reason)
                changed += 1
        if changed:
            db.commit()
            log.info("Requested or forced cancel on %s stuck running jobs", changed)
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


def expire_finding_treatments() -> None:
    db: Session = SessionLocal()
    try:
        from app.treatments import expire_due_treatments

        expired = expire_due_treatments(db)
        if expired:
            db.commit()
            log.info("Expired %s finding treatments", expired)
        else:
            db.commit()
    except Exception:
        log.exception("Finding treatment expiration failed")
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


def reset_discovery_metadata_cursor() -> None:
    global _discovery_metadata_after_id
    _discovery_metadata_after_id = 0


def refresh_discovery_metadata_job():
    """One Device keyset page per tick. Never load the whole Device table."""
    global _discovery_metadata_after_id
    from app.inventory import DISCOVERY_METADATA_BATCH_SIZE, refresh_discovery_metadata

    db: Session = SessionLocal()
    try:
        page = refresh_discovery_metadata(
            db,
            batch_size=DISCOVERY_METADATA_BATCH_SIZE,
            after_id=_discovery_metadata_after_id,
        )
        if page.complete:
            _discovery_metadata_after_id = 0
        else:
            _discovery_metadata_after_id = page.last_id
        if page.updated:
            log.info(
                "Discovery metadata page scanned=%s updated=%s last_id=%s complete=%s",
                page.scanned,
                page.updated,
                page.last_id,
                page.complete,
            )
        return page
    except Exception:
        log.exception("Discovery metadata refresh failed")
        db.rollback()
        return None
    finally:
        db.close()


def cleanup_raw_artifacts() -> None:
    db: Session = SessionLocal()
    try:
        from app.raw_artifacts import CLEANUP_BATCH_SIZE, cleanup_expired_artifacts

        cleaned = cleanup_expired_artifacts(db, batch_size=CLEANUP_BATCH_SIZE)
        if cleaned:
            db.commit()
            log.info("Retention-deleted %s raw scan artifacts", cleaned)
        else:
            db.commit()
    except Exception:
        log.exception("Raw artifact retention cleanup failed")
        db.rollback()
    finally:
        db.close()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(tick_schedules, "interval", seconds=30, id="schedules", replace_existing=True)
    scheduler.add_job(mark_stale_devices, "interval", minutes=30, id="stale", replace_existing=True)
    scheduler.add_job(mark_inactive_assets, "interval", minutes=30, id="asset-inactive", replace_existing=True)
    scheduler.add_job(
        refresh_discovery_metadata_job,
        "interval",
        minutes=5,
        id="discovery-metadata",
        replace_existing=True,
    )
    from app.policy import reconcile_asset_handling_job

    scheduler.add_job(
        reconcile_asset_handling_job,
        "interval",
        minutes=20,
        id="policy-reconcile",
        replace_existing=True,
    )
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
    scheduler.add_job(
        expire_finding_treatments,
        "interval",
        minutes=15,
        id="treatment-expiration",
        replace_existing=True,
    )
    from app.alert_engine import process_pending_deliveries_job, route_pending_events_job

    scheduler.add_job(
        route_pending_events_job,
        "interval",
        seconds=15,
        id="alert-routing",
        replace_existing=True,
    )
    scheduler.add_job(
        process_pending_deliveries_job,
        "interval",
        seconds=20,
        id="alert-delivery",
        replace_existing=True,
    )
    scheduler.add_job(
        cleanup_raw_artifacts,
        "interval",
        hours=1,
        id="raw-artifact-retention",
        replace_existing=True,
    )
    scheduler.start()
