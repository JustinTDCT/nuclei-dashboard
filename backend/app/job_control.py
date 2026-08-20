"""Shared cancel/deadline view of a ScanJob for workers and the control plane."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.models import JOB_CANCELLED, JOB_FAILED, JOB_RUNNING, ScanJob
from app.settings_store import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def job_timeout_minutes(db: Session) -> int:
    return max(30, int(get_settings(db).get("job_timeout_minutes") or 180))


def deadline_for_start(db: Session, *, now: datetime | None = None) -> datetime:
    current = now or utcnow()
    return current + timedelta(minutes=job_timeout_minutes(db))


def cancel_grace() -> timedelta:
    return timedelta(seconds=max(15, settings.scanner_cancel_grace_seconds))


def job_is_cancelled_or_failed(job: ScanJob) -> bool:
    return job.status in {JOB_CANCELLED, JOB_FAILED}


def job_cancel_requested(job: ScanJob, *, now: datetime | None = None) -> bool:
    current = now or utcnow()
    if job.cancel_requested_at is not None:
        return True
    if job.status != JOB_RUNNING:
        return True
    deadline = job.deadline_at
    if deadline is not None:
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        if deadline <= current:
            return True
    return False


def job_control_payload(job: ScanJob, *, now: datetime | None = None) -> dict[str, Any]:
    current = now or utcnow()
    deadline = job.deadline_at
    return {
        "job_id": job.id,
        "status": job.status,
        "cancel_requested": job_cancel_requested(job, now=current),
        "deadline_at": deadline.isoformat() if deadline is not None else None,
    }


def mark_cancel_requested(job: ScanJob, *, now: datetime | None = None, reason: str | None = None) -> bool:
    if job.status != JOB_RUNNING:
        return False
    current = now or utcnow()
    if job.cancel_requested_at is None:
        job.cancel_requested_at = current
    if job.deadline_at is None:
        job.deadline_at = current
    if reason and not job.error:
        job.error = reason
    return True
