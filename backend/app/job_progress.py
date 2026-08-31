"""Live scan progress derived from job status, snapshot, and worker reports.

No schema change. Workers may store a small ``progress`` object on
``scan_jobs.runtime_provenance``. Claim, status, and execution_snapshot
are never written here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models import (
    JOB_CANCELLED,
    JOB_DONE,
    JOB_FAILED,
    JOB_MISSED,
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_WAITING_FOR_AGENT,
    ScanJob,
)
from app.scan_snapshot import merge_provenance

STAGE_LABELS = {
    "queued": "Queued",
    "waiting_for_agent": "Waiting for Agent",
    "discovery": "Host identity",
    "port_discovery": "Port scan",
    "fingerprint": "Fingerprint",
    "vulnerability": "Vulnerability scan",
    "upload": "Uploading results",
    "scanning": "Scanning",
}

TERMINAL_STATUSES = {JOB_DONE, JOB_FAILED, JOB_CANCELLED, JOB_MISSED}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def planned_stage_ids(snapshot: dict[str, Any] | None) -> list[str]:
    stages = (snapshot or {}).get("stages") if isinstance(snapshot, dict) else None
    if not isinstance(stages, dict):
        stages = {}
    planned: list[str] = []
    if stages.get("discovery"):
        planned.append("discovery")
    port_mode = str(stages.get("port_mode") or "none").strip()
    if port_mode and port_mode != "none":
        planned.append("port_discovery")
    if stages.get("fingerprint"):
        planned.append("fingerprint")
    if stages.get("vulnerability"):
        planned.append("vulnerability")
    planned.append("upload")
    return planned


def _reported(job: ScanJob) -> dict[str, Any]:
    provenance = job.runtime_provenance if isinstance(job.runtime_provenance, dict) else {}
    raw = provenance.get("progress")
    return dict(raw) if isinstance(raw, dict) else {}


def _elapsed_seconds(job: ScanJob, *, now: datetime | None = None) -> int | None:
    started = job.started_at
    if started is None:
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    end = job.finished_at or now or utcnow()
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return max(0, int((end - started).total_seconds()))


def record_job_progress(
    job: ScanJob,
    *,
    activity: str | None = None,
    stage: str | None = None,
    message: str | None = None,
    completed_stages: list[str] | None = None,
    now: datetime | None = None,
) -> None:
    current = _reported(job)
    if activity:
        current["activity"] = str(activity)[:80]
    if stage:
        current["stage"] = str(stage)[:80]
    if message:
        current["message"] = str(message)[:500]
    if completed_stages is not None:
        current["completed_stages"] = [str(item)[:80] for item in completed_stages if item]
    current["updated_at"] = (now or utcnow()).isoformat()
    job.runtime_provenance = merge_provenance(job.runtime_provenance, {"progress": current})


def apply_worker_progress(job: ScanJob, body: dict[str, Any] | None, *, activity: str | None = None) -> None:
    incoming = dict(body or {})
    completed = incoming.get("completed_stages")
    if completed is not None and not isinstance(completed, list):
        completed = None
    record_job_progress(
        job,
        activity=activity or incoming.get("activity"),
        stage=incoming.get("stage"),
        message=incoming.get("message"),
        completed_stages=completed,
    )


def progress_view(job: ScanJob, *, now: datetime | None = None) -> dict[str, Any]:
    snapshot = job.execution_snapshot if isinstance(job.execution_snapshot, dict) else {}
    planned = planned_stage_ids(snapshot)
    reported = _reported(job)
    status = job.status
    stage = reported.get("stage") if isinstance(reported.get("stage"), str) else None
    activity = reported.get("activity") if isinstance(reported.get("activity"), str) else None
    message = reported.get("message") if isinstance(reported.get("message"), str) else None
    completed = [item for item in (reported.get("completed_stages") or []) if isinstance(item, str)]
    approximate = False
    percent: int | None = None
    current = stage

    if status == JOB_DONE:
        percent = 100
        current = None
        completed = list(planned)
        message = message or "Scan complete"
    elif status in {JOB_FAILED, JOB_CANCELLED, JOB_MISSED}:
        done_count = len([item for item in planned if item in completed])
        percent = int(100 * done_count / len(planned)) if planned else 0
        current = stage or status
        message = message or (job.error or status.replace("_", " "))
    elif status == JOB_QUEUED:
        percent = 0
        current = "queued"
    elif status == JOB_WAITING_FOR_AGENT:
        percent = 0
        current = "waiting_for_agent"
    elif status == JOB_RUNNING:
        done_count = len([item for item in planned if item in completed])
        if stage in planned and stage not in completed:
            percent = int(100 * (done_count + 0.5) / len(planned)) if planned else 5
        elif planned and (completed or stage in planned):
            percent = int(100 * done_count / len(planned))
        else:
            percent = 5
            approximate = True
            current = stage or "scanning"
            if not message:
                message = "Scan is running. Stage-level percent is available after the Agent reports stages."
    else:
        percent = 0

    stages = []
    for item in planned:
        if status == JOB_DONE or item in completed:
            state = "done"
        elif item == current:
            state = "active"
        elif current == "scanning" and status == JOB_RUNNING:
            state = "pending"
        else:
            state = "pending"
        stages.append({"id": item, "label": STAGE_LABELS.get(item, item.replace("_", " ").title()), "state": state})

    label = STAGE_LABELS.get(current or "", None)
    if label is None:
        if status == JOB_DONE:
            label = "Complete"
        elif status == JOB_RUNNING:
            label = "In progress"
        else:
            label = status.replace("_", " ").title()

    return {
        "percent": percent,
        "approximate": approximate,
        "label": label,
        "stage": current,
        "message": message,
        "activity": activity,
        "updated_at": reported.get("updated_at"),
        "elapsed_seconds": _elapsed_seconds(job, now=now),
        "stages": stages,
    }
