"""In-process scan progress for heartbeat / progress POSTs.

One worker runs at a time. Bind a job id when work starts; the heartbeat
thread reads ``snapshot()`` without touching claim or /start.
"""

from __future__ import annotations

import threading
from typing import Any

_lock = threading.Lock()
_job_id: int | None = None
_stage: str | None = None
_message: str | None = None
_completed: list[str] = []


def bind_job(job_id: Any, *, reset: bool = True) -> None:
    global _job_id, _stage, _message, _completed
    parsed = None
    if job_id is not None and str(job_id).strip() != "":
        parsed = int(job_id)
    with _lock:
        if not reset and _job_id == parsed:
            return
        _job_id = parsed
        _stage = None
        _message = None
        _completed = []


def clear_job() -> None:
    bind_job(None)


def note_stage(stage: str, message: str | None = None, *, complete: bool = False) -> None:
    global _stage, _message, _completed
    with _lock:
        if _job_id is None:
            return
        _stage = str(stage)
        if message:
            _message = str(message)[:500]
        if complete and _stage not in _completed:
            _completed.append(_stage)


def note_message(message: str) -> None:
    global _message
    with _lock:
        if _job_id is None:
            return
        _message = str(message)[:500]


def snapshot() -> dict[str, Any] | None:
    with _lock:
        if _job_id is None:
            return None
        return {
            "job_id": _job_id,
            "stage": _stage,
            "message": _message,
            "completed_stages": list(_completed),
            "activity": "scanning" if _stage else "idle",
        }
