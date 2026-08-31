"""Dedicated control-plane scheduler process.

The API process must not import or run this module. Exactly one process
holds the PostgreSQL leader lock and owns APScheduler.
"""

from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable

from sqlalchemy.engine import Connection

from app.database import engine
from app.scheduler import (
    leader_session_is_current,
    release_scheduler_leader_lock,
    scheduler_backend_pid,
    start_scheduler,
    stop_scheduler,
    try_acquire_scheduler_leader_lock,
)

log = logging.getLogger("scheduler")

LEADER_PROBE_SECONDS = 2.0

_stop = False


def _request_stop(_signum, _frame) -> None:
    global _stop
    _stop = True


def hold_leadership(
    conn: Connection,
    *,
    probe_seconds: float = LEADER_PROBE_SECONDS,
    should_stop: Callable[[], bool] | None = None,
) -> str:
    """Run APScheduler only while this connection remains the original backend.

    Returns ``stopped`` on graceful request or ``lost`` when the leader session
    is no longer proven. APScheduler is always stopped with wait=True before
    this returns. The advisory lock is released only after that wait, and only
    when the session is still ours. A lost session already dropped the lock in
    PostgreSQL; this process must not reacquire or keep running jobs.
    """
    stop = should_stop or (lambda: False)
    leader_pid = scheduler_backend_pid(conn)
    start_scheduler()
    outcome = "stopped"
    try:
        while not stop():
            if not leader_session_is_current(conn, leader_pid):
                log.error(
                    "Scheduler leader session lost (expected backend pid %s); stopping APScheduler",
                    leader_pid,
                )
                outcome = "lost"
                break
            time.sleep(probe_seconds)
        return outcome
    finally:
        try:
            stop_scheduler(wait=True)
        finally:
            if outcome != "lost":
                try:
                    release_scheduler_leader_lock(conn)
                except Exception:
                    log.exception("Failed to release scheduler leader lock")


def run_scheduler_process(*, retry_seconds: float = 5.0, probe_seconds: float = LEADER_PROBE_SECONDS) -> None:
    """Block until SIGTERM/SIGINT or leader-session loss. Do not run jobs without a proven lock."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    log.info("Scheduler process waiting for leader lock")
    with engine.connect() as conn:
        while not _stop:
            if try_acquire_scheduler_leader_lock(conn):
                log.info("Acquired scheduler leader lock")
                break
            log.warning("Scheduler leader lock held elsewhere; retrying in %ss", retry_seconds)
            time.sleep(retry_seconds)
        if _stop:
            return
        outcome = hold_leadership(conn, probe_seconds=probe_seconds, should_stop=lambda: _stop)
        if outcome == "lost":
            log.error("Leader session lost; exiting so the process can restart")
            raise SystemExit(1)
        log.info("Scheduler leader released")


def main() -> None:
    run_scheduler_process()


if __name__ == "__main__":
    main()
