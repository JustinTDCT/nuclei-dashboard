"""Dedicated control-plane scheduler process.

The API process must not import or run this module. Exactly one process
holds the PostgreSQL leader lock and owns APScheduler.
"""

from __future__ import annotations

import logging
import signal
import time

from app.database import engine
from app.scheduler import (
    release_scheduler_leader_lock,
    start_scheduler,
    stop_scheduler,
    try_acquire_scheduler_leader_lock,
)

log = logging.getLogger("scheduler")

_stop = False


def _request_stop(_signum, _frame) -> None:
    global _stop
    _stop = True


def run_scheduler_process(*, retry_seconds: float = 5.0) -> None:
    """Block until SIGTERM/SIGINT. Start APScheduler only while this process is leader."""
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
        start_scheduler()
        try:
            while not _stop:
                time.sleep(1)
        finally:
            stop_scheduler()
            release_scheduler_leader_lock(conn)
            log.info("Scheduler leader released")


def main() -> None:
    run_scheduler_process()


if __name__ == "__main__":
    main()
