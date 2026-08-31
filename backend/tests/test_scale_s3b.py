"""S3B: APScheduler lives in one scheduler process, never in the API."""

from __future__ import annotations

import inspect
from pathlib import Path

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
FROZEN_JOB_CATALOG = [
    {"id": "schedules", "seconds": 30},
    {"id": "stale", "minutes": 30},
    {"id": "asset-inactive", "minutes": 30},
    {"id": "discovery-metadata", "minutes": 5},
    {"id": "policy-reconcile", "minutes": 20},
    {"id": "stuck-jobs", "minutes": 5},
    {"id": "vuln-intel", "minutes": 15},
    {"id": "finding-age-priority", "hours": 12},
    {"id": "treatment-expiration", "minutes": 15},
    {"id": "alert-routing", "seconds": 15},
    {"id": "alert-delivery", "seconds": 20},
    {"id": "raw-artifact-retention", "hours": 1},
]


def test_s3b_has_no_schema_revision():
    names = [path.name for path in (BACKEND_ROOT / "alembic" / "versions").glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_agent_pin_unchanged():
    from app.agent_source import PINNED_AGENT_GIT_COMMIT

    assert PINNED_AGENT_GIT_COMMIT == "3cdb52c42a87552db98e609e9ec7c1c01e86b23b"


def test_api_source_has_zero_scheduler_side_effects():
    from app import main

    lifespan_src = inspect.getsource(main.lifespan)
    prepare_src = inspect.getsource(main.prepare_control_plane)
    main_text = (BACKEND_ROOT / "app" / "main.py").read_text()
    for blob in (lifespan_src, prepare_src, main_text):
        assert "start_scheduler" not in blob
        assert "stop_scheduler" not in blob
        assert "scheduler_process" not in blob
        assert "BackgroundScheduler" not in blob


def test_job_catalog_matches_former_in_process_schedule():
    from app.scheduler import _scheduler_job_callables, scheduler_job_catalog

    catalog = scheduler_job_catalog()
    assert catalog == FROZEN_JOB_CATALOG
    callables = _scheduler_job_callables()
    assert [job_id for _, job_id, _ in callables] == [row["id"] for row in catalog]
    for spec, (_func, job_id, interval) in zip(catalog, callables, strict=True):
        assert spec["id"] == job_id
        assert {key: value for key, value in spec.items() if key != "id"} == interval


def test_compose_defines_one_scheduler_process():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    assert "command: [\"python\", \"-m\", \"app.scheduler_process\"]" in compose
    assert compose.count("app.scheduler_process") == 1
    api_cmd = (BACKEND_ROOT / "Dockerfile").read_text()
    assert "uvicorn" in api_cmd
    assert "scheduler_process" not in api_cmd


@requires_postgres
def test_two_api_lifespans_do_not_start_scheduler(reset_db):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.migrate import apply_schema
    from app.scheduler import scheduler

    apply_schema()
    assert scheduler.running is False
    with TestClient(app) as first:
        assert first.get("/api/health").json() == {"ok": True}
        assert scheduler.running is False
    assert scheduler.running is False
    with TestClient(app) as second:
        assert second.get("/api/health").json() == {"ok": True}
        assert scheduler.running is False
    assert scheduler.running is False


@requires_postgres
def test_only_one_connection_holds_scheduler_leader_lock(reset_db):
    from app.database import engine
    from app.scheduler import (
        release_scheduler_leader_lock,
        try_acquire_scheduler_leader_lock,
    )

    first = engine.connect()
    second = engine.connect()
    try:
        assert try_acquire_scheduler_leader_lock(first) is True
        assert try_acquire_scheduler_leader_lock(second) is False
        release_scheduler_leader_lock(first)
        assert try_acquire_scheduler_leader_lock(second) is True
    finally:
        first.close()
        second.close()


@requires_postgres
def test_second_leader_attempt_does_not_start_apscheduler(reset_db):
    from app.database import engine
    from app.scheduler import (
        release_scheduler_leader_lock,
        scheduler,
        start_scheduler_if_leader,
        stop_scheduler,
    )

    first = engine.connect()
    second = engine.connect()
    try:
        assert start_scheduler_if_leader(first) is True
        assert scheduler.running is True
        assert start_scheduler_if_leader(second) is False
        assert scheduler.running is True
    finally:
        stop_scheduler(wait=True)
        release_scheduler_leader_lock(first)
        first.close()
        second.close()
    assert scheduler.running is False
