from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.job_progress import planned_stage_ids, progress_view, record_job_progress
from app.models import JOB_DONE, JOB_QUEUED, JOB_RUNNING
from tests.conftest import page_items, requires_postgres
from tests.test_phase1d import _agent_headers, _client, _headers, _lan_scan, _login, _world
from tests.test_phase2a import _start_lan


def _job(**kwargs):
    now = datetime.now(timezone.utc)
    job = SimpleNamespace(
        status=JOB_RUNNING,
        error=None,
        started_at=now - timedelta(minutes=4),
        finished_at=None,
        execution_snapshot={
            "stages": {
                "discovery": True,
                "port_mode": "common",
                "fingerprint": True,
                "vulnerability": True,
            }
        },
        runtime_provenance={},
    )
    job.__dict__.update(kwargs)
    return job


def test_planned_stages_follow_snapshot():
    assert planned_stage_ids({"stages": {"discovery": True, "port_mode": "none"}}) == ["discovery", "upload"]
    assert "port_discovery" in planned_stage_ids({"stages": {"port_mode": "common"}})
    assert planned_stage_ids({"stages": {"vulnerability": True}})[-1] == "upload"


def test_running_without_stage_report_is_approximate():
    view = progress_view(_job())
    assert view["approximate"] is True
    assert view["percent"] == 5
    assert view["stage"] == "scanning"
    assert view["elapsed_seconds"] >= 240
    assert [row["id"] for row in view["stages"]] == [
        "discovery",
        "port_discovery",
        "fingerprint",
        "vulnerability",
        "upload",
    ]


def test_reported_stage_sets_real_percent():
    job = _job(runtime_provenance={"progress": {"stage": "fingerprint", "completed_stages": ["discovery", "port_discovery"]}})
    view = progress_view(job)
    assert view["approximate"] is False
    assert view["percent"] == 50
    assert view["stage"] == "fingerprint"
    states = {row["id"]: row["state"] for row in view["stages"]}
    assert states["discovery"] == "done"
    assert states["fingerprint"] == "active"
    assert states["vulnerability"] == "pending"


def test_done_job_is_complete():
    view = progress_view(_job(status=JOB_DONE, finished_at=datetime.now(timezone.utc)))
    assert view["percent"] == 100
    assert all(row["state"] == "done" for row in view["stages"])


def test_queued_is_zero():
    view = progress_view(_job(status=JOB_QUEUED, started_at=None))
    assert view["percent"] == 0
    assert view["stage"] == "queued"


def test_record_job_progress_merges_without_dropping_versions():
    job = _job(runtime_provenance={"runtime_version": "1.2.3"})
    record_job_progress(job, activity="scanning", stage="port_discovery", message="Starting port_discovery (naabu)")
    assert job.runtime_provenance["runtime_version"] == "1.2.3"
    assert job.runtime_provenance["progress"]["stage"] == "port_discovery"
    assert job.runtime_provenance["progress"]["activity"] == "scanning"


@requires_postgres
def test_heartbeat_persists_progress_for_owned_running_job(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world)
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        headers = _agent_headers(world["agent1"])
        beat = client.post(
            "/api/agent/heartbeat",
            headers=headers,
            json={"job_id": job_id, "activity": "scanning"},
        )
        assert beat.status_code == 200, beat.text
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/jobs", headers=_headers(token))
        assert listed.status_code == 200
        row = next(item for item in page_items(listed.json()) if item["id"] == job_id)
        assert row["progress"]["stage"] == "scanning"
        assert row["progress"]["approximate"] is True
        assert row["status"] == "running"
        detailed = client.get(f"/api/jobs/{job_id}", headers=_headers(token))
        assert detailed.status_code == 200
        assert detailed.json()["progress"]["stages"]
        staged = client.post(
            f"/api/agent/jobs/{job_id}/progress",
            headers=headers,
            json={"stage": "port_discovery", "message": "Starting port_discovery (naabu)", "completed_stages": ["discovery"]},
        )
        assert staged.status_code == 200, staged.text
        again = client.get(f"/api/jobs/{job_id}", headers=_headers(token)).json()
        assert again["progress"]["approximate"] is False
        assert again["progress"]["stage"] == "port_discovery"
        assert again["status"] == "running"
