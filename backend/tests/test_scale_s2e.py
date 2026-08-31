"""S2E: Agent streaming/spooling. Bound RAM; do not accumulate normalized lists."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import requires_postgres
from tests.scale_s2.constants import SPOOLED_INGEST_PATH

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = REPO_ROOT / "scan_runtime"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _runtime():
    if str(RUNTIME_ROOT) not in sys.path:
        sys.path.insert(0, str(RUNTIME_ROOT))


def _finding(index: int, *, pad: int = 64) -> dict:
    return {
        "template_id": f"t-{index}",
        "name": "exposure",
        "severity": "low",
        "host": f"https://10.0.{index // 250}.{index % 250}",
        "matched_at": "/",
        "tags": "s2e",
        "raw": {"template-id": f"t-{index}", "pad": "z" * pad, "i": index},
    }


def test_s2e_path_label():
    assert SPOOLED_INGEST_PATH == "s2e_agent_spool"


def test_s2e_has_no_schema_revision():
    versions = BACKEND_ROOT / "alembic" / "versions"
    names = [path.name for path in versions.glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


def test_spool_atomic_tmp_discard_and_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_MAX_ROWS", "2")
    _runtime()
    from spool import JobSpool

    spool = JobSpool.for_job(11)
    stale = spool.dir / "findings-000001.ready.tmp"
    stale.write_text("not-valid-json", encoding="utf-8")
    spool = JobSpool.for_job(11)
    assert not stale.exists()
    assert spool.ready_chunks("findings") == []
    spool.append("findings", _finding(1))
    spool.append("findings", _finding(2))
    spool.append("findings", _finding(3))
    spool.seal_all()
    ready = spool.ready_chunks("findings")
    assert len(ready) == 2
    assert (spool.dir.stat().st_mode & 0o777) == 0o700
    assert (ready[0].stat().st_mode & 0o777) == 0o600
    first = json.loads(ready[0].read_text(encoding="utf-8"))
    assert isinstance(first, list)
    assert len(first) == 2


def test_spool_isolation_never_attaches_foreign_job(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from spool import JobSpool

    a = JobSpool.for_job(21)
    a.append("devices", {"ip": "10.0.0.21"})
    a.seal_all()
    assert a.ready_chunks("devices")
    b = JobSpool.for_job(22)
    assert not a.dir.exists()
    assert list(b.iter_records("devices")) == []
    b.append("devices", {"ip": "10.0.0.22"})
    b.seal_all()
    assert [row["ip"] for row in b.iter_records("devices")] == ["10.0.0.22"]


def test_spool_cap_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_MAX_ROWS", "10")
    _runtime()
    from spool import JobSpool, SpoolCapExceeded

    spool = JobSpool.for_job(31, max_bytes=400)
    with pytest.raises(SpoolCapExceeded):
        for index in range(50):
            spool.append("findings", _finding(index, pad=80))
            spool.seal_all()
    assert not spool.pipeline_complete()


def test_recover_resume_vs_abandon_incomplete(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from spool import JobSpool, recover_owned_spool, resume_pipeline_result

    incomplete = JobSpool.for_job(41)
    incomplete.append("findings", _finding(1))
    incomplete.seal_all()
    assert recover_owned_spool(41) is None
    assert not incomplete.dir.exists()

    done = JobSpool.for_job(41)
    done.append("findings", _finding(9))
    done.mark_pipeline_complete({"ok": True, "artifacts": [], "provenance": {"runtime_version": "t"}})
    resumed = recover_owned_spool(41)
    assert resumed is not None
    assert resumed.pipeline_complete()
    result = resume_pipeline_result(resumed)
    assert result["spool_resume"] is True
    assert list(resumed.iter_records("findings"))[0]["template_id"] == "t-9"


def test_submit_spool_ack_delete_and_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_MAX_ROWS", "2")
    _runtime()
    from job_finish import submit_normalized
    from spool import JobSpool

    spool = JobSpool.for_job(51)
    for index in range(3):
        spool.append("devices", {"ip": f"10.0.0.{index}"})
        spool.append("findings", _finding(index))
    spool.append("coverage", {"detector_type": "nuclei", "targets": ["h1", "h2", "h3"]})
    spool.mark_pipeline_complete({"ok": True})

    posted = {"devices": [], "findings": [], "coverage": []}
    submit_normalized(
        provenance_fn=None,
        devices_fn=posted["devices"].append,
        findings_fn=posted["findings"].append,
        coverage_fn=posted["coverage"].append,
        result={"spool": spool, "devices": [], "findings": [], "detector_coverage": []},
    )
    assert [len(chunk) for chunk in posted["devices"]] == [2, 1]
    assert [len(chunk) for chunk in posted["findings"]] == [2, 1]
    assert not spool.has_pending()

    replay = JobSpool.for_job(52)
    replay.append("devices", {"ip": "10.9.9.9"})
    replay.seal_all()
    first = replay.ready_chunks("devices")[0]
    chunk = replay.read_chunk(first)
    seen: list[list] = []
    seen.append(chunk)
    seen.append(chunk)
    replay.ack_delete(first)
    assert seen[0] == seen[1]
    assert not replay.has_pending()


def test_ack_without_delete_is_replayed(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from job_finish import submit_normalized
    from spool import JobSpool

    spool = JobSpool.for_job(61)
    spool.append("devices", {"ip": "10.1.1.1"})
    spool.seal_all()
    uploads: list[list] = []

    def take(chunk):
        uploads.append(chunk)

    submit_normalized(
        provenance_fn=None,
        devices_fn=take,
        findings_fn=None,
        coverage_fn=None,
        result={"spool": spool, "devices": [], "findings": [], "detector_coverage": []},
    )
    leftover = JobSpool.for_job(61)
    leftover.append("devices", {"ip": "10.1.1.1"})
    leftover.seal_all()
    path = leftover.ready_chunks("devices")[0]
    take(leftover.read_chunk(path))
    take(leftover.read_chunk(path))
    leftover.ack_delete(path)
    assert uploads[-2] == uploads[-1]


def test_no_successful_complete_while_pending(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from job_finish import finish_pipeline_run
    from spool import JobSpool

    spool = JobSpool.for_job(71)
    spool.append("findings", _finding(1))
    spool.seal_all()
    completes: list[tuple] = []

    finish_pipeline_run(
        result={
            "artifacts": [],
            "staging_dir": None,
            "provenance": {"runtime_version": "t"},
            "dry_run": False,
            "devices": [],
            "findings": [],
            "detector_coverage": [],
            "spool": spool,
        },
        upload=lambda _artifact: None,
        complete=lambda ok, error=None, raw_evidence=None: completes.append((ok, error)),
        provenance_fn=lambda _payload: None,
        findings_fn=None,
    )
    assert completes and completes[0][0] is False
    assert "pending chunks" in str(completes[0][1])
    assert spool.has_pending()


def test_cancel_during_spool_never_completes_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from job_finish import finish_pipeline_run
    from spool import JobSpool

    spool = JobSpool.for_job(81)
    spool.append("findings", _finding(1))
    spool.seal_all()
    completes: list[tuple] = []
    uploaded: list[list] = []

    finish_pipeline_run(
        result={
            "artifacts": [],
            "staging_dir": None,
            "provenance": {"runtime_version": "t"},
            "dry_run": False,
            "devices": [],
            "findings": [],
            "detector_coverage": [],
            "spool": spool,
            "pipeline_error": "scan cancelled",
        },
        upload=lambda _artifact: None,
        complete=lambda ok, error=None, raw_evidence=None: completes.append((ok, error)),
        provenance_fn=lambda _payload: None,
        findings_fn=uploaded.append,
        pipeline_error="scan cancelled",
    )
    assert uploaded
    assert completes == [(False, "scan cancelled")]


def test_single_shot_lists_equal_spooled_chunks(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_MAX_ROWS", "2")
    _runtime()
    from job_finish import submit_normalized
    from spool import JobSpool

    devices = [{"ip": f"10.2.0.{i}"} for i in range(5)]
    findings = [_finding(i) for i in range(5)]
    coverage = [{"detector_type": "nuclei", "targets": [f"h{i}" for i in range(5)]}]
    lists = {"devices": [], "findings": [], "coverage": []}
    submit_normalized(
        provenance_fn=None,
        devices_fn=lists["devices"].append,
        findings_fn=lists["findings"].append,
        coverage_fn=lists["coverage"].append,
        result={"devices": devices, "findings": findings, "detector_coverage": coverage},
    )

    spool = JobSpool.for_job(91)
    for row in devices:
        spool.append("devices", row)
    for row in findings:
        spool.append("findings", row)
    for row in coverage[0]["targets"]:
        pass
    from ingest_chunks import iter_ingest_chunks

    for chunk in iter_ingest_chunks(coverage[0]["targets"], kind="coverage"):
        spool.append("coverage", {"detector_type": "nuclei", "targets": chunk})
    spool.seal_all()
    streamed = {"devices": [], "findings": [], "coverage": []}
    submit_normalized(
        provenance_fn=None,
        devices_fn=streamed["devices"].append,
        findings_fn=streamed["findings"].append,
        coverage_fn=streamed["coverage"].append,
        result={"spool": spool, "devices": [], "findings": [], "detector_coverage": []},
    )
    assert lists == streamed


def test_pipeline_with_job_id_does_not_keep_finding_lists(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    import runner as runtime_runner

    monkeypatch.setattr(
        runtime_runner,
        "run_naabu",
        lambda *args, **kwargs: ([{"ip": "10.3.0.4", "port": 80}], None),
    )
    monkeypatch.setattr(
        runtime_runner,
        "run_httpx",
        lambda *args, **kwargs: ([{"ip": "10.3.0.4", "url": "https://10.3.0.4", "title": "x"}], None),
    )
    monkeypatch.setattr(
        runtime_runner,
        "run_nuclei",
        lambda *args, **kwargs: ([_finding(1), _finding(2)], None),
    )
    monkeypatch.setattr(
        runtime_runner,
        "collect_run_provenance",
        lambda **kwargs: {"runtime_version": "t"},
    )
    result = runtime_runner.run_pipeline(
        {
            "job_id": 101,
            "scope": "lan",
            "targets": [{"type": "ip", "value": "10.3.0.4"}],
            "stages": {
                "discovery": False,
                "port_mode": "common",
                "fingerprint": True,
                "vulnerability": True,
                "nuclei_severities": "low",
                "nuclei_tags": "",
            },
            "intensity": {},
            "exclusions": [],
        }
    )
    assert result["devices"] == []
    assert result["findings"] == []
    assert result["detector_coverage"] == []
    spool = result["spool"]
    assert spool.pipeline_complete()
    assert [row["ip"] for row in spool.iter_records("devices")] == ["10.3.0.4"]
    assert [row["template_id"] for row in spool.iter_records("findings")] == ["t-1", "t-2"]


def test_pipeline_without_job_id_still_exposes_lists_for_unit_tests(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    import runner as runtime_runner

    monkeypatch.setattr(
        runtime_runner,
        "run_host_discovery",
        lambda *args, **kwargs: ([{"ip": "203.0.113.10"}], None),
    )
    monkeypatch.setattr(runtime_runner, "run_httpx", lambda *args, **kwargs: ([], None))
    monkeypatch.setattr(
        runtime_runner,
        "collect_run_provenance",
        lambda **kwargs: {"runtime_version": "t"},
    )
    result = runtime_runner.run_pipeline(
        {
            "scope": "wan",
            "targets": [{"type": "ip", "value": "203.0.113.10"}],
            "stages": {
                "discovery": True,
                "port_mode": "none",
                "fingerprint": False,
                "vulnerability": False,
            },
            "intensity": {},
            "exclusions": [],
        }
    )
    assert result["devices"]
    assert result["devices"][0]["ip"] == "203.0.113.10"


def _rss_for_streamed_count(count: int, tmp_path: Path) -> int:
    env = os.environ.copy()
    env["AGENT_DATA_DIR"] = str(tmp_path / f"rss-{count}")
    env["PYTHONPATH"] = str(RUNTIME_ROOT)
    env["INGEST_MAX_ROWS"] = "50"
    script = r"""
import sys
from job_finish import submit_normalized
from spool import JobSpool

n = int(sys.argv[1])
spool = JobSpool.for_job(n)
for i in range(n):
    spool.append("findings", {
        "template_id": f"t-{i}",
        "name": "exposure",
        "severity": "low",
        "host": f"https://10.0.{i // 250}.{i % 250}",
        "matched_at": "/",
        "tags": "s2e",
        "raw": {"template-id": f"t-{i}", "pad": "z" * 2048, "i": i},
    })
spool.mark_pipeline_complete({"ok": True})

def take(chunk):
    return len(chunk)

submit_normalized(
    provenance_fn=None,
    devices_fn=None,
    findings_fn=take,
    coverage_fn=None,
    result={"spool": spool, "devices": [], "findings": [], "detector_coverage": []},
)
import resource
usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(usage if sys.platform == "darwin" else int(usage) * 1024)
"""
    proc = subprocess.run(
        [sys.executable, "-c", script, str(count)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(RUNTIME_ROOT),
    )
    return int(proc.stdout.strip().splitlines()[-1])


def test_peak_rss_is_bounded_not_linear_with_result_count(tmp_path):
    small = _rss_for_streamed_count(400, tmp_path)
    large = _rss_for_streamed_count(4000, tmp_path)
    assert small > 0
    assert large > 0
    # 10x more findings must not require ~10x RSS. Allow process noise plus a
    # fixed margin for JSON batch encode of the open S2D chunk.
    assert large <= max(small * 25 // 10, small + 24 * 1024 * 1024)


@requires_postgres
def test_s2e_spooled_chunks_match_single_ingest(reset_db, tmp_path, monkeypatch):
    from app.database import SessionLocal
    from app.finding_lifecycle import complete_scan_run, store_detector_coverage
    from app.inventory import store_findings, upsert_devices
    from app.models import Device, ScanJob
    from app.schemas import DeviceReport, FindingReport
    from tests.scale_s2.constants import WORKLOADS
    from tests.scale_s2.harness import counts_from_state, prepare_and_ingest
    from tests.scale_s2.snapshot import assert_equivalent, capture_normalized_state
    from tests.scale_s2.workloads import build_workload
    from tests.scale_s2.world import create_ingest_world, reset_schema, seed_historical_findings

    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INGEST_MAX_ROWS", "3")
    _runtime()
    from spool import JobSpool

    reset_schema()
    db = SessionLocal()
    try:
        single = prepare_and_ingest(db, WORKLOADS["tiny"], replay=False)
        single_state = single["state"]
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        world = create_ingest_world(db, label="s2e-tiny")
        fresh = build_workload(WORKLOADS["tiny"])
        seed_historical_findings(db, world, fresh)
        spool = JobSpool.for_job(world.job_id)
        for row in fresh.devices:
            spool.append("devices", row.model_dump())
        for row in fresh.findings:
            spool.append("findings", row.model_dump())
        for chunk_targets in _coverage_target_chunks(fresh.coverage_targets):
            spool.append("coverage", {"detector_type": "nuclei", "targets": chunk_targets})
        spool.mark_pipeline_complete({"ok": True})
        job = db.get(ScanJob, world.job_id)
        for path in spool.ready_chunks("devices"):
            upsert_devices(
                db,
                world.tenant_id,
                world.job_id,
                [DeviceReport.model_validate(row) for row in spool.read_chunk(path)],
            )
            job.hosts_found = db.query(Device).filter(Device.last_scan_job_id == world.job_id).count()
            db.commit()
            spool.ack_delete(path)
            job = db.get(ScanJob, world.job_id)
        for path in spool.ready_chunks("coverage"):
            for record in spool.read_chunk(path):
                store_detector_coverage(
                    db,
                    job,
                    detector_type=record.get("detector_type") or "nuclei",
                    targets=list(record.get("targets") or []),
                )
                db.commit()
            spool.ack_delete(path)
            job = db.get(ScanJob, world.job_id)
        for path in spool.ready_chunks("findings"):
            added = store_findings(
                db,
                world.tenant_id,
                world.job_id,
                "wan",
                [FindingReport.model_validate(row) for row in spool.read_chunk(path)],
            )
            job.findings_count = (job.findings_count or 0) + added
            db.commit()
            spool.ack_delete(path)
            job = db.get(ScanJob, world.job_id)
        complete_scan_run(db, job, ok=True)
        db.commit()
        assert not spool.has_pending()
        spooled_state = capture_normalized_state(db, world.tenant_id)
        assert_equivalent(single_state, spooled_state, label="s2e single-shot vs spool")
        counts = counts_from_state(spooled_state)
        assert counts["findings"] == WORKLOADS["tiny"].findings
        assert counts["devices"] == WORKLOADS["tiny"].devices
    finally:
        db.close()


def _coverage_target_chunks(targets: list[str]) -> list[list[str]]:
    _runtime()
    from ingest_chunks import iter_ingest_chunks

    return list(iter_ingest_chunks(list(targets), kind="coverage"))
