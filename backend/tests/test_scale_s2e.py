"""S2E: Agent streaming/spooling. Bound RAM; do not accumulate normalized lists."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import requires_postgres
from tests.scale_s2.constants import SPOOLED_INGEST_PATH
from tests.test_phase1d import (
    _agent_headers,
    _client,
    _headers,
    _heartbeat,
    _lan_scan,
    _login,
    _scanner_headers,
    _wan_scan,
    _world,
)
from tests.test_phase2a import _start_lan

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

    monkeypatch.setattr(runtime_runner, "discover_liveness", lambda *args, **kwargs: [])
    monkeypatch.setattr(runtime_runner, "read_neighbor_table", lambda *args, **kwargs: {})
    monkeypatch.setattr(runtime_runner, "discover_udp", lambda *args, **kwargs: [])
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


def test_raw_artifacts_survive_tmp_loss_on_resume(tmp_path, monkeypatch):
    data = tmp_path / "data"
    tmp = tmp_path / "tmp"
    data.mkdir()
    tmp.mkdir()
    monkeypatch.setenv("AGENT_DATA_DIR", str(data))
    monkeypatch.setenv("TMPDIR", str(tmp))
    _runtime()
    import runner as runtime_runner
    from job_finish import persist_artifacts
    from spool import recover_owned_spool, resume_pipeline_result

    def fake_discovery(*_args, **kwargs):
        staging = Path(kwargs["staging_dir"])
        gz = staging / "discovery.naabu.jsonl.gz"
        gz.write_bytes(b"\x1f\x8b")
        return (
            [{"ip": "10.1.0.9"}],
            {
                "artifact_key": "discovery.naabu",
                "stage": "discovery",
                "tool": "naabu",
                "path": str(gz),
            },
        )

    monkeypatch.setattr(runtime_runner, "discover_liveness", lambda *args, **kwargs: [])
    monkeypatch.setattr(runtime_runner, "read_neighbor_table", lambda *args, **kwargs: {})
    monkeypatch.setattr(runtime_runner, "discover_udp", lambda *args, **kwargs: [])
    monkeypatch.setattr(runtime_runner, "run_host_discovery", fake_discovery)
    monkeypatch.setattr(runtime_runner, "run_httpx", lambda *args, **kwargs: ([], None))
    monkeypatch.setattr(
        runtime_runner,
        "collect_run_provenance",
        lambda **kwargs: {"runtime_version": "t"},
    )
    result = runtime_runner.run_pipeline(
        {
            "job_id": 77,
            "scope": "lan",
            "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
            "stages": {
                "discovery": True,
                "port_mode": "none",
                "port_scope": "detected",
                "fingerprint": False,
                "vulnerability": False,
            },
            "intensity": {},
            "exclusions": [],
        }
    )
    artifact_path = Path(result["artifacts"][0]["path"])
    staging = Path(result["staging_dir"])
    assert staging.is_relative_to(data)
    assert artifact_path.is_relative_to(data)
    assert artifact_path.exists()
    import shutil

    shutil.rmtree(tmp)
    tmp.mkdir()
    assert artifact_path.exists()
    resumed = recover_owned_spool(77)
    assert resumed is not None
    replay = resume_pipeline_result(resumed)
    uploaded: list[dict] = []
    persist_artifacts(uploaded.append, replay["artifacts"], replay["provenance"], skip_missing=False)
    assert uploaded and uploaded[0]["artifact_key"] == "discovery.naabu"


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


def _compose_service(text: str, name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n", text, re.M)
    assert match, f"service {name} missing"
    nxt = re.search(r"^  [a-zA-Z0-9_-]+:\n", text[match.end() :], re.M)
    end = match.end() + nxt.start() if nxt else len(text)
    return text[match.start() : end]


def test_atomic_write_retries_short_writes_and_fsyncs_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from spool import JobSpool

    real_write = os.write
    write_sizes: list[int] = []

    def short_write(fd, data):
        raw = data.tobytes() if isinstance(data, memoryview) else bytes(data)
        chunk = raw[: max(1, len(raw) // 2)]
        write_sizes.append(len(chunk))
        return real_write(fd, chunk)

    fsync_calls = []
    real_fsync = os.fsync

    def spy_fsync(fd):
        fsync_calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "write", short_write)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    spool = JobSpool.for_job(12)
    payload = {"ok": True, "note": "n" * 80}
    spool.mark_pipeline_complete(payload)
    assert spool.pipeline_meta()["note"] == payload["note"]
    assert len(write_sizes) >= 2
    assert len(fsync_calls) >= 2


def test_discover_completed_jobs_does_not_reclaim_siblings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    from spool import JobSpool, abandon_job_spool, discover_completed_job_ids, spool_root

    root = spool_root()
    first = JobSpool(root, 201)
    first.mark_pipeline_complete({"ok": True})
    second = JobSpool(root, 202)
    second.mark_pipeline_complete({"ok": True})
    assert discover_completed_job_ids() == [201, 202]
    abandon_job_spool(201)
    assert discover_completed_job_ids() == [202]
    assert not first.dir.exists()
    assert second.dir.exists()


def test_central_scanner_persists_own_data_volume():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    scanner = _compose_service(compose, "scanner")
    agent = _compose_service(compose, "nuclei-agent")
    assert "AGENT_DATA_DIR: /data" in scanner
    assert "scanner-data:/data" in scanner
    assert "agent-keys" not in scanner
    assert "agent-keys:/data" in agent
    assert "scanner-data:/data" not in agent
    assert re.search(r"^  scanner-data:$", compose, re.M)


class _LiveWorker:
    def __init__(self, http, headers: dict, prefix: str):
        self.http = http
        self.headers = headers
        self.prefix = prefix
        self.start_calls: list[int] = []

    def _json(self, response, method: str, path: str):
        from api_client import ApiError

        if response.status_code >= 400:
            raise ApiError(f"{method} {path} -> {response.status_code} {response.text}")
        return response.json() if response.content else {}

    def jobs(self, token=None):
        return self._json(self.http.get(self.prefix, headers=self.headers), "GET", self.prefix)

    def owned_running_job(self, token, job_id: int):
        path = f"{self.prefix}/{job_id}"
        return self._json(self.http.get(path, headers=self.headers), "GET", path)

    def job_status(self, job_id: int):
        path = f"{self.prefix}/{job_id}"
        return self._json(self.http.get(path, headers=self.headers), "GET", path)

    def start(self, *args):
        job_id = args[-1]
        self.start_calls.append(int(job_id))
        path = f"{self.prefix}/{job_id}/start"
        return self._json(self.http.post(path, headers=self.headers), "POST", path)

    def devices(self, *args):
        job_id, devices = args[-2], args[-1]
        path = f"{self.prefix}/{job_id}/devices"
        return self._json(self.http.post(path, headers=self.headers, json=devices), "POST", path)

    def findings(self, *args):
        job_id, findings = args[-2], args[-1]
        path = f"{self.prefix}/{job_id}/findings"
        return self._json(self.http.post(path, headers=self.headers, json=findings), "POST", path)

    def detector_coverage(self, *args):
        job_id, payload = args[-2], args[-1]
        path = f"{self.prefix}/{job_id}/detector-coverage"
        return self._json(self.http.post(path, headers=self.headers, json=payload), "POST", path)

    def provenance(self, *args):
        job_id, payload = args[-2], args[-1]
        path = f"{self.prefix}/{job_id}/provenance"
        return self._json(self.http.post(path, headers=self.headers, json=payload), "POST", path)

    def complete(self, *args, ok=True, error=None, raw_evidence=None, **kwargs):
        if args and isinstance(args[0], int):
            job_id = args[0]
        elif len(args) >= 2:
            job_id = args[1]
        else:
            job_id = kwargs.get("job_id")
        path = f"{self.prefix}/{job_id}/complete"
        params = {"ok": str(ok).lower()}
        if error:
            params["error"] = error
        extra = {"headers": self.headers, "params": params}
        if raw_evidence is not None:
            extra["json"] = raw_evidence
        return self._json(self.http.post(path, **extra), "POST", path)

    def upload_artifact(self, *args, **kwargs):
        raise AssertionError("resume test should skip missing artifacts")


def _seed_done_spool(job_id: int, *, scope: str, ip: str, host: str):
    from spool import JobSpool

    spool = JobSpool.for_job(job_id)
    spool.append("devices", {"ip": ip, "scope": scope, "hostname": "resume-host"})
    spool.append("findings", _finding(1))
    spool.append("coverage", {"detector_type": "nuclei", "targets": [host]})
    spool.mark_pipeline_complete({"ok": True, "artifacts": [], "provenance": {}, "dry_run": True})
    return spool


@requires_postgres
def test_lan_restart_resumes_owned_running_job_without_start(reset_db, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    import agent_main
    from app.models import ScanJob
    from app.database import SessionLocal
    from spool import JobSpool, discover_completed_job_ids

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _lan_scan(client, token, world, intensity_config={"preset": "normal", "dry_run": True})
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        queued = _lan_scan(client, token, world, name="Queued LAN", intensity_config={"preset": "normal", "dry_run": True})
        queued_id = client.post(f"/api/scans/{queued['id']}/run", headers=_headers(token)).json()["id"]
        _seed_done_spool(job_id, scope="lan", ip="10.1.0.10", host="https://10.1.0.10")
        headers = _agent_headers(world["agent1"])
        agent_token = headers["Authorization"].split(" ", 1)[1]

        polled = client.get("/api/agent/jobs", headers=headers)
        assert polled.status_code == 200
        assert polled.json() == []
        assert client.post(f"/api/agent/jobs/{job_id}/start", headers=headers).status_code == 404
        owned = client.get(f"/api/agent/jobs/{job_id}", headers=headers)
        assert owned.status_code == 200, owned.text
        assert owned.json()["job_id"] == job_id
        _heartbeat(world["agent2"]["id"])
        assert client.get(f"/api/agent/jobs/{job_id}", headers=_agent_headers(world["agent2"])).status_code == 404
        assert client.get(f"/api/agent/jobs/{queued_id}", headers=headers).status_code == 404
        assert discover_completed_job_ids() == [job_id]

        live = _LiveWorker(client, headers, "/api/agent/jobs")

        def refuse_start(*args, **kwargs):
            raise AssertionError("LAN resume must not call /start")

        live.start = refuse_start
        runtime = agent_main.AgentRuntime(
            live,
            world["agent1"]["uuid"],
            "secret",
            "pub",
            object(),
            authenticate_fn=lambda *args, **kwargs: agent_token,
        )
        runtime._set_token(agent_token)
        assert runtime.current_job() == (None, "idle")
        runtime._poll_once()
        assert runtime.current_job() == (job_id, "scanning")
        work = runtime._work
        assert work["_resume"] is True
        agent_main.run_job(live, agent_token, work, refresh_token=lambda: agent_token)

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "done"
            assert job.findings_count >= 1
        finally:
            db.close()
        leftover = JobSpool.for_job(job_id)
        assert not leftover.has_pending()


@requires_postgres
def test_wan_restart_resumes_owned_running_job_without_start(reset_db, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_DATA_DIR", str(tmp_path))
    _runtime()
    import scanner_main
    from app.database import SessionLocal
    from app.models import ScanJob
    from spool import JobSpool, discover_completed_job_ids

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _wan_scan(client, token, world, intensity_config={"preset": "normal", "dry_run": True})
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        started = client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())
        assert started.status_code == 200, started.text
        _seed_done_spool(job_id, scope="wan", ip="203.0.113.10", host="https://203.0.113.10")
        stale = JobSpool(JobSpool.for_job(job_id).root, 999001)
        stale.mark_pipeline_complete({"ok": True})
        headers = _scanner_headers()

        assert client.get("/api/internal/scanner/jobs", headers=headers).json() == []
        assert client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=headers).status_code == 404
        status = client.get(f"/api/internal/scanner/jobs/{job_id}", headers=headers)
        assert status.status_code == 200, status.text
        assert status.json()["status"] == "running"
        assert status.json()["owned_running"] is True
        assert discover_completed_job_ids() == [job_id, 999001]

        live = _LiveWorker(client, headers, "/api/internal/scanner/jobs")

        def refuse_start(*args, **kwargs):
            raise AssertionError("WAN resume must not call /start")

        live.start = refuse_start
        assert scanner_main.try_resume_completed_jobs(live) is True

        db = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            assert job is not None
            assert job.status == "done"
            assert job.findings_count >= 1
        finally:
            db.close()
        leftover = JobSpool.for_job(job_id)
        assert not leftover.has_pending()
        assert not stale.dir.exists()

