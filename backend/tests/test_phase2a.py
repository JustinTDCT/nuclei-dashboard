from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import inspect, text

from tests.conftest import requires_postgres
from tests.test_phase1d import (
    _agent_headers,
    _client,
    _create_staff,
    _headers,
    _heartbeat,
    _lan_scan,
    _login,
    _scanner_headers,
    _wan_scan,
    _world,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE1D_HEAD = "0006_scan_definition_execution"
PHASE2A_INITIAL = "0007_vulnerability_finding_lifecycle"
PHASE2A_COVERAGE = "0008_phase2a_finding_identity_repair"
PHASE2A_HEAD = "0009_phase2a_detector_identity_partition"
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
PHASE3A_HEAD = "0013_event_alert_engine"
FROZEN = (
    "0001_baseline_current_schema.py",
    "0002_sites_networks.py",
    "0003_assets_observations.py",
    "0004_asset_observation_integrity.py",
    "0005_asset_correlation_lifecycle.py",
    "0006_scan_definition_execution.py",
    "0007_vulnerability_finding_lifecycle.py",
    "0008_phase2a_finding_identity_repair.py",
    "0009_phase2a_detector_identity_partition.py",
    "0010_cve_intelligence_priority.py",
)
VULN_STAGES = {
    "discovery": True,
    "port_mode": "common",
    "fingerprint": True,
    "vulnerability": True,
    "nuclei_severities": "critical,high,medium",
    "nuclei_tags": "",
}


def _tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _vuln_scan(client, token, world, **extra):
    extra.setdefault("stage_config", dict(VULN_STAGES))
    extra.setdefault("name", "Vuln LAN")
    return _lan_scan(client, token, world, network_ids=[world["net1"]["id"]], **extra)


def _start_lan(client, world, job_id: int):
    _heartbeat(world["agent1"]["id"])
    started = client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(world["agent1"]))
    assert started.status_code == 200, started.text
    return started.json()


def _post_device(client, world, job_id: int, ip="10.1.0.10", hostname="asset-a"):
    posted = client.post(
        f"/api/agent/jobs/{job_id}/devices",
        headers=_agent_headers(world["agent1"]),
        json=[{"ip": ip, "scope": "lan", "hostname": hostname}],
    )
    assert posted.status_code == 200, posted.text
    return posted.json()


def _finding_payload(template="exposed-panel", name="Exposed panel", severity="high", tags="panel", host="https://10.1.0.10", extra_raw=None):
    raw = {"template-id": template, "info": {"name": name, "severity": severity, "tags": [part for part in tags.split(",") if part]}}
    if extra_raw:
        raw.update(extra_raw)
    return {
        "template_id": template,
        "name": name,
        "severity": severity,
        "host": host,
        "matched_at": f"{host}/",
        "tags": tags,
        "raw": raw,
    }


def _post_coverage(client, world, job_id: int, targets, detector_type="nuclei"):
    posted = client.post(
        f"/api/agent/jobs/{job_id}/detector-coverage",
        headers=_agent_headers(world["agent1"]),
        json={"detector_type": detector_type, "targets": list(targets)},
    )
    assert posted.status_code == 200, posted.text
    return posted.json()


def _post_findings(client, world, job_id: int, items=None):
    posted = client.post(
        f"/api/agent/jobs/{job_id}/findings",
        headers=_agent_headers(world["agent1"]),
        json=items or [_finding_payload()],
    )
    assert posted.status_code == 200, posted.text
    return posted.json()


def _complete(client, world, job_id: int, ok=True, error=None):
    posted = client.post(
        f"/api/agent/jobs/{job_id}/complete",
        headers=_agent_headers(world["agent1"]),
        params={"ok": "true" if ok else "false", "error": error or ""},
    )
    return posted


def _run_detected(client, token, world, hostname="asset-a", ip="10.1.0.10", findings=None):
    scan = _vuln_scan(client, token, world)
    job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
    _start_lan(client, world, job_id)
    _post_device(client, world, job_id, ip=ip, hostname=hostname)
    _post_coverage(client, world, job_id, [f"https://{ip}"])
    result = _post_findings(
        client,
        world,
        job_id,
        findings or [_finding_payload(host=f"https://{ip}", extra_raw=None)],
    )
    done = _complete(client, world, job_id)
    assert done.status_code == 200, done.text
    return scan, job_id, result


def _run_clean(client, token, world, scan_id: int, hostname="asset-a", ip="10.1.0.10"):
    job_id = client.post(f"/api/scans/{scan_id}/run", headers=_headers(token)).json()["id"]
    _start_lan(client, world, job_id)
    _post_device(client, world, job_id, ip=ip, hostname=hostname)
    _post_coverage(client, world, job_id, [f"https://{ip}"])
    done = _complete(client, world, job_id)
    assert done.status_code == 200, done.text
    return job_id


@requires_postgres
def test_fresh_db_reaches_phase2a_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3A_HEAD
    tables = _tables(engine)
    assert {
        "vulnerabilities",
        "vulnerability_detector_mappings",
        "asset_findings",
        "asset_finding_history",
        "asset_finding_run_evaluations",
        "scan_run_detector_coverage",
    }.issubset(tables)


def test_0001_through_0008_remain_frozen():
    import hashlib

    from tests.test_migrations import FROZEN_MIGRATION_HASHES

    for name in FROZEN:
        source = (BACKEND_ROOT / "alembic" / "versions" / name).read_text()
        assert "from app.database import Base" not in source
        assert "import app.models" not in source
        digest = hashlib.sha256((BACKEND_ROOT / "alembic" / "versions" / name).read_bytes()).hexdigest()
        assert digest == FROZEN_MIGRATION_HASHES[name]


@requires_postgres
def test_downgrade_from_0007_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE2A_INITIAL)
    try:
        command.downgrade(alembic_config(), PHASE1D_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0007_vulnerability_finding_lifecycle" in str(exc)
        return
    raise AssertionError("0007 downgrade must refuse")


@requires_postgres
def test_downgrade_from_0008_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE2A_COVERAGE)
    try:
        command.downgrade(alembic_config(), PHASE2A_INITIAL)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0008_phase2a_finding_identity_repair" in str(exc)
        return
    raise AssertionError("0008 downgrade must refuse")


@requires_postgres
def test_downgrade_from_0009_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE2A_HEAD)
    try:
        command.downgrade(alembic_config(), PHASE2A_COVERAGE)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0009_phase2a_detector_identity_partition" in str(exc)
        return
    raise AssertionError("0009 downgrade must refuse")


@requires_postgres
def test_0006_to_0007_preserves_legacy_findings_and_does_not_fabricate_resolution(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision, head_revision
    from app.models import AssetFinding, Finding

    command.upgrade(alembic_config(), PHASE1D_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 2A', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        asset_id = conn.execute(
            text(
                """
                INSERT INTO assets (tenant_id, site_id, display_name, classification, description, lifecycle_state, disposition, criticality, is_expected, created_at, updated_at)
                VALUES (:t, :s, 'srv', 'Server', '', 'active', 'unreviewed', 'normal', false, :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        device_id = conn.execute(
            text(
                """
                INSERT INTO devices (tenant_id, site_id, ip, hostname, scope, status, classification, description, auto_label, title, tech, ports, asset_id)
                VALUES (:t, :s, '10.1.0.9', 'legacy-host', 'lan', 'known', 'Server', '', '', '', '', '[]'::jsonb, :a)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "a": asset_id},
        ).scalar_one()
        scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old', 'lan', 'discovery_nuclei', 'high', '', '[]'::jsonb, true)
                RETURNING id
                """
            ),
            {"t": tenant_id},
        ).scalar_one()
        job_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'done', 1, 2) RETURNING id"),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()
        for found in (now - timedelta(days=2), now - timedelta(days=1)):
            conn.execute(
                text(
                    """
                    INSERT INTO findings (tenant_id, scan_job_id, device_id, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                    VALUES (:t, :j, :d, 'exposed-panel', 'Panel', 'high', 'legacy-host', '10.1.0.9', 'https://10.1.0.9/', 'panel', :f, '{}'::jsonb)
                    """
                ),
                {"t": tenant_id, "j": job_id, "d": device_id, "f": found},
            )
        unlinked_id = conn.execute(
            text(
                """
                INSERT INTO findings (tenant_id, scan_job_id, device_id, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                VALUES (:t, :j, NULL, 'orphan-template', 'Orphan', 'low', 'unknown', '10.9.9.9', '', '', :f, '{}'::jsonb)
                RETURNING id
                """
            ),
            {"t": tenant_id, "j": job_id, "f": now},
        ).scalar_one()

    command.upgrade(alembic_config(), "head")
    assert current_revision() == head_revision() == PHASE3A_HEAD
    db = SessionLocal()
    try:
        evidence = db.query(Finding).filter(Finding.tenant_id == tenant_id).order_by(Finding.id).all()
        assert len(evidence) == 3
        assert {row.template_id for row in evidence} == {"exposed-panel", "orphan-template"}
        assert all(row.id for row in evidence)
        linked = [row for row in evidence if row.template_id == "exposed-panel"]
        assert len(linked) == 2
        assert {row.asset_finding_id for row in linked} == {linked[0].asset_finding_id}
        assert linked[0].asset_id == asset_id
        af = db.get(AssetFinding, linked[0].asset_finding_id)
        assert af is not None
        assert af.technical_state == "open"
        assert af.treatment_state == "unaddressed"
        assert af.consecutive_clean_scans == 0
        assert af.first_seen < af.last_seen
        orphan = db.get(Finding, unlinked_id)
        assert orphan is not None
        assert orphan.asset_finding_id is None
        assert orphan.asset_id is None
        assert db.query(AssetFinding).filter(AssetFinding.tenant_id == tenant_id).count() == 1
        from app.models import Vulnerability, VulnerabilityDetectorMapping

        mapping = (
            db.query(VulnerabilityDetectorMapping)
            .filter(
                VulnerabilityDetectorMapping.detector_type == "nuclei",
                VulnerabilityDetectorMapping.detector_key == "orphan-template",
            )
            .one()
        )
        vuln = db.get(Vulnerability, mapping.vulnerability_id)
        assert vuln.canonical_key == "nuclei:orphan-template"
        assert db.query(AssetFinding).filter(AssetFinding.vulnerability_id == vuln.id).count() == 0
    finally:
        db.close()


def test_catalog_identity_is_not_fuzzy():
    from app.finding_lifecycle import catalog_identity, extract_explicit_cve, parse_detector_identity
    from app.schemas import FindingReport

    assert extract_explicit_cve({"info": {"classification": {"cve-id": ["CVE-2021-44228"]}}}) == "CVE-2021-44228"
    assert extract_explicit_cve({"info": {"classification": {"cve-id": ["CVE-2020-0001", "CVE-2020-0002"]}}}) is None
    assert extract_explicit_cve({"info": {"name": "Looks like CVE-2021-44228"}}) is None
    from app.finding_lifecycle import cve_union

    assert cve_union(
        [
            {"info": {"classification": {"cve-id": ["CVE-2024-1111"]}}},
            {"info": {"classification": {"cve-id": ["CVE-2024-1111", "CVE-2024-2222"]}}},
        ]
    ) == {"CVE-2024-1111", "CVE-2024-2222"}
    assert catalog_identity("nuclei", "exposed-panel", None) == "nuclei:exposed-panel"
    assert catalog_identity("nuclei", "log4j", "CVE-2021-44228") == "cve:CVE-2021-44228"
    one = parse_detector_identity(FindingReport(template_id="panel-a", name="Admin panel A", severity="high"))
    two = parse_detector_identity(FindingReport(template_id="panel-b", name="Admin panel A", severity="high"))
    assert one.canonical_key != two.canonical_key


@requires_postgres
def test_first_detection_repeat_idempotence_and_later_run_reuse(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan = _vuln_scan(client, token, world)
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id)
        first = _post_findings(client, world, job_id)
        replay = _post_findings(client, world, job_id)
        assert first["added"] == 1
        assert replay["added"] == 0
        assert _complete(client, world, job_id).status_code == 200
        from app.database import SessionLocal
        from app.models import AssetFinding, Finding

        db = SessionLocal()
        try:
            afs = db.query(AssetFinding).all()
            assert len(afs) == 1
            af = afs[0]
            assert af.technical_state == "open"
            assert af.treatment_state == "unaddressed"
            assert af.consecutive_clean_scans == 0
            first_seen = af.first_seen
            evidence = db.query(Finding).filter(Finding.asset_finding_id == af.id).all()
            assert len(evidence) == 1
        finally:
            db.close()
        db = SessionLocal()
        try:
            assert db.query(Finding).count() == 1
            assert db.query(AssetFinding).count() == 1
            af = db.query(AssetFinding).one()
            assert af.first_seen == first_seen
        finally:
            db.close()

        later = _run_detected(client, token, world)
        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert db.query(Finding).filter(Finding.asset_finding_id == af.id).count() == 2
            assert af.last_seen > af.first_seen
            assert af.first_seen == first_seen
            assert later[1] != job_id
        finally:
            db.close()


@requires_postgres
def test_clean_scan_resolution_reopen_and_history(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan, first_job, _ = _run_detected(client, token, world)
        clean1 = _run_clean(client, token, world, scan["id"])
        from app.database import SessionLocal
        from app.models import AssetFinding, AssetFindingHistory, DomainEvent, Finding

        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.technical_state == "open"
            assert af.consecutive_clean_scans == 1
            assert af.treatment_state == "unaddressed"
            assert db.query(AssetFindingHistory).filter(AssetFindingHistory.transition_type == "resolved").count() == 0
        finally:
            db.close()

        discovery = _lan_scan(
            client,
            token,
            world,
            name="Discovery only",
            network_ids=[world["net1"]["id"]],
            stage_config={"discovery": True, "port_mode": "common", "fingerprint": False, "vulnerability": False},
        )
        _run_clean(client, token, world, discovery["id"])
        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.technical_state == "open"
            assert af.consecutive_clean_scans == 1
        finally:
            db.close()

        clean2 = _run_clean(client, token, world, scan["id"])
        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            original_first = af.first_seen
            assert af.technical_state == "resolved"
            assert af.consecutive_clean_scans == 2
            assert af.resolved_at is not None
            assert af.treatment_state == "unaddressed"
            resolved = db.query(AssetFindingHistory).filter(AssetFindingHistory.transition_type == "resolved").all()
            assert len(resolved) == 1
            assert db.query(DomainEvent).filter(DomainEvent.event_type == "vulnerability_resolved").count() == 1
        finally:
            db.close()

        _run_detected(client, token, world)
        db = SessionLocal()
        try:
            afs = db.query(AssetFinding).all()
            assert len(afs) == 1
            af = afs[0]
            assert af.technical_state == "open"
            assert af.resolved_at is None
            assert af.first_seen == original_first
            assert af.consecutive_clean_scans == 0
            assert af.reopened_count == 1
            assert db.query(AssetFindingHistory).filter(AssetFindingHistory.transition_type == "reopened").count() == 1
            assert db.query(Finding).filter(Finding.asset_finding_id == af.id).count() == 2
            assert db.query(DomainEvent).filter(DomainEvent.event_type == "vulnerability_reopened").count() == 1
            assert clean1 != clean2 != first_job
        finally:
            db.close()


@requires_postgres
def test_non_applicable_runs_do_not_count_and_detection_resets_streak(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan, _job, _ = _run_detected(client, token, world)
        _run_clean(client, token, world, scan["id"])

        failed_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, failed_id)
        _post_device(client, world, failed_id)
        failed = _complete(client, world, failed_id, ok=False, error="nuclei crashed")
        assert failed.status_code == 200

        from app.database import SessionLocal
        from app.models import AssetFinding, JOB_MISSED, ScanJob

        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.consecutive_clean_scans == 1
            assert af.technical_state == "open"
        finally:
            db.close()

        missed_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        db = SessionLocal()
        try:
            job = db.get(ScanJob, missed_id)
            job.status = JOB_MISSED
            db.commit()
        finally:
            db.close()
        db = SessionLocal()
        try:
            assert db.query(AssetFinding).one().consecutive_clean_scans == 1
        finally:
            db.close()

        off = _lan_scan(
            client,
            token,
            world,
            name="Vuln off",
            network_ids=[world["net1"]["id"]],
            stage_config={"discovery": True, "port_mode": "common", "fingerprint": True, "vulnerability": False},
        )
        _run_clean(client, token, world, off["id"])
        other = _vuln_scan(client, token, world, name="Other host")
        other_job = client.post(f"/api/scans/{other['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, other_job)
        _post_device(client, world, other_job, ip="10.1.0.99", hostname="other-host")
        assert _complete(client, world, other_job).status_code == 200

        sev = _lan_scan(
            client,
            token,
            world,
            name="Sev filter",
            network_ids=[world["net1"]["id"]],
            stage_config={**VULN_STAGES, "nuclei_severities": "critical"},
        )
        _run_clean(client, token, world, sev["id"])
        tags = _lan_scan(
            client,
            token,
            world,
            name="Tag filter",
            network_ids=[world["net1"]["id"]],
            stage_config={**VULN_STAGES, "nuclei_tags": "cve"},
        )
        _run_clean(client, token, world, tags["id"])
        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.consecutive_clean_scans == 1
            assert af.technical_state == "open"
        finally:
            db.close()

        detect_job = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, detect_job)
        _post_device(client, world, detect_job)
        _post_findings(client, world, detect_job)
        assert _complete(client, world, detect_job).status_code == 200
        db = SessionLocal()
        try:
            assert db.query(AssetFinding).one().consecutive_clean_scans == 0
        finally:
            db.close()


@requires_postgres
def test_snapshot_not_current_definition_and_finalize_is_idempotent(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan, _job, _ = _run_detected(client, token, world)
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id)
        _post_coverage(client, world, job_id, ["https://10.1.0.10"])
        edited = client.patch(
            f"/api/scans/{scan['id']}",
            headers=_headers(token),
            json={
                "name": scan["name"],
                "scope": scan["scope"],
                "site_id": scan["site_id"],
                "network_ids": scan["network_ids"],
                "is_enabled": True,
                "stage_config": {**VULN_STAGES, "vulnerability": False, "fingerprint": True},
            },
        )
        assert edited.status_code == 200, edited.text
        assert _complete(client, world, job_id).status_code == 200
        from app.database import SessionLocal
        from app.finding_lifecycle import finalize_run_lifecycle
        from app.models import AssetFinding, ScanJob

        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.consecutive_clean_scans == 1
            job = db.get(ScanJob, job_id)
            finalize_run_lifecycle(db, job)
            finalize_run_lifecycle(db, job)
            db.commit()
            db.refresh(af)
            assert af.consecutive_clean_scans == 1
            assert af.technical_state == "open"
        finally:
            db.close()


@requires_postgres
def test_treatment_independent_and_counts(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        scan, first_job, first = _run_detected(client, token, world)
        _run_detected(client, token, world)
        summary = client.get(f"/api/tenants/{world['tenant']['id']}/summary", headers=_headers(token)).json()
        assert summary["findings"]["high"] == 1
        from app.database import SessionLocal
        from app.models import TREATMENT_FALSE_POSITIVE, AssetFinding, ScanJob

        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            af.treatment_state = TREATMENT_FALSE_POSITIVE
            db.commit()
            job = db.get(ScanJob, first_job)
            assert job.findings_count == first["added"] == 1
        finally:
            db.close()
        _run_clean(client, token, world, scan["id"])
        _run_clean(client, token, world, scan["id"])
        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            assert af.technical_state == "resolved"
            assert af.treatment_state == TREATMENT_FALSE_POSITIVE
            af.treatment_state = "accepted_risk"
            db.commit()
            assert af.technical_state == "resolved"
        finally:
            db.close()
        summary = client.get(f"/api/tenants/{world['tenant']['id']}/summary", headers=_headers(token)).json()
        assert summary["findings"]["high"] == 0


@requires_postgres
def test_cross_tenant_and_authorization(reset_db):
    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        _run_detected(client, admin, world)
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other", "notes": ""}).json()
        from app.database import SessionLocal
        from app.models import AssetFinding

        db = SessionLocal()
        try:
            af = db.query(AssetFinding).one()
            af_id = af.id
        finally:
            db.close()
        denied = client.get(f"/api/tenants/{other['id']}/asset-findings/{af_id}", headers=_headers(admin))
        assert denied.status_code == 404
        allowed = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings/{af_id}", headers=_headers(admin))
        assert allowed.status_code == 200
        viewer = _create_staff(client, admin, "auditor", "viewer")
        readable = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(viewer))
        assert readable.status_code == 200
        settings = client.get("/api/admin/settings", headers=_headers(admin)).json()
        blocked = client.put("/api/admin/settings", headers=_headers(viewer), json=settings)
        assert blocked.status_code == 403
        settings["finding_resolution_clean_scans"] = 0
        bad = client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        assert bad.status_code == 422
        settings["finding_resolution_clean_scans"] = 3
        good = client.put("/api/admin/settings", headers=_headers(admin), json=settings)
        assert good.status_code == 200
        assert good.json()["finding_resolution_clean_scans"] == 3
        legacy = client.get(f"/api/tenants/{world['tenant']['id']}/findings", headers=_headers(viewer))
        assert legacy.status_code == 200
        assert len(legacy.json()) == 1


@requires_postgres
def test_asset_merge_inactivity_and_split_keep_findings_safe(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world, hostname="keep-host", ip="10.1.0.10")
        _run_detected(client, token, world, hostname="donor-host", ip="10.1.0.11")
        from app.database import SessionLocal
        from app.identity_ops import merge_assets, split_observations_to_new_asset
        from app.lifecycle import mark_inactive_assets
        from app.models import LIFECYCLE_INACTIVE, Asset, AssetFinding, Finding, User
        from app.settings_store import save_settings

        db = SessionLocal()
        try:
            assets = db.query(Asset).filter(Asset.merged_into_asset_id.is_(None)).order_by(Asset.id).all()
            assert len(assets) == 2
            keep, donor = assets
            actor = db.query(User).filter(User.username == "admin").one()
            keep_finding = db.query(AssetFinding).filter(AssetFinding.asset_id == keep.id).one()
            donor_finding = db.query(AssetFinding).filter(AssetFinding.asset_id == donor.id).one()
            assert keep_finding.vulnerability_id == donor_finding.vulnerability_id
            evidence_before = db.query(Finding).count()
            merge_assets(db, target=keep, source_ids=[donor.id], actor=actor, reason="same host family")
            db.commit()
            assert db.query(AssetFinding).filter(AssetFinding.asset_id == keep.id).count() == 1
            assert db.query(Finding).count() == evidence_before
            assert db.query(Finding).filter(Finding.asset_id == keep.id).count() == evidence_before
            af = db.query(AssetFinding).filter(AssetFinding.asset_id == keep.id).one()
            assert af.technical_state == "open"
            save_settings(db, {"asset_inactive_days": 1})
            keep.last_seen = datetime.now(timezone.utc) - timedelta(days=5)
            db.commit()
            assert mark_inactive_assets(db) >= 1
            db.refresh(keep)
            db.refresh(af)
            assert keep.lifecycle_state == LIFECYCLE_INACTIVE
            assert af.technical_state == "open"
        finally:
            db.close()

        _run_detected(client, token, world, hostname="keep-host", ip="10.1.0.10")
        db = SessionLocal()
        try:
            canonical = db.query(AssetFinding).all()
            assert len(canonical) == 1
            actor = db.query(User).filter(User.username == "admin").one()
            source = db.get(Asset, canonical[0].asset_id)
            obs_ids = [row.id for row in source.observations]
            assert obs_ids
            split_observations_to_new_asset(db, source=source, observation_ids=[obs_ids[0]], actor=actor, reason="split")
            db.commit()
            assert db.query(AssetFinding).count() == 1
            assert db.query(AssetFinding).one().asset_id == source.id
        finally:
            db.close()


@requires_postgres
def test_agent_and_central_use_same_lifecycle_and_legacy_api(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world)
        wan = _wan_scan(client, token, world, stage_config=dict(VULN_STAGES))
        job_id = client.post(f"/api/scans/{wan['id']}/run", headers=_headers(token)).json()["id"]
        started = client.post(f"/api/internal/scanner/jobs/{job_id}/start", headers=_scanner_headers())
        assert started.status_code == 200, started.text
        devices = client.post(
            f"/api/internal/scanner/jobs/{job_id}/devices",
            headers=_scanner_headers(),
            json=[{"ip": "203.0.113.10", "scope": "wan", "hostname": "edge-1"}],
        )
        assert devices.status_code == 200, devices.text
        coverage = client.post(
            f"/api/internal/scanner/jobs/{job_id}/detector-coverage",
            headers=_scanner_headers(),
            json={"detector_type": "nuclei", "targets": ["https://203.0.113.10"]},
        )
        assert coverage.status_code == 200, coverage.text
        findings = client.post(
            f"/api/internal/scanner/jobs/{job_id}/findings",
            headers=_scanner_headers(),
            json=[_finding_payload(host="https://203.0.113.10")],
        )
        assert findings.status_code == 200, findings.text
        done = client.post(
            f"/api/internal/scanner/jobs/{job_id}/complete",
            headers=_scanner_headers(),
            params={"ok": "true"},
        )
        assert done.status_code == 200, done.text
        from app.database import SessionLocal
        from app.models import AssetFinding, Finding

        db = SessionLocal()
        try:
            assert db.query(AssetFinding).count() == 2
            assert db.query(Finding).count() == 2
        finally:
            db.close()
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/findings", headers=_headers(token))
        assert listed.status_code == 200
        assert len(listed.json()) == 2
        logical = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(token))
        assert logical.status_code == 200
        assert len(logical.json()) == 2
        detail = client.get(f"/api/asset-findings/{logical.json()[0]['id']}", headers=_headers(token))
        assert detail.status_code == 200
        assert detail.json()["history"]
        assert detail.json()["evidence"]


def test_httpx_urls_become_nuclei_coverage_targets():
    import runner as runtime_runner
    from unittest.mock import patch

    def _httpx(hosts, log=None, intensity=None):
        return [{"ip": "10.1.0.11", "url": "https://10.1.0.11"}]

    def _nuclei(targets, **kwargs):
        captured["targets"] = list(targets)
        return []

    captured = {}
    with (
        patch.object(runtime_runner, "run_naabu", return_value=[{"ip": "10.1.0.10", "port": 22}, {"ip": "10.1.0.11", "port": 80}]),
        patch.object(runtime_runner, "run_httpx", side_effect=_httpx),
        patch.object(runtime_runner, "run_nuclei", side_effect=_nuclei),
    ):
        result = runtime_runner.run_pipeline(
            {
                "scope": "lan",
                "targets": [{"type": "cidr", "value": "10.1.0.0/24"}],
                "stages": dict(VULN_STAGES),
                "intensity": {},
                "exclusions": [],
            }
        )
    assert captured["targets"] == ["https://10.1.0.11"]
    assert result["detector_coverage"] == [{"detector_type": "nuclei", "targets": ["https://10.1.0.11"]}]


@requires_postgres
def test_naabu_only_ssh_asset_is_not_cleaned_when_nuclei_scanned_http_asset(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world, hostname="ssh-only", ip="10.1.0.10")
        scan, _job, _ = _run_detected(client, token, world, hostname="http-host", ip="10.1.0.11")
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id, ip="10.1.0.10", hostname="ssh-only")
        _post_device(client, world, job_id, ip="10.1.0.11", hostname="http-host")
        _post_coverage(client, world, job_id, ["https://10.1.0.11"])
        assert _complete(client, world, job_id).status_code == 200
        from app.database import SessionLocal
        from app.models import AssetFinding

        db = SessionLocal()
        try:
            from app.models import IDENTIFIER_HOSTNAME, AssetIdentifier

            findings = db.query(AssetFinding).all()
            assert len(findings) == 2
            by_host = {}
            for row in findings:
                hostname = (
                    db.query(AssetIdentifier.value)
                    .filter(
                        AssetIdentifier.asset_id == row.asset_id,
                        AssetIdentifier.identifier_type == IDENTIFIER_HOSTNAME,
                    )
                    .scalar()
                )
                by_host[hostname] = row
            assert by_host["ssh-only"].consecutive_clean_scans == 0
            assert by_host["ssh-only"].technical_state == "open"
            assert by_host["http-host"].consecutive_clean_scans == 1
        finally:
            db.close()


@requires_postgres
def test_clean_uses_supporting_detector_not_first_cve_mapping(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        cve_raw = {"info": {"classification": {"cve-id": ["CVE-2021-44228"]}, "tags": ["cve"]}}
        _run_detected(
            client,
            token,
            world,
            hostname="other-host",
            ip="10.1.0.20",
            findings=[
                _finding_payload(
                    template="template-a",
                    name="Log4j A",
                    severity="critical",
                    tags="cve",
                    host="https://10.1.0.20",
                    extra_raw=cve_raw,
                )
            ],
        )
        scan, _job, _ = _run_detected(
            client,
            token,
            world,
            hostname="asset-a",
            ip="10.1.0.10",
            findings=[
                _finding_payload(
                    template="template-b",
                    name="Log4j B",
                    severity="critical",
                    tags="panel",
                    host="https://10.1.0.10",
                    extra_raw={"info": {"classification": {"cve-id": ["CVE-2021-44228"]}, "tags": ["panel"]}},
                )
            ],
        )
        filtered = _lan_scan(
            client,
            token,
            world,
            name="CVE tags only",
            network_ids=[world["net1"]["id"]],
            stage_config={**VULN_STAGES, "nuclei_tags": "cve", "nuclei_severities": "critical,high,medium"},
        )
        _run_clean(client, token, world, filtered["id"])
        from app.database import SessionLocal
        from app.models import AssetFinding

        db = SessionLocal()
        try:
            from app.models import IDENTIFIER_HOSTNAME, AssetIdentifier

            rows = db.query(AssetFinding).all()
            assert len(rows) == 2
            asset_a_id = (
                db.query(AssetIdentifier.asset_id)
                .filter(AssetIdentifier.identifier_type == IDENTIFIER_HOSTNAME, AssetIdentifier.value == "asset-a")
                .scalar()
            )
            asset_a = next(row for row in rows if row.asset_id == asset_a_id)
            assert asset_a.consecutive_clean_scans == 0
            assert asset_a.technical_state == "open"
        finally:
            db.close()


@requires_postgres
def test_vuln_only_result_does_not_attach_to_stale_dhcp_device(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world, hostname="old-owner", ip="10.1.0.10")
        scan = _lan_scan(
            client,
            token,
            world,
            name="Vuln only",
            network_ids=[world["net1"]["id"]],
            stage_config={
                "discovery": False,
                "port_mode": "none",
                "fingerprint": False,
                "vulnerability": True,
                "nuclei_severities": "critical,high,medium",
                "nuclei_tags": "",
            },
        )
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(token)).json()["id"]
        _start_lan(client, world, job_id)
        posted = _post_findings(client, world, job_id, [_finding_payload(host="https://10.1.0.10")])
        assert posted["added"] == 1
        assert _complete(client, world, job_id).status_code == 200
        from app.database import SessionLocal
        from app.models import AssetFinding, Finding

        db = SessionLocal()
        try:
            assert db.query(AssetFinding).count() == 1
            unlinked = db.query(Finding).filter(Finding.asset_finding_id.is_(None)).one()
            assert unlinked.host == "https://10.1.0.10"
            assert unlinked.asset_id is None
            assert unlinked.device_id is None
        finally:
            db.close()


@requires_postgres
def test_0006_to_0008_repairs_catalog_orderings_and_multi_cve(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config
    from app.models import AssetFinding, Finding, Vulnerability, VulnerabilityDetectorMapping

    command.upgrade(alembic_config(), PHASE1D_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Repair 2A', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        asset_id = conn.execute(
            text(
                """
                INSERT INTO assets (tenant_id, site_id, display_name, classification, description, lifecycle_state, disposition, criticality, is_expected, created_at, updated_at)
                VALUES (:t, :s, 'srv', 'Server', '', 'active', 'unreviewed', 'normal', false, :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        device_id = conn.execute(
            text(
                """
                INSERT INTO devices (tenant_id, site_id, ip, hostname, scope, status, classification, description, auto_label, title, tech, ports, asset_id)
                VALUES (:t, :s, '10.1.0.9', 'legacy-host', 'lan', 'known', 'Server', '', '', '', '', '[]'::jsonb, :a)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "a": asset_id},
        ).scalar_one()
        scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old', 'lan', 'discovery_nuclei', 'high', '', '[]'::jsonb, true)
                RETURNING id
                """
            ),
            {"t": tenant_id},
        ).scalar_one()
        job_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'done', 1, 5) RETURNING id"),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()

        def _insert_finding(template, raw, found, device=device_id):
            conn.execute(
                text(
                    """
                    INSERT INTO findings (tenant_id, scan_job_id, device_id, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                    VALUES (:t, :j, :d, :tmpl, :name, 'high', 'legacy-host', '10.1.0.9', '', '', :f, CAST(:raw AS jsonb))
                    """
                ),
                {
                    "t": tenant_id,
                    "j": job_id,
                    "d": device,
                    "tmpl": template,
                    "name": template,
                    "f": found,
                    "raw": json.dumps(raw),
                },
            )

        _insert_finding("order-missing-first", {"info": {"name": "plain"}}, now - timedelta(days=2))
        _insert_finding(
            "order-missing-first",
            {"info": {"classification": {"cve-id": ["CVE-2021-44228"]}}},
            now - timedelta(days=1),
        )
        _insert_finding(
            "order-cve-first",
            {"info": {"classification": {"cve-id": ["CVE-2022-0001"]}}},
            now - timedelta(days=2),
        )
        _insert_finding("order-cve-first", {"info": {"name": "later plain"}}, now - timedelta(days=1))
        _insert_finding(
            "multi-cve",
            {"info": {"classification": {"cve-id": ["CVE-2020-0001", "CVE-2020-0002"]}}},
            now,
        )
        conn.execute(
            text(
                """
                INSERT INTO findings (tenant_id, scan_job_id, device_id, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                VALUES (:t, :j, NULL, 'unlinked-known', 'Unlinked', 'low', 'unknown', '10.9.9.9', '', '', :f, '{}'::jsonb)
                """
            ),
            {"t": tenant_id, "j": job_id, "f": now},
        )

    command.upgrade(alembic_config(), "head")
    db = SessionLocal()
    try:
        def _mapping(key: str) -> VulnerabilityDetectorMapping:
            return (
                db.query(VulnerabilityDetectorMapping)
                .filter(
                    VulnerabilityDetectorMapping.detector_type == "nuclei",
                    VulnerabilityDetectorMapping.detector_key == key,
                )
                .one()
            )

        missing_first = _mapping("order-missing-first")
        cve_first = _mapping("order-cve-first")
        multi = _mapping("multi-cve")
        unlinked = _mapping("unlinked-known")
        assert db.get(Vulnerability, missing_first.vulnerability_id).canonical_key == "cve:CVE-2021-44228"
        assert db.get(Vulnerability, cve_first.vulnerability_id).canonical_key == "cve:CVE-2022-0001"
        assert db.get(Vulnerability, multi.vulnerability_id).canonical_key == "nuclei:multi-cve"
        assert db.get(Vulnerability, unlinked.vulnerability_id).canonical_key == "nuclei:unlinked-known"
        assert db.query(AssetFinding).filter(AssetFinding.vulnerability_id == unlinked.vulnerability_id).count() == 0
        for key, canonical in (
            ("order-missing-first", "cve:CVE-2021-44228"),
            ("order-cve-first", "cve:CVE-2022-0001"),
            ("multi-cve", "nuclei:multi-cve"),
        ):
            mapping = _mapping(key)
            afs = (
                db.query(AssetFinding)
                .filter(AssetFinding.vulnerability_id == mapping.vulnerability_id, AssetFinding.asset_id == asset_id)
                .all()
            )
            assert len(afs) == 1
            assert db.get(Vulnerability, mapping.vulnerability_id).canonical_key == canonical
            evidence = db.query(Finding).filter(Finding.detector_key == key, Finding.asset_id == asset_id).all()
            assert evidence
            assert {row.asset_finding_id for row in evidence} == {afs[0].id}
    finally:
        db.close()


@requires_postgres
def test_list_and_dashboard_queries_are_bounded_and_severity_filters_before_limit(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(client, token, world)
        from sqlalchemy import event

        from app.database import SessionLocal, engine
        from app.models import TECHNICAL_OPEN, TREATMENT_UNADDRESSED, Asset, AssetFinding, Finding, Vulnerability

        db = SessionLocal()
        try:
            tenant_id = world["tenant"]["id"]
            site_id = world["site"]["id"]
            now = datetime.now(timezone.utc)
            asset = db.query(Asset).filter(Asset.tenant_id == tenant_id).first()
            vulns = []
            for index in range(2100):
                vuln = Vulnerability(canonical_key=f"nuclei:scale-{index}", title=f"Scale {index}")
                db.add(vuln)
                vulns.append(vuln)
            db.flush()
            findings = []
            for index, vuln in enumerate(vulns):
                severity = "critical" if index < 50 else "high"
                af = AssetFinding(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    technical_state=TECHNICAL_OPEN,
                    treatment_state=TREATMENT_UNADDRESSED,
                    first_seen=now,
                    last_seen=now + timedelta(seconds=index),
                    consecutive_clean_scans=0,
                )
                db.add(af)
                db.flush()
                db.add(
                    Finding(
                        tenant_id=tenant_id,
                        asset_id=asset.id,
                        asset_finding_id=af.id,
                        detector_type="nuclei",
                        detector_key=f"scale-{index}",
                        evidence_key=f"scale:{index}",
                        template_id=f"scale-{index}",
                        name=f"Scale {index}",
                        severity=severity,
                        hostname="asset-a",
                        host="https://10.1.0.10",
                        found_at=now + timedelta(seconds=index),
                    )
                )
                findings.append(af)
            db.commit()
        finally:
            db.close()

        count = {"n": 0}

        def _before(*_args, **_kwargs):
            count["n"] += 1

        event.listen(engine, "before_cursor_execute", _before)
        try:
            listed = client.get(
                f"/api/tenants/{world['tenant']['id']}/asset-findings",
                headers=_headers(token),
                params={"severity": "critical"},
            )
            dashboard = client.get("/api/dashboard", headers=_headers(token))
            summary = client.get(f"/api/tenants/{world['tenant']['id']}/summary", headers=_headers(token))
        finally:
            event.remove(engine, "before_cursor_execute", _before)
        assert listed.status_code == 200, listed.text
        assert len(listed.json()) == 50
        assert all(row["severity"] == "critical" for row in listed.json())
        assert dashboard.status_code == 200
        assert dashboard.json()["findings"]["critical"] == 50
        assert dashboard.json()["findings"]["high"] == 2051
        assert summary.json()["findings"]["critical"] == 50
        assert count["n"] < 60


def _cve_info(cves, tags="cve"):
    return {"info": {"classification": {"cve-id": list(cves)}, "tags": [tags]}}


def _assert_mapping(db, detector_key: str, canonical: str):
    from app.models import Vulnerability, VulnerabilityDetectorMapping

    mapping = (
        db.query(VulnerabilityDetectorMapping)
        .filter(
            VulnerabilityDetectorMapping.detector_type == "nuclei",
            VulnerabilityDetectorMapping.detector_key == detector_key,
        )
        .one()
    )
    vuln = db.get(Vulnerability, mapping.vulnerability_id)
    assert vuln.canonical_key == canonical
    return mapping, vuln


@requires_postgres
def test_runtime_mixed_and_conflicting_cve_history_fails_closed(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(
            client,
            token,
            world,
            hostname="mixed-host",
            ip="10.1.0.30",
            findings=[
                _finding_payload(
                    template="mixed-template",
                    name="Mixed",
                    host="https://10.1.0.30",
                    extra_raw=_cve_info(["CVE-2024-1111"]),
                )
            ],
        )
        _run_detected(
            client,
            token,
            world,
            hostname="mixed-host",
            ip="10.1.0.30",
            findings=[
                _finding_payload(
                    template="mixed-template",
                    name="Mixed later",
                    host="https://10.1.0.30",
                    extra_raw=_cve_info(["CVE-2024-1111", "CVE-2024-2222"]),
                )
            ],
        )
        from app.database import SessionLocal
        from app.models import AssetFinding, Finding

        db = SessionLocal()
        try:
            _assert_mapping(db, "mixed-template", "nuclei:mixed-template")
            assert db.query(AssetFinding).count() == 1
            af = db.query(AssetFinding).one()
            assert af.vulnerability.canonical_key == "nuclei:mixed-template"
            assert db.query(Finding).filter(Finding.asset_finding_id == af.id).count() == 2
        finally:
            db.close()

        _run_detected(
            client,
            token,
            world,
            hostname="rev-host",
            ip="10.1.0.31",
            findings=[
                _finding_payload(
                    template="reverse-template",
                    name="Reverse",
                    host="https://10.1.0.31",
                    extra_raw=_cve_info(["CVE-2024-1111", "CVE-2024-2222"]),
                )
            ],
        )
        _run_detected(
            client,
            token,
            world,
            hostname="rev-host",
            ip="10.1.0.31",
            findings=[
                _finding_payload(
                    template="reverse-template",
                    name="Reverse later",
                    host="https://10.1.0.31",
                    extra_raw=_cve_info(["CVE-2024-1111"]),
                )
            ],
        )
        db = SessionLocal()
        try:
            _assert_mapping(db, "reverse-template", "nuclei:reverse-template")
        finally:
            db.close()

        _run_detected(
            client,
            token,
            world,
            hostname="two-host",
            ip="10.1.0.32",
            findings=[
                _finding_payload(
                    template="two-cve-template",
                    name="Two A",
                    host="https://10.1.0.32",
                    extra_raw=_cve_info(["CVE-2024-0001"]),
                )
            ],
        )
        _run_detected(
            client,
            token,
            world,
            hostname="two-host",
            ip="10.1.0.32",
            findings=[
                _finding_payload(
                    template="two-cve-template",
                    name="Two B",
                    host="https://10.1.0.32",
                    extra_raw=_cve_info(["CVE-2024-0002"]),
                )
            ],
        )
        db = SessionLocal()
        try:
            _assert_mapping(db, "two-cve-template", "nuclei:two-cve-template")
            assert db.query(AssetFinding).filter(AssetFinding.vulnerability.has(canonical_key="nuclei:two-cve-template")).count() == 1
        finally:
            db.close()


@requires_postgres
def test_runtime_partitions_shared_cve_finding_when_one_template_diverges(reset_db):
    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        _run_detected(
            client,
            token,
            world,
            hostname="shared-host",
            ip="10.1.0.40",
            findings=[
                _finding_payload(
                    template="template-a",
                    name="Shared A",
                    tags="cve",
                    host="https://10.1.0.40",
                    extra_raw=_cve_info(["CVE-2024-9999"]),
                ),
                _finding_payload(
                    template="template-b",
                    name="Shared B",
                    tags="cve",
                    host="https://10.1.0.40",
                    extra_raw=_cve_info(["CVE-2024-9999"]),
                ),
            ],
        )
        from app.database import SessionLocal
        from app.models import AssetFinding, AssetFindingHistory, Finding

        db = SessionLocal()
        try:
            assert db.query(AssetFinding).count() == 1
            shared = db.query(AssetFinding).one()
            shared_id = shared.id
            assert shared.vulnerability.canonical_key == "cve:CVE-2024-9999"
            assert db.query(Finding).filter(Finding.asset_finding_id == shared_id).count() == 2
            original_history = db.query(AssetFindingHistory).filter(AssetFindingHistory.asset_finding_id == shared_id).count()
        finally:
            db.close()

        _run_detected(
            client,
            token,
            world,
            hostname="shared-host",
            ip="10.1.0.40",
            findings=[
                _finding_payload(
                    template="template-a",
                    name="Diverged A",
                    tags="cve",
                    host="https://10.1.0.40",
                    extra_raw=_cve_info(["CVE-2024-9999", "CVE-2024-8888"]),
                )
            ],
        )
        db = SessionLocal()
        try:
            mapping_a, vuln_a = _assert_mapping(db, "template-a", "nuclei:template-a")
            mapping_b, vuln_b = _assert_mapping(db, "template-b", "cve:CVE-2024-9999")
            assert vuln_a.id != vuln_b.id
            afs = db.query(AssetFinding).order_by(AssetFinding.id).all()
            assert len(afs) == 2
            cve_af = next(row for row in afs if row.vulnerability_id == vuln_b.id)
            fallback_af = next(row for row in afs if row.vulnerability_id == vuln_a.id)
            assert cve_af.id == shared_id
            assert {row.detector_key for row in cve_af.evidence} == {"template-b"}
            assert {row.detector_key for row in fallback_af.evidence} == {"template-a"}
            assert db.query(Finding).filter(Finding.detector_key == "template-a").count() == 2
            assert all(row.asset_finding_id == fallback_af.id for row in db.query(Finding).filter(Finding.detector_key == "template-a"))
            assert db.query(AssetFindingHistory).filter(AssetFindingHistory.asset_finding_id == shared_id).count() == original_history
            opened = (
                db.query(AssetFindingHistory)
                .filter(
                    AssetFindingHistory.asset_finding_id == fallback_af.id,
                    AssetFindingHistory.transition_type == "opened",
                )
                .one()
            )
            assert opened.details["reason"] == "detector_identity_partition"
        finally:
            db.close()


@requires_postgres
def test_0008_to_0009_repairs_mixed_cve_union_and_partitions_shared_findings(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config
    from app.models import AssetFinding, Finding, Vulnerability, VulnerabilityDetectorMapping

    command.upgrade(alembic_config(), PHASE1D_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Partition 2A', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name, created_at) VALUES (:t, 'HQ', :n) RETURNING id"),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        asset_id = conn.execute(
            text(
                """
                INSERT INTO assets (tenant_id, site_id, display_name, classification, description, lifecycle_state, disposition, criticality, is_expected, created_at, updated_at)
                VALUES (:t, :s, 'srv', 'Server', '', 'active', 'unreviewed', 'normal', false, :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        device_id = conn.execute(
            text(
                """
                INSERT INTO devices (tenant_id, site_id, ip, hostname, scope, status, classification, description, auto_label, title, tech, ports, asset_id)
                VALUES (:t, :s, '10.1.0.9', 'legacy-host', 'lan', 'known', 'Server', '', '', '', '', '[]'::jsonb, :a)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "a": asset_id},
        ).scalar_one()
        scan_id = conn.execute(
            text(
                """
                INSERT INTO scans (tenant_id, name, scope, profile, nuclei_severities, nuclei_tags, subnet_ids, is_enabled)
                VALUES (:t, 'Old', 'lan', 'discovery_nuclei', 'high', '', '[]'::jsonb, true)
                RETURNING id
                """
            ),
            {"t": tenant_id},
        ).scalar_one()
        job_id = conn.execute(
            text("INSERT INTO scan_jobs (scan_id, tenant_id, status, hosts_found, findings_count) VALUES (:s, :t, 'done', 1, 8) RETURNING id"),
            {"s": scan_id, "t": tenant_id},
        ).scalar_one()

        def _insert(template, raw, found):
            conn.execute(
                text(
                    """
                    INSERT INTO findings (tenant_id, scan_job_id, device_id, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                    VALUES (:t, :j, :d, :tmpl, :name, 'high', 'legacy-host', '10.1.0.9', '', '', :f, CAST(:raw AS jsonb))
                    """
                ),
                {
                    "t": tenant_id,
                    "j": job_id,
                    "d": device_id,
                    "tmpl": template,
                    "name": template,
                    "f": found,
                    "raw": json.dumps(raw),
                },
            )

        _insert("mixed-first-single", _cve_info(["CVE-2024-1111"]), now - timedelta(days=4))
        _insert("mixed-first-single", _cve_info(["CVE-2024-1111", "CVE-2024-2222"]), now - timedelta(days=3))
        _insert("mixed-first-multi", _cve_info(["CVE-2024-1111", "CVE-2024-2222"]), now - timedelta(days=4))
        _insert("mixed-first-multi", _cve_info(["CVE-2024-1111"]), now - timedelta(days=3))
        _insert("two-singles", _cve_info(["CVE-2024-0001"]), now - timedelta(days=2))
        _insert("two-singles", _cve_info(["CVE-2024-0002"]), now - timedelta(days=1))
        _insert("template-a", _cve_info(["CVE-2024-9999"]), now - timedelta(days=2))
        _insert("template-b", _cve_info(["CVE-2024-9999"]), now - timedelta(days=2))
        _insert("template-a", _cve_info(["CVE-2024-9999", "CVE-2024-8888"]), now - timedelta(days=1))

    command.upgrade(alembic_config(), PHASE2A_COVERAGE)
    with engine.connect() as conn:
        mixed_id = conn.execute(
            text("SELECT vulnerability_id FROM vulnerability_detector_mappings WHERE detector_key = 'mixed-first-single'")
        ).scalar_one()
        canonical = conn.execute(
            text("SELECT canonical_key FROM vulnerabilities WHERE id = :id"),
            {"id": mixed_id},
        ).scalar_one()
        assert canonical == "cve:CVE-2024-1111"
        shared = conn.execute(
            text(
                """
                SELECT DISTINCT asset_findings.id
                FROM asset_findings
                JOIN findings ON findings.asset_finding_id = asset_findings.id
                WHERE findings.detector_key IN ('template-a', 'template-b')
                """
            )
        ).all()
        assert len(shared) == 1

    command.upgrade(alembic_config(), "head")
    db = SessionLocal()
    try:
        _assert_mapping(db, "mixed-first-single", "nuclei:mixed-first-single")
        _assert_mapping(db, "mixed-first-multi", "nuclei:mixed-first-multi")
        _assert_mapping(db, "two-singles", "nuclei:two-singles")
        mapping_a, vuln_a = _assert_mapping(db, "template-a", "nuclei:template-a")
        mapping_b, vuln_b = _assert_mapping(db, "template-b", "cve:CVE-2024-9999")
        assert vuln_a.id != vuln_b.id
        cve_af = (
            db.query(AssetFinding)
            .filter(AssetFinding.asset_id == asset_id, AssetFinding.vulnerability_id == vuln_b.id)
            .one()
        )
        fallback_af = (
            db.query(AssetFinding)
            .filter(AssetFinding.asset_id == asset_id, AssetFinding.vulnerability_id == vuln_a.id)
            .one()
        )
        assert {row.detector_key for row in cve_af.evidence} == {"template-b"}
        assert {row.detector_key for row in fallback_af.evidence} == {"template-a"}
        assert db.query(Finding).filter(Finding.detector_key == "template-a", Finding.asset_finding_id == fallback_af.id).count() == 2
        assert db.query(Finding).filter(Finding.detector_key == "template-b", Finding.asset_finding_id == cve_af.id).count() == 1
    finally:
        db.close()
