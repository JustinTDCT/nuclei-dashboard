from __future__ import annotations

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
PHASE2A_HEAD = "0007_vulnerability_finding_lifecycle"
FROZEN = (
    "0001_baseline_current_schema.py",
    "0002_sites_networks.py",
    "0003_assets_observations.py",
    "0004_asset_observation_integrity.py",
    "0005_asset_correlation_lifecycle.py",
    "0006_scan_definition_execution.py",
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
    done = _complete(client, world, job_id)
    assert done.status_code == 200, done.text
    return job_id


@requires_postgres
def test_fresh_db_reaches_phase2a_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE2A_HEAD
    tables = _tables(engine)
    assert {
        "vulnerabilities",
        "vulnerability_detector_mappings",
        "asset_findings",
        "asset_finding_history",
        "asset_finding_run_evaluations",
    }.issubset(tables)


def test_0001_through_0006_remain_frozen():
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

    apply_schema()
    try:
        command.downgrade(alembic_config(), PHASE1D_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0007_vulnerability_finding_lifecycle" in str(exc)
        return
    raise AssertionError("0007 downgrade must refuse")


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
    assert current_revision() == head_revision() == PHASE2A_HEAD
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
    finally:
        db.close()


def test_catalog_identity_is_not_fuzzy():
    from app.finding_lifecycle import catalog_identity, extract_explicit_cve, parse_detector_identity
    from app.schemas import FindingReport

    assert extract_explicit_cve({"info": {"classification": {"cve-id": ["CVE-2021-44228"]}}}) == "CVE-2021-44228"
    assert extract_explicit_cve({"info": {"name": "Looks like CVE-2021-44228"}}) is None
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
