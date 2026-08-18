from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError

from tests.conftest import requires_postgres
from tests.test_phase1d import _client, _create_staff, _headers, _login, _world
from tests.test_phase2a import _finding_payload, _run_detected

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE2B_HEAD = "0010_cve_intelligence_priority"
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
NIST_BUNDLE = BACKEND_ROOT / "app" / "data" / "compliance" / "nist_sp_800_171_rev3.json"


def _now():
    return datetime.now(timezone.utc)


def _treat_url(tenant_id, af_id, suffix=""):
    return f"/api/tenants/{tenant_id}/asset-findings/{af_id}/treatments{suffix}"


def _open_finding(client, token, world, **kwargs):
    hostname = kwargs.get("hostname", "asset-a")
    scan, job_id, _posted = _run_detected(client, token, world, **kwargs)
    tenant_id = world["tenant"]["id"]
    rows = client.get(f"/api/tenants/{tenant_id}/asset-findings", headers=_headers(token)).json()
    matched = [
        row
        for row in rows
        if hostname in (row.get("asset_hostname") or "") or hostname in (row.get("asset_display_name") or "")
    ]
    evidence = client.get(f"/api/tenants/{tenant_id}/findings", headers=_headers(token)).json()
    return {
        "scan": scan,
        "job_id": job_id,
        "asset_findings": matched or rows,
        "findings": [row for row in evidence if row.get("hostname") == hostname] or evidence,
    }


@requires_postgres
def test_fresh_db_reaches_0011(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE2C_HEAD
    tables = set(inspect(engine).get_table_names())
    assert {
        "finding_treatments",
        "compensating_controls",
        "compliance_frameworks",
        "compliance_controls",
        "compliance_control_references",
    }.issubset(tables)


@requires_postgres
def test_0010_to_0011_preserves_phase2b_and_imports_legacy_projection(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision
    from app.models import (
        LEGACY_TREATMENT_RATIONALE,
        AssetFinding,
        Finding,
        FindingTreatment,
        Vulnerability,
        VulnerabilityDetectorMapping,
        VulnerabilityIntelligence,
    )

    command.upgrade(alembic_config(), PHASE2B_HEAD)
    now = _now()
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 2C', '') RETURNING id")).scalar_one()
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
        vuln_id = conn.execute(
            text("INSERT INTO vulnerabilities (canonical_key, cve_id, title, description) VALUES ('cve:CVE-2024-1234', 'CVE-2024-1234', 'Old', 'kept') RETURNING id")
        ).scalar_one()
        mapping_id = conn.execute(
            text(
                "INSERT INTO vulnerability_detector_mappings (vulnerability_id, detector_type, detector_key, last_severity) VALUES (:v, 'nuclei', 'tpl', 'high') RETURNING id"
            ),
            {"v": vuln_id},
        ).scalar_one()
        af_id = conn.execute(
            text(
                """
                INSERT INTO asset_findings (
                    tenant_id, asset_id, vulnerability_id, technical_state, treatment_state,
                    first_seen, last_seen, consecutive_clean_scans, reopened_count,
                    priority, priority_score, priority_model_version
                )
                VALUES (:t, :a, :v, 'open', 'mitigated', :n, :n, 1, 0, 'p2', 55, '2b.1')
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": asset_id, "v": vuln_id, "n": now},
        ).scalar_one()
        finding_id = conn.execute(
            text(
                """
                INSERT INTO findings (tenant_id, asset_id, asset_finding_id, detector_type, detector_key, template_id, name, severity, hostname, host, matched_at, tags, found_at, raw_json)
                VALUES (:t, :a, :af, 'nuclei', 'tpl', 'tpl', 'Old', 'high', 'srv', '10.1.0.10', '', '', :n, '{}'::jsonb)
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": asset_id, "af": af_id, "n": now},
        ).scalar_one()
        hist_id = conn.execute(
            text(
                """
                INSERT INTO asset_finding_history (asset_finding_id, tenant_id, transition_type, new_technical_state, occurred_at, details, idempotence_key)
                VALUES (:af, :t, 'opened', 'open', :n, '{}'::jsonb, 'opened-keep-2c')
                RETURNING id
                """
            ),
            {"af": af_id, "t": tenant_id, "n": now},
        ).scalar_one()
        conn.execute(
            text(
                """
                INSERT INTO vulnerability_intelligence (vulnerability_id, cvss_base_score, cvss_version, kev, created_at, updated_at)
                VALUES (:v, 9.8, '3.1', true, :n, :n)
                """
            ),
            {"v": vuln_id, "n": now},
        )

    command.upgrade(alembic_config(), PHASE2C_HEAD)
    assert current_revision() == PHASE2C_HEAD
    db = SessionLocal()
    try:
        vuln = db.get(Vulnerability, vuln_id)
        assert vuln.canonical_key == "cve:CVE-2024-1234"
        assert db.get(VulnerabilityDetectorMapping, mapping_id).vulnerability_id == vuln_id
        af = db.get(AssetFinding, af_id)
        assert af.vulnerability_id == vuln_id
        assert af.treatment_state == "mitigated"
        assert af.priority == "p2"
        assert af.priority_score == 55
        assert af.priority_model_version == "2b.1"
        assert db.get(Finding, finding_id).asset_finding_id == af_id
        from app.models import AssetFindingHistory

        assert db.get(AssetFindingHistory, hist_id) is not None
        intel = db.get(VulnerabilityIntelligence, vuln_id)
        assert float(intel.cvss_base_score) == 9.8
        assert intel.kev is True
        imported = db.query(FindingTreatment).filter(FindingTreatment.asset_finding_id == af_id).all()
        assert len(imported) == 1
        row = imported[0]
        assert row.source == "legacy_projection"
        assert row.status == "active"
        assert row.treatment_type == "mitigated"
        assert row.rationale == LEGACY_TREATMENT_RATIONALE
        assert row.reviewed_by_user_id is None
    finally:
        db.close()


@requires_postgres
def test_downgrade_from_0011_is_refused(reset_db):
    from alembic import command
    from alembic.util import CommandError

    from app.migrate import alembic_config

    command.upgrade(alembic_config(), PHASE2C_HEAD)
    try:
        command.downgrade(alembic_config(), PHASE2B_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0011_phase2c_treatments_compliance" in str(exc)
        return
    raise AssertionError("0011 downgrade must refuse")


@requires_postgres
def test_treatment_workflow_detection_priority_and_auth(reset_db):
    from app.database import SessionLocal
    from app.models import AssetFinding, AuditLog, Finding, FindingTreatment, PRIORITY_MODEL_VERSION
    from app.treatments import expire_due_treatments

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        user = _create_staff(client, admin, "tech2c", "user")
        viewer = _create_staff(client, admin, "view2c", "viewer")
        other_tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other 2C", "notes": ""}).json()
        opened = _open_finding(client, admin, world)
        finding = opened["asset_findings"][0]
        af_id = finding["id"]
        score_before = finding["priority_score"]
        headers = _headers(user)

        mitigation = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "mitigated", "rationale": "Firewall blocks inbound access"},
        )
        assert mitigation.status_code == 200, mitigation.text
        assert mitigation.json()["status"] == "active"
        assert mitigation.json()["display_status"] == "active"
        listed = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert listed["technical_state"] == "open"
        assert listed["treatment_state"] == "mitigated"
        assert listed["priority_score"] == score_before
        assert listed["priority_model_version"] == PRIORITY_MODEL_VERSION
        assert listed["current_treatment"]["id"] == mitigation.json()["id"]

        accepted = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "accepted_risk", "rationale": "Business accepted residual risk"},
        )
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "pending_review"
        still = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert still["treatment_state"] == "mitigated"
        assert still["current_treatment"]["treatment_type"] == "mitigated"

        approved = client.post(
            _treat_url(tenant_id, af_id, f"/{accepted.json()['id']}/approve"),
            headers=headers,
            json={"review_notes": "Reviewed and accepted"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "active"
        assert approved.json()["reviewed_by_username"] == "tech2c"
        after = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert after["treatment_state"] == "accepted_risk"
        assert after["technical_state"] == "open"
        history = {row["id"]: row["status"] for row in after["treatments"]}
        assert history[mitigation.json()["id"]] == "superseded"
        assert history[accepted.json()["id"]] == "active"

        fp = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "false_positive", "rationale": "Template matched a banner only"},
        )
        assert fp.json()["status"] == "pending_review"
        pending_fp = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert pending_fp["treatment_state"] == "accepted_risk"
        client.post(_treat_url(tenant_id, af_id, f"/{fp.json()['id']}/approve"), headers=headers, json={})
        fp_active = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert fp_active["treatment_state"] == "false_positive"
        assert fp_active["technical_state"] == "open"

        before_evidence = len(fp_active["evidence"])
        again = _open_finding(client, admin, world)
        assert again["asset_findings"][0]["id"] == af_id
        refreshed = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert refreshed["technical_state"] == "open"
        assert refreshed["treatment_state"] == "false_positive"
        assert len(refreshed["evidence"]) > before_evidence

        control = client.post(
            _treat_url(tenant_id, af_id, f"/{fp.json()['id']}/compensating-controls"),
            headers=headers,
            json={"name": "Internet access restricted by firewall", "description": "WAN deny", "evidence_notes": "rule 22"},
        )
        assert control.status_code == 200
        retired = client.post(
            _treat_url(tenant_id, af_id, f"/{fp.json()['id']}/compensating-controls/{control.json()['id']}/retire"),
            headers=headers,
            json={"reason": "Rule removed after network change"},
        )
        assert retired.status_code == 200
        assert retired.json()["status"] == "retired"
        assert client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()["treatments"][-1][
            "compensating_controls"
        ][0]["status"] == "retired"

        revoke = client.post(
            _treat_url(tenant_id, af_id, f"/{fp.json()['id']}/revoke"),
            headers=headers,
            json={"reason": "Need to reopen treatment"},
        )
        assert revoke.status_code == 200
        revoked = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert revoked["treatment_state"] == "unaddressed"
        assert revoked["technical_state"] == "open"

        expiring = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={
                "treatment_type": "mitigated",
                "rationale": "Temporary ACL",
                "review_due_at": (_now() - timedelta(days=1)).isoformat(),
                "expires_at": (_now() + timedelta(days=7)).isoformat(),
            },
        )
        assert expiring.status_code == 200
        overdue = client.get(
            f"/api/tenants/{tenant_id}/asset-findings?treatment_review_overdue=true",
            headers=headers,
        )
        assert overdue.status_code == 200
        assert any(row["id"] == af_id for row in overdue.json())
        detail = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=headers).json()
        assert detail["treatment_display_status"] == "review_overdue"
        assert detail["treatment_state"] == "mitigated"

        db = SessionLocal()
        try:
            row = db.get(FindingTreatment, expiring.json()["id"])
            row.expires_at = _now() - timedelta(minutes=1)
            db.commit()
            expired = expire_due_treatments(db)
            db.commit()
            assert expired == 1
            af = db.get(AssetFinding, af_id)
            assert af.technical_state == "open"
            assert af.treatment_state == "unaddressed"
            audits = {item.action for item in db.query(AuditLog).filter(AuditLog.object_type.in_(["finding_treatment", "compensating_control"])).all()}
            assert {
                "treatment.created",
                "treatment.approved",
                "treatment.superseded",
                "treatment.revoked",
                "treatment.expired",
                "compensating_control.created",
                "compensating_control.retired",
            }.issubset(audits)
        finally:
            db.close()

        assert client.delete(_treat_url(tenant_id, af_id, f"/{expiring.json()['id']}"), headers=headers).status_code in {404, 405}
        assert client.post(_treat_url(tenant_id, af_id), headers=_headers(viewer), json={"treatment_type": "mitigated", "rationale": "no"}).status_code == 403
        assert client.post(_treat_url(tenant_id, af_id, f"/{expiring.json()['id']}/approve"), headers=_headers(viewer), json={}).status_code == 403
        assert client.get(_treat_url(other_tenant["id"], af_id), headers=_headers(admin)).status_code == 404
        assert client.post(
            _treat_url(other_tenant["id"], af_id),
            headers=_headers(admin),
            json={"treatment_type": "mitigated", "rationale": "cross"},
        ).status_code == 404


@requires_postgres
def test_clean_resolve_reopen_and_active_uniqueness(reset_db):
    from app.database import SessionLocal, engine
    from app.models import AssetFinding, FindingTreatment, TREATMENT_STATUS_ACTIVE
    from tests.test_phase2a import _run_clean

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        first = _open_finding(client, token, world)
        af_id = first["asset_findings"][0]["id"]
        scan_id = first["scan"]["id"]
        client.post(_treat_url(tenant_id, af_id), headers=_headers(token), json={"treatment_type": "mitigated", "rationale": "Compensating ACL"})
        _run_clean(client, token, world, scan_id)
        _run_clean(client, token, world, scan_id)
        resolved = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=_headers(token)).json()
        assert resolved["technical_state"] == "resolved"
        assert resolved["treatments"]
        reopened = _open_finding(client, token, world)
        assert reopened["asset_findings"][0]["id"] == af_id
        open_again = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af_id}", headers=_headers(token)).json()
        assert open_again["technical_state"] == "open"
        assert len(open_again["treatments"]) >= 1

        db = SessionLocal()
        try:
            db.add(
                FindingTreatment(
                    tenant_id=tenant_id,
                    asset_finding_id=af_id,
                    treatment_type="accepted_risk",
                    status=TREATMENT_STATUS_ACTIVE,
                    rationale="second active",
                    source="manual",
                )
            )
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()
        assert engine.dialect.name == "postgresql"


@requires_postgres
def test_compliance_catalog_references_and_tenant_safety(reset_db):
    from app.compliance import import_builtin_framework, import_builtin_frameworks
    from app.database import SessionLocal
    from app.models import ComplianceControl, ComplianceFramework

    bundle = json.loads(NIST_BUNDLE.read_text())
    expected_keys = {item["control_key"] for item in bundle["controls"]}
    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        user = _create_staff(client, admin, "map2c", "user")
        viewer = _create_staff(client, admin, "read2c", "viewer")
        other_tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other Map", "notes": ""}).json()
        opened = _open_finding(client, admin, world)
        af = opened["asset_findings"][0]
        evidence_id = opened["findings"][0]["id"]
        job_id = opened["job_id"]

        frameworks = client.get("/api/compliance/frameworks", headers=_headers(user))
        assert frameworks.status_code == 200
        nist = next(row for row in frameworks.json() if row["slug"] == "nist-sp-800-171" and row["version"] == "Rev. 3")
        catalog = json.dumps(nist).lower()
        assert "cmmc passed" not in catalog
        assert "is certified" not in catalog
        assert "is compliant" not in catalog
        assert "control satisfied" not in catalog
        controls = client.get(f"/api/compliance/frameworks/{nist['id']}/controls?control_key=03.01.01", headers=_headers(user))
        assert controls.status_code == 200
        sample = next(row for row in controls.json() if row["control_key"] == "03.01.01")
        all_controls = client.get(f"/api/compliance/frameworks/{nist['id']}/controls", headers=_headers(user)).json()
        assert {row["control_key"] for row in all_controls} == expected_keys
        assert any(row["control_key"] == "03.05.03" for row in all_controls)
        assert any(row["control_key"] == "03.11.02" for row in all_controls)
        assert any(row["control_key"] == "03.17.01" for row in all_controls)
        assert not any(row["slug"] == "cmmc" for row in frameworks.json())

        db = SessionLocal()
        try:
            first = db.query(ComplianceControl).count()
            import_builtin_frameworks(db)
            db.commit()
            assert db.query(ComplianceControl).count() == first
            assert db.query(ComplianceFramework).filter(ComplianceFramework.slug == "nist-sp-800-171").count() == 1
        finally:
            db.close()

        custom = client.post(
            "/api/compliance/frameworks",
            headers=_headers(admin),
            json={"slug": "internal-lab", "name": "Internal Lab", "version": "1", "publisher": "Ops"},
        )
        assert custom.status_code == 200
        created = client.post(
            f"/api/compliance/frameworks/{custom.json()['id']}/controls",
            headers=_headers(admin),
            json={"control_key": "LAB-1", "title": "Segment lab network", "family": "Network"},
        )
        assert created.status_code == 200
        assert client.post(
            "/api/compliance/frameworks",
            headers=_headers(user),
            json={"slug": "nope", "name": "Nope", "version": "1"},
        ).status_code == 403

        mitigation = client.post(
            _treat_url(tenant_id, af["id"]),
            headers=_headers(user),
            json={"treatment_type": "mitigated", "rationale": "Segmented"},
        ).json()
        subjects = [
            ("asset", af["asset_id"]),
            ("asset_finding", af["id"]),
            ("finding", evidence_id),
            ("treatment", mitigation["id"]),
            ("scan_job", job_id),
        ]
        for subject_type, subject_id in subjects:
            added = client.post(
                f"/api/tenants/{tenant_id}/control-references",
                headers=_headers(user),
                json={
                    "control_id": sample["id"],
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "reference_type": "evidence",
                    "notes": f"{subject_type} mapping",
                },
            )
            assert added.status_code == 200, added.text
            body = added.text.lower()
            assert "cmmc passed" not in body
            assert "is certified" not in body
            assert "is compliant" not in body
            assert added.json()["mapping_disclaimer"].startswith("A control mapping")
            dup = client.post(
                f"/api/tenants/{tenant_id}/control-references",
                headers=_headers(user),
                json={"control_id": sample["id"], "subject_type": subject_type, "subject_id": subject_id},
            )
            assert dup.status_code == 409
            listed = client.get(
                f"/api/tenants/{tenant_id}/control-references?subject_type={subject_type}&subject_id={subject_id}",
                headers=_headers(user),
            )
            assert listed.status_code == 200
            assert listed.json()[0]["control_key"] == "03.01.01"
            removed = client.post(
                f"/api/tenants/{tenant_id}/control-references/{added.json()['id']}/remove",
                headers=_headers(user),
                json={"reason": "No longer relevant"},
            )
            assert removed.status_code == 200
            assert removed.json()["removed_at"]
            still = client.get(
                f"/api/tenants/{tenant_id}/control-references?subject_type={subject_type}&subject_id={subject_id}&include_removed=true",
                headers=_headers(user),
            )
            assert any(row["removed_at"] for row in still.json())

        archived = client.post(f"/api/compliance/controls/{sample['id']}/archive", headers=_headers(admin))
        assert archived.status_code == 200
        blocked = client.post(
            f"/api/tenants/{tenant_id}/control-references",
            headers=_headers(user),
            json={"control_id": sample["id"], "subject_type": "asset", "subject_id": af["asset_id"]},
        )
        assert blocked.status_code == 400
        history = client.get(
            f"/api/tenants/{tenant_id}/control-references?subject_type=asset&subject_id={af['asset_id']}&include_removed=true",
            headers=_headers(viewer),
        )
        assert history.status_code == 200
        assert client.post(
            f"/api/tenants/{tenant_id}/control-references",
            headers=_headers(viewer),
            json={"control_id": created.json()["id"], "subject_type": "asset", "subject_id": af["asset_id"]},
        ).status_code == 403
        assert client.post(
            f"/api/tenants/{other_tenant['id']}/control-references",
            headers=_headers(admin),
            json={"control_id": created.json()["id"], "subject_type": "asset", "subject_id": af["asset_id"]},
        ).status_code == 404
        other_fw = client.get("/api/compliance/frameworks", headers=_headers(admin)).json()
        assert all("notes" not in row or "Segmented" not in json.dumps(row) for row in other_fw)

    db = SessionLocal()
    try:
        from pathlib import Path
        import tempfile

        bad = Path(tempfile.gettempdir()) / "bad-framework.json"
        bad.write_text('{"framework": {"slug": "x", "name": "X", "version": "1"}, "controls": []}', encoding="utf-8")
        before = db.query(ComplianceFramework).count()
        with pytest.raises(Exception):
            import_builtin_framework(db, bad)
        db.rollback()
        assert db.query(ComplianceFramework).count() == before
    finally:
        db.close()


@requires_postgres
def test_merge_collision_and_partition_do_not_copy_treatment(reset_db):
    from app.database import SessionLocal
    from app.finding_lifecycle import merge_asset_findings, partition_asset_finding_for_mapping
    from app.models import (
        Asset,
        AssetFinding,
        Finding,
        FindingTreatment,
        TREATMENT_STATUS_ACTIVE,
        TREATMENT_UNADDRESSED,
        Vulnerability,
        VulnerabilityDetectorMapping,
    )
    from app.treatments import MERGE_COLLISION_REASON

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        first = _open_finding(client, token, world, hostname="keep-a", ip="10.1.0.10")
        second = _open_finding(client, token, world, hostname="donor-b", ip="10.1.0.11")
        keep_af = first["asset_findings"][0]
        donor_af = [row for row in second["asset_findings"] if row["id"] != keep_af["id"]][0]
        assert keep_af["id"] != donor_af["id"]
        client.post(_treat_url(tenant_id, keep_af["id"]), headers=_headers(token), json={"treatment_type": "mitigated", "rationale": "ACL on A"})
        risk = client.post(
            _treat_url(tenant_id, donor_af["id"]),
            headers=_headers(token),
            json={"treatment_type": "accepted_risk", "rationale": "Accepted on B"},
        ).json()
        client.post(_treat_url(tenant_id, donor_af["id"], f"/{risk['id']}/approve"), headers=_headers(token), json={})

        db = SessionLocal()
        try:
            keeper_asset = db.get(Asset, keep_af["asset_id"])
            donor_asset = db.get(Asset, donor_af["asset_id"])
            merge_asset_findings(db, target=keeper_asset, sources=[donor_asset])
            db.commit()
            keeper = db.get(AssetFinding, keep_af["id"])
            assert keeper is not None
            assert db.get(AssetFinding, donor_af["id"]) is None
            treatments = db.query(FindingTreatment).filter(FindingTreatment.asset_finding_id == keeper.id).all()
            assert len(treatments) == 2
            assert {row.status for row in treatments} == {"superseded"}
            assert keeper.treatment_state == TREATMENT_UNADDRESSED
            assert any(MERGE_COLLISION_REASON in (row.review_notes or "") for row in treatments)
        finally:
            db.close()

        third = _open_finding(
            client,
            token,
            world,
            hostname="part-a",
            ip="10.1.0.12",
            findings=[
                _finding_payload(
                    template="panel-a",
                    name="Panel A",
                    host="https://10.1.0.12",
                    extra_raw={"info": {"classification": {"cve-id": ["CVE-2024-7777"]}, "name": "Panel A", "severity": "high"}},
                ),
                _finding_payload(
                    template="panel-b",
                    name="Panel B",
                    host="https://10.1.0.12",
                    extra_raw={"info": {"classification": {"cve-id": ["CVE-2024-7777"]}, "name": "Panel B", "severity": "high"}},
                ),
            ],
        )
        source_af = third["asset_findings"][0]["id"]
        client.post(_treat_url(tenant_id, source_af), headers=_headers(token), json={"treatment_type": "mitigated", "rationale": "Donor only"})
        db = SessionLocal()
        try:
            donor = db.get(AssetFinding, source_af)
            mapping = (
                db.query(VulnerabilityDetectorMapping)
                .filter(VulnerabilityDetectorMapping.detector_key == "panel-b")
                .one()
            )
            new_vuln = Vulnerability(canonical_key="nuclei:panel-b-split", title="Split", description="")
            db.add(new_vuln)
            db.flush()
            created = partition_asset_finding_for_mapping(db, donor=donor, mapping=mapping, vulnerability=new_vuln)
            db.commit()
            donor = db.get(AssetFinding, source_af)
            assert created.id != donor.id
            assert created.treatment_state == TREATMENT_UNADDRESSED
            assert db.query(FindingTreatment).filter(FindingTreatment.asset_finding_id == created.id).count() == 0
            assert db.query(FindingTreatment).filter(FindingTreatment.asset_finding_id == donor.id).count() == 1
            assert donor.treatment_state == "mitigated"
        finally:
            db.close()


@requires_postgres
def test_exactly_one_subject_and_list_query_bound(reset_db):
    from app.database import SessionLocal, engine
    from app.models import ComplianceControlReference

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        opened = _open_finding(client, token, world)
        af = opened["asset_findings"][0]
        queries = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            queries.append(statement)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        event.listen(listen_on, "before_cursor_execute", before_cursor)
        try:
            listed = client.get(f"/api/tenants/{tenant_id}/asset-findings?treatment_state=unaddressed", headers=_headers(token))
            assert listed.status_code == 200
            assert all(row["treatment_state"] == "unaddressed" for row in listed.json())
            detail = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af['id']}", headers=_headers(token))
            assert detail.status_code == 200
            assert len(queries) < 60
        finally:
            event.remove(listen_on, "before_cursor_execute", before_cursor)

        db = SessionLocal()
        try:
            control = db.query(__import__("app.models", fromlist=["ComplianceControl"]).ComplianceControl).first()
            row = ComplianceControlReference(
                tenant_id=tenant_id,
                control_id=control.id,
                asset_id=af["asset_id"],
                asset_finding_id=af["id"],
                reference_type="related",
            )
            db.add(row)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        finally:
            db.close()


@requires_postgres
def test_merge_audits_control_reference_move_and_duplicate_remove(reset_db):
    from app.database import SessionLocal
    from app.finding_lifecycle import merge_asset_findings
    from app.models import Asset, AssetFinding, AuditLog, ComplianceControl

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        first = _open_finding(client, token, world, hostname="keep-map", ip="10.1.0.20")
        second = _open_finding(client, token, world, hostname="donor-map", ip="10.1.0.21")
        keep_af = first["asset_findings"][0]
        donor_af = [row for row in second["asset_findings"] if row["id"] != keep_af["id"]][0]
        db = SessionLocal()
        try:
            shared, unique = (
                db.query(ComplianceControl)
                .filter(ComplianceControl.control_key.in_(["03.01.01", "03.05.03"]))
                .order_by(ComplianceControl.control_key.asc())
                .all()
            )
        finally:
            db.close()
        headers = _headers(token)
        for subject_id, control_id in (
            (keep_af["id"], shared.id),
            (donor_af["id"], shared.id),
            (donor_af["id"], unique.id),
        ):
            added = client.post(
                f"/api/tenants/{tenant_id}/control-references",
                headers=headers,
                json={
                    "control_id": control_id,
                    "subject_type": "asset_finding",
                    "subject_id": subject_id,
                    "reference_type": "evidence",
                },
            )
            assert added.status_code == 200, added.text
        db = SessionLocal()
        try:
            merge_asset_findings(db, target=db.get(Asset, keep_af["asset_id"]), sources=[db.get(Asset, donor_af["asset_id"])])
            db.commit()
            keeper = db.get(AssetFinding, keep_af["id"])
            assert keeper is not None
            audits = [
                row
                for row in db.query(AuditLog).filter(AuditLog.object_type == "control_reference").all()
                if row.action in {"control_reference.moved", "control_reference.removed"}
                and (row.details or {}).get("donor_asset_finding_id") == donor_af["id"]
            ]
            actions = {row.action for row in audits}
            assert "control_reference.moved" in actions
            assert "control_reference.removed" in actions
            for row in audits:
                details = row.details or {}
                assert details["keeper_asset_finding_id"] == keep_af["id"]
                assert details["control_id"]
                assert details["reference_id"] == row.object_id
                assert details["old_subject"] == {"subject_type": "asset_finding", "subject_id": donor_af["id"]}
                assert details["new_disposition"] in {"moved", "removed"}
                assert details["reason"]
                assert row.actor_user_id is None
        finally:
            db.close()


@requires_postgres
def test_elapsed_treatment_expires_on_mutation_instead_of_supersede(reset_db):
    from app.database import SessionLocal
    from app.models import AssetFinding, AuditLog, FindingTreatment, TREATMENT_STATUS_ACTIVE

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        opened = _open_finding(client, token, world)
        af_id = opened["asset_findings"][0]["id"]
        headers = _headers(token)
        first = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={
                "treatment_type": "mitigated",
                "rationale": "Temporary ACL",
                "expires_at": (_now() + timedelta(hours=2)).isoformat(),
            },
        )
        assert first.status_code == 200, first.text
        db = SessionLocal()
        try:
            row = db.get(FindingTreatment, first.json()["id"])
            row.expires_at = _now() - timedelta(minutes=5)
            db.commit()
        finally:
            db.close()
        second = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "mitigated", "rationale": "Replacement ACL"},
        )
        assert second.status_code == 200, second.text
        db = SessionLocal()
        try:
            old = db.get(FindingTreatment, first.json()["id"])
            new = db.get(FindingTreatment, second.json()["id"])
            finding = db.get(AssetFinding, af_id)
            assert old.status == "expired"
            assert new.status == "active"
            assert finding.treatment_state == "mitigated"
            assert finding.technical_state == "open"
            expired_audits = [
                row
                for row in db.query(AuditLog).filter(AuditLog.action == "treatment.expired", AuditLog.object_id == old.id).all()
            ]
            assert expired_audits
            assert expired_audits[0].details["treatment_state"] == "unaddressed"
            assert not any(
                row.action == "treatment.superseded" and row.object_id == old.id
                for row in db.query(AuditLog).filter(AuditLog.object_id == old.id).all()
            )
        finally:
            db.close()

        pending = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "accepted_risk", "rationale": "Accept after elapsed mitigation"},
        )
        assert pending.json()["status"] == "pending_review"
        db = SessionLocal()
        try:
            current = (
                db.query(FindingTreatment)
                .filter(FindingTreatment.asset_finding_id == af_id, FindingTreatment.status == TREATMENT_STATUS_ACTIVE)
                .one()
            )
            current.expires_at = _now() - timedelta(minutes=1)
            db.commit()
            active_id = current.id
        finally:
            db.close()
        approved = client.post(_treat_url(tenant_id, af_id, f"/{pending.json()['id']}/approve"), headers=headers, json={})
        assert approved.status_code == 200, approved.text
        db = SessionLocal()
        try:
            elapsed = db.get(FindingTreatment, active_id)
            accepted = db.get(FindingTreatment, pending.json()["id"])
            finding = db.get(AssetFinding, af_id)
            assert elapsed.status == "expired"
            assert accepted.status == "active"
            assert finding.treatment_state == "accepted_risk"
            assert finding.technical_state == "open"
            assert not any(
                row.action == "treatment.superseded" and row.object_id == elapsed.id
                for row in db.query(AuditLog).filter(AuditLog.object_id == elapsed.id).all()
            )
        finally:
            db.close()


@requires_postgres
def test_control_reference_list_query_count_is_bounded(reset_db):
    from app.compliance import add_control_reference, create_control, create_framework
    from app.database import SessionLocal, engine
    from app.models import User

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        opened = _open_finding(client, admin, world)
        af = opened["asset_findings"][0]
        db = SessionLocal()
        try:
            actor = db.query(User).filter(User.username == "admin").one()
            framework = create_framework(db, actor=actor, slug="bulk-map", name="Bulk Map", version="1")
            for index in range(250):
                control = create_control(
                    db,
                    actor=actor,
                    framework_id=framework.id,
                    control_key=f"BM-{index:03d}",
                    title=f"Bulk {index}",
                )
                add_control_reference(
                    db,
                    tenant_id=tenant_id,
                    control_id=control.id,
                    subject_type="asset_finding",
                    subject_id=af["id"],
                    actor=actor,
                    reference_type="related",
                )
            db.commit()
        finally:
            db.close()

        queries = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            queries.append(statement)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        event.listen(listen_on, "before_cursor_execute", before_cursor)
        try:
            listed = client.get(
                f"/api/tenants/{tenant_id}/control-references?subject_type=asset_finding&subject_id={af['id']}",
                headers=_headers(admin),
            )
            assert listed.status_code == 200
            assert len(listed.json()) == 250
            username_lookups = [sql for sql in queries if "from users" in sql.lower() and " in (" in sql.lower()]
            assert len(username_lookups) == 1
            assert len(queries) < 25
            queries.clear()
            detail = client.get(f"/api/tenants/{tenant_id}/asset-findings/{af['id']}", headers=_headers(admin))
            assert detail.status_code == 200
            assert len(detail.json()["control_references"]) == 250
            username_lookups = [sql for sql in queries if "from users" in sql.lower() and " in (" in sql.lower()]
            assert len(username_lookups) <= 2
            assert len(queries) < 40
        finally:
            event.remove(listen_on, "before_cursor_execute", before_cursor)


@requires_postgres
def test_builtin_import_rejects_checksum_mismatch(reset_db):
    import tempfile

    from app.compliance import ComplianceError, import_builtin_framework
    from app.database import SessionLocal
    from app.migrate import apply_schema
    from app.models import ComplianceFramework

    apply_schema()
    bundle = json.loads(NIST_BUNDLE.read_text())
    bundle["provenance"]["controls_checksum_sha256"] = "0" * 64
    db = SessionLocal()
    try:
        before = db.query(ComplianceFramework).count()
        bad = Path(tempfile.gettempdir()) / "bad-checksum-framework.json"
        bad.write_text(json.dumps(bundle), encoding="utf-8")
        with pytest.raises(ComplianceError, match="checksum"):
            import_builtin_framework(db, bad)
        db.rollback()
        assert db.query(ComplianceFramework).count() == before
    finally:
        db.close()


@requires_postgres
def test_cannot_activate_treatment_that_has_already_expired(reset_db):
    from app.database import SessionLocal
    from app.models import AssetFinding, AuditLog, FindingTreatment

    with _client() as client:
        token = _login(client)
        world = _world(client, token)
        tenant_id = world["tenant"]["id"]
        opened = _open_finding(client, token, world)
        af_id = opened["asset_findings"][0]["id"]
        headers = _headers(token)
        mitigation = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={"treatment_type": "mitigated", "rationale": "Current compensating ACL"},
        )
        assert mitigation.status_code == 200, mitigation.text
        past = client.post(
            _treat_url(tenant_id, af_id),
            headers=headers,
            json={
                "treatment_type": "mitigated",
                "rationale": "Already expired ACL",
                "expires_at": (_now() - timedelta(minutes=1)).isoformat(),
            },
        )
        assert past.status_code in {400, 422}

        def _reject_expired_pending(treatment_type: str):
            pending = client.post(
                _treat_url(tenant_id, af_id),
                headers=headers,
                json={
                    "treatment_type": treatment_type,
                    "rationale": f"Document {treatment_type}",
                    "expires_at": (_now() + timedelta(days=1)).isoformat(),
                },
            )
            assert pending.status_code == 200, pending.text
            assert pending.json()["status"] == "pending_review"
            db = SessionLocal()
            try:
                row = db.get(FindingTreatment, pending.json()["id"])
                row.expires_at = _now() - timedelta(minutes=1)
                db.commit()
            finally:
                db.close()
            approved = client.post(
                _treat_url(tenant_id, af_id, f"/{pending.json()['id']}/approve"),
                headers=headers,
                json={"review_notes": "Too late"},
            )
            assert approved.status_code == 400
            assert "expired" in approved.text.lower()
            db = SessionLocal()
            try:
                finding = db.get(AssetFinding, af_id)
                row = db.get(FindingTreatment, pending.json()["id"])
                current = db.get(FindingTreatment, mitigation.json()["id"])
                assert finding.technical_state == "open"
                assert finding.treatment_state == "mitigated"
                assert row.status == "pending_review"
                assert current.status == "active"
                audits = db.query(AuditLog).filter(AuditLog.object_id == row.id).all()
                assert not any(item.action == "treatment.approved" for item in audits)
                assert not any(item.action == "treatment.superseded" for item in audits)
                assert not any(
                    item.action == "treatment.superseded" and item.object_id == current.id
                    for item in db.query(AuditLog).filter(AuditLog.object_id == current.id).all()
                )
            finally:
                db.close()

        _reject_expired_pending("accepted_risk")
        _reject_expired_pending("false_positive")
