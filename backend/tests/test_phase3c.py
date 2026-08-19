from __future__ import annotations

import csv
import hashlib
import io
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic import command
from alembic.util import CommandError
from fastapi.testclient import TestClient
from sqlalchemy import event, inspect, text
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres
from tests.test_migrations import FROZEN_MIGRATION_HASHES
from tests.test_phase1d import _client, _create_staff, _headers, _login, _world

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE3B_HEAD = "0013_event_alert_engine"
PHASE3C_HEAD = "0014_reports_auditor_access"
PHASE3B_GIT_BLOB = "478c3be4f0cc0a4c62b03aabee48f4120379dd7c"
PHASE3B_SHA256 = "72792866df1caf6a6a263bad8dc348b2abee8e507e2a4bd656cda97e8dba6578"
PHASE3C_GIT_BLOB = "bf44ca9fcc7fdbbf76e42bee3453e9381dd232f9"
PHASE3C_SHA256 = "4f8167d0c2f22c37eec0ae96fff5cdfe637977ab7b531bc0084270b09e46bfc5"
FRONTEND_SRC = BACKEND_ROOT.parent / "frontend" / "src"


def _create_viewer(client, admin, username, *, all_tenants=False, tenant_ids=None, expires_at=None) -> tuple[str, int]:
    body = {
        "username": username,
        "email": f"{username}@example.com",
        "password": f"{username}-password",
        "role": "viewer",
        "viewer_all_tenants": all_tenants,
        "viewer_tenant_ids": tenant_ids or [],
    }
    if expires_at is not None:
        body["viewer_expires_at"] = expires_at.isoformat()
    response = client.post("/api/users", headers=_headers(admin), json=body)
    assert response.status_code == 200, response.text
    return _login(client, username, f"{username}-password"), response.json()["id"]


def _tenant_pair(client, admin):
    a = client.post("/api/tenants", headers=_headers(admin), json={"name": "Acme-3C", "notes": ""}).json()
    b = client.post("/api/tenants", headers=_headers(admin), json={"name": "Beta-3C", "notes": ""}).json()
    c = client.post("/api/tenants", headers=_headers(admin), json={"name": "Delta-3C", "notes": ""}).json()
    return a, b, c


@requires_postgres
def test_fresh_db_reaches_0014_and_freezes_0013(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3C_HEAD
    assert "viewer_tenant_grants" in inspect(engine).get_table_names()
    for name, sha256, blob_id in (
        ("0013_event_alert_engine.py", PHASE3B_SHA256, PHASE3B_GIT_BLOB),
        ("0014_reports_auditor_access.py", PHASE3C_SHA256, PHASE3C_GIT_BLOB),
    ):
        path = BACKEND_ROOT / "alembic" / "versions" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha256
        assert FROZEN_MIGRATION_HASHES[name] == sha256
        blob = subprocess.check_output(["git", "hash-object", str(path)], cwd=BACKEND_ROOT.parent, text=True).strip()
        assert blob == blob_id


@requires_postgres
def test_0013_to_0014_existing_viewers_get_zero_grants(reset_db):
    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision

    command.upgrade(alembic_config(), PHASE3B_HEAD)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, role, is_active) "
                "VALUES ('legacy-viewer', 'legacy-viewer@localhost', 'x', 'viewer', true)"
            )
        )
        conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Legacy Tenant', '')"))
    command.upgrade(alembic_config(), PHASE3C_HEAD)
    assert current_revision() == PHASE3C_HEAD
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT viewer_all_tenants, viewer_expires_at FROM users WHERE username='legacy-viewer'")).one()
        assert row[0] is False
        assert row[1] is None
        assert db.execute(text("SELECT COUNT(*) FROM viewer_tenant_grants")).scalar_one() == 0
    finally:
        db.close()


@requires_postgres
def test_empty_0014_downgrade_allowed_configured_refused(reset_db):
    from app.database import SessionLocal
    from app.migrate import alembic_config, apply_schema, current_revision

    apply_schema()
    command.downgrade(alembic_config(), PHASE3B_HEAD)
    assert current_revision() == PHASE3B_HEAD
    command.upgrade(alembic_config(), PHASE3C_HEAD)
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO users (username, email, password_hash, role, is_active, viewer_all_tenants) "
                "VALUES ('configured-viewer', 'configured-viewer@localhost', 'x', 'viewer', true, true)"
            )
        )
        db.commit()
    finally:
        db.close()
    try:
        command.downgrade(alembic_config(), PHASE3B_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0014_reports_auditor_access" in str(exc)
        return
    raise AssertionError("configured 0014 downgrade must refuse")


@requires_postgres
def test_viewer_matrix_and_expiration(reset_db):
    with _client() as client:
        admin = _login(client)
        user = _create_staff(client, admin, "operator3c", "user")
        a, b, c = _tenant_pair(client, admin)
        viewer_a, viewer_a_id = _create_viewer(client, admin, "viewer-a", tenant_ids=[a["id"]])
        viewer_ab, _ = _create_viewer(client, admin, "viewer-ab", tenant_ids=[a["id"], b["id"]])
        viewer_all, _ = _create_viewer(client, admin, "viewer-all", all_tenants=True)
        viewer_none, none_id = _create_viewer(client, admin, "viewer-none")
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        expired_login = client.post(
            "/api/users",
            headers=_headers(admin),
            json={
                "username": "viewer-exp",
                "email": "viewer-exp@example.com",
                "password": "viewer-exp-password",
                "role": "viewer",
                "viewer_all_tenants": True,
                "viewer_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            },
        )
        assert expired_login.status_code == 200
        exp_id = expired_login.json()["id"]
        exp_token = _login(client, "viewer-exp", "viewer-exp-password")
        client.patch(
            f"/api/users/{exp_id}",
            headers=_headers(admin),
            json={"viewer_expires_at": past.isoformat()},
        )
        disabled, dis_id = _create_viewer(client, admin, "viewer-dis", all_tenants=True)
        client.patch(f"/api/users/{dis_id}", headers=_headers(admin), json={"is_active": False})

        for token in (admin, user, viewer_all):
            names = {row["name"] for row in client.get("/api/tenants", headers=_headers(token)).json()}
            assert {"Acme-3C", "Beta-3C", "Delta-3C"}.issubset(names)
        assert {row["name"] for row in client.get("/api/tenants", headers=_headers(viewer_a)).json()} == {"Acme-3C"}
        assert {row["name"] for row in client.get("/api/tenants", headers=_headers(viewer_ab)).json()} == {"Acme-3C", "Beta-3C"}
        assert client.get("/api/tenants", headers=_headers(viewer_none)).json() == []
        assert client.get(f"/api/tenants/{b['id']}", headers=_headers(viewer_a)).status_code == 404
        assert client.get(f"/api/tenants/{a['id']}", headers=_headers(viewer_a)).status_code == 200
        assert client.post("/api/auth/login", json={"username": "viewer-exp", "password": "viewer-exp-password"}).status_code == 401
        assert client.get("/api/tenants", headers=_headers(exp_token)).status_code == 401
        assert client.get("/api/tenants", headers=_headers(disabled)).status_code == 401
        client.patch(f"/api/users/{exp_id}", headers=_headers(admin), json={"viewer_expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()})
        restored = _login(client, "viewer-exp", "viewer-exp-password")
        assert client.get("/api/tenants", headers=_headers(restored)).status_code == 200
        own = client.patch(f"/api/users/{viewer_a_id}", headers=_headers(viewer_a), json={"viewer_all_tenants": True})
        assert own.status_code == 403
        assert none_id


@requires_postgres
def test_direct_id_and_reports_scope(reset_db):
    with _client() as client:
        admin = _login(client)
        world_a = _world(client, admin)
        tenant_b = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other-3C", "notes": ""}).json()
        site_b = client.post(f"/api/tenants/{tenant_b['id']}/sites", headers=_headers(admin), json={"name": "Other Site"}).json()
        viewer, _ = _create_viewer(client, admin, "scope-a", tenant_ids=[world_a["tenant"]["id"]])
        headers = _headers(viewer)
        net_b = client.post(
            f"/api/sites/{site_b['id']}/networks",
            headers=_headers(admin),
            json={"name": "Other Net", "cidr": "10.66.0.0/24"},
        ).json()
        agent_b = client.post(
            f"/api/tenants/{tenant_b['id']}/agents",
            headers=_headers(admin),
            json={"name": "Other Agent", "site_id": site_b["id"]},
        ).json()
        assert client.get(f"/api/tenants/{tenant_b['id']}", headers=headers).status_code == 404
        assert client.get(f"/api/sites/{site_b['id']}", headers=headers).status_code == 404
        assert client.get(f"/api/networks/{net_b['id']}", headers=headers).status_code == 404
        assert client.get(f"/api/agents/{agent_b['id']}", headers=headers).status_code == 404
        assert client.get(f"/api/tenants/{tenant_b['id']}/assets", headers=headers).status_code == 404
        assert client.get(f"/api/tenants/{tenant_b['id']}/assets/export", headers=headers).status_code == 404
        assert client.get(f"/api/tenants/{tenant_b['id']}/devices", headers=headers).status_code == 404
        assert client.get(f"/api/tenants/{tenant_b['id']}/findings", headers=headers).status_code == 404
        assert client.get(f"/api/alerts?tenant_id={tenant_b['id']}", headers=headers).status_code == 404
        assert client.get(f"/api/reports/asset_inventory/preview?tenant_id={tenant_b['id']}", headers=headers).status_code == 404
        own_agent = client.get(f"/api/agents/{world_a['agent1']['id']}", headers=headers).json()
        assert own_agent.get("enrollment_secret") in (None, "")
        listed = client.get("/api/reports/catalog", headers=headers)
        assert listed.status_code == 200
        assert len(listed.json()) == 10
        preview = client.get(
            f"/api/reports/executive/preview?tenant_id={world_a['tenant']['id']}",
            headers=headers,
        )
        assert preview.status_code == 200
        assert preview.json()["page_size"] <= 200
        audits = client.get("/api/audit-history", headers=_headers(admin)).json()
        before = audits["total"]
        csv_resp = client.get(
            f"/api/reports/asset_inventory/export?format=csv&tenant_id={world_a['tenant']['id']}",
            headers=headers,
        )
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]
        pdf_resp = client.get(
            f"/api/reports/open_findings/export?format=pdf&tenant_id={world_a['tenant']['id']}",
            headers=headers,
        )
        assert pdf_resp.status_code == 200
        assert pdf_resp.content[:4] == b"%PDF"
        assert b"enrollment_secret" not in pdf_resp.content
        after = client.get("/api/audit-history", headers=_headers(admin)).json()
        assert after["total"] >= before + 2
        preview2 = client.get(
            f"/api/reports/executive/preview?tenant_id={world_a['tenant']['id']}",
            headers=headers,
        )
        assert preview2.status_code == 200
        history = client.get("/api/audit-history", headers=headers).json()
        assert all(item["tenant_id"] == world_a["tenant"]["id"] for item in history["items"])
        assert all(item["tenant_id"] is not None for item in history["items"])


@requires_postgres
def test_viewer_admin_audits_and_role_reset(reset_db):
    with _client() as client:
        admin = _login(client)
        a, b, _ = _tenant_pair(client, admin)
        created = client.post(
            "/api/users",
            headers=_headers(admin),
            json={
                "username": "auditor-reset",
                "email": "auditor-reset@example.com",
                "password": "auditor-reset-password",
                "role": "viewer",
                "viewer_tenant_ids": [a["id"], b["id"]],
            },
        )
        assert created.status_code == 200
        assert created.json()["viewer_tenant_ids"] == [a["id"], b["id"]]
        user_id = created.json()["id"]
        switched = client.patch(
            f"/api/users/{user_id}",
            headers=_headers(admin),
            json={"viewer_all_tenants": True, "viewer_tenant_ids": []},
        )
        assert switched.status_code == 200
        assert switched.json()["viewer_all_tenants"] is True
        assert switched.json()["viewer_tenant_ids"] == []
        to_user = client.patch(f"/api/users/{user_id}", headers=_headers(admin), json={"role": "user"})
        assert to_user.status_code == 200
        assert to_user.json()["viewer_access_status"] == "not_applicable"
        back = client.patch(f"/api/users/{user_id}", headers=_headers(admin), json={"role": "viewer"})
        assert back.status_code == 200
        assert back.json()["viewer_all_tenants"] is False
        assert back.json()["viewer_tenant_ids"] == []
        from app.database import SessionLocal
        from app.models import AuditLog

        db = SessionLocal()
        try:
            actions = {row.action for row in db.query(AuditLog).filter(AuditLog.object_id == user_id).all()}
            assert "user.created" in actions
            assert "viewer.scope_changed" in actions
            assert "user.role_changed" in actions
            for row in db.query(AuditLog).filter(AuditLog.object_id == user_id).all():
                blob = str(row.details)
                assert "password" not in blob.lower() or "password_hash" not in blob
                assert "auditor-reset-password" not in blob
        finally:
            db.close()


@requires_postgres
def test_report_semantics_csv_pdf_and_history(reset_db):
    from app.database import SessionLocal
    from app.models import (
        TECHNICAL_OPEN,
        TECHNICAL_RESOLVED,
        TREATMENT_RECORD_ACCEPTED_RISK,
        TREATMENT_RECORD_MITIGATED,
        TREATMENT_STATUS_ACTIVE,
        TREATMENT_STATUS_EXPIRED,
        Asset,
        AssetFinding,
        AuditLog,
        DomainEvent,
        FindingTreatment,
        Vulnerability,
        VulnerabilityIntelligence,
    )

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        site_id = world["site"]["id"]
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            asset = Asset(
                tenant_id=tenant_id,
                site_id=site_id,
                display_name="Report Asset",
                classification="Server",
                description="",
                lifecycle_state="active",
                disposition="unreviewed",
                criticality="critical",
                is_expected=False,
            )
            inactive = Asset(
                tenant_id=tenant_id,
                site_id=site_id,
                display_name="Inactive Asset",
                classification="Server",
                description="",
                lifecycle_state="inactive",
                disposition="unreviewed",
                criticality="normal",
                is_expected=False,
            )
            db.add_all([asset, inactive])
            db.flush()
            cve = Vulnerability(canonical_key="cve:CVE-2024-0001", cve_id="CVE-2024-0001", title="Test CVE")
            other = Vulnerability(canonical_key="nuclei:exposed", title="Exposed admin")
            db.add_all([cve, other])
            db.flush()
            db.add(
                VulnerabilityIntelligence(
                    vulnerability_id=cve.id,
                    cvss_base_score=9.8,
                    epss_score=0.9,
                    kev=True,
                )
            )
            open_cve = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=cve.id,
                technical_state=TECHNICAL_OPEN,
                treatment_state="mitigated",
                first_seen=now - timedelta(days=40),
                last_seen=now,
                priority="p1",
            )
            open_non = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=other.id,
                technical_state=TECHNICAL_OPEN,
                treatment_state="accepted_risk",
                first_seen=now - timedelta(days=10),
                last_seen=now,
                priority="p3",
            )
            resolved = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=other.id + 1000 if False else other.id,
                technical_state=TECHNICAL_RESOLVED,
                treatment_state="unaddressed",
                first_seen=now - timedelta(days=80),
                last_seen=now - timedelta(days=2),
                resolved_at=now - timedelta(days=2),
                reopened_count=1,
            )
            db.add_all([open_cve, open_non])
            db.flush()
            resolved.vulnerability_id = other.id
            # second resolved needs own vuln to satisfy unique
            resolved_vuln = Vulnerability(canonical_key="cve:CVE-2024-0099", cve_id="CVE-2024-0099", title="Resolved CVE")
            db.add(resolved_vuln)
            db.flush()
            resolved.vulnerability_id = resolved_vuln.id
            db.add(resolved)
            db.flush()
            db.add(
                FindingTreatment(
                    tenant_id=tenant_id,
                    asset_finding_id=open_cve.id,
                    treatment_type=TREATMENT_RECORD_MITIGATED,
                    status=TREATMENT_STATUS_ACTIVE,
                    rationale="Compensating firewall",
                )
            )
            db.add(
                FindingTreatment(
                    tenant_id=tenant_id,
                    asset_finding_id=open_non.id,
                    treatment_type=TREATMENT_RECORD_ACCEPTED_RISK,
                    status=TREATMENT_STATUS_EXPIRED,
                    rationale="Accepted last quarter",
                    expires_at=now - timedelta(days=1),
                )
            )
            db.add(
                DomainEvent(
                    event_type="new_asset",
                    tenant_id=tenant_id,
                    site_id=site_id,
                    asset_id=asset.id,
                    occurred_at=now,
                    source="manual",
                    details={"display_name": "Report Asset"},
                    idempotence_key="3c-new-asset",
                )
            )
            db.commit()
            asset_id = asset.id
            open_cve_id = open_cve.id
            resolved_id = resolved.id
        finally:
            db.close()

        viewer, _ = _create_viewer(client, admin, "report-a", tenant_ids=[tenant_id])
        exec_preview = client.get(f"/api/reports/executive/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert exec_preview["summary"]["open_asset_findings"] >= 2
        assert exec_preview["summary"]["open_kev"] >= 1
        summary_text = str(exec_preview["summary"]).lower()
        assert "is secure" not in summary_text
        assert "certified" not in summary_text
        open_preview = client.get(f"/api/reports/open_findings/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        open_ids = {row["asset_finding_id"] for row in open_preview["rows"]}
        assert open_cve_id in open_ids
        assert resolved_id not in open_ids
        assert any(row["treatment_state"] == "mitigated" for row in open_preview["rows"])
        aging = client.get(f"/api/reports/cve_aging/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert all(row.get("cve_id") for row in aging["rows"])
        assert any(row["age_bucket"] == "31-60" for row in aging["rows"])
        treat = client.get(f"/api/reports/treatments/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert {row["treatment_type"] for row in treat["rows"]} >= {"mitigated", "accepted_risk"}
        assert any(row["status"] == "expired" for row in treat["rows"])
        inventory = client.get(f"/api/reports/asset_inventory/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        names = {row["display_name"] for row in inventory["rows"]}
        assert "Report Asset" in names
        assert "Inactive Asset" in names
        changes = client.get(f"/api/reports/asset_changes/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert any(row["change_type"] == "new_asset" for row in changes["rows"])
        assert "service" not in changes["summary"]["service_change_history"].lower() or "not" in changes["summary"]["service_change_history"].lower()
        agents = client.get(f"/api/reports/agent_health/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert all("enrollment_secret" not in row for row in agents["rows"])
        csv_resp = client.get(
            f"/api/reports/open_findings/export?format=csv&tenant_id={tenant_id}",
            headers=_headers(viewer),
        )
        parsed = list(csv.reader(io.StringIO(csv_resp.text)))
        assert parsed[0][0] == "asset_finding_id"
        formula = client.get(
            f"/api/reports/asset_inventory/export?format=csv&tenant_id={tenant_id}",
            headers=_headers(viewer),
        )
        assert "=cmd" not in formula.text or "'=" in formula.text
        compat = client.get(f"/api/tenants/{tenant_id}/assets/export", headers=_headers(viewer))
        assert compat.status_code == 200
        events = client.get(f"/api/domain-events?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert events["items"]
        assert all(item.get("event_type") for item in events["items"])


@requires_postgres
def test_control_evidence_disclaimer_and_query_bound(reset_db):
    from app.database import SessionLocal
    from app.models import Asset, ComplianceControl, ComplianceControlReference, ComplianceFramework

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other-Evidence", "notes": ""}).json()
        db = SessionLocal()
        try:
            framework = ComplianceFramework(slug="demo-3c", name="Demo Framework", version="1.0", builtin=False)
            db.add(framework)
            db.flush()
            control = ComplianceControl(framework_id=framework.id, control_key="AC.L1-3.1.1", family="AC", title="Access")
            empty = ComplianceControl(framework_id=framework.id, control_key="AC.L1-3.1.2", family="AC", title="Empty")
            db.add_all([control, empty])
            db.flush()
            asset = db.query(Asset).filter(Asset.tenant_id == world["tenant"]["id"]).first()
            if asset is None:
                asset = Asset(
                    tenant_id=world["tenant"]["id"],
                    site_id=world["site"]["id"],
                    display_name="Evidence Asset",
                    classification="Server",
                    description="",
                    lifecycle_state="active",
                    disposition="unreviewed",
                    criticality="normal",
                    is_expected=False,
                )
                db.add(asset)
                db.flush()
            db.add(
                ComplianceControlReference(
                    tenant_id=world["tenant"]["id"],
                    control_id=control.id,
                    asset_id=asset.id,
                    reference_type="evidence",
                    notes="mapped",
                )
            )
            db.commit()
            framework_id = framework.id
            ref_id = db.query(ComplianceControlReference).first().id
        finally:
            db.close()
        viewer, _ = _create_viewer(client, admin, "cmmc-a", tenant_ids=[world["tenant"]["id"]])
        preview = client.get(
            f"/api/reports/control_evidence/preview?tenant_id={world['tenant']['id']}&framework_id={framework_id}",
            headers=_headers(viewer),
        ).json()
        text_blob = str(preview).lower()
        assert "compliant" not in text_blob
        assert "noncompliant" not in text_blob
        assert "no mapped evidence in the application" in text_blob
        assert "evidence/reference is mapped" in text_blob
        assert preview["summary"]["disclaimer"]
        page = client.get(
            f"/api/reports/control_evidence/preview?tenant_id={world['tenant']['id']}&framework_id={framework_id}&page=1&page_size=1",
            headers=_headers(viewer),
        ).json()
        assert page["total"] >= 2
        assert len(page["rows"]) == 1
        assert client.get(
            f"/api/reports/control_evidence/preview?tenant_id={other['id']}&framework_id={framework_id}",
            headers=_headers(viewer),
        ).status_code == 404
        assert client.get(
            f"/api/tenants/{other['id']}/control-references?subject_type=asset&subject_id={ref_id}",
            headers=_headers(viewer),
        ).status_code == 404
        pdf = client.get(
            f"/api/reports/control_evidence/export?format=pdf&tenant_id={world['tenant']['id']}&framework_id={framework_id}",
            headers=_headers(viewer),
        )
        assert pdf.status_code == 200
        assert pdf.content[:4] == b"%PDF"
        assert b"compliant" not in pdf.content.lower()


@requires_postgres
def test_csv_formula_and_bounded_preview(reset_db):
    from app.database import SessionLocal
    from app.models import Asset

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        db = SessionLocal()
        try:
            db.add(
                Asset(
                    tenant_id=world["tenant"]["id"],
                    site_id=world["site"]["id"],
                    display_name="=HYPERLINK(\"http://evil\")",
                    classification="Server",
                    description="",
                    lifecycle_state="active",
                    disposition="unreviewed",
                    criticality="normal",
                    is_expected=False,
                )
            )
            db.commit()
        finally:
            db.close()
        csv_resp = client.get(
            f"/api/reports/asset_inventory/export?format=csv&tenant_id={world['tenant']['id']}",
            headers=_headers(admin),
        )
        assert "'=HYPERLINK" in csv_resp.text or any(line.startswith("'=") for line in csv_resp.text.splitlines())
        preview = client.get(
            f"/api/reports/asset_inventory/preview?tenant_id={world['tenant']['id']}&page_size=50",
            headers=_headers(admin),
        ).json()
        assert preview["page_size"] == 50
        too_big = client.get(
            f"/api/reports/asset_inventory/preview?tenant_id={world['tenant']['id']}&page_size=500",
            headers=_headers(admin),
        )
        assert too_big.status_code == 422


@requires_postgres
def test_dashboard_and_history_sql_scope(reset_db):
    with _client() as client:
        admin = _login(client)
        a, b, _ = _tenant_pair(client, admin)
        viewer, _ = _create_viewer(client, admin, "dash-a", tenant_ids=[a["id"]])
        dash = client.get("/api/dashboard", headers=_headers(viewer)).json()
        assert dash["tenants"] == 1
        assert dash["users"] == 0
        history = client.get("/api/audit-history?tenant_id=" + str(b["id"]), headers=_headers(viewer))
        assert history.status_code == 404
        global_admin = client.get("/api/audit-history", headers=_headers(viewer)).json()
        assert all(item["tenant_id"] is not None for item in global_admin["items"])


@requires_postgres
def test_resolved_pending_scan_history_and_query_bound(reset_db):
    from app.database import SessionLocal, engine
    from app.models import (
        HISTORY_RESOLVED,
        TECHNICAL_OPEN,
        TECHNICAL_RESOLVED,
        TREATMENT_RECORD_ACCEPTED_RISK,
        TREATMENT_STATUS_PENDING_REVIEW,
        Asset,
        AssetFinding,
        AssetFindingHistory,
        FindingTreatment,
        Scan,
        ScanJob,
        Vulnerability,
    )

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            asset = Asset(
                tenant_id=tenant_id,
                site_id=world["site"]["id"],
                display_name="Bound Asset",
                classification="Server",
                description="",
                lifecycle_state="active",
                disposition="unreviewed",
                criticality="normal",
                is_expected=False,
            )
            db.add(asset)
            db.flush()
            vuln = Vulnerability(canonical_key="cve:CVE-2024-1111", cve_id="CVE-2024-1111", title="Resolved item")
            pending_vuln = Vulnerability(canonical_key="nuclei:pending", title="Pending accepted")
            db.add_all([vuln, pending_vuln])
            db.flush()
            resolved = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                technical_state=TECHNICAL_RESOLVED,
                treatment_state="unaddressed",
                first_seen=now - timedelta(days=20),
                last_seen=now - timedelta(days=1),
                resolved_at=now - timedelta(days=1),
                reopened_count=2,
            )
            pending_finding = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=pending_vuln.id,
                technical_state=TECHNICAL_OPEN,
                treatment_state="unaddressed",
                first_seen=now - timedelta(days=3),
                last_seen=now,
            )
            db.add_all([resolved, pending_finding])
            db.flush()
            db.add(
                AssetFindingHistory(
                    asset_finding_id=resolved.id,
                    tenant_id=tenant_id,
                    transition_type=HISTORY_RESOLVED,
                    previous_technical_state=TECHNICAL_OPEN,
                    new_technical_state=TECHNICAL_RESOLVED,
                    occurred_at=now - timedelta(days=1),
                    details={"required_clean_scans": 2, "source": "policy"},
                    idempotence_key="3c-resolved-history",
                )
            )
            db.add(
                FindingTreatment(
                    tenant_id=tenant_id,
                    asset_finding_id=pending_finding.id,
                    treatment_type=TREATMENT_RECORD_ACCEPTED_RISK,
                    status=TREATMENT_STATUS_PENDING_REVIEW,
                    rationale="Need review",
                )
            )
            scan = Scan(
                tenant_id=tenant_id,
                site_id=world["site"]["id"],
                name="History Scan",
                scope="lan",
                profile="discovery",
                is_enabled=True,
            )
            db.add(scan)
            db.flush()
            db.add(
                ScanJob(
                    scan_id=scan.id,
                    tenant_id=tenant_id,
                    status="done",
                    definition_revision=3,
                    snapshot_version="snap-1",
                    started_at=now - timedelta(minutes=10),
                    finished_at=now - timedelta(minutes=5),
                )
            )
            db.commit()
            resolved_id = resolved.id
        finally:
            db.close()

        viewer, _ = _create_viewer(client, admin, "bound-a", tenant_ids=[tenant_id])
        resolved_preview = client.get(
            f"/api/reports/resolved_findings/preview?tenant_id={tenant_id}",
            headers=_headers(viewer),
        ).json()
        assert any(row["asset_finding_id"] == resolved_id and row["reopened_count"] == 2 for row in resolved_preview["rows"])
        treat = client.get(f"/api/reports/treatments/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert any(row["status"] == "pending_review" for row in treat["rows"])
        assert any(row["technical_state"] == "open" for row in treat["rows"])
        scans = client.get(f"/api/reports/scan_history/preview?tenant_id={tenant_id}", headers=_headers(viewer)).json()
        assert any(row["definition_revision"] == 3 and row["snapshot_version"] == "snap-1" for row in scans["rows"])
        assert any(row["nuclei_version"] == "Not Recorded" for row in scans["rows"])
        statements: list[str] = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", before_cursor)
        try:
            preview = client.get(
                f"/api/reports/asset_inventory/preview?tenant_id={tenant_id}&page_size=50",
                headers=_headers(viewer),
            )
            assert preview.status_code == 200
        finally:
            event.remove(engine, "before_cursor_execute", before_cursor)
        assert len(statements) < 40


def test_0014_is_frozen_byte_for_byte():
    path = BACKEND_ROOT / "alembic" / "versions" / "0014_reports_auditor_access.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PHASE3C_SHA256
    assert FROZEN_MIGRATION_HASHES["0014_reports_auditor_access.py"] == PHASE3C_SHA256
    blob = subprocess.check_output(["git", "hash-object", str(path)], cwd=BACKEND_ROOT.parent, text=True).strip()
    assert blob == PHASE3C_GIT_BLOB


def test_viewer_expiration_datetime_local_round_trip():
    from zoneinfo import ZoneInfo

    utc = datetime(2026, 8, 20, 21, 0, tzinfo=timezone.utc)
    local = utc.astimezone(ZoneInfo("America/New_York"))
    local_value = f"{local.year:04d}-{local.month:02d}-{local.day:02d}T{local.hour:02d}:{local.minute:02d}"
    assert local_value == "2026-08-20T17:00"
    parsed = datetime.fromisoformat(local_value).replace(tzinfo=ZoneInfo("America/New_York"))
    assert parsed.astimezone(timezone.utc) == utc
    sliced = utc.isoformat().replace("+00:00", "Z")[:16]
    assert sliced == "2026-08-20T21:00"
    assert sliced != local_value
    admin = (FRONTEND_SRC / "pages" / "AdminUsers.tsx").read_text()
    helper = (FRONTEND_SRC / "datetimeLocal.ts").read_text()
    assert "utcToDatetimeLocal" in admin
    assert "datetimeLocalToUtc" in admin
    assert "viewer_expires_at.slice(0, 16)" not in admin
    assert "export function utcToDatetimeLocal" in helper
    assert "export function datetimeLocalToUtc" in helper


def test_auditor_ui_exposes_site_pagination_and_filters():
    reports = (FRONTEND_SRC / "pages" / "Reports.tsx").read_text()
    history = (FRONTEND_SRC / "pages" / "History.tsx").read_text()
    assert 'params.set("site_id"' in reports
    assert "unauthorized" in reports
    assert '["low", "normal", "high", "critical"]' in reports
    assert "Previous" in reports and "Next" in reports
    assert "page_size=50" in reports
    assert "offset" in history
    assert "Previous" in history and "Next" in history


def _site_asset(db, tenant_id: int, site_id: int, name: str):
    from app.models import Asset

    asset = Asset(
        tenant_id=tenant_id,
        site_id=site_id,
        display_name=name,
        classification="Server",
        description="",
        lifecycle_state="active",
        disposition="unreviewed",
        criticality="critical",
        is_expected=False,
    )
    db.add(asset)
    db.flush()
    return asset


def _open_critical(db, tenant_id: int, asset, key: str, *, priority="p1"):
    from app.models import TECHNICAL_OPEN, AssetFinding, Finding, Vulnerability

    now = datetime.now(timezone.utc)
    vuln = Vulnerability(canonical_key=key, title=key)
    db.add(vuln)
    db.flush()
    finding = AssetFinding(
        tenant_id=tenant_id,
        asset_id=asset.id,
        vulnerability_id=vuln.id,
        technical_state=TECHNICAL_OPEN,
        treatment_state="unaddressed",
        first_seen=now - timedelta(days=5),
        last_seen=now,
        priority=priority,
    )
    db.add(finding)
    db.flush()
    db.add(
        Finding(
            tenant_id=tenant_id,
            asset_id=asset.id,
            asset_finding_id=finding.id,
            template_id=key,
            name=key,
            severity="critical",
            hostname=asset.display_name,
            host=asset.display_name,
            found_at=now,
            evidence_key=f"ev-{key}",
            raw_json={},
        )
    )
    return finding


@requires_postgres
def test_executive_site_scope_and_history_resolution(reset_db):
    from app.database import SessionLocal
    from app.models import HISTORY_REOPENED, HISTORY_RESOLVED, TECHNICAL_OPEN, TECHNICAL_RESOLVED, AssetFindingHistory

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        hartford = client.post(
            f"/api/tenants/{tenant_id}/sites",
            headers=_headers(admin),
            json={"name": "Hartford", "timezone": "America/New_York"},
        ).json()
        boston = client.post(
            f"/api/tenants/{tenant_id}/sites",
            headers=_headers(admin),
            json={"name": "Boston", "timezone": "America/New_York"},
        ).json()
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            hart_asset = _site_asset(db, tenant_id, hartford["id"], "Hartford Host")
            bos_asset = _site_asset(db, tenant_id, boston["id"], "Boston Host")
            hart_finding = _open_critical(db, tenant_id, hart_asset, "nuclei:hartford-crit")
            for idx in range(10):
                _open_critical(db, tenant_id, bos_asset, f"nuclei:boston-crit-{idx}")
            db.add(
                AssetFindingHistory(
                    asset_finding_id=hart_finding.id,
                    tenant_id=tenant_id,
                    transition_type=HISTORY_RESOLVED,
                    previous_technical_state=TECHNICAL_OPEN,
                    new_technical_state=TECHNICAL_RESOLVED,
                    occurred_at=now - timedelta(days=2),
                    details={},
                    idempotence_key="3c-hart-resolved",
                )
            )
            db.add(
                AssetFindingHistory(
                    asset_finding_id=hart_finding.id,
                    tenant_id=tenant_id,
                    transition_type=HISTORY_REOPENED,
                    previous_technical_state=TECHNICAL_RESOLVED,
                    new_technical_state=TECHNICAL_OPEN,
                    occurred_at=now - timedelta(days=1),
                    details={},
                    idempotence_key="3c-hart-reopened",
                )
            )
            db.commit()
        finally:
            db.close()
        viewer, _ = _create_viewer(client, admin, "site-exec", tenant_ids=[tenant_id])
        hart = client.get(
            f"/api/reports/executive/preview?tenant_id={tenant_id}&site_id={hartford['id']}",
            headers=_headers(viewer),
        ).json()
        bos = client.get(
            f"/api/reports/executive/preview?tenant_id={tenant_id}&site_id={boston['id']}",
            headers=_headers(viewer),
        ).json()
        assert hart["summary"]["open_by_severity"]["critical"] == 1
        assert bos["summary"]["open_by_severity"]["critical"] == 10
        assert hart["summary"]["open_by_priority"]["p1"] == 1
        assert bos["summary"]["open_by_priority"]["p1"] == 10
        assert hart["summary"]["reopened_in_period"] == 1
        assert bos["summary"]["reopened_in_period"] == 0
        assert hart["summary"]["resolved_in_period"] == 1
        assert bos["summary"]["resolved_in_period"] == 0


@requires_postgres
def test_scan_history_uses_immutable_snapshot_site(reset_db):
    from app.database import SessionLocal
    from app.models import Scan, ScanJob

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        hartford = client.post(
            f"/api/tenants/{tenant_id}/sites",
            headers=_headers(admin),
            json={"name": "Hartford", "timezone": "America/New_York"},
        ).json()
        boston = client.post(
            f"/api/tenants/{tenant_id}/sites",
            headers=_headers(admin),
            json={"name": "Boston", "timezone": "America/New_York"},
        ).json()
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            scan = Scan(
                tenant_id=tenant_id,
                site_id=hartford["id"],
                name="Moved Scan",
                scope="lan",
                profile="discovery",
                is_enabled=True,
            )
            db.add(scan)
            db.flush()
            db.add(
                ScanJob(
                    scan_id=scan.id,
                    tenant_id=tenant_id,
                    status="done",
                    started_at=now - timedelta(hours=1),
                    finished_at=now,
                    execution_snapshot={
                        "scope": "lan",
                        "site": {"id": hartford["id"], "name": "Hartford", "timezone": "America/New_York"},
                    },
                    snapshot_version="snap-site",
                    definition_revision=1,
                )
            )
            scan.site_id = boston["id"]
            db.commit()
        finally:
            db.close()
        viewer, _ = _create_viewer(client, admin, "scan-site", tenant_ids=[tenant_id])
        hart = client.get(
            f"/api/reports/scan_history/preview?tenant_id={tenant_id}&site_id={hartford['id']}",
            headers=_headers(viewer),
        ).json()
        bos = client.get(
            f"/api/reports/scan_history/preview?tenant_id={tenant_id}&site_id={boston['id']}",
            headers=_headers(viewer),
        ).json()
        assert any(row["site"] == "Hartford" and row["scan_name"] == "Moved Scan" for row in hart["rows"])
        assert not any(row["scan_name"] == "Moved Scan" for row in bos["rows"])


@requires_postgres
def test_resolved_findings_filter_uses_resolution_timestamp(reset_db):
    from app.database import SessionLocal
    from app.models import HISTORY_RESOLVED, TECHNICAL_RESOLVED, AssetFinding, AssetFindingHistory, Vulnerability

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            asset = _site_asset(db, tenant_id, world["site"]["id"], "Old First Seen")
            vuln = Vulnerability(canonical_key="cve:CVE-2024-3333", cve_id="CVE-2024-3333", title="Old CVE")
            db.add(vuln)
            db.flush()
            finding = AssetFinding(
                tenant_id=tenant_id,
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                technical_state=TECHNICAL_RESOLVED,
                treatment_state="unaddressed",
                first_seen=now - timedelta(days=200),
                last_seen=now - timedelta(days=1),
                resolved_at=now - timedelta(days=1),
            )
            db.add(finding)
            db.flush()
            db.add(
                AssetFindingHistory(
                    asset_finding_id=finding.id,
                    tenant_id=tenant_id,
                    transition_type=HISTORY_RESOLVED,
                    previous_technical_state="open",
                    new_technical_state=TECHNICAL_RESOLVED,
                    occurred_at=now - timedelta(days=1),
                    details={"source": "policy"},
                    idempotence_key="3c-old-first-seen-resolved",
                )
            )
            db.commit()
            finding_id = finding.id
        finally:
            db.close()
        start = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        viewer, _ = _create_viewer(client, admin, "resolved-date", tenant_ids=[tenant_id])
        preview = client.get(
            f"/api/reports/resolved_findings/preview?tenant_id={tenant_id}&date_from={start}",
            headers=_headers(viewer),
        )
        assert preview.status_code == 200, preview.text
        assert any(row["asset_finding_id"] == finding_id for row in preview.json()["rows"])


@requires_postgres
def test_finding_preview_uses_latest_evidence_sql(reset_db):
    from app.database import SessionLocal, engine
    from app.models import Finding

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        db = SessionLocal()
        try:
            asset = _site_asset(db, tenant_id, world["site"]["id"], "Evidence Host")
            finding = _open_critical(db, tenant_id, asset, "nuclei:evidence-bound")
            now = datetime.now(timezone.utc)
            for idx in range(80):
                db.add(
                    Finding(
                        tenant_id=tenant_id,
                        asset_id=asset.id,
                        asset_finding_id=finding.id,
                        template_id="hist",
                        name="hist",
                        severity="high",
                        hostname=asset.display_name,
                        host=asset.display_name,
                        found_at=now - timedelta(minutes=idx),
                        evidence_key=f"bound-ev-{idx}",
                        raw_json={},
                    )
                )
            db.commit()
        finally:
            db.close()
        viewer, _ = _create_viewer(client, admin, "ev-bound", tenant_ids=[tenant_id])
        statements: list[str] = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", before_cursor)
        try:
            preview = client.get(
                f"/api/reports/open_findings/preview?tenant_id={tenant_id}&page_size=50",
                headers=_headers(viewer),
            )
            assert preview.status_code == 200
            assert preview.json()["rows"]
        finally:
            event.remove(engine, "before_cursor_execute", before_cursor)
        finding_sql = [stmt for stmt in statements if "from findings" in stmt.lower()]
        assert finding_sql
        for stmt in finding_sql:
            upper = stmt.upper()
            assert "DISTINCT ON" in upper or "COUNT(" in upper


@requires_postgres
def test_pdf_export_is_chunked_and_audit_follows_success(reset_db):
    from app.database import SessionLocal
    from app.models import AuditLog, DomainEvent
    from app.reporting import service as report_service

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            for idx in range(3):
                db.add(
                    DomainEvent(
                        event_type="new_asset",
                        tenant_id=tenant_id,
                        site_id=world["site"]["id"],
                        occurred_at=now - timedelta(minutes=idx),
                        source="manual",
                        details={"display_name": f"Change {idx}"},
                        idempotence_key=f"3c-change-{idx}",
                    )
                )
            db.commit()
        finally:
            db.close()
        viewer, _ = _create_viewer(client, admin, "pdf-bound", tenant_ids=[tenant_id])
        dataset_calls = []
        original = report_service._dataset

        def wrapped(ctx, report_key, *, offset=None, limit=None):
            dataset_calls.append((report_key, offset, limit))
            return original(ctx, report_key, offset=offset, limit=limit)

        with patch.object(report_service, "_dataset", wrapped):
            pdf = client.get(
                f"/api/reports/asset_inventory/export?format=pdf&tenant_id={tenant_id}",
                headers=_headers(viewer),
            )
        assert pdf.status_code == 200
        assert pdf.content[:4] == b"%PDF"
        assert dataset_calls == []
        changes = client.get(
            f"/api/reports/asset_changes/preview?tenant_id={tenant_id}&page=1&page_size=1",
            headers=_headers(viewer),
        ).json()
        assert changes["total"] >= 3
        assert len(changes["rows"]) == 1
        db = SessionLocal()
        try:
            before = db.query(AuditLog).filter(AuditLog.action == "report.export").count()
        finally:
            db.close()
        with patch.object(report_service, "build_pdf_bytes", side_effect=RuntimeError("forced render failure")):
            with pytest.raises(RuntimeError, match="forced render failure"):
                client.get(
                    f"/api/reports/asset_inventory/export?format=pdf&tenant_id={tenant_id}",
                    headers=_headers(viewer),
                )
        db = SessionLocal()
        try:
            after = db.query(AuditLog).filter(AuditLog.action == "report.export").count()
        finally:
            db.close()
        assert after == before
