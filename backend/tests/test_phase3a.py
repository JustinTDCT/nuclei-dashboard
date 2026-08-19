from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, inspect, text

from tests.conftest import requires_postgres
from tests.test_phase1d import _client, _create_staff, _headers, _login, _world
from tests.test_phase2a import _finding_payload, _run_clean, _run_detected

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE2C_HEAD = "0011_phase2c_treatments_compliance"
PHASE3A_HEAD = "0012_policy_engine"
PHASE3B_HEAD = "0016_scanner_runtime_inventory"
PHASE2C_GIT_BLOB = "430857e2a96017a43ffffd164eb78b0ab684918e"
PHASE2C_SHA256 = "f78ddcd7fb8753ec652ef8377d74758f737394c505012c4786b6b71868fb22d1"


def _policy(client, token, **kwargs):
    body = {
        "name": kwargs.pop("name", "Policy"),
        "description": kwargs.pop("description", ""),
        "category": kwargs.pop("category", "asset_handling"),
        "scope_type": kwargs.pop("scope_type", "global"),
        "tenant_id": kwargs.pop("tenant_id", None),
        "site_id": kwargs.pop("site_id", None),
        "network_id": kwargs.pop("network_id", None),
        "priority": kwargs.pop("priority", 100),
        "conditions": kwargs.pop("conditions", []),
        "actions": kwargs.pop("actions", {"classification": "Desktop"}),
    }
    body.update(kwargs)
    return client.post("/api/policies", headers=_headers(token), json=body)


@requires_postgres
def test_fresh_db_reaches_0012_and_freezes_0011(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3B_HEAD
    assert "policy_rules" in set(inspect(engine).get_table_names())
    content = (BACKEND_ROOT / "alembic" / "versions" / "0011_phase2c_treatments_compliance.py").read_bytes()
    assert hashlib.sha256(content).hexdigest() == PHASE2C_SHA256
    blob = subprocess.check_output(
        ["git", "hash-object", str(BACKEND_ROOT / "alembic" / "versions" / "0011_phase2c_treatments_compliance.py")],
        cwd=BACKEND_ROOT.parent,
        text=True,
    ).strip()
    assert blob == PHASE2C_GIT_BLOB


@requires_postgres
def test_0011_to_0012_preserves_phase2c_data_and_downgrade_safety(reset_db):
    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision
    from app.models import AssetFinding, FindingTreatment, PolicyRule, Vulnerability

    command.upgrade(alembic_config(), PHASE2C_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 3A', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name) VALUES (:t, 'Keep Site') RETURNING id"),
            {"t": tenant_id},
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
            text("INSERT INTO vulnerabilities (canonical_key, cve_id, title) VALUES ('cve:CVE-2024-3333', 'CVE-2024-3333', 'Keep') RETURNING id")
        ).scalar_one()
        af_id = conn.execute(
            text(
                """
                INSERT INTO asset_findings (tenant_id, asset_id, vulnerability_id, technical_state, treatment_state, first_seen, last_seen, created_at, updated_at, priority, priority_score, priority_model_version)
                VALUES (:t, :a, :v, 'open', 'mitigated', :n, :n, :n, :n, 'p2', 55, '2b.1')
                RETURNING id
                """
            ),
            {"t": tenant_id, "a": asset_id, "v": vuln_id, "n": now},
        ).scalar_one()
        treatment_id = conn.execute(
            text(
                """
                INSERT INTO finding_treatments (tenant_id, asset_finding_id, treatment_type, status, rationale, created_at, updated_at)
                VALUES (:t, :af, 'mitigated', 'active', 'keep', :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "af": af_id, "n": now},
        ).scalar_one()

    command.upgrade(alembic_config(), PHASE3A_HEAD)
    assert current_revision() == PHASE3A_HEAD
    db = SessionLocal()
    try:
        assert db.get(Vulnerability, vuln_id).cve_id == "CVE-2024-3333"
        assert db.get(AssetFinding, af_id).priority_model_version == "2b.1"
        assert db.get(FindingTreatment, treatment_id).status == "active"
        assert db.query(PolicyRule).count() == 0
    finally:
        db.close()

    command.downgrade(alembic_config(), PHASE2C_HEAD)
    assert current_revision() == PHASE2C_HEAD
    command.upgrade(alembic_config(), PHASE3A_HEAD)
    db = SessionLocal()
    try:
        db.add(
            PolicyRule(
                name="populated",
                description="",
                category="asset_handling",
                scope_type="global",
                priority=1,
                enabled=True,
                conditions=[],
                actions={"classification": "Desktop"},
                revision=1,
            )
        )
        db.commit()
    finally:
        db.close()
    try:
        command.downgrade(alembic_config(), PHASE2C_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0012_policy_engine" in str(exc)
        return
    raise AssertionError("populated 0012 downgrade must refuse")


@requires_postgres
def test_scope_inheritance_priority_and_validation(reset_db):
    from app.database import SessionLocal
    from app.models import POLICY_CATEGORY_ASSET_HANDLING, Asset
    from app.policy import PolicyError, PolicyResolver, contexts_for_assets, validate_conditions

    with _client() as client:
        admin = _login(client)
        user = _create_staff(client, admin, "policy-user", "user")
        viewer = _create_staff(client, admin, "policy-viewer", "viewer")
        world = _world(client, admin)
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other Tenant", "notes": ""}).json()
        other_site = client.post(
            f"/api/tenants/{other['id']}/sites", headers=_headers(admin), json={"name": "Other Site"}
        ).json()

        global_rule = _policy(client, admin, name="Global Desktop", actions={"classification": "Unknown", "disposition": "unreviewed"})
        assert global_rule.status_code == 200, global_rule.text
        tenant_rule = _policy(
            client,
            user,
            name="Tenant Desktop",
            scope_type="tenant",
            tenant_id=world["tenant"]["id"],
            actions={"classification": "Desktop"},
        )
        assert tenant_rule.status_code == 200, tenant_rule.text
        site_rule = _policy(
            client,
            user,
            name="Site Laptop",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            actions={"classification": "Laptop"},
        )
        assert site_rule.status_code == 200
        network_rule = _policy(
            client,
            user,
            name="Net Approved",
            scope_type="network",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            network_id=world["net1"]["id"],
            priority=50,
            actions={"disposition": "approved"},
        )
        assert network_rule.status_code == 200
        same_scope_high = _policy(
            client,
            user,
            name="Site Server High",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            priority=200,
            actions={"classification": "Server"},
        )
        assert same_scope_high.status_code == 200

        cross = _policy(
            client,
            user,
            name="Cross",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=other_site["id"],
            actions={"classification": "IoT Device"},
        )
        assert cross.status_code in {400, 404}
        wrong_net = _policy(
            client,
            user,
            name="Wrong net",
            scope_type="network",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            network_id=999999,
            actions={"disposition": "approved"},
        )
        assert wrong_net.status_code in {400, 404}
        forbidden_global = _policy(client, user, name="User Global", actions={"disposition": "approved"})
        assert forbidden_global.status_code == 403
        viewer_write = _policy(client, viewer, name="Viewer", scope_type="tenant", tenant_id=world["tenant"]["id"])
        assert viewer_write.status_code == 403
        listed = client.get("/api/policies", headers=_headers(viewer))
        assert listed.status_code == 200
        deleted = client.delete(f"/api/policies/{global_rule.json()['id']}", headers=_headers(admin))
        assert deleted.status_code in {404, 405}

        unsupported = _policy(
            client,
            admin,
            name="Bad field",
            conditions=[{"field": "sql", "op": "equals", "value": "1"}],
            actions={"classification": "Desktop"},
        )
        assert unsupported.status_code == 400
        bad_op = _policy(
            client,
            admin,
            name="Bad op",
            conditions=[{"field": "hostname", "op": "regex", "value": "LT-.*"}],
            actions={"classification": "Desktop"},
        )
        assert bad_op.status_code == 400
        expr = _policy(
            client,
            admin,
            name="Expr",
            conditions=[{"field": "hostname", "op": "equals", "value": "x", "expr": "os.system('x')"}],
            actions={"classification": "Desktop"},
        )
        assert expr.status_code in {400, 422}
        with pytest.raises(PolicyError):
            validate_conditions([{"field": "hostname", "op": "equals", "value": "x", "eval": "1"}], category="asset_handling")

        disabled = _policy(client, admin, name="Disabled", priority=500, actions={"classification": "UPS"})
        assert disabled.status_code == 200
        client.post(f"/api/policies/{disabled.json()['id']}/disable", headers=_headers(admin))
        archived = _policy(client, admin, name="Archived", priority=600, actions={"classification": "Switch"})
        client.post(f"/api/policies/{archived.json()['id']}/archive", headers=_headers(admin), json={"reason": "done"})
        updated = client.patch(
            f"/api/policies/{tenant_rule.json()['id']}",
            headers=_headers(user),
            json={"description": "updated"},
        )
        assert updated.status_code == 200
        assert updated.json()["revision"] == 2

        db = SessionLocal()
        try:
            asset = Asset(
                tenant_id=world["tenant"]["id"],
                site_id=world["site"]["id"],
                display_name="LT-100",
                classification="Unknown",
                disposition="unreviewed",
                criticality="normal",
                is_expected=False,
            )
            db.add(asset)
            db.flush()
            from app.models import AssetObservation

            db.add(
                AssetObservation(
                    asset_id=asset.id,
                    tenant_id=asset.tenant_id,
                    site_id=world["site"]["id"],
                    network_id=world["net1"]["id"],
                    observed_at=datetime.now(timezone.utc),
                    hostname="LT-100",
                    ip="10.1.0.25",
                    snapshot={"hostname": "LT-100", "ports": []},
                    observation_key="lt-100",
                )
            )
            db.flush()
            resolver = PolicyResolver(db)
            context = contexts_for_assets(db, [asset])[asset.id]
            result = resolver.evaluate(context, POLICY_CATEGORY_ASSET_HANDLING)
            assert result.effective["classification"] == "Server"
            assert result.effective["disposition"] == "approved"
            assert result.actions["classification"].rule_name == "Site Server High"
            assert result.actions["disposition"].rule_name == "Net Approved"
            assert result.actions["disposition"].overrode is None or result.actions["disposition"].source == "policy"
            other_ctx = contexts_for_assets(db, [asset])[asset.id]
            other_ctx.network_id = world["net2"]["id"]
            other_result = resolver.evaluate(other_ctx, POLICY_CATEGORY_ASSET_HANDLING)
            assert other_result.effective["classification"] == "Server"
            assert other_result.effective["disposition"] == "unreviewed"
        finally:
            db.close()


@requires_postgres
def test_asset_handling_application_audit_and_auto_approval_safety(reset_db):
    from app.database import SessionLocal
    from app.models import PRIORITY_MODEL_VERSION, Asset, AuditLog, AssetCorrelationDecision

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        from tests.test_phase2a import _complete, _post_coverage, _post_device, _start_lan, _vuln_scan

        first = _run_detected(client, admin, world, hostname="repeat-host", ip="10.1.0.40")
        db = SessionLocal()
        try:
            asset = db.query(Asset).filter(Asset.display_name.ilike("%repeat-host%")).first()
            assert asset is not None
            assert asset.disposition == "unreviewed"
            asset_id = asset.id
            decision = (
                db.query(AssetCorrelationDecision)
                .filter(AssetCorrelationDecision.selected_asset_id == asset.id)
                .order_by(AssetCorrelationDecision.id.asc())
                .first()
            )
            decision_id = decision.id
            score = decision.score
            confidence = decision.confidence
            selected = decision.selected_asset_id
        finally:
            db.close()
        _run_clean(client, admin, world, first[0]["id"], hostname="repeat-host", ip="10.1.0.40")
        _run_clean(client, admin, world, first[0]["id"], hostname="repeat-host", ip="10.1.0.40")
        db = SessionLocal()
        try:
            asset = db.get(Asset, asset_id)
            assert asset.disposition == "unreviewed"
            original = db.get(AssetCorrelationDecision, decision_id)
            assert original.score == score
            assert original.confidence == confidence
            assert original.selected_asset_id == selected == asset_id
            assert db.query(AuditLog).filter(AuditLog.action == "asset.policy_disposition_changed", AuditLog.object_id == asset.id).count() == 0
        finally:
            db.close()

        created = _policy(
            client,
            admin,
            name="Approve LT",
            scope_type="network",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            network_id=world["net1"]["id"],
            conditions=[{"field": "hostname", "op": "glob", "value": "LT-*"}],
            actions={"classification": "Laptop", "disposition": "approved"},
        )
        assert created.status_code == 200
        scan = _vuln_scan(client, admin, world, name="lt-scan")
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id, ip="10.1.0.50", hostname="LT-100")
        _post_coverage(client, world, job_id, ["https://10.1.0.50"])
        assert _complete(client, world, job_id).status_code == 200
        listed = client.get(f"/api/tenants/{world['tenant']['id']}/assets", headers=_headers(admin))
        lt = next(row for row in listed.json() if row["hostname"] == "LT-100" or row["display_name"] == "LT-100")
        assert lt["classification"] == "Laptop"
        assert lt["disposition"] == "approved"
        db = SessionLocal()
        try:
            audits = db.query(AuditLog).filter(AuditLog.object_id == lt["id"], AuditLog.action.in_(["asset.policy_classification_changed", "asset.policy_disposition_changed"])).all()
            assert {row.action for row in audits} == {"asset.policy_classification_changed", "asset.policy_disposition_changed"}
            assert all(row.actor_user_id is None for row in audits)
            before = len(audits)
        finally:
            db.close()
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id, ip="10.1.0.50", hostname="LT-100")
        _post_coverage(client, world, job_id, ["https://10.1.0.50"])
        assert _complete(client, world, job_id).status_code == 200
        db = SessionLocal()
        try:
            after = db.query(AuditLog).filter(AuditLog.object_id == lt["id"], AuditLog.action.in_(["asset.policy_classification_changed", "asset.policy_disposition_changed"])).count()
            assert after == before
            assert db.query(Asset).filter(Asset.id == lt["id"]).one().id == lt["id"]
        finally:
            db.close()

        miss = _policy(
            client,
            admin,
            name="Approve DESK",
            scope_type="tenant",
            tenant_id=world["tenant"]["id"],
            conditions=[{"field": "hostname", "op": "glob", "value": "DESK-*"}],
            actions={"disposition": "approved"},
        )
        assert miss.status_code == 200
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin)).json()["id"]
        _start_lan(client, world, job_id)
        _post_device(client, world, job_id, ip="10.1.0.60", hostname="SRV-1")
        _post_coverage(client, world, job_id, ["https://10.1.0.60"])
        assert _complete(client, world, job_id).status_code == 200
        assets = client.get(f"/api/tenants/{world['tenant']['id']}/assets", headers=_headers(admin)).json()
        srv = next(row for row in assets if "SRV-1" in (row["hostname"] or "") or "SRV-1" in row["display_name"])
        assert srv["disposition"] == "unreviewed"

        tagged = next(row for row in assets if row["id"] == lt["id"])
        client.post(f"/api/tenants/{world['tenant']['id']}/tags", headers=_headers(admin), json={"name": "Production"})
        client.post(f"/api/assets/{lt['id']}/tags", headers=_headers(admin), json={"name": "Production"})
        tag_policy = _policy(
            client,
            admin,
            name="Prod high",
            scope_type="tenant",
            tenant_id=world["tenant"]["id"],
            conditions=[
                {"field": "tag", "op": "has", "value": "Production"},
                {"field": "criticality", "op": "equals", "value": "normal"},
                {"field": "is_expected", "op": "equals", "value": False},
            ],
            actions={"classification": "Laptop"},
        )
        assert tag_policy.status_code == 200
        port_policy = _policy(
            client,
            admin,
            name="Port 22",
            scope_type="tenant",
            tenant_id=world["tenant"]["id"],
            conditions=[{"field": "observed_port", "op": "equals", "value": 22}],
            actions={"classification": "Server"},
        )
        assert port_policy.status_code == 200
        evaluation = client.get(f"/api/tenants/{world['tenant']['id']}/assets/{lt['id']}/policy-evaluation", headers=_headers(admin))
        assert evaluation.status_code == 200
        body = evaluation.json()
        assert "classification" in body["effective"]
        assert body["actions"]["classification"]["rule_id"]
        assert body["actions"]["classification"]["matched_conditions"]
        audits_before = SessionLocal()
        try:
            count = audits_before.query(AuditLog).count()
        finally:
            audits_before.close()
        again = client.get(f"/api/tenants/{world['tenant']['id']}/assets/{lt['id']}/policy-evaluation", headers=_headers(admin))
        assert again.status_code == 200
        audits_after = SessionLocal()
        try:
            assert audits_after.query(AuditLog).count() == count
            assert PRIORITY_MODEL_VERSION == "2b.1"
        finally:
            audits_after.close()


@requires_postgres
def test_inactivity_policy_and_query_bound(reset_db):
    from app.database import SessionLocal, engine
    from app.lifecycle import mark_inactive_assets
    from app.models import LIFECYCLE_ACTIVE, LIFECYCLE_INACTIVE, Asset, DomainEvent

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        other_tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other Inactive", "notes": ""}).json()
        other_site = client.post(
            f"/api/tenants/{other_tenant['id']}/sites", headers=_headers(admin), json={"name": "Elsewhere"}
        ).json()
        created = _policy(
            client,
            admin,
            name="Hartford inactive 10",
            category="asset_inactivity",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            actions={"inactive_after_days": 10},
        )
        assert created.status_code == 200
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            local = Asset(
                tenant_id=world["tenant"]["id"],
                site_id=world["site"]["id"],
                display_name="old-local",
                classification="Unknown",
                disposition="unreviewed",
                lifecycle_state=LIFECYCLE_ACTIVE,
                criticality="normal",
                first_seen=now - timedelta(days=40),
                last_seen=now - timedelta(days=12),
            )
            fresh = Asset(
                tenant_id=world["tenant"]["id"],
                site_id=world["site"]["id"],
                display_name="fresh-local",
                classification="Unknown",
                disposition="unreviewed",
                lifecycle_state=LIFECYCLE_ACTIVE,
                criticality="normal",
                first_seen=now - timedelta(days=5),
                last_seen=now - timedelta(days=5),
            )
            remote = Asset(
                tenant_id=other_tenant["id"],
                site_id=other_site["id"],
                display_name="old-remote",
                classification="Unknown",
                disposition="unreviewed",
                lifecycle_state=LIFECYCLE_ACTIVE,
                criticality="normal",
                first_seen=now - timedelta(days=40),
                last_seen=now - timedelta(days=12),
            )
            db.add_all([local, fresh, remote])
            db.commit()
            local_id, fresh_id, remote_id = local.id, fresh.id, remote.id
        finally:
            db.close()
        queries = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            queries.append(statement)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        event.listen(listen_on, "before_cursor_execute", before_cursor)
        try:
            changed = mark_inactive_assets()
        finally:
            event.remove(listen_on, "before_cursor_execute", before_cursor)
        assert changed == 1
        policy_loads = [sql for sql in queries if "from policy_rules" in sql.lower()]
        assert len(policy_loads) <= 2
        db = SessionLocal()
        try:
            assert db.get(Asset, local_id).lifecycle_state == LIFECYCLE_INACTIVE
            assert db.get(Asset, fresh_id).lifecycle_state == LIFECYCLE_ACTIVE
            assert db.get(Asset, remote_id).lifecycle_state == LIFECYCLE_ACTIVE
            events = db.query(DomainEvent).filter(DomainEvent.asset_id == local_id, DomainEvent.event_type == "asset_became_inactive").all()
            assert len(events) == 1
            mark_inactive_assets()
            assert db.query(DomainEvent).filter(DomainEvent.asset_id == local_id, DomainEvent.event_type == "asset_became_inactive").count() == 1
        finally:
            db.close()


@requires_postgres
def test_finding_lifecycle_policy_threshold_and_history(reset_db):
    from app.database import SessionLocal
    from app.models import PRIORITY_MODEL_VERSION, AssetFinding, AssetFindingHistory

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        created = _policy(
            client,
            admin,
            name="Critical needs 3",
            category="finding_lifecycle",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            conditions=[{"field": "severity", "op": "equals", "value": "critical"}],
            actions={"resolution_clean_scans": 3},
        )
        assert created.status_code == 200, created.text
        scan, _job_id, _result = _run_detected(
            client,
            admin,
            world,
            hostname="crit-host",
            ip="10.1.0.70",
            findings=[_finding_payload(template="crit-tpl", name="Critical hole", severity="critical", host="https://10.1.0.70")],
        )
        rows = client.get(f"/api/tenants/{world['tenant']['id']}/asset-findings", headers=_headers(admin)).json()
        af_id = rows[0]["id"]
        from tests.test_phase2a import _complete, _post_device, _start_lan

        skipped = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin)).json()["id"]
        _start_lan(client, world, skipped)
        _post_device(client, world, skipped, ip="10.1.0.70", hostname="crit-host")
        assert _complete(client, world, skipped).status_code == 200
        db = SessionLocal()
        try:
            assert db.get(AssetFinding, af_id).consecutive_clean_scans == 0
        finally:
            db.close()
        _run_clean(client, admin, world, scan["id"], hostname="crit-host", ip="10.1.0.70")
        db = SessionLocal()
        try:
            finding = db.get(AssetFinding, af_id)
            assert finding.technical_state == "open"
            assert finding.consecutive_clean_scans == 1
        finally:
            db.close()
        _run_clean(client, admin, world, scan["id"], hostname="crit-host", ip="10.1.0.70")
        db = SessionLocal()
        try:
            assert db.get(AssetFinding, af_id).technical_state == "open"
            assert db.get(AssetFinding, af_id).consecutive_clean_scans == 2
        finally:
            db.close()
        _run_clean(client, admin, world, scan["id"], hostname="crit-host", ip="10.1.0.70")
        db = SessionLocal()
        try:
            finding = db.get(AssetFinding, af_id)
            assert finding.technical_state == "resolved"
            history = (
                db.query(AssetFindingHistory)
                .filter(AssetFindingHistory.asset_finding_id == af_id, AssetFindingHistory.transition_type == "resolved")
                .one()
            )
            assert history.details["threshold"] == 3
            assert history.details["threshold_source"] == "policy"
            assert history.details["policy_rule_id"] == created.json()["id"]
            assert history.details["policy_revision"] == 1
            first_seen = finding.first_seen
            treatment = finding.treatment_state
            score = finding.priority_score
        finally:
            db.close()
        patched = client.patch(f"/api/policies/{created.json()['id']}", headers=_headers(admin), json={"priority": 80})
        assert patched.json()["revision"] == 2
        db = SessionLocal()
        try:
            history = (
                db.query(AssetFindingHistory)
                .filter(AssetFindingHistory.asset_finding_id == af_id, AssetFindingHistory.transition_type == "resolved")
                .one()
            )
            assert history.details["policy_revision"] == 1
        finally:
            db.close()
        scan2, _job2, _ = _run_detected(
            client,
            admin,
            world,
            hostname="crit-host",
            ip="10.1.0.70",
            findings=[_finding_payload(template="crit-tpl", name="Critical hole", severity="critical", host="https://10.1.0.70")],
        )
        db = SessionLocal()
        try:
            finding = db.get(AssetFinding, af_id)
            assert finding.technical_state == "open"
            assert finding.first_seen == first_seen
            assert finding.treatment_state == treatment
            assert finding.priority_model_version == PRIORITY_MODEL_VERSION == "2b.1"
            assert finding.priority_score == score
        finally:
            db.close()
        evaluation = client.get(
            f"/api/tenants/{world['tenant']['id']}/asset-findings/{af_id}/policy-evaluation",
            headers=_headers(admin),
        )
        assert evaluation.status_code == 200
        assert evaluation.json()["effective"]["resolution_clean_scans"] == 3


@requires_postgres
def test_manual_inheritance_scenario_and_performance(reset_db):
    from app.database import SessionLocal, engine
    from app.lifecycle import mark_inactive_assets
    from app.models import Asset
    from app.policy import PolicyResolver, contexts_for_assets, reconcile_asset_handling

    with _client() as client:
        admin = _login(client)
        tenant = client.post("/api/tenants", headers=_headers(admin), json={"name": "Tenant A", "notes": ""}).json()
        site = client.post(f"/api/tenants/{tenant['id']}/sites", headers=_headers(admin), json={"name": "Hartford"}).json()
        lan = client.post(f"/api/sites/{site['id']}/networks", headers=_headers(admin), json={"name": "User LAN", "cidr": "10.10.0.0/24"}).json()
        other_net = client.post(f"/api/sites/{site['id']}/networks", headers=_headers(admin), json={"name": "Printers", "cidr": "10.20.0.0/24"}).json()
        agent = client.post(f"/api/tenants/{tenant['id']}/agents", headers=_headers(admin), json={"name": "Hartford Agent", "site_id": site["id"]}).json()
        client.put(f"/api/networks/{lan['id']}/authorized-agents", headers=_headers(admin), json={"agent_ids": [agent["id"]]})
        client.put(f"/api/networks/{other_net['id']}/authorized-agents", headers=_headers(admin), json={"agent_ids": [agent["id"]]})
        world = {"tenant": tenant, "site": site, "net1": lan, "net2": other_net, "agent1": agent}
        assert _policy(client, admin, name="Global baseline", priority=100, actions={"classification": "Unknown"}).status_code == 200
        assert _policy(
            client,
            admin,
            name="Tenant Desktop",
            scope_type="tenant",
            tenant_id=tenant["id"],
            priority=100,
            actions={"classification": "Desktop"},
        ).status_code == 200
        assert _policy(
            client,
            admin,
            name="Hartford Laptops",
            scope_type="site",
            tenant_id=tenant["id"],
            site_id=site["id"],
            priority=100,
            actions={"classification": "Laptop"},
        ).status_code == 200
        assert _policy(
            client,
            admin,
            name="User LAN approve",
            scope_type="network",
            tenant_id=tenant["id"],
            site_id=site["id"],
            network_id=lan["id"],
            priority=50,
            actions={"disposition": "approved"},
        ).status_code == 200

        from tests.test_phase1d import _lan_scan
        from tests.test_phase2a import VULN_STAGES, _complete, _post_coverage, _agent_headers

        scan = _lan_scan(
            client,
            admin,
            world,
            name="Hartford scan",
            network_ids=[lan["id"], other_net["id"]],
            stage_config=dict(VULN_STAGES),
        )
        job_id = client.post(f"/api/scans/{scan['id']}/run", headers=_headers(admin)).json()["id"]
        from tests.test_phase1d import _heartbeat
        from tests.test_phase2a import _agent_headers

        _heartbeat(agent["id"])
        assert client.post(f"/api/agent/jobs/{job_id}/start", headers=_agent_headers(agent)).status_code == 200
        assert client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(agent),
            json=[{"ip": "10.10.0.10", "scope": "lan", "hostname": "LT-100"}],
        ).status_code == 200
        assert client.post(
            f"/api/agent/jobs/{job_id}/devices",
            headers=_agent_headers(agent),
            json=[{"ip": "10.20.0.10", "scope": "lan", "hostname": "LT-200"}],
        ).status_code == 200
        _post_coverage(client, world, job_id, ["https://10.10.0.10", "https://10.20.0.10"])
        assert _complete(client, world, job_id).status_code == 200
        rows = client.get(f"/api/tenants/{tenant['id']}/assets", headers=_headers(admin)).json()
        lan_asset = next(row for row in rows if "LT-100" in (row["hostname"] or row["display_name"]))
        other_asset = next(row for row in rows if "LT-200" in (row["hostname"] or row["display_name"]))
        assert lan_asset["classification"] == "Laptop"
        assert lan_asset["disposition"] == "approved"
        assert other_asset["classification"] == "Laptop"
        assert other_asset["disposition"] == "unreviewed"
        explained = client.get(
            f"/api/tenants/{tenant['id']}/assets/{lan_asset['id']}/policy-evaluation",
            headers=_headers(admin),
        ).json()
        assert explained["actions"]["classification"]["rule_name"] == "Hartford Laptops"
        assert explained["actions"]["disposition"]["rule_name"] == "User LAN approve"
        assert explained["actions"]["disposition"]["priority"] == 50

        db = SessionLocal()
        try:
            assets = []
            now = datetime.now(timezone.utc)
            for index in range(500):
                assets.append(
                    Asset(
                        tenant_id=tenant["id"],
                        site_id=site["id"],
                        display_name=f"bulk-{index}",
                        classification="Unknown",
                        disposition="unreviewed",
                        lifecycle_state="active",
                        criticality="normal",
                        first_seen=now - timedelta(days=2),
                        last_seen=now - timedelta(days=2),
                    )
                )
            db.add_all(assets)
            db.commit()
            loaded = db.query(Asset).filter(Asset.tenant_id == tenant["id"], Asset.display_name.like("bulk-%")).all()
        finally:
            db.close()

        db = SessionLocal()
        queries = []

        def before_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            queries.append(statement)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        event.listen(listen_on, "before_cursor_execute", before_cursor)
        try:
            resolver = PolicyResolver(db)
            contexts = contexts_for_assets(db, loaded)
            for asset in loaded:
                resolver.evaluate(contexts[asset.id], "asset_handling")
            reconcile_asset_handling(db)
        finally:
            event.remove(listen_on, "before_cursor_execute", before_cursor)
            db.close()
        policy_loads = [sql for sql in queries if "from policy_rules" in sql.lower()]
        assert len(policy_loads) < 20
        assert len(policy_loads) < len(loaded) / 10
        mark_inactive_assets()


def _escalate(client, token, policy_id: int):
    return client.patch(
        f"/api/policies/{policy_id}",
        headers=_headers(token),
        json={"scope_type": "global", "tenant_id": None, "site_id": None, "network_id": None},
    )


@requires_postgres
def test_user_cannot_escalate_scoped_policy_to_global(reset_db):
    from app.database import SessionLocal
    from app.models import AuditLog, PolicyRule

    with _client() as client:
        admin = _login(client)
        user = _create_staff(client, admin, "escalate-user", "user")
        world = _world(client, admin)
        tenant_rule = _policy(
            client,
            user,
            name="Tenant stay tenant",
            scope_type="tenant",
            tenant_id=world["tenant"]["id"],
            actions={"classification": "Desktop"},
        )
        site_rule = _policy(
            client,
            user,
            name="Site stay site",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            actions={"classification": "Laptop"},
        )
        network_rule = _policy(
            client,
            user,
            name="Network stay network",
            scope_type="network",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            network_id=world["net1"]["id"],
            actions={"disposition": "approved"},
        )
        assert tenant_rule.status_code == site_rule.status_code == network_rule.status_code == 200
        originals = {
            row.json()["id"]: row.json()
            for row in (tenant_rule, site_rule, network_rule)
        }
        db = SessionLocal()
        try:
            audits_before = db.query(AuditLog).filter(AuditLog.action == "policy.changed").count()
        finally:
            db.close()
        for policy_id, original in originals.items():
            response = _escalate(client, user, policy_id)
            assert response.status_code == 403, response.text
            current = client.get(f"/api/policies/{policy_id}", headers=_headers(user))
            assert current.status_code == 200
            body = current.json()
            assert body["scope_type"] == original["scope_type"]
            assert body["tenant_id"] == original["tenant_id"]
            assert body["site_id"] == original["site_id"]
            assert body["network_id"] == original["network_id"]
            assert body["revision"] == original["revision"]
        db = SessionLocal()
        try:
            assert db.query(AuditLog).filter(AuditLog.action == "policy.changed").count() == audits_before
            for policy_id, original in originals.items():
                row = db.get(PolicyRule, policy_id)
                assert row.scope_type == original["scope_type"]
                assert row.tenant_id == original["tenant_id"]
        finally:
            db.close()
        promoted = _escalate(client, admin, tenant_rule.json()["id"])
        assert promoted.status_code == 200, promoted.text
        assert promoted.json()["scope_type"] == "global"
        assert promoted.json()["tenant_id"] is None
        assert promoted.json()["revision"] == tenant_rule.json()["revision"] + 1


@requires_postgres
def test_site_move_evaluates_new_site_not_historical_network(reset_db):
    from app.database import SessionLocal
    from app.models import Asset, AssetObservation, AuditLog
    from app.policy import apply_asset_handling

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        site_b = client.post(
            f"/api/tenants/{world['tenant']['id']}/sites",
            headers=_headers(admin),
            json={"name": "Hartford"},
        ).json()
        site_a_rule = _policy(
            client,
            admin,
            name="Site A Server",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=world["site"]["id"],
            actions={"classification": "Server"},
        )
        site_b_rule = _policy(
            client,
            admin,
            name="Site B Laptop",
            scope_type="site",
            tenant_id=world["tenant"]["id"],
            site_id=site_b["id"],
            actions={"classification": "Laptop"},
        )
        assert site_a_rule.status_code == site_b_rule.status_code == 200
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            asset = Asset(
                tenant_id=world["tenant"]["id"],
                site_id=world["site"]["id"],
                display_name="moved-host",
                classification="Unknown",
                disposition="unreviewed",
                criticality="normal",
                is_expected=False,
            )
            db.add(asset)
            db.flush()
            observation = AssetObservation(
                asset_id=asset.id,
                tenant_id=asset.tenant_id,
                site_id=world["site"]["id"],
                network_id=world["net1"]["id"],
                observed_at=now,
                hostname="moved-host",
                ip="10.1.0.88",
                snapshot={"hostname": "moved-host", "ports": []},
                observation_key="moved-host-a",
            )
            db.add(observation)
            db.flush()
            apply_asset_handling(db, asset)
            assert asset.classification == "Server"
            asset_id = asset.id
            observation_id = observation.id
            db.commit()
        finally:
            db.close()
        moved = client.post(
            f"/api/assets/{asset_id}/move-site",
            headers=_headers(admin),
            json={"site_id": site_b["id"], "reason": "relocate"},
        )
        assert moved.status_code == 200, moved.text
        assert moved.json()["site_id"] == site_b["id"]
        assert moved.json()["classification"] == "Laptop"
        evaluation = client.get(
            f"/api/tenants/{world['tenant']['id']}/assets/{asset_id}/policy-evaluation",
            headers=_headers(admin),
        )
        assert evaluation.status_code == 200
        body = evaluation.json()
        assert body["site_id"] == site_b["id"]
        assert body["network_id"] is None
        assert body["actions"]["classification"]["rule_name"] == "Site B Laptop"
        assert body["actions"]["classification"]["site_id"] == site_b["id"]
        db = SessionLocal()
        try:
            kept = db.get(AssetObservation, observation_id)
            assert kept.site_id == world["site"]["id"]
            assert kept.network_id == world["net1"]["id"]
            audits = (
                db.query(AuditLog)
                .filter(
                    AuditLog.object_id == asset_id,
                    AuditLog.action == "asset.policy_classification_changed",
                )
                .order_by(AuditLog.id.desc())
                .all()
            )
            assert audits
            latest = audits[0]
            assert latest.details["new"] == "Laptop"
            assert latest.details["policy_rule_id"] == site_b_rule.json()["id"]
            assert latest.details["policy_name"] == "Site B Laptop"
            assert latest.details["site_id"] == site_b["id"]
            assert latest.details["network_id"] is None
            assert db.get(Asset, asset_id).classification == "Laptop"
        finally:
            db.close()


@requires_postgres
def test_latest_observation_and_evidence_queries_are_row_bounded(reset_db):
    from app.database import SessionLocal, engine
    from app.models import Asset, AssetFinding, AssetObservation, Finding, Vulnerability
    from app.policy import _latest_observation_map, context_for_findings

    with _client() as client:
        admin = _login(client)
        world = _world(client, admin)
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            assets = []
            for index in range(3):
                asset = Asset(
                    tenant_id=world["tenant"]["id"],
                    site_id=world["site"]["id"],
                    display_name=f"hist-{index}",
                    classification="Unknown",
                    disposition="unreviewed",
                    criticality="normal",
                    first_seen=now - timedelta(days=40),
                    last_seen=now,
                )
                db.add(asset)
                db.flush()
                assets.append(asset)
                for obs in range(40):
                    db.add(
                        AssetObservation(
                            asset_id=asset.id,
                            tenant_id=asset.tenant_id,
                            site_id=world["site"]["id"],
                            network_id=world["net1"]["id"],
                            observed_at=now - timedelta(hours=40 - obs),
                            hostname=f"hist-{index}",
                            ip=f"10.1.0.{10 + index}",
                            snapshot={"hostname": f"hist-{index}", "ports": []},
                            observation_key=f"hist-{index}-{obs}",
                        )
                    )
            vuln = Vulnerability(canonical_key="cve:CVE-2024-9999", cve_id="CVE-2024-9999", title="Hist")
            db.add(vuln)
            db.flush()
            findings = []
            for asset in assets:
                finding = AssetFinding(
                    tenant_id=asset.tenant_id,
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    technical_state="open",
                    treatment_state="unaddressed",
                    first_seen=now - timedelta(days=10),
                    last_seen=now,
                    priority="p2",
                )
                db.add(finding)
                db.flush()
                findings.append(finding)
                for ev in range(40):
                    db.add(
                        Finding(
                            tenant_id=asset.tenant_id,
                            asset_id=asset.id,
                            asset_finding_id=finding.id,
                            template_id="hist-tpl",
                            name="Hist",
                            severity="high" if ev < 39 else "critical",
                            hostname=asset.display_name,
                            host=f"https://10.1.0.{10 + asset.id}",
                            found_at=now - timedelta(hours=40 - ev),
                            evidence_key=f"hist-ev-{asset.id}-{ev}",
                            raw_json={},
                        )
                    )
            db.commit()
            asset_ids = [asset.id for asset in assets]
            finding_ids = [finding.id for finding in findings]
        finally:
            db.close()

        observation_sql: list[str] = []
        evidence_sql: list[str] = []
        observation_rows: list[int] = []
        evidence_rows: list[int] = []

        def after_cursor(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
            sql = statement.lower()
            if "from asset_observations" in sql:
                observation_sql.append(statement)
                observation_rows.append(cursor.rowcount)
            if "from findings" in sql and "asset_finding_id" in sql:
                evidence_sql.append(statement)
                evidence_rows.append(cursor.rowcount)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        db = SessionLocal()
        event.listen(listen_on, "after_cursor_execute", after_cursor)
        try:
            latest = _latest_observation_map(db, asset_ids)
            assert set(latest) == set(asset_ids)
            assert all(row.observation_key.endswith("-39") for row in latest.values())
            loaded = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
            af_rows = db.query(AssetFinding).filter(AssetFinding.id.in_(finding_ids)).all()
            contexts = context_for_findings(db, af_rows, assets=loaded)
            assert {ctx.severity for ctx in contexts.values()} == {"critical"}
        finally:
            event.remove(listen_on, "after_cursor_execute", after_cursor)
            db.close()
        assert observation_sql
        assert any("distinct on" in sql.lower() for sql in observation_sql)
        assert max(observation_rows) <= len(asset_ids)
        assert evidence_sql
        assert any("distinct on" in sql.lower() for sql in evidence_sql)
        assert max(evidence_rows) <= len(finding_ids)
