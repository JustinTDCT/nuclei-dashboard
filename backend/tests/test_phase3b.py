from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
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
from tests.test_phase1d import _client, _create_staff, _headers, _login, _world
from tests.test_migrations import FROZEN_MIGRATION_HASHES

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PHASE3A_HEAD = "0012_policy_engine"
PHASE3B_HEAD = "0013_event_alert_engine"
PHASE3A_GIT_BLOB = "a4c0b9c7a204b31db7c042b00d1cd3d91b5b3e9d"
PHASE3A_SHA256 = "fc539d809f4decf5107fb5e4d88c9aeb50f1131a5154366bca68c0f1bedeefb9"


def _policy(client, token, **kwargs):
    body = {
        "name": kwargs.pop("name", "Alert policy"),
        "description": kwargs.pop("description", ""),
        "category": kwargs.pop("category", "alerting"),
        "scope_type": kwargs.pop("scope_type", "global"),
        "tenant_id": kwargs.pop("tenant_id", None),
        "site_id": kwargs.pop("site_id", None),
        "network_id": kwargs.pop("network_id", None),
        "priority": kwargs.pop("priority", 100),
        "conditions": kwargs.pop("conditions", [{"field": "event_type", "op": "equals", "value": "new_asset"}]),
        "actions": kwargs.pop("actions", {"dashboard": True, "email": "staff", "severity": "medium"}),
    }
    body.update(kwargs)
    return client.post("/api/policies", headers=_headers(token), json=body)


def _route(db: Session) -> int:
    from app.alert_engine import route_pending_events

    return route_pending_events(db)


def _deliver(db: Session, *, webhook_post=None, mail_send=None) -> int:
    from app.alert_engine import process_pending_deliveries
    from app.emailer import MailResult

    kwargs = {}
    if webhook_post is not None:
        kwargs["webhook_post"] = webhook_post
    if mail_send is not None:
        kwargs["mail_send"] = mail_send
    else:
        kwargs["mail_send"] = lambda *_a, **_k: MailResult(ok=True)
    return process_pending_deliveries(db, **kwargs)


@requires_postgres
def test_fresh_db_reaches_0013_and_freezes_0012(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE3B_HEAD
    tables = set(inspect(engine).get_table_names())
    assert {"event_alert_queue", "alert_deliveries", "alert_event_routes"}.issubset(tables)
    content = (BACKEND_ROOT / "alembic" / "versions" / "0012_policy_engine.py").read_bytes()
    assert hashlib.sha256(content).hexdigest() == PHASE3A_SHA256
    assert FROZEN_MIGRATION_HASHES["0012_policy_engine.py"] == PHASE3A_SHA256
    blob = subprocess.check_output(
        ["git", "hash-object", str(BACKEND_ROOT / "alembic" / "versions" / "0012_policy_engine.py")],
        cwd=BACKEND_ROOT.parent,
        text=True,
    ).strip()
    assert blob == PHASE3A_GIT_BLOB


@requires_postgres
def test_0012_to_0013_preserves_history_and_does_not_queue_historical_events(reset_db):
    from app.database import SessionLocal, engine
    from app.migrate import alembic_config, current_revision
    from app.models import Alert, DomainEvent, EventAlertQueue, PolicyRule

    command.upgrade(alembic_config(), PHASE3A_HEAD)
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        user_id = conn.execute(
            text("INSERT INTO users (username, email, password_hash, role, is_active) VALUES ('keep3b', 'k3b@localhost', 'x', 'admin', true) RETURNING id")
        ).scalar_one()
        tenant_id = conn.execute(text("INSERT INTO tenants (name, notes) VALUES ('Keep 3B', '') RETURNING id")).scalar_one()
        site_id = conn.execute(
            text("INSERT INTO sites (tenant_id, name) VALUES (:t, 'Hartford') RETURNING id"),
            {"t": tenant_id},
        ).scalar_one()
        asset_id = conn.execute(
            text(
                """
                INSERT INTO assets (tenant_id, site_id, display_name, classification, description, lifecycle_state, disposition, criticality, is_expected, created_at, updated_at)
                VALUES (:t, :s, 'legacy-asset', 'Unknown', '', 'active', 'unreviewed', 'normal', false, :n, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "n": now},
        ).scalar_one()
        event_id = conn.execute(
            text(
                """
                INSERT INTO domain_events (event_type, tenant_id, site_id, asset_id, occurred_at, source, details, idempotence_key)
                VALUES ('new_asset', :t, :s, :a, :n, 'scanner', '{}'::jsonb, 'legacy-new-asset-1')
                RETURNING id
                """
            ),
            {"t": tenant_id, "s": site_id, "a": asset_id, "n": now},
        ).scalar_one()
        alert_id = conn.execute(
            text(
                """
                INSERT INTO alerts (tenant_id, type, title, body, is_acknowledged, created_at)
                VALUES (:t, 'new_device', 'Legacy new device', 'historical', false, :n)
                RETURNING id
                """
            ),
            {"t": tenant_id, "n": now},
        ).scalar_one()
        conn.execute(
            text(
                """
                INSERT INTO policy_rules (name, description, category, scope_type, priority, enabled, conditions, actions, revision)
                VALUES ('Keep handling', '', 'asset_handling', 'global', 1, true, '[]'::jsonb, '{"classification":"Desktop"}'::jsonb, 1)
                """
            )
        )
        conn.execute(
            text("INSERT INTO audit_logs (actor_user_id, actor_username, action, object_type, details) VALUES (:u, 'keep3b', 'login', 'user', '{}'::jsonb)"),
            {"u": user_id},
        )

    command.upgrade(alembic_config(), PHASE3B_HEAD)
    assert current_revision() == PHASE3B_HEAD
    db = SessionLocal()
    try:
        assert db.get(DomainEvent, event_id).event_type == "new_asset"
        legacy = db.get(Alert, alert_id)
        assert legacy is not None
        assert legacy.type == "new_device"
        assert legacy.domain_event_id is None
        assert db.query(EventAlertQueue).count() == 0
        assert db.query(PolicyRule).filter(PolicyRule.category == "asset_handling").count() == 1
    finally:
        db.close()

    command.downgrade(alembic_config(), PHASE3A_HEAD)
    assert current_revision() == PHASE3A_HEAD
    command.upgrade(alembic_config(), PHASE3B_HEAD)


@requires_postgres
def test_downgrade_refuses_populated_phase3b_history(reset_db):
    from app.database import SessionLocal
    from app.migrate import alembic_config, apply_schema
    from app.models import DomainEvent, EventAlertQueue

    apply_schema()
    db = SessionLocal()
    try:
        event = DomainEvent(
            event_type="new_asset",
            tenant_id=None,
            occurred_at=datetime.now(timezone.utc),
            source="manual",
            details={},
            idempotence_key="downgrade-guard-event",
        )
        db.add(event)
        db.flush()
        db.add(EventAlertQueue(domain_event_id=event.id))
        db.commit()
    finally:
        db.close()
    try:
        command.downgrade(alembic_config(), PHASE3A_HEAD)
    except (CommandError, RuntimeError) as exc:
        assert "Refusing to downgrade 0013_event_alert_engine" in str(exc)
        return
    raise AssertionError("populated 0013 downgrade must refuse")


@requires_postgres
def test_empty_phase3b_downgrade_is_allowed(reset_db):
    from app.migrate import alembic_config, apply_schema, current_revision

    apply_schema()
    command.downgrade(alembic_config(), PHASE3A_HEAD)
    assert current_revision() == PHASE3A_HEAD


@requires_postgres
def test_domain_event_emission_idempotence_and_new_types(reset_db):
    from app.database import SessionLocal
    from app.events import (
        emit_asset_disposition_changed,
        emit_domain_event,
        emit_new_asset,
        emit_policy_changed,
        emit_scan_failed,
        emit_treatment_created,
        emit_treatment_expired,
    )
    from app.migrate import apply_schema
    from app.models import (
        EVENT_NEW_ASSET,
        Asset,
        DomainEvent,
        EventAlertQueue,
        FindingTreatment,
        PolicyRule,
        Scan,
        ScanJob,
        Tenant,
    )

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Acme", notes="")
        db.add(tenant)
        db.flush()
        from app.models import Site

        site = Site(tenant_id=tenant.id, name="Hartford")
        db.add(site)
        db.flush()
        asset = Asset(
            tenant_id=tenant.id,
            site_id=site.id,
            display_name="srv1",
            classification="Unknown",
            lifecycle_state="active",
            disposition="unreviewed",
            criticality="normal",
            first_seen=datetime.now(timezone.utc),
        )
        db.add(asset)
        db.flush()
        first = emit_new_asset(db, asset)
        second = emit_new_asset(db, asset)
        assert first.id == second.id
        assert db.query(DomainEvent).filter(DomainEvent.event_type == EVENT_NEW_ASSET).count() == 1
        assert db.query(EventAlertQueue).filter(EventAlertQueue.domain_event_id == first.id).count() == 1
        assert emit_asset_disposition_changed(db, asset, previous="unreviewed", new="unreviewed", source="manual") is None
        changed = emit_asset_disposition_changed(db, asset, previous="unreviewed", new="approved", source="manual")
        assert changed is not None and changed[1] is True
        assert emit_asset_disposition_changed(db, asset, previous="unreviewed", new="approved", source="manual")[1] is False

        scan = Scan(tenant_id=tenant.id, name="s", scope="wan", profile="discovery")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        db.add(job)
        db.flush()
        failed, created = emit_scan_failed(db, job, reason="tool failed")
        assert created is True
        assert emit_scan_failed(db, job, reason="tool failed again")[1] is False

        from app.models import AssetFinding, Vulnerability

        vuln = Vulnerability(canonical_key="cve:CVE-2024-1", cve_id="CVE-2024-1", title="x")
        db.add(vuln)
        db.flush()
        finding = AssetFinding(
            tenant_id=tenant.id,
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            technical_state="open",
            treatment_state="unaddressed",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.flush()
        treatment = FindingTreatment(
            tenant_id=tenant.id,
            asset_finding_id=finding.id,
            treatment_type="mitigated",
            status="active",
            rationale="ok",
        )
        db.add(treatment)
        db.flush()
        assert emit_treatment_created(db, treatment, finding)[1] is True
        assert emit_treatment_created(db, treatment, finding)[1] is False
        assert emit_treatment_expired(db, treatment, finding)[1] is True
        assert emit_treatment_expired(db, treatment, finding)[1] is False

        rule = PolicyRule(
            name="r",
            category="alerting",
            scope_type="global",
            priority=1,
            enabled=True,
            conditions=[{"field": "event_type", "op": "equals", "value": "new_asset"}],
            actions={"dashboard": True},
            revision=2,
        )
        db.add(rule)
        db.flush()
        assert emit_policy_changed(db, rule)[1] is True
        assert emit_policy_changed(db, rule)[1] is False
        db.commit()
    finally:
        db.close()


@requires_postgres
def test_legacy_cutover_new_asset_and_agent_mismatch(reset_db):
    from app.database import SessionLocal
    from app.events import emit_agent_identity_mismatch
    from app.inventory import upsert_devices
    from app.migrate import apply_schema
    from app.models import Alert, AlertDelivery, DomainEvent, Tenant
    from app.schemas import DeviceReport
    from tests.test_phase1c import _job

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Cutover", notes="")
        db.add(tenant)
        db.flush()
        created, devices = upsert_devices(
            db,
            tenant.id,
            _job(db, tenant.id, scope="wan"),
            [DeviceReport(ip="203.0.113.10", scope="wan", hostname="edge01")],
        )
        assert created == 1
        assert db.query(Alert).filter(Alert.type == "new_device").count() == 0
        events = db.query(DomainEvent).filter(DomainEvent.event_type == "new_asset").all()
        assert len(events) == 1
        _route(db)
        alerts = db.query(Alert).filter(Alert.type == "new_asset").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        assert alerts[0].dashboard_visible is True
        emails = db.query(AlertDelivery).filter(AlertDelivery.channel == "email").all()
        assert len(emails) == 1
        assert emails[0].payload_snapshot.get("mode") == "staff"

        from app.models import Agent, Site

        site = Site(tenant_id=tenant.id, name="Site")
        db.add(site)
        db.flush()
        agent = Agent(tenant_id=tenant.id, site_id=site.id, name="A1", uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", status="approved")
        db.add(agent)
        db.flush()
        emit_agent_identity_mismatch(db, agent, reason="key mismatch", source_ip="10.1.1.8")
        details = db.query(DomainEvent).filter(DomainEvent.event_type == "agent_identity_mismatch").one().details
        assert "enrollment_secret" not in details
        assert "private_key" not in str(details)
        _route(db)
        mismatch = db.query(Alert).filter(Alert.type == "agent_identity_mismatch").one()
        assert mismatch.severity == "critical"
        admin_mail = (
            db.query(AlertDelivery)
            .filter(AlertDelivery.alert_id == mismatch.id, AlertDelivery.channel == "email")
            .one()
        )
        assert admin_mail.payload_snapshot.get("mode") == "admins"
        db.commit()
    finally:
        db.close()


@requires_postgres
def test_alert_policy_precedence_and_authorization(reset_db):
    from app.database import SessionLocal
    from app.events import emit_new_asset
    from app.migrate import apply_schema
    from app.models import Alert, AlertEventRoute, Asset, DomainEvent

    apply_schema()
    with _client() as client:
        admin = _login(client)
        user = _create_staff(client, admin, "tech", "user")
        viewer = _create_staff(client, admin, "audit", "viewer")
        world = _world(client, admin)
        tenant_id = world["tenant"]["id"]
        db = SessionLocal()
        try:
            assert db.query(DomainEvent).filter(DomainEvent.event_type == "wan_target_changed").count() >= 1
        finally:
            db.close()
        site_id = world["site"]["id"]
        net_id = world["net1"]["id"]
        assert _policy(client, viewer).status_code == 403
        assert _policy(client, user, scope_type="global").status_code == 403
        scoped = _policy(
            client,
            user,
            scope_type="site",
            tenant_id=tenant_id,
            site_id=site_id,
            actions={"severity": "high"},
        )
        assert scoped.status_code == 200, scoped.text
        patch = client.patch(
            f"/api/policies/{scoped.json()['id']}",
            headers=_headers(user),
            json={"scope_type": "global", "tenant_id": None, "site_id": None, "network_id": None},
        )
        assert patch.status_code == 403
        assert _policy(
            client,
            admin,
            name="Global new asset",
            priority=100,
            actions={"severity": "medium", "dashboard": True, "email": "staff", "suppress_for_minutes": 60},
        ).status_code == 200
        assert _policy(
            client,
            user,
            name="Hartford high",
            scope_type="site",
            tenant_id=tenant_id,
            site_id=site_id,
            priority=100,
            actions={"severity": "high"},
        ).status_code == 200
        assert _policy(
            client,
            user,
            name="LAN email off",
            scope_type="network",
            tenant_id=tenant_id,
            site_id=site_id,
            network_id=net_id,
            priority=50,
            conditions=[
                {"field": "event_type", "op": "equals", "value": "new_asset"},
                {"field": "classification", "op": "equals", "value": "Unknown"},
            ],
            actions={"email": "off"},
        ).status_code == 200
        bad = _policy(client, admin, conditions=[{"field": "event_type", "op": "equals", "value": "not_a_type"}])
        assert bad.status_code == 400
        no_event = _policy(client, admin, name="no event", conditions=[{"field": "criticality", "op": "equals", "value": "high"}])
        assert no_event.status_code == 400
        expr = _policy(client, admin, conditions=[{"field": "event_type", "op": "equals", "value": "new_asset", "expr": "1==1"}])
        assert expr.status_code in {400, 422}
        other = client.post("/api/tenants", headers=_headers(admin), json={"name": "Other", "notes": ""}).json()
        cross = _policy(client, user, scope_type="site", tenant_id=other["id"], site_id=site_id, actions={"email": "off"})
        assert cross.status_code in {400, 404}

        db = SessionLocal()
        try:
            from app.models import Asset as AssetModel

            asset = AssetModel(
                tenant_id=tenant_id,
                site_id=site_id,
                display_name="unknown-lan",
                classification="Unknown",
                lifecycle_state="active",
                disposition="unreviewed",
                criticality="normal",
                first_seen=datetime.now(timezone.utc),
            )
            db.add(asset)
            db.flush()
            emit_new_asset(db, asset, network_id=net_id)
            _route(db)
            alert = db.query(Alert).filter(Alert.asset_id == asset.id).one()
            assert alert.severity == "high"
            route = db.query(AlertEventRoute).filter(AlertEventRoute.alert_id == alert.id).one()
            assert route.effective_actions["severity"] == "high"
            assert route.effective_actions["dashboard"] is True
            assert route.effective_actions["email"] == "off"
            assert route.effective_actions["suppress_for_minutes"] == 60
            db.commit()
        finally:
            db.close()


@requires_postgres
def test_system_defaults_suppression_and_ack_behavior(reset_db):
    from app.database import SessionLocal
    from app.events import emit_domain_event, emit_new_asset
    from app.migrate import apply_schema
    from app.models import Alert, AlertEventRoute, AlertDelivery, Asset, DomainEvent, Site, Tenant

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Supp", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        a1 = Asset(tenant_id=tenant.id, site_id=site.id, display_name="one", classification="Unknown", first_seen=datetime.now(timezone.utc))
        a2 = Asset(tenant_id=tenant.id, site_id=site.id, display_name="two", classification="Unknown", first_seen=datetime.now(timezone.utc))
        db.add_all([a1, a2])
        db.flush()
        ev1, _ = emit_domain_event(
            db,
            event_type="asset_became_inactive",
            tenant_id=tenant.id,
            site_id=site.id,
            asset_id=a1.id,
            idempotence_key="inactive-1",
            details={"last_seen": "x"},
            source="scheduler",
        )
        _route(db)
        assert db.query(Alert).filter(Alert.domain_event_id == ev1.id).count() == 0
        assert db.query(AlertEventRoute).filter(AlertEventRoute.domain_event_id == ev1.id).one().routing_result == "no_notification"

        from app.models import PolicyRule

        db.add(
            PolicyRule(
                name="suppress window",
                category="alerting",
                scope_type="global",
                priority=10,
                enabled=True,
                conditions=[{"field": "event_type", "op": "equals", "value": "new_asset"}],
                actions={"dashboard": True, "email": "off", "suppress_for_minutes": 60, "severity": "high"},
                revision=1,
            )
        )
        db.flush()
        first = emit_new_asset(db, a1)
        _route(db)
        open_alerts = db.query(Alert).filter(Alert.asset_id == a1.id, Alert.type == "new_asset").all()
        assert len(open_alerts) == 1
        emit_domain_event(
            db,
            event_type="new_asset",
            tenant_id=tenant.id,
            site_id=site.id,
            asset_id=a1.id,
            idempotence_key="new-asset-repeat-window",
            details={"display_name": "one"},
        )
        _route(db)
        again = db.query(Alert).filter(Alert.asset_id == a1.id, Alert.type == "new_asset").all()
        assert len(again) == 1
        assert again[0].occurrence_count == 2
        assert db.query(DomainEvent).filter(DomainEvent.asset_id == a1.id, DomainEvent.event_type == "new_asset").count() == 2
        emit_new_asset(db, a2)
        _route(db)
        assert db.query(Alert).filter(Alert.asset_id == a2.id, Alert.type == "new_asset").count() == 1
        again[0].is_acknowledged = True
        again[0].acknowledged_at = datetime.now(timezone.utc)
        db.flush()
        emit_domain_event(
            db,
            event_type="new_asset",
            tenant_id=tenant.id,
            site_id=site.id,
            asset_id=a1.id,
            idempotence_key="new-asset-after-ack",
            details={"display_name": "one"},
        )
        _route(db)
        assert db.query(Alert).filter(Alert.asset_id == a1.id, Alert.type == "new_asset").count() == 2
        _route(db)
        assert db.query(Alert).filter(Alert.asset_id == a1.id, Alert.type == "new_asset").count() == 2
        db.commit()
    finally:
        db.close()


@requires_postgres
def test_email_and_webhook_delivery_mocked(reset_db):
    from app.alert_engine import WebhookDeliveryError
    from app.database import SessionLocal
    from app.emailer import MailDeliveryError, MailResult
    from app.events import emit_new_asset
    from app.migrate import apply_schema
    from app.models import Alert, AlertDelivery, Asset, PolicyRule, Site, Tenant

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Mail", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        asset = Asset(tenant_id=tenant.id, site_id=site.id, display_name="n1", classification="Unknown", first_seen=datetime.now(timezone.utc))
        db.add(asset)
        db.flush()
        db.add(
            PolicyRule(
                name="wh",
                category="alerting",
                scope_type="global",
                priority=1,
                enabled=True,
                conditions=[{"field": "event_type", "op": "equals", "value": "new_asset"}],
                actions={
                    "dashboard": True,
                    "email": "staff",
                    "webhook": {"enabled": True, "url": "https://hooks.example.test/alert"},
                    "severity": "high",
                },
                revision=1,
            )
        )
        db.flush()
        emit_new_asset(db, asset)
        _route(db)
        alert = db.query(Alert).filter(Alert.asset_id == asset.id).one()
        assert db.query(AlertDelivery).count() == 2
        db.commit()

        calls = []

        def webhook_ok(url, payload):
            calls.append((url, payload))
            assert "enrollment_secret" not in str(payload)
            assert payload["alert_id"] == alert.id
            return 200

        _deliver(db, webhook_post=webhook_ok, mail_send=lambda *_a, **_k: MailResult(ok=True))
        db2 = SessionLocal()
        try:
            rows = {row.channel: row for row in db2.query(AlertDelivery).all()}
            assert rows["email"].status == "sent"
            assert rows["webhook"].status == "sent"
            assert db2.get(Alert, alert.id) is not None
        finally:
            db2.close()

        fail_asset = Asset(tenant_id=tenant.id, site_id=site.id, display_name="n2", classification="Unknown", first_seen=datetime.now(timezone.utc))
        db.add(fail_asset)
        db.flush()
        emit_new_asset(db, fail_asset)
        _route(db)
        db.commit()

        def webhook_500(url, payload):
            raise WebhookDeliveryError("Webhook HTTP 500", status_code=500)

        _deliver(
            db,
            webhook_post=webhook_500,
            mail_send=lambda *_a, **_k: (_ for _ in ()).throw(MailDeliveryError("smtp down")),
        )
        db3 = SessionLocal()
        try:
            retry_rows = db3.query(AlertDelivery).filter(AlertDelivery.alert_id != alert.id).all()
            assert retry_rows
            assert all(row.status in {"pending", "failed"} for row in retry_rows)
            assert db3.query(Alert).filter(Alert.asset_id == fail_asset.id).count() == 1
        finally:
            db3.close()
    finally:
        db.close()


@requires_postgres
def test_webhook_validation_and_alert_api(reset_db):
    from app.database import SessionLocal
    from app.events import emit_new_asset
    from app.migrate import apply_schema
    from app.models import Alert, Asset, AuditLog, Site, Tenant

    apply_schema()
    with _client() as client:
        admin = _login(client)
        viewer = _create_staff(client, admin, "look", "viewer")
        user = _create_staff(client, admin, "ops", "user")
        assert _policy(
            client,
            admin,
            actions={"webhook": {"enabled": True, "url": "ftp://evil"}},
        ).status_code == 400
        assert _policy(
            client,
            admin,
            actions={"webhook": {"enabled": True, "url": "https://user:pass@hooks.test/x"}},
        ).status_code == 400
        db = SessionLocal()
        try:
            tenant = Tenant(name="API", notes="")
            db.add(tenant)
            db.flush()
            site = Site(tenant_id=tenant.id, name="HQ")
            db.add(site)
            db.flush()
            asset = Asset(tenant_id=tenant.id, site_id=site.id, display_name="api", classification="Unknown", first_seen=datetime.now(timezone.utc))
            db.add(asset)
            db.flush()
            event = emit_new_asset(db, asset)
            _route(db)
            db.commit()
            event_id = event.id
            alert_id = db.query(Alert).filter(Alert.asset_id == asset.id).one().id
        finally:
            db.close()
        listed = client.get("/api/alerts?open_only=true&event_type=new_asset&severity=high", headers=_headers(viewer))
        assert listed.status_code == 200
        assert any(row["id"] == alert_id for row in listed.json())
        detail = client.get(f"/api/alerts/{alert_id}", headers=_headers(viewer))
        assert detail.status_code == 200
        assert detail.json()["source_event"]["id"] == event_id
        assert detail.json()["policy_explanation"]
        assert client.post(f"/api/alerts/{alert_id}/ack", headers=_headers(viewer)).status_code == 403
        ack = client.post(f"/api/alerts/{alert_id}/ack", headers=_headers(user))
        assert ack.status_code == 200
        again = client.post(f"/api/alerts/{alert_id}/ack", headers=_headers(user))
        assert again.status_code == 200
        db = SessionLocal()
        try:
            audits = db.query(AuditLog).filter(AuditLog.action == "alert.acknowledged").all()
            assert len(audits) == 1
        finally:
            db.close()
        eval_resp = client.get(f"/api/events/{event_id}/alert-policy-evaluation", headers=_headers(viewer))
        assert eval_resp.status_code == 200
        body = eval_resp.json()
        assert body["effective"]["email"] == "staff"
        assert body["actions"]["email"]["source"] == "system_default"
        db = SessionLocal()
        try:
            from app.models import Alert, AlertDelivery, EventAlertQueue

            assert db.query(Alert).count() == 1
            assert db.query(AlertDelivery).count() >= 1
        finally:
            db.close()
        assert client.delete(f"/api/alerts/{alert_id}", headers=_headers(admin)).status_code == 405


@requires_postgres
def test_webhook_permanent_4xx_and_smtp_unconfigured(reset_db):
    from app.alert_engine import WebhookDeliveryError
    from app.database import SessionLocal
    from app.emailer import MailResult
    from app.events import emit_new_asset
    from app.migrate import apply_schema
    from app.models import Alert, AlertDelivery, Asset, PolicyRule, Site, Tenant

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Perm", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        asset = Asset(tenant_id=tenant.id, site_id=site.id, display_name="p1", classification="Unknown", first_seen=datetime.now(timezone.utc))
        db.add(asset)
        db.flush()
        db.add(
            PolicyRule(
                name="perm",
                category="alerting",
                scope_type="global",
                priority=1,
                enabled=True,
                conditions=[{"field": "event_type", "op": "equals", "value": "new_asset"}],
                actions={
                    "dashboard": True,
                    "email": "staff",
                    "webhook": {"enabled": True, "url": "https://hooks.example.test/x"},
                    "severity": "low",
                },
                revision=1,
            )
        )
        emit_new_asset(db, asset)
        _route(db)
        db.commit()
        _deliver(
            db,
            webhook_post=lambda *_a, **_k: (_ for _ in ()).throw(
                WebhookDeliveryError("Webhook HTTP 400", status_code=400, permanent=True)
            ),
            mail_send=lambda *_a, **_k: MailResult(ok=False, error="SMTP not configured", permanent=True),
        )
        db2 = SessionLocal()
        try:
            rows = {row.channel: row for row in db2.query(AlertDelivery).all()}
            assert rows["webhook"].status == "failed"
            assert rows["email"].status == "failed"
            assert db2.query(Alert).count() == 1
        finally:
            db2.close()
    finally:
        db.close()


@requires_postgres
def test_scan_failed_transition_and_policy_change_events(reset_db):
    from app.database import SessionLocal
    from app.jobs import fail_job, transition_job_to_failed
    from app.migrate import apply_schema
    from app.models import DomainEvent, Scan, ScanJob, Tenant

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Fail", notes="")
        db.add(tenant)
        db.flush()
        scan = Scan(tenant_id=tenant.id, name="s", scope="wan", profile="discovery")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_id=scan.id, tenant_id=tenant.id, status="running")
        db.add(job)
        db.flush()
        assert transition_job_to_failed(db, job, "boom") is True
        assert db.query(DomainEvent).filter(DomainEvent.event_type == "scan_failed").count() == 1
        assert transition_job_to_failed(db, job, "already") is False
        assert db.query(DomainEvent).filter(DomainEvent.event_type == "scan_failed").count() == 1
        db.commit()
    finally:
        db.close()
    with _client() as client:
        admin = _login(client)
        created = _policy(client, admin, name="chg", actions={"dashboard": True})
        assert created.status_code == 200
        policy_id = created.json()["id"]
        client.post(f"/api/policies/{policy_id}/disable", headers=_headers(admin))
        db = SessionLocal()
        try:
            events = db.query(DomainEvent).filter(DomainEvent.event_type == "policy_changed").all()
            assert len(events) >= 2
            keys = {row.idempotence_key for row in events}
            assert len(keys) == len(events)
        finally:
            db.close()


@requires_postgres
def test_routing_and_list_query_counts_are_bounded(reset_db):
    from app.database import SessionLocal, engine
    from app.events import emit_new_asset
    from app.migrate import apply_schema
    from app.models import Asset, PolicyRule, Site, Tenant

    apply_schema()
    db = SessionLocal()
    try:
        tenant = Tenant(name="Perf", notes="")
        db.add(tenant)
        db.flush()
        site = Site(tenant_id=tenant.id, name="HQ")
        db.add(site)
        db.flush()
        for scope in ("global",):
            db.add(
                PolicyRule(
                    name=f"{scope}-alert",
                    category="alerting",
                    scope_type=scope,
                    priority=1,
                    enabled=True,
                    conditions=[{"field": "event_type", "op": "equals", "value": "new_asset"}],
                    actions={"dashboard": True, "email": "off", "severity": "low"},
                    revision=1,
                )
            )
        assets = []
        for idx in range(40):
            asset = Asset(
                tenant_id=tenant.id,
                site_id=site.id,
                display_name=f"h{idx}",
                classification="Unknown",
                first_seen=datetime.now(timezone.utc),
            )
            db.add(asset)
            assets.append(asset)
        db.flush()
        tenant_id = tenant.id
        for asset in assets:
            emit_new_asset(db, asset)
        db.commit()
        queries: list[str] = []

        def before_cursor(_conn, _cursor, statement, _params, _context, _executemany):
            queries.append(statement)

        listen_on = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        event.listen(listen_on, "before_cursor_execute", before_cursor)
        try:
            routed = _route(db)
            db.commit()
        finally:
            event.remove(listen_on, "before_cursor_execute", before_cursor)
        assert routed == 40
        policy_loads = [q for q in queries if "policy_rules" in q.lower()]
        assert len(policy_loads) <= 4
        db.close()
        queries.clear()
        with _client() as client:
            token = _login(client)
            event.listen(listen_on, "before_cursor_execute", before_cursor)
            try:
                response = client.get(f"/api/alerts?tenant_id={tenant_id}&open_only=true", headers=_headers(token))
                assert response.status_code == 200
                assert len(response.json()) == 40
            finally:
                event.remove(listen_on, "before_cursor_execute", before_cursor)
        assert len(queries) <= 16
    finally:
        db.close()
