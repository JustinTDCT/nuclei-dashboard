from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres


def _tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _columns(engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


@requires_postgres
def test_fresh_database_reaches_head(reset_db):
    from app.database import engine
    from app.migrate import apply_schema, current_revision, head_revision

    assert "users" not in _tables(engine)
    revision = apply_schema()
    assert revision == head_revision() == current_revision() == "0001_baseline"
    expected = {
        "alembic_version",
        "users",
        "tenants",
        "subnets",
        "agents",
        "scans",
        "scan_jobs",
        "devices",
        "findings",
        "alerts",
        "settings",
    }
    assert expected.issubset(_tables(engine))
    assert "sites" not in _tables(engine)
    assert "assets" not in _tables(engine)


@requires_postgres
def test_existing_schema_adoption_preserves_data(reset_db):
    from app.database import Base, SessionLocal, engine, ensure_columns
    from app.migrate import apply_schema, current_revision, head_revision
    from app.models import Agent, Device, Finding, Tenant, User

    Base.metadata.create_all(bind=engine)
    ensure_columns()
    assert "alembic_version" not in _tables(engine)

    db = SessionLocal()
    try:
        user = User(
            username="keep-admin",
            email="keep@localhost",
            password_hash="not-a-real-hash",
            role="admin",
            is_active=True,
        )
        tenant = Tenant(name="Keep Tenant", notes="representative")
        db.add_all([user, tenant])
        db.flush()
        agent = Agent(
            tenant_id=tenant.id,
            name="Keep Agent",
            uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            enrollment_secret="keep-enrollment-secret",
            status="pending_enrollment",
        )
        device = Device(
            tenant_id=tenant.id,
            ip="10.1.2.3",
            hostname="keep-host",
            scope="lan",
            status="known",
            classification="Server",
            description="must survive",
            ports=[{"port": 443, "protocol": "tcp"}],
        )
        db.add_all([agent, device])
        db.flush()
        finding = Finding(
            tenant_id=tenant.id,
            device_id=device.id,
            template_id="keep-template",
            name="Keep finding",
            severity="high",
            hostname="keep-host",
            host="10.1.2.3",
            matched_at="https://10.1.2.3",
            found_at=datetime.now(timezone.utc),
            raw_json={"id": "keep"},
        )
        db.add(finding)
        db.commit()
        ids = {
            "user": user.id,
            "tenant": tenant.id,
            "agent": agent.id,
            "device": device.id,
            "finding": finding.id,
        }
    finally:
        db.close()

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == "0001_baseline"

    db = SessionLocal()
    try:
        kept_user = db.get(User, ids["user"])
        kept_tenant = db.get(Tenant, ids["tenant"])
        kept_agent = db.get(Agent, ids["agent"])
        kept_device = db.get(Device, ids["device"])
        kept_finding = db.get(Finding, ids["finding"])
        assert kept_user is not None and kept_user.username == "keep-admin"
        assert kept_tenant is not None and kept_tenant.name == "Keep Tenant"
        assert kept_agent is not None
        assert kept_agent.enrollment_secret == "keep-enrollment-secret"
        assert kept_agent.uuid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert kept_device is not None
        assert kept_device.hostname == "keep-host"
        assert kept_device.description == "must survive"
        assert kept_device.ports == [{"port": 443, "protocol": "tcp"}]
        assert kept_finding is not None
        assert kept_finding.template_id == "keep-template"
        assert kept_finding.raw_json == {"id": "keep"}
    finally:
        db.close()


@requires_postgres
def test_apply_schema_and_ensure_columns_are_idempotent(reset_db):
    from app.database import engine, ensure_columns
    from app.migrate import apply_schema, current_revision, head_revision

    first = apply_schema()
    ensure_columns()
    second = apply_schema()
    ensure_columns()
    apply_schema()
    assert first == second == current_revision() == head_revision()
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
    assert [r[0] for r in rows] == [head_revision()]


@requires_postgres
def test_head_matches_current_models(reset_db):
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from app.database import Base, engine
    from app.migrate import apply_schema
    import app.models  # noqa: F401

    apply_schema()
    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        diffs = compare_metadata(context, Base.metadata)
    assert diffs == []
    assert "hostname" in _columns(engine, "devices")
    assert "description" in _columns(engine, "devices")
    assert "hostname" in _columns(engine, "findings")


@requires_postgres
def test_legacy_compatibility_restores_missing_columns_without_dropping_rows(reset_db):
    from app.database import Base, SessionLocal, engine, ensure_columns
    from app.migrate import apply_schema
    from app.models import Device, Tenant

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        tenant = Tenant(name="Compat Tenant")
        db.add(tenant)
        db.flush()
        db.add(
            Device(
                tenant_id=tenant.id,
                ip="10.9.9.9",
                hostname="compat-host",
                scope="wan",
                description="before-drop",
            )
        )
        db.commit()
        tenant_id = tenant.id
    finally:
        db.close()

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS hostname"))
        conn.execute(text("ALTER TABLE devices DROP COLUMN IF EXISTS description"))

    revision = apply_schema()
    assert revision == "0001_baseline"
    assert "hostname" in _columns(engine, "findings")
    assert "description" in _columns(engine, "devices")

    db: Session = SessionLocal()
    try:
        device = db.query(Device).filter(Device.tenant_id == tenant_id).one()
        assert device.hostname == "compat-host"
        assert device.ip == "10.9.9.9"
    finally:
        db.close()
    ensure_columns()
