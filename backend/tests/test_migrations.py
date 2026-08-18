from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, Table, inspect, text
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = BACKEND_ROOT / "alembic" / "versions" / "0001_baseline_current_schema.py"


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


def test_baseline_revision_is_frozen_not_live_metadata():
    source = BASELINE_PATH.read_text()
    assert "from app.database import Base" not in source
    assert "import app.models" not in source
    assert "create_all" not in source
    assert "drop_all" not in source
    assert "op.create_table" in source
    assert 'op.create_table(\n        "users"' in source
    assert '"sites"' not in source
    assert '"assets"' not in source


@requires_postgres
def test_partial_pre_alembic_schema_fails_closed(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(80) NOT NULL
                );
                CREATE TABLE tenants (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL
                );
                CREATE TABLE devices (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL
                );
                """
            )
        )
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial pre-Alembic schema"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)
    assert "subnets" not in _tables(engine)


@requires_postgres
def test_compare_metadata_detects_unmigrated_model_table(reset_db):
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from app.database import Base, engine
    from app.migrate import apply_schema
    import app.models  # noqa: F401

    apply_schema()
    copied = MetaData()
    for table in Base.metadata.sorted_tables:
        table.to_metadata(copied)
    Table("sites", copied, Column("id", Integer, primary_key=True))
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), copied)
    assert diffs, "compare_metadata must report a model table that has no migration"


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
