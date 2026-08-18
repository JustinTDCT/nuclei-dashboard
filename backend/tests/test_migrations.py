from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, Table, inspect, text
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = BACKEND_ROOT / "alembic" / "versions" / "0001_baseline_current_schema.py"
PHASE1A_REVISION = "0002_sites_networks"
PHASE1B_HEAD = "0004_asset_observation_integrity"
PHASE1C_HEAD = "0005_asset_correlation_lifecycle"
PHASE1B_TABLES = {
    "assets",
    "asset_identifiers",
    "asset_addresses",
    "asset_services",
    "asset_observations",
    "tags",
    "asset_tags",
    "site_tags",
    "network_tags",
}


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
    assert revision == head_revision() == current_revision() == PHASE1C_HEAD
    expected = {
        "alembic_version",
        "users",
        "tenants",
        "subnets",
        "sites",
        "networks",
        "network_agents",
        "audit_logs",
        "agents",
        "scans",
        "scan_jobs",
        "devices",
        "findings",
        "alerts",
        "settings",
    }
    assert expected.issubset(_tables(engine))
    assert PHASE1B_TABLES.issubset(_tables(engine))
    assert {"asset_correlation_decisions", "domain_events"}.issubset(_tables(engine))
    assert "asset_id" in _columns(engine, "devices")
    assert "site_id" in _columns(engine, "devices")
    assert "merged_into_asset_id" in _columns(engine, "assets")
    assert "validity" in _columns(engine, "asset_identifiers")


@requires_postgres
def test_existing_schema_adoption_preserves_data(reset_db):
    from alembic import command

    from app.database import SessionLocal, engine, ensure_columns
    from app.migrate import alembic_config, apply_schema, current_revision, head_revision
    from app.models import Agent, Device, Finding, Tenant, User

    command.upgrade(alembic_config(), "0001_baseline")
    ensure_columns()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    assert "alembic_version" not in _tables(engine)
    assert "sites" not in _tables(engine)

    with engine.begin() as conn:
        user_id = conn.execute(
            text(
                """
                INSERT INTO users (username, email, password_hash, role, is_active)
                VALUES ('keep-admin', 'keep@localhost', 'not-a-real-hash', 'admin', true)
                RETURNING id
                """
            )
        ).scalar_one()
        tenant_id = conn.execute(
            text("INSERT INTO tenants (name, notes) VALUES ('Keep Tenant', 'representative') RETURNING id")
        ).scalar_one()
        agent_id = conn.execute(
            text(
                """
                INSERT INTO agents (tenant_id, name, uuid, enrollment_secret, status)
                VALUES (:tid, 'Keep Agent', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                        'keep-enrollment-secret', 'pending_enrollment')
                RETURNING id
                """
            ),
            {"tid": tenant_id},
        ).scalar_one()
        device_id = conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports
                )
                VALUES (
                    :tid, '10.1.2.3', 'keep-host', 'lan', 'known', 'Server', 'must survive',
                    '', '', '', CAST(:ports AS jsonb)
                )
                RETURNING id
                """
            ),
            {"tid": tenant_id, "ports": '[{"port": 443, "protocol": "tcp"}]'},
        ).scalar_one()
        finding_id = conn.execute(
            text(
                """
                INSERT INTO findings (
                    tenant_id, device_id, template_id, name, severity, hostname, host,
                    matched_at, tags, found_at, raw_json
                )
                VALUES (
                    :tid, :did, 'keep-template', 'Keep finding', 'high', 'keep-host',
                    '10.1.2.3', 'https://10.1.2.3', '', :found, CAST(:raw AS jsonb)
                )
                RETURNING id
                """
            ),
            {
                "tid": tenant_id,
                "did": device_id,
                "found": datetime.now(timezone.utc),
                "raw": '{"id": "keep"}',
            },
        ).scalar_one()
        ids = {
            "user": user_id,
            "tenant": tenant_id,
            "agent": agent_id,
            "device": device_id,
            "finding": finding_id,
        }

    revision = apply_schema()
    assert revision == head_revision() == current_revision() == PHASE1C_HEAD

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
        assert kept_agent.site_id is not None
        assert kept_device is not None
        assert kept_device.asset_id is not None
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
    Table("unmigrated_probe", copied, Column("id", Integer, primary_key=True))
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
    from alembic import command

    from app.database import SessionLocal, engine, ensure_columns
    from app.migrate import alembic_config, apply_schema
    from app.models import Device

    command.upgrade(alembic_config(), "0001_baseline")
    with engine.begin() as conn:
        tenant_id = conn.execute(
            text("INSERT INTO tenants (name, notes) VALUES ('Compat Tenant', '') RETURNING id")
        ).scalar_one()
        conn.execute(
            text(
                """
                INSERT INTO devices (
                    tenant_id, ip, hostname, scope, status, classification, description,
                    auto_label, title, tech, ports
                )
                VALUES (
                    :tid, '10.9.9.9', 'compat-host', 'wan', 'new', 'Unknown', 'before-drop',
                    '', '', '', '[]'::jsonb
                )
                """
            ),
            {"tid": tenant_id},
        )
        conn.execute(text("DROP TABLE alembic_version"))

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE findings DROP COLUMN IF EXISTS hostname"))
        conn.execute(text("ALTER TABLE devices DROP COLUMN IF EXISTS description"))

    revision = apply_schema()
    assert revision == PHASE1C_HEAD
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


@requires_postgres
def test_unversioned_phase1a_tables_fail_closed(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    apply_schema()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    assert "sites" in _tables(engine)
    assert "alembic_version" not in _tables(engine)
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)


@requires_postgres
def test_unversioned_phase1a_marker_columns_fail_closed(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, alembic_config, apply_schema

    command.upgrade(alembic_config(), "0001_baseline")
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE agents ADD COLUMN site_id INTEGER"))
        conn.execute(text("ALTER TABLE subnets ADD COLUMN network_id INTEGER"))
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)
    assert "sites" not in _tables(engine)


@requires_postgres
def test_unversioned_sites_networks_only_is_not_fresh(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE sites (id SERIAL PRIMARY KEY, name VARCHAR(200) NOT NULL)"))
        conn.execute(text("CREATE TABLE networks (id SERIAL PRIMARY KEY, name VARCHAR(200) NOT NULL)"))
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)
    assert "users" not in _tables(engine)


@requires_postgres
def test_unversioned_phase1b_tables_fail_closed(reset_db):
    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, apply_schema

    apply_schema()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    assert "assets" in _tables(engine)
    assert "alembic_version" not in _tables(engine)
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)


@requires_postgres
def test_unversioned_phase1b_marker_columns_fail_closed(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, alembic_config, apply_schema

    command.upgrade(alembic_config(), PHASE1A_REVISION)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE devices ADD COLUMN asset_id INTEGER"))
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)
    assert "assets" not in _tables(engine)


@requires_postgres
def test_unversioned_phase1b_observation_key_fail_closed(reset_db):
    from alembic import command

    from app.database import engine
    from app.migrate import UnrecognizedSchemaError, alembic_config, apply_schema

    command.upgrade(alembic_config(), "0003_assets_observations")
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE asset_observations ADD COLUMN observation_key VARCHAR(64)"))
        conn.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    with pytest.raises(UnrecognizedSchemaError, match="Unrecognized/partial"):
        apply_schema()
    assert "alembic_version" not in _tables(engine)


def test_phase1a_and_baseline_revisions_remain_frozen():
    phase1a = (BACKEND_ROOT / "alembic" / "versions" / "0002_sites_networks.py").read_text()
    phase1b = (BACKEND_ROOT / "alembic" / "versions" / "0003_assets_observations.py").read_text()
    assert "from app.database import Base" not in phase1a
    assert "import app.models" not in phase1a
    assert '"assets"' not in phase1a
    assert "from app.database import Base" not in phase1b
    assert "import app.models" not in phase1b
    assert 'down_revision: str | None = "0002_sites_networks"' in phase1b
    phase1b_fix = (BACKEND_ROOT / "alembic" / "versions" / "0004_asset_observation_integrity.py").read_text()
    assert "from app.database import Base" not in phase1b_fix
    assert "import app.models" not in phase1b_fix
    assert 'down_revision: str | None = "0003_assets_observations"' in phase1b_fix
    phase1c = (BACKEND_ROOT / "alembic" / "versions" / "0005_asset_correlation_lifecycle.py").read_text()
    assert "from app.database import Base" not in phase1c
    assert "import app.models" not in phase1c
    assert 'down_revision: str | None = "0004_asset_observation_integrity"' in phase1c
