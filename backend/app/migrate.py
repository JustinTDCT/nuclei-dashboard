"""Alembic-backed schema apply with pre-Alembic adoption.

Paths:
- Fresh database (no managed application tables or Phase 1A markers):
  alembic upgrade head.
- Recognized complete pre-Alembic Phase 0 schema (all Phase 0 tables,
  no post-baseline tables/columns, no alembic_version): run the
  retained compatibility helper, validate, stamp 0001_baseline, then
  upgrade head.
- Already-migrated database: alembic upgrade head.
- Partial, unknown, or unversioned post-baseline schema: fail closed.

Do not add future ALTER TABLE statements here. New schema changes are
Alembic revisions. ensure_columns() remains a Phase 0 safety net only.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from app.config import settings
from app.database import engine

log = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
BASELINE_REVISION = "0001_baseline"

# Complete Phase 0 table set. A recognized legacy install has all of these
# and none of the post-baseline markers.
APPLICATION_TABLES = frozenset(
    {
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
)
PHASE0_TABLES = APPLICATION_TABLES

# Managed after 0001. Presence without alembic_version is not a fresh DB
# and is not a pre-Alembic Phase 0 install.
POST_BASELINE_TABLES = frozenset(
    {
        "sites",
        "networks",
        "network_agents",
        "audit_logs",
    }
)
PHASE1A_MARKER_COLUMNS = {
    "agents": frozenset({"site_id"}),
    "subnets": frozenset({"site_id", "network_id"}),
}
MANAGED_TABLES = PHASE0_TABLES | POST_BASELINE_TABLES


class UnrecognizedSchemaError(RuntimeError):
    """Partial or unknown pre-Alembic schema; refuse to guess."""


def alembic_config() -> Config:
    if not ALEMBIC_INI.is_file():
        raise FileNotFoundError(f"Alembic config not found: {ALEMBIC_INI}")
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    return cfg


def current_revision() -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def head_revision() -> str:
    script = ScriptDirectory.from_config(alembic_config())
    head = script.get_current_head()
    if head is None:
        raise RuntimeError("Alembic script directory has no head revision")
    return head


def _column_names(inspector, table: str) -> set[str]:
    return {c["name"] for c in inspector.get_columns(table)}


def _post_baseline_markers(inspector, tables: set[str]) -> set[str]:
    markers = set(tables & POST_BASELINE_TABLES)
    for table, columns in PHASE1A_MARKER_COLUMNS.items():
        if table not in tables:
            continue
        present = _column_names(inspector, table) & columns
        markers.update(f"{table}.{name}" for name in present)
    return markers


def _validate_adopted_schema() -> None:
    inspector = inspect(engine)
    present = set(inspector.get_table_names())
    missing = PHASE0_TABLES - present
    if missing:
        raise UnrecognizedSchemaError(
            "Unrecognized/partial pre-Alembic schema: missing tables "
            + ", ".join(sorted(missing))
        )
    markers = _post_baseline_markers(inspector, present)
    if markers:
        raise UnrecognizedSchemaError(
            "Unrecognized/partial schema: post-baseline markers present without "
            "alembic_version: " + ", ".join(sorted(markers))
        )
    device_cols = _column_names(inspector, "devices")
    finding_cols = _column_names(inspector, "findings")
    missing_cols: list[str] = []
    if "hostname" not in device_cols:
        missing_cols.append("devices.hostname")
    if "description" not in device_cols:
        missing_cols.append("devices.description")
    if "hostname" not in finding_cols:
        missing_cols.append("findings.hostname")
    if missing_cols:
        raise UnrecognizedSchemaError(
            "Unrecognized/partial pre-Alembic schema: missing columns "
            + ", ".join(missing_cols)
        )


def apply_schema() -> str | None:
    """Bring the connected database to Alembic head. Returns the revision."""
    cfg = alembic_config()
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    app_tables = tables & PHASE0_TABLES
    managed = tables & MANAGED_TABLES
    markers = _post_baseline_markers(inspector, tables)

    if "alembic_version" in tables:
        log.info("Alembic: upgrading existing versioned database to head")
        command.upgrade(cfg, "head")
        engine.dispose()
        return current_revision()

    if not managed and not markers:
        log.info("Alembic: fresh database, upgrading to head")
        command.upgrade(cfg, "head")
        engine.dispose()
        return current_revision()

    if PHASE0_TABLES.issubset(tables) and not markers:
        from app.database import ensure_columns

        log.info(
            "Alembic: adopting pre-Alembic schema as %s (UTC stamp, non-destructive)",
            BASELINE_REVISION,
        )
        ensure_columns()
        _validate_adopted_schema()
        command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, "head")
        engine.dispose()
        return current_revision()

    found = ", ".join(sorted(managed | markers)) or ", ".join(sorted(app_tables))
    raise UnrecognizedSchemaError(
        "Unrecognized/partial pre-Alembic schema: found "
        + found
        + ". Refusing to stamp or upgrade."
    )
