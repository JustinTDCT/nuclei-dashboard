"""Alembic-backed schema apply with pre-Alembic adoption.

Paths:
- Fresh database (no application tables): alembic upgrade head.
- Existing current-schema database (tables, no alembic_version): run the
  retained compatibility helper, stamp 0001_baseline, then upgrade head.
- Already-migrated database: alembic upgrade head.

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

# Tables that identify a pre-Alembic install of the current application.
_PRE_ALEMBIC_TABLES = frozenset(
    {"users", "tenants", "agents", "devices", "findings", "scans", "settings"}
)


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


def apply_schema() -> str | None:
    """Bring the connected database to Alembic head. Returns the revision."""
    cfg = alembic_config()
    tables = set(inspect(engine).get_table_names())

    if "alembic_version" in tables:
        log.info("Alembic: upgrading existing versioned database to head")
        command.upgrade(cfg, "head")
        engine.dispose()
        return current_revision()

    if _PRE_ALEMBIC_TABLES.issubset(tables):
        from app.database import ensure_columns

        log.info(
            "Alembic: adopting pre-Alembic schema as %s (UTC stamp, non-destructive)",
            BASELINE_REVISION,
        )
        ensure_columns()
        command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, "head")
        engine.dispose()
        return current_revision()

    log.info("Alembic: fresh database, upgrading to head")
    command.upgrade(cfg, "head")
    engine.dispose()
    return current_revision()
