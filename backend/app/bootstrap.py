"""Serialize API process bootstrap across replicas.

``apply_schema()`` may call ``engine.dispose()``. The advisory lock therefore
lives on a dedicated engine so dispose cannot drop the PostgreSQL session that
holds the lock. Distinct from ``scheduler.SCHEDULER_LEADER_LOCK_KEY``.
"""

from __future__ import annotations

from sqlalchemy import create_engine, text

from app.config import settings
from app.database import SessionLocal, ensure_columns
from app.migrate import apply_schema

# Distinct from scheduler.SCHEDULER_LEADER_LOCK_KEY (91304701).
API_BOOTSTRAP_LOCK_KEY = 91304702


def run_api_bootstrap() -> None:
    """Apply schema and seed once, even when two API processes start together."""
    from app.main import prepare_control_plane

    lock_engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
        isolation_level="AUTOCOMMIT",
    )
    conn = lock_engine.connect()
    try:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": API_BOOTSTRAP_LOCK_KEY})
        apply_schema()
        # Retained until existing-install adoption is proven. Do not add new ALTER TABLE here.
        ensure_columns()
        db = SessionLocal()
        try:
            prepare_control_plane(db)
        finally:
            db.close()
    finally:
        try:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": API_BOOTSTRAP_LOCK_KEY})
        finally:
            conn.close()
            lock_engine.dispose()
