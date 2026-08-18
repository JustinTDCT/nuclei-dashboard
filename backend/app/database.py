from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def ensure_columns() -> None:
    """Legacy compatibility for pre-Alembic databases.

    Frozen for Phase 0. Future schema changes must be Alembic revisions,
    not new statements in this function.
    """
    inspector = inspect(engine)
    if "devices" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("devices")}
    statements = []
    if "hostname" not in cols:
        statements.append("ALTER TABLE devices ADD COLUMN hostname VARCHAR(255) DEFAULT ''")
    if "description" not in cols:
        statements.append("ALTER TABLE devices ADD COLUMN description TEXT DEFAULT ''")
    if "findings" in inspector.get_table_names():
        finding_cols = {c["name"] for c in inspector.get_columns("findings")}
        if "hostname" not in finding_cols:
            statements.append("ALTER TABLE findings ADD COLUMN hostname VARCHAR(255) DEFAULT ''")
    if statements:
        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
    _migrate_device_identity()
    with engine.begin() as conn:
        if "findings" in inspect(engine).get_table_names() and "hostname" in {
            c["name"] for c in inspect(engine).get_columns("findings")
        }:
            conn.execute(
                text(
                    "UPDATE findings f SET hostname = d.hostname "
                    "FROM devices d WHERE f.device_id = d.id "
                    "AND (f.hostname IS NULL OR btrim(f.hostname) = '')"
                )
            )


def _migrate_device_identity() -> None:
    with engine.begin() as conn:
        conn.execute(text("UPDATE devices SET hostname = ip WHERE hostname IS NULL OR btrim(hostname) = ''"))
        conn.execute(text("UPDATE devices SET hostname = lower(rtrim(hostname, '.')) WHERE hostname IS NOT NULL"))
        dupes = conn.execute(
            text(
                "SELECT tenant_id, hostname, scope FROM devices "
                "GROUP BY tenant_id, hostname, scope HAVING count(*) > 1"
            )
        ).fetchall()
        for tenant_id, hostname, scope in dupes:
            rows = conn.execute(
                text(
                    "SELECT id FROM devices "
                    "WHERE tenant_id = :t AND hostname = :h AND scope = :s "
                    "ORDER BY last_seen DESC NULLS LAST, id DESC"
                ),
                {"t": tenant_id, "h": hostname, "s": scope},
            ).fetchall()
            keep = rows[0][0]
            for (donor_id,) in rows[1:]:
                conn.execute(text("UPDATE findings SET device_id = :k WHERE device_id = :d"), {"k": keep, "d": donor_id})
                conn.execute(text("UPDATE alerts SET device_id = :k WHERE device_id = :d"), {"k": keep, "d": donor_id})
                conn.execute(text("DELETE FROM devices WHERE id = :d"), {"d": donor_id})
        conn.execute(text("ALTER TABLE devices DROP CONSTRAINT IF EXISTS uq_device_tenant_ip_scope"))
        exists = conn.execute(
            text("SELECT 1 FROM pg_constraint WHERE conname = 'uq_device_tenant_hostname_scope'")
        ).scalar()
        if not exists:
            conn.execute(
                text(
                    "ALTER TABLE devices ADD CONSTRAINT uq_device_tenant_hostname_scope "
                    "UNIQUE (tenant_id, hostname, scope)"
                )
            )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
