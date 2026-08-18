"""Asset inactivity evaluation.

Uses the explicit Asset setting asset_inactive_days. Does not reuse
legacy Device stale_days, which still only marks Device.status.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.events import emit_asset_became_inactive
from app.models import LIFECYCLE_ACTIVE, LIFECYCLE_INACTIVE, Asset
from app.settings_store import get_settings

DEFAULT_ASSET_INACTIVE_DAYS = 30


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def asset_inactive_days(db: Session) -> int:
    raw = get_settings(db).get("asset_inactive_days")
    try:
        days = int(raw if raw is not None else DEFAULT_ASSET_INACTIVE_DAYS)
    except (TypeError, ValueError):
        days = DEFAULT_ASSET_INACTIVE_DAYS
    return max(1, days)


def mark_inactive_assets(db: Session | None = None, *, now: datetime | None = None) -> int:
    from app.database import SessionLocal

    owns = db is None
    session = db or SessionLocal()
    try:
        cutoff = (now or utcnow()) - timedelta(days=asset_inactive_days(session))
        rows = (
            session.query(Asset)
            .filter(
                Asset.lifecycle_state == LIFECYCLE_ACTIVE,
                Asset.last_seen.isnot(None),
                Asset.last_seen < cutoff,
                Asset.merged_into_asset_id.is_(None),
            )
            .all()
        )
        changed = 0
        for asset in rows:
            if asset.first_seen is None:
                continue
            previous = asset.lifecycle_state
            asset.lifecycle_state = LIFECYCLE_INACTIVE
            emit_asset_became_inactive(session, asset, last_seen=asset.last_seen)
            if previous != LIFECYCLE_INACTIVE:
                changed += 1
        if owns:
            session.commit()
        else:
            session.flush()
        return changed
    except Exception:
        if owns:
            session.rollback()
        raise
    finally:
        if owns:
            session.close()


__all__ = ["DEFAULT_ASSET_INACTIVE_DAYS", "asset_inactive_days", "mark_inactive_assets"]
