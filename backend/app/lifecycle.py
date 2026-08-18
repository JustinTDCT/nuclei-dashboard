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
    from app.models import POLICY_CATEGORY_ASSET_INACTIVITY
    from app.policy import PolicyResolver, contexts_for_assets

    owns = db is None
    session = db or SessionLocal()
    try:
        moment = now or utcnow()
        min_cutoff = moment - timedelta(days=1)
        rows = (
            session.query(Asset)
            .filter(
                Asset.lifecycle_state == LIFECYCLE_ACTIVE,
                Asset.last_seen.isnot(None),
                Asset.last_seen < min_cutoff,
                Asset.first_seen.isnot(None),
                Asset.merged_into_asset_id.is_(None),
            )
            .order_by(Asset.id.asc())
            .all()
        )
        if not rows:
            if owns:
                session.commit()
            return 0
        resolver = PolicyResolver(session)
        contexts = contexts_for_assets(session, rows)
        changed = 0
        for asset in rows:
            result = resolver.evaluate(contexts[asset.id], POLICY_CATEGORY_ASSET_INACTIVITY)
            days = int(result.effective["inactive_after_days"])
            cutoff = moment - timedelta(days=days)
            if asset.last_seen is None or asset.last_seen >= cutoff:
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
