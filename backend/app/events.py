"""Minimal append-oriented domain events for Phase 1C.

Phase 3B owns alert routing, suppression, email/webhook/Teams policies.
This module only persists the Asset lifecycle events required now.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.assets import utcnow
from app.models import (
    EVENT_ASSET_BECAME_INACTIVE,
    EVENT_NEW_ASSET,
    EVENT_PREVIOUSLY_INACTIVE_RETURNED,
    EVENT_SCAN_MISSED_UNAVAILABLE_AGENT,
    SOURCE_SCANNER,
    DomainEvent,
)


def emit_domain_event(
    db: Session,
    *,
    event_type: str,
    tenant_id: int,
    site_id: int | None,
    asset_id: int | None,
    idempotence_key: str,
    details: dict[str, Any] | None = None,
    source: str = SOURCE_SCANNER,
    occurred_at: datetime | None = None,
) -> tuple[DomainEvent, bool]:
    existing = (
        db.query(DomainEvent)
        .filter(DomainEvent.idempotence_key == idempotence_key)
        .first()
    )
    if existing is not None:
        return existing, False
    row = DomainEvent(
        event_type=event_type,
        tenant_id=tenant_id,
        site_id=site_id,
        asset_id=asset_id,
        occurred_at=occurred_at or utcnow(),
        source=source,
        details=details or {},
        idempotence_key=idempotence_key,
    )
    db.add(row)
    db.flush()
    return row, True


def emit_new_asset(db: Session, asset, *, source: str = SOURCE_SCANNER) -> DomainEvent:
    event, _ = emit_domain_event(
        db,
        event_type=EVENT_NEW_ASSET,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        asset_id=asset.id,
        idempotence_key=f"new_asset:{asset.id}",
        details={"display_name": asset.display_name},
        source=source,
        occurred_at=asset.first_seen or utcnow(),
    )
    return event


def emit_asset_became_inactive(db: Session, asset, *, last_seen: datetime) -> tuple[DomainEvent, bool]:
    key = f"asset_became_inactive:{asset.id}:{last_seen.isoformat()}"
    return emit_domain_event(
        db,
        event_type=EVENT_ASSET_BECAME_INACTIVE,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        asset_id=asset.id,
        idempotence_key=key,
        details={"last_seen": last_seen.isoformat()},
        source="scheduler",
        occurred_at=utcnow(),
    )


def emit_previously_inactive_returned(db: Session, asset, *, observation_key: str) -> tuple[DomainEvent, bool]:
    last_seen = asset.last_seen.isoformat() if asset.last_seen else ""
    key = f"previously_inactive_asset_returned:{asset.id}:{last_seen}:{observation_key}"
    return emit_domain_event(
        db,
        event_type=EVENT_PREVIOUSLY_INACTIVE_RETURNED,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        asset_id=asset.id,
        idempotence_key=key,
        details={"observation_key": observation_key},
        source=SOURCE_SCANNER,
    )


def emit_scan_missed_unavailable_agent(db: Session, job) -> tuple[DomainEvent, bool]:
    key = f"scan_missed_unavailable_agent:{job.id}"
    site_id = None
    snapshot = job.execution_snapshot or {}
    site = snapshot.get("site") or {}
    if isinstance(site, dict):
        site_id = site.get("id")
    return emit_domain_event(
        db,
        event_type=EVENT_SCAN_MISSED_UNAVAILABLE_AGENT,
        tenant_id=job.tenant_id,
        site_id=site_id,
        asset_id=None,
        idempotence_key=key,
        details={"scan_job_id": job.id, "scan_id": job.scan_id},
        source="scheduler",
    )


__all__ = [
    "emit_asset_became_inactive",
    "emit_domain_event",
    "emit_new_asset",
    "emit_previously_inactive_returned",
    "emit_scan_missed_unavailable_agent",
]
