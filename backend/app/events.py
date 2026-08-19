"""Canonical domain-event emission.

Domain events are facts. Alert routing is a separate outbox projection.
This module persists events and enqueues NEW events for Phase 3B routing.
Idempotent retries do not create duplicate queue work.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.assets import utcnow
from app.models import (
    ALERT_QUEUE_PENDING,
    DOMAIN_EVENT_TYPES,
    EVENT_AGENT_IDENTITY_MISMATCH,
    EVENT_ASSET_BECAME_INACTIVE,
    EVENT_ASSET_DISPOSITION_CHANGED,
    EVENT_NEW_ASSET,
    EVENT_POLICY_CHANGED,
    EVENT_PREVIOUSLY_INACTIVE_RETURNED,
    EVENT_SCAN_FAILED,
    EVENT_SCAN_MISSED_UNAVAILABLE_AGENT,
    EVENT_TREATMENT_CREATED,
    EVENT_TREATMENT_EXPIRED,
    EVENT_WAN_TARGET_CHANGED,
    SOURCE_MANUAL,
    SOURCE_SCANNER,
    Asset,
    DomainEvent,
    EventAlertQueue,
    FindingTreatment,
    PolicyRule,
    ScanJob,
)


class DomainEventError(Exception):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _enqueue_alert_routing(db: Session, event: DomainEvent) -> None:
    existing = (
        db.query(EventAlertQueue.id)
        .filter(EventAlertQueue.domain_event_id == event.id)
        .first()
    )
    if existing is not None:
        return
    db.add(
        EventAlertQueue(
            domain_event_id=event.id,
            status=ALERT_QUEUE_PENDING,
            attempts=0,
            next_attempt_at=utcnow(),
            updated_at=utcnow(),
        )
    )
    db.flush()


def emit_domain_event(
    db: Session,
    *,
    event_type: str,
    tenant_id: int | None,
    site_id: int | None,
    asset_id: int | None,
    idempotence_key: str,
    details: dict[str, Any] | None = None,
    source: str = SOURCE_SCANNER,
    occurred_at: datetime | None = None,
    network_id: int | None = None,
    asset_finding_id: int | None = None,
    scan_job_id: int | None = None,
    agent_id: int | None = None,
    treatment_id: int | None = None,
    policy_rule_id: int | None = None,
) -> tuple[DomainEvent, bool]:
    if event_type not in DOMAIN_EVENT_TYPES:
        raise DomainEventError(f"Unsupported event type: {event_type}")
    existing = (
        db.query(DomainEvent)
        .filter(DomainEvent.idempotence_key == idempotence_key)
        .first()
    )
    if existing is not None:
        return existing, False
    if network_id is not None and site_id is None:
        network_id = None
    safe_details = dict(details or {})
    for secret_key in ("enrollment_secret", "private_key", "password", "smtp_password", "token", "bearer"):
        safe_details.pop(secret_key, None)
    row = DomainEvent(
        event_type=event_type,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=asset_id,
        asset_finding_id=asset_finding_id,
        scan_job_id=scan_job_id,
        agent_id=agent_id,
        treatment_id=treatment_id,
        policy_rule_id=policy_rule_id,
        occurred_at=occurred_at or utcnow(),
        source=source,
        details=safe_details,
        idempotence_key=idempotence_key,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
            _enqueue_alert_routing(db, row)
        return row, True
    except IntegrityError:
        db.expire_all()
        existing = (
            db.query(DomainEvent)
            .filter(DomainEvent.idempotence_key == idempotence_key)
            .first()
        )
        if existing is None:
            raise
        return existing, False


def emit_new_asset(
    db: Session,
    asset,
    *,
    source: str = SOURCE_SCANNER,
    network_id: int | None = None,
    scan_job_id: int | None = None,
) -> DomainEvent:
    event, _ = emit_domain_event(
        db,
        event_type=EVENT_NEW_ASSET,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        network_id=network_id,
        asset_id=asset.id,
        scan_job_id=scan_job_id,
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
    network_id = None
    snapshot = job.execution_snapshot or {}
    site = snapshot.get("site") or {}
    network = snapshot.get("network") or {}
    if isinstance(site, dict):
        site_id = site.get("id")
    if isinstance(network, dict):
        network_id = network.get("id")
    return emit_domain_event(
        db,
        event_type=EVENT_SCAN_MISSED_UNAVAILABLE_AGENT,
        tenant_id=job.tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=None,
        scan_job_id=job.id,
        idempotence_key=key,
        details={"scan_job_id": job.id, "scan_id": job.scan_id},
        source="scheduler",
    )


def emit_scan_failed(db: Session, job: ScanJob, *, reason: str) -> tuple[DomainEvent, bool]:
    site_id = None
    network_id = None
    snapshot = job.execution_snapshot or {}
    site = snapshot.get("site") or {}
    network = snapshot.get("network") or {}
    if isinstance(site, dict):
        site_id = site.get("id")
    if isinstance(network, dict):
        network_id = network.get("id")
    summary = " ".join(str(reason or "scan failed").split())[:400]
    return emit_domain_event(
        db,
        event_type=EVENT_SCAN_FAILED,
        tenant_id=job.tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=None,
        scan_job_id=job.id,
        idempotence_key=f"scan_failed:{job.id}",
        details={"scan_job_id": job.id, "scan_id": job.scan_id, "reason": summary},
        source="scheduler",
    )


def emit_asset_disposition_changed(
    db: Session,
    asset: Asset,
    *,
    previous: str,
    new: str,
    source: str,
    policy_rule_id: int | None = None,
    policy_revision: int | None = None,
    network_id: int | None = None,
) -> tuple[DomainEvent, bool] | None:
    if previous == new:
        return None
    details = {
        "previous_disposition": previous,
        "new_disposition": new,
        "source": source,
    }
    if policy_rule_id is not None:
        details["policy_rule_id"] = policy_rule_id
        details["policy_revision"] = policy_revision
    return emit_domain_event(
        db,
        event_type=EVENT_ASSET_DISPOSITION_CHANGED,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        network_id=network_id,
        asset_id=asset.id,
        policy_rule_id=policy_rule_id,
        idempotence_key=f"asset_disposition_changed:{asset.id}:{previous}:{new}:{source}:{policy_rule_id or 0}:{policy_revision or 0}",
        details=details,
        source=source if source in {SOURCE_SCANNER, SOURCE_MANUAL, "policy"} else SOURCE_MANUAL,
    )


def emit_treatment_created(db: Session, treatment: FindingTreatment, finding) -> tuple[DomainEvent, bool]:
    asset = getattr(finding, "asset", None)
    return emit_domain_event(
        db,
        event_type=EVENT_TREATMENT_CREATED,
        tenant_id=treatment.tenant_id,
        site_id=asset.site_id if asset is not None else None,
        asset_id=finding.asset_id,
        asset_finding_id=finding.id,
        treatment_id=treatment.id,
        idempotence_key=f"treatment_created:{treatment.id}",
        details={
            "treatment_id": treatment.id,
            "asset_finding_id": finding.id,
            "treatment_type": treatment.treatment_type,
            "status": treatment.status,
        },
        source=SOURCE_MANUAL,
    )


def emit_treatment_expired(db: Session, treatment: FindingTreatment, finding) -> tuple[DomainEvent, bool]:
    asset = getattr(finding, "asset", None)
    return emit_domain_event(
        db,
        event_type=EVENT_TREATMENT_EXPIRED,
        tenant_id=treatment.tenant_id,
        site_id=asset.site_id if asset is not None else None,
        asset_id=finding.asset_id,
        asset_finding_id=finding.id,
        treatment_id=treatment.id,
        idempotence_key=f"treatment_expired:{treatment.id}",
        details={
            "treatment_id": treatment.id,
            "asset_finding_id": finding.id,
            "treatment_type": treatment.treatment_type,
        },
        source="scheduler",
    )


def emit_agent_identity_mismatch(
    db: Session,
    agent,
    *,
    reason: str,
    source_ip: str | None = None,
) -> tuple[DomainEvent, bool]:
    occurred = utcnow()
    safe_reason = " ".join(str(reason).split())[:300]
    return emit_domain_event(
        db,
        event_type=EVENT_AGENT_IDENTITY_MISMATCH,
        tenant_id=agent.tenant_id,
        site_id=agent.site_id,
        asset_id=None,
        agent_id=agent.id,
        idempotence_key=(
            f"agent_identity_mismatch:{agent.id}:{safe_reason}:{source_ip or '-'}:{occurred.strftime('%Y%m%d%H%M%S')}"
        ),
        details={
            "agent_id": agent.id,
            "agent_uuid": agent.uuid,
            "agent_name": agent.name,
            "reason": safe_reason,
            "source_ip": source_ip or "",
        },
        source="agent",
        occurred_at=occurred,
    )


def emit_wan_target_changed(
    db: Session,
    target,
    *,
    change: str,
) -> tuple[DomainEvent, bool]:
    return emit_domain_event(
        db,
        event_type=EVENT_WAN_TARGET_CHANGED,
        tenant_id=target.tenant_id,
        site_id=None,
        asset_id=None,
        idempotence_key=f"wan_target_changed:{target.id}:{change}",
        details={
            "wan_target_id": target.id,
            "change": change,
            "name": target.name,
            "target_type": target.target_type,
            "normalized_value": target.normalized_value,
        },
        source=SOURCE_MANUAL,
    )


def emit_policy_changed(db: Session, row: PolicyRule) -> tuple[DomainEvent, bool]:
    return emit_domain_event(
        db,
        event_type=EVENT_POLICY_CHANGED,
        tenant_id=row.tenant_id,
        site_id=row.site_id,
        network_id=row.network_id,
        asset_id=None,
        policy_rule_id=row.id,
        idempotence_key=f"policy_changed:{row.id}:{row.revision}",
        details={
            "policy_id": row.id,
            "revision": row.revision,
            "category": row.category,
            "scope_type": row.scope_type,
            "name": row.name,
            "enabled": row.enabled,
            "archived": row.archived_at is not None,
        },
        source=SOURCE_MANUAL,
    )


__all__ = [
    "DomainEventError",
    "emit_agent_identity_mismatch",
    "emit_asset_became_inactive",
    "emit_asset_disposition_changed",
    "emit_domain_event",
    "emit_new_asset",
    "emit_policy_changed",
    "emit_previously_inactive_returned",
    "emit_scan_failed",
    "emit_scan_missed_unavailable_agent",
    "emit_treatment_created",
    "emit_treatment_expired",
    "emit_wan_target_changed",
]
