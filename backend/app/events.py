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
    Agent,
    Asset,
    AssetFinding,
    AssetObservation,
    AuditLog,
    DomainEvent,
    EventAlertQueue,
    FindingTreatment,
    Network,
    PolicyRule,
    ScanJob,
    Site,
    Tenant,
)


class DomainEventError(Exception):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _fail_closed(detail: str) -> None:
    raise DomainEventError(detail)


def assert_event_locality(
    *,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
    asset_id: int | None = None,
    asset_finding_id: int | None = None,
    scan_job_id: int | None = None,
    agent_id: int | None = None,
    treatment_id: int | None = None,
    policy_rule_id: int | None = None,
    tenant: Tenant | None = None,
    site: Site | None = None,
    network: Network | None = None,
    asset: Asset | None = None,
    finding: AssetFinding | None = None,
    scan_job: ScanJob | None = None,
    agent: Agent | None = None,
    treatment: FindingTreatment | None = None,
    policy: PolicyRule | None = None,
) -> None:
    """Fail closed when event FKs are missing or cross Tenant/Site/Network."""
    tenant_scoped = any(
        item is not None
        for item in (site_id, network_id, asset_id, asset_finding_id, scan_job_id, agent_id, treatment_id)
    )
    if tenant_scoped and tenant_id is None:
        _fail_closed("Tenant-scoped event subjects require tenant_id")
    if tenant_id is not None and tenant is None:
        _fail_closed("Event tenant does not exist")
    if site_id is not None:
        if site is None:
            _fail_closed("Event site does not exist")
        if site.tenant_id != tenant_id:
            _fail_closed("Event site does not belong to the event tenant")
    if network_id is not None:
        if site_id is None:
            _fail_closed("Network-scoped events require a trusted site_id")
        if network is None:
            _fail_closed("Event network does not exist")
        if network.site_id != site_id or network.tenant_id != tenant_id:
            _fail_closed("Event network does not belong to the event site/tenant")
    if asset_id is not None:
        if asset is None:
            _fail_closed("Event asset does not exist")
        if asset.tenant_id != tenant_id:
            _fail_closed("Event asset does not belong to the event tenant")
    if asset_finding_id is not None:
        if finding is None:
            _fail_closed("Event finding does not exist")
        if finding.tenant_id != tenant_id:
            _fail_closed("Event finding does not belong to the event tenant")
        if asset_id is not None and finding.asset_id != asset_id:
            _fail_closed("Event finding does not belong to the event asset")
    if scan_job_id is not None:
        if scan_job is None:
            _fail_closed("Event scan job does not exist")
        if scan_job.tenant_id != tenant_id:
            _fail_closed("Event scan job does not belong to the event tenant")
    if agent_id is not None:
        if agent is None:
            _fail_closed("Event agent does not exist")
        if agent.tenant_id != tenant_id:
            _fail_closed("Event agent does not belong to the event tenant")
        if site_id is not None and agent.site_id != site_id:
            _fail_closed("Event agent does not belong to the event site")
    if treatment_id is not None:
        if treatment is None:
            _fail_closed("Event treatment does not exist")
        if treatment.tenant_id != tenant_id:
            _fail_closed("Event treatment does not belong to the event tenant")
        if asset_finding_id is not None and treatment.asset_finding_id != asset_finding_id:
            _fail_closed("Event treatment does not belong to the event finding")
    if policy_rule_id is not None:
        if policy is None:
            _fail_closed("Event policy does not exist")
        if policy.tenant_id is not None and policy.tenant_id != tenant_id:
            _fail_closed("Event policy does not belong to the event tenant")
        if policy.site_id is not None and site_id is not None and policy.site_id != site_id:
            _fail_closed("Event policy site does not match the event site")
        if policy.network_id is not None and network_id is not None and policy.network_id != network_id:
            _fail_closed("Event policy network does not match the event network")


def load_event_subjects(
    db: Session,
    *,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
    asset_id: int | None = None,
    asset_finding_id: int | None = None,
    scan_job_id: int | None = None,
    agent_id: int | None = None,
    treatment_id: int | None = None,
    policy_rule_id: int | None = None,
) -> dict[str, Any]:
    return {
        "tenant": db.get(Tenant, tenant_id) if tenant_id is not None else None,
        "site": db.get(Site, site_id) if site_id is not None else None,
        "network": db.get(Network, network_id) if network_id is not None else None,
        "asset": db.get(Asset, asset_id) if asset_id is not None else None,
        "finding": db.get(AssetFinding, asset_finding_id) if asset_finding_id is not None else None,
        "scan_job": db.get(ScanJob, scan_job_id) if scan_job_id is not None else None,
        "agent": db.get(Agent, agent_id) if agent_id is not None else None,
        "treatment": db.get(FindingTreatment, treatment_id) if treatment_id is not None else None,
        "policy": db.get(PolicyRule, policy_rule_id) if policy_rule_id is not None else None,
    }


def validate_event_relationships(
    db: Session,
    *,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
    asset_id: int | None = None,
    asset_finding_id: int | None = None,
    scan_job_id: int | None = None,
    agent_id: int | None = None,
    treatment_id: int | None = None,
    policy_rule_id: int | None = None,
) -> None:
    subjects = load_event_subjects(
        db,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=asset_id,
        asset_finding_id=asset_finding_id,
        scan_job_id=scan_job_id,
        agent_id=agent_id,
        treatment_id=treatment_id,
        policy_rule_id=policy_rule_id,
    )
    assert_event_locality(
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=asset_id,
        asset_finding_id=asset_finding_id,
        scan_job_id=scan_job_id,
        agent_id=agent_id,
        treatment_id=treatment_id,
        policy_rule_id=policy_rule_id,
        **subjects,
    )


def trusted_run_locality(
    db: Session,
    job: ScanJob,
    *,
    asset: Asset | None = None,
) -> tuple[int | None, int | None]:
    """Trusted Site/Network from the run snapshot or this run's observation."""
    snapshot = job.execution_snapshot or {}
    site = snapshot.get("site") if isinstance(snapshot.get("site"), dict) else {}
    site_id = site.get("id")
    targets = snapshot.get("targets") if isinstance(snapshot.get("targets"), dict) else {}
    raw_networks = targets.get("networks") if isinstance(targets, dict) else []
    network_ids = [
        row.get("id")
        for row in (raw_networks or [])
        if isinstance(row, dict) and row.get("id") is not None
    ]
    network_id = network_ids[0] if len(network_ids) == 1 else None
    if asset is not None and (site_id is None or network_id is None):
        observation = (
            db.query(AssetObservation)
            .filter(
                AssetObservation.scan_job_id == job.id,
                AssetObservation.asset_id == asset.id,
                AssetObservation.tenant_id == job.tenant_id,
            )
            .order_by(AssetObservation.observed_at.desc(), AssetObservation.id.desc())
            .first()
        )
        if observation is not None:
            if site_id is None:
                site_id = observation.site_id
            if network_id is None:
                network_id = observation.network_id
    if site_id is None and asset is not None:
        site_id = asset.site_id
    return site_id, network_id


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
    validate_event_relationships(
        db,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=asset_id,
        asset_finding_id=asset_finding_id,
        scan_job_id=scan_job_id,
        agent_id=agent_id,
        treatment_id=treatment_id,
        policy_rule_id=policy_rule_id,
    )
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
    site_id, network_id = trusted_run_locality(db, job)
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
    site_id, network_id = trusted_run_locality(db, job)
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
    audit: AuditLog,
    policy_rule_id: int | None = None,
    policy_revision: int | None = None,
    network_id: int | None = None,
) -> tuple[DomainEvent, bool] | None:
    if previous == new:
        return None
    if audit.id is None:
        db.flush()
    if audit.id is None:
        raise DomainEventError("Disposition change requires a persisted AuditLog")
    details = {
        "previous_disposition": previous,
        "new_disposition": new,
        "source": source,
        "audit_id": audit.id,
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
        idempotence_key=f"asset_disposition_changed:{asset.id}:{audit.id}",
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
    "assert_event_locality",
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
    "trusted_run_locality",
    "validate_event_relationships",
]
