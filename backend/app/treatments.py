"""Finding treatment and compensating-control domain service."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.audit import record_audit
from app.models import (
    LEGACY_TREATMENT_RATIONALE,
    TREATMENT_DISPLAY_ACTIVE,
    TREATMENT_DISPLAY_EXPIRED,
    TREATMENT_DISPLAY_PENDING_REVIEW,
    TREATMENT_DISPLAY_REVIEW_DUE,
    TREATMENT_DISPLAY_REVIEW_OVERDUE,
    TREATMENT_DISPLAY_REVOKED,
    TREATMENT_DISPLAY_SUPERSEDED,
    TREATMENT_DISPLAY_UNADDRESSED,
    TREATMENT_RECORD_MITIGATED,
    TREATMENT_RECORD_TYPES,
    TREATMENT_SOURCE_MANUAL,
    TREATMENT_SOURCES,
    TREATMENT_STATUS_ACTIVE,
    TREATMENT_STATUS_EXPIRED,
    TREATMENT_STATUS_PENDING_REVIEW,
    TREATMENT_STATUS_REVOKED,
    TREATMENT_STATUS_SUPERSEDED,
    TREATMENT_UNADDRESSED,
    AssetFinding,
    CompensatingControl,
    COMPENSATING_STATUS_ACTIVE,
    COMPENSATING_STATUS_RETIRED,
    FindingTreatment,
    User,
)

MERGE_COLLISION_REASON = (
    "Asset finding merge collision: conflicting active treatments require manual review."
)


class TreatmentError(Exception):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def display_status(treatment: FindingTreatment | None, *, now: datetime | None = None) -> str:
    if treatment is None:
        return TREATMENT_DISPLAY_UNADDRESSED
    current = now or utcnow()
    if treatment.status == TREATMENT_STATUS_PENDING_REVIEW:
        return TREATMENT_DISPLAY_PENDING_REVIEW
    if treatment.status == TREATMENT_STATUS_REVOKED:
        return TREATMENT_DISPLAY_REVOKED
    if treatment.status == TREATMENT_STATUS_SUPERSEDED:
        return TREATMENT_DISPLAY_SUPERSEDED
    if treatment.status == TREATMENT_STATUS_EXPIRED:
        return TREATMENT_DISPLAY_EXPIRED
    if treatment.status != TREATMENT_STATUS_ACTIVE:
        return treatment.status
    expires = _aware(treatment.expires_at)
    if expires is not None and expires <= current:
        return TREATMENT_DISPLAY_EXPIRED
    due = _aware(treatment.review_due_at)
    if due is not None and due <= current:
        return TREATMENT_DISPLAY_REVIEW_OVERDUE
    if due is not None:
        return TREATMENT_DISPLAY_REVIEW_DUE
    return TREATMENT_DISPLAY_ACTIVE


def _recalculate_priority(db: Session, finding: AssetFinding) -> None:
    from app.intel.priority import recalculate_asset_finding_priorities

    recalculate_asset_finding_priorities(db, [finding])


def _is_elapsed(treatment: FindingTreatment, now: datetime) -> bool:
    expires = _aware(treatment.expires_at)
    return expires is not None and expires <= now


def expire_elapsed_treatments_for_finding(
    db: Session,
    finding: AssetFinding,
    *,
    now: datetime | None = None,
) -> int:
    current = now or utcnow()
    rows = (
        db.query(FindingTreatment)
        .filter(
            FindingTreatment.asset_finding_id == finding.id,
            FindingTreatment.status == TREATMENT_STATUS_ACTIVE,
            FindingTreatment.expires_at.isnot(None),
            FindingTreatment.expires_at <= current,
        )
        .with_for_update()
        .order_by(FindingTreatment.id.asc())
        .all()
    )
    expired_rows = [
        treatment
        for treatment in rows
        if treatment.status == TREATMENT_STATUS_ACTIVE and _is_elapsed(treatment, current)
    ]
    if not expired_rows:
        return 0
    for treatment in expired_rows:
        treatment.status = TREATMENT_STATUS_EXPIRED
        treatment.updated_at = current
    db.flush()
    reconcile_treatment_projection(db, finding)
    db.flush()
    for treatment in expired_rows:
        expires = _aware(treatment.expires_at)
        record_audit(
            db,
            actor=None,
            action="treatment.expired",
            object_type="finding_treatment",
            object_id=treatment.id,
            tenant_id=finding.tenant_id,
            details={
                "asset_finding_id": finding.id,
                "treatment_type": treatment.treatment_type,
                "expires_at": expires.isoformat() if expires else None,
                "technical_state": finding.technical_state,
                "treatment_state": finding.treatment_state,
                "actor": "system",
            },
        )
        from app.events import emit_treatment_expired

        emit_treatment_expired(db, treatment, finding)
    return len(expired_rows)


def _lock_finding(db: Session, tenant_id: int, asset_finding_id: int) -> AssetFinding:
    row = (
        db.query(AssetFinding)
        .filter(AssetFinding.id == asset_finding_id, AssetFinding.tenant_id == tenant_id)
        .with_for_update()
        .first()
    )
    if row is None:
        raise TreatmentError("Asset finding not found", 404)
    expire_elapsed_treatments_for_finding(db, row)
    return row


def _get_treatment(db: Session, tenant_id: int, asset_finding_id: int, treatment_id: int) -> FindingTreatment:
    row = (
        db.query(FindingTreatment)
        .options(selectinload(FindingTreatment.compensating_controls))
        .filter(
            FindingTreatment.id == treatment_id,
            FindingTreatment.tenant_id == tenant_id,
            FindingTreatment.asset_finding_id == asset_finding_id,
        )
        .with_for_update()
        .first()
    )
    if row is None:
        raise TreatmentError("Treatment not found", 404)
    return row


def current_active_treatment(db: Session, asset_finding_id: int, *, lock: bool = False) -> FindingTreatment | None:
    db.flush()
    query = db.query(FindingTreatment).filter(
        FindingTreatment.asset_finding_id == asset_finding_id,
        FindingTreatment.status == TREATMENT_STATUS_ACTIVE,
    )
    if lock:
        query = query.with_for_update()
    row = query.order_by(FindingTreatment.id.asc()).first()
    if row is None or row.status != TREATMENT_STATUS_ACTIVE:
        return None
    if _is_elapsed(row, utcnow()):
        finding = db.get(AssetFinding, asset_finding_id)
        if finding is not None:
            expire_elapsed_treatments_for_finding(db, finding)
        return None
    return row


def reconcile_treatment_projection(db: Session, finding: AssetFinding) -> None:
    active = current_active_treatment(db, finding.id)
    finding.treatment_state = active.treatment_type if active is not None else TREATMENT_UNADDRESSED
    finding.updated_at = utcnow()
    _recalculate_priority(db, finding)


def _supersede_current(
    db: Session,
    finding: AssetFinding,
    incoming: FindingTreatment,
    *,
    actor: User | None,
    now: datetime,
) -> FindingTreatment | None:
    current = current_active_treatment(db, finding.id, lock=True)
    if current is None or current.id == incoming.id:
        return None
    current.status = TREATMENT_STATUS_SUPERSEDED
    current.updated_at = now
    record_audit(
        db,
        actor=actor,
        action="treatment.superseded",
        object_type="finding_treatment",
        object_id=current.id,
        tenant_id=finding.tenant_id,
        details={
            "asset_finding_id": finding.id,
            "superseded_treatment_type": current.treatment_type,
            "replacement_treatment_id": incoming.id,
            "replacement_treatment_type": incoming.treatment_type,
        },
    )
    return current


def _require_expiration_not_due(expires_at: datetime | None, now: datetime, *, approve: bool) -> None:
    expires = _aware(expires_at)
    if expires is not None and expires <= now:
        if approve:
            raise TreatmentError("Treatment has already expired and cannot be approved")
        raise TreatmentError("Expiration is already due; the treatment cannot be created")


def _activate(
    db: Session,
    finding: AssetFinding,
    treatment: FindingTreatment,
    *,
    actor: User | None,
    now: datetime,
) -> None:
    _require_expiration_not_due(treatment.expires_at, now, approve=True)
    _supersede_current(db, finding, treatment, actor=actor, now=now)
    treatment.status = TREATMENT_STATUS_ACTIVE
    treatment.updated_at = now
    finding.treatment_state = treatment.treatment_type
    finding.updated_at = now
    _recalculate_priority(db, finding)


def create_treatment(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_type: str,
    rationale: str,
    actor: User,
    evidence_notes: str = "",
    review_due_at: datetime | None = None,
    expires_at: datetime | None = None,
    source: str = TREATMENT_SOURCE_MANUAL,
) -> FindingTreatment:
    kind = (treatment_type or "").strip()
    if kind not in TREATMENT_RECORD_TYPES:
        raise TreatmentError("Unsupported treatment type")
    text = (rationale or "").strip()
    if not text:
        raise TreatmentError("Rationale is required")
    if source not in TREATMENT_SOURCES:
        raise TreatmentError("Unsupported treatment source")
    now = utcnow()
    _require_expiration_not_due(expires_at, now, approve=False)
    finding = _lock_finding(db, tenant_id, asset_finding_id)
    row = FindingTreatment(
        tenant_id=finding.tenant_id,
        asset_finding_id=finding.id,
        treatment_type=kind,
        status=TREATMENT_STATUS_PENDING_REVIEW,
        rationale=text,
        evidence_notes=(evidence_notes or "").strip(),
        source=source,
        created_by_user_id=actor.id,
        review_due_at=_aware(review_due_at),
        expires_at=_aware(expires_at),
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    if kind == TREATMENT_RECORD_MITIGATED:
        try:
            _activate(db, finding, row, actor=actor, now=now)
            db.flush()
        except IntegrityError as exc:
            raise TreatmentError("An active treatment already exists for this finding", 409) from exc
    record_audit(
        db,
        actor=actor,
        action="treatment.created",
        object_type="finding_treatment",
        object_id=row.id,
        tenant_id=finding.tenant_id,
        details={
            "asset_finding_id": finding.id,
            "treatment_type": row.treatment_type,
            "status": row.status,
            "source": row.source,
            "rationale": row.rationale,
            "technical_state": finding.technical_state,
        },
    )
    from app.events import emit_treatment_created

    emit_treatment_created(db, row, finding)
    return row


def approve_treatment(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    actor: User,
    review_notes: str | None = None,
) -> FindingTreatment:
    now = utcnow()
    finding = _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    if treatment.status != TREATMENT_STATUS_PENDING_REVIEW:
        raise TreatmentError("Only treatments pending review can be approved")
    _require_expiration_not_due(treatment.expires_at, now, approve=True)
    treatment.reviewed_by_user_id = actor.id
    treatment.reviewed_at = now
    if review_notes is not None:
        treatment.review_notes = review_notes.strip()
    try:
        _activate(db, finding, treatment, actor=actor, now=now)
        db.flush()
    except IntegrityError as exc:
        raise TreatmentError("An active treatment already exists for this finding", 409) from exc
    record_audit(
        db,
        actor=actor,
        action="treatment.approved",
        object_type="finding_treatment",
        object_id=treatment.id,
        tenant_id=finding.tenant_id,
        details={
            "asset_finding_id": finding.id,
            "treatment_type": treatment.treatment_type,
            "review_notes": treatment.review_notes,
            "technical_state": finding.technical_state,
        },
    )
    return treatment


def review_treatment(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    actor: User,
    review_notes: str | None = None,
    review_due_at: datetime | None = None,
) -> FindingTreatment:
    now = utcnow()
    finding = _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    if treatment.status not in {TREATMENT_STATUS_PENDING_REVIEW, TREATMENT_STATUS_ACTIVE}:
        raise TreatmentError("Only pending or active treatments can be reviewed")
    treatment.reviewed_by_user_id = actor.id
    treatment.reviewed_at = now
    treatment.updated_at = now
    if review_notes is not None:
        treatment.review_notes = review_notes.strip()
    if review_due_at is not None:
        treatment.review_due_at = _aware(review_due_at)
    record_audit(
        db,
        actor=actor,
        action="treatment.reviewed",
        object_type="finding_treatment",
        object_id=treatment.id,
        tenant_id=finding.tenant_id,
        details={
            "asset_finding_id": finding.id,
            "status": treatment.status,
            "review_notes": treatment.review_notes,
            "review_due_at": treatment.review_due_at.isoformat() if treatment.review_due_at else None,
        },
    )
    return treatment


def revoke_treatment(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    actor: User,
    reason: str,
) -> FindingTreatment:
    text = (reason or "").strip()
    if not text:
        raise TreatmentError("Revocation reason is required")
    now = utcnow()
    finding = _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    if treatment.status not in {TREATMENT_STATUS_PENDING_REVIEW, TREATMENT_STATUS_ACTIVE}:
        raise TreatmentError("Only pending or active treatments can be revoked")
    was_active = treatment.status == TREATMENT_STATUS_ACTIVE
    treatment.status = TREATMENT_STATUS_REVOKED
    treatment.revoked_by_user_id = actor.id
    treatment.revoked_at = now
    treatment.revocation_reason = text
    treatment.updated_at = now
    if was_active:
        reconcile_treatment_projection(db, finding)
    record_audit(
        db,
        actor=actor,
        action="treatment.revoked",
        object_type="finding_treatment",
        object_id=treatment.id,
        tenant_id=finding.tenant_id,
        details={
            "asset_finding_id": finding.id,
            "treatment_type": treatment.treatment_type,
            "reason": text,
            "was_active": was_active,
            "technical_state": finding.technical_state,
            "treatment_state": finding.treatment_state,
        },
    )
    return treatment


def expire_due_treatments(db: Session, *, now: datetime | None = None) -> int:
    current = now or utcnow()
    due = (
        db.query(FindingTreatment.tenant_id, FindingTreatment.asset_finding_id)
        .filter(
            FindingTreatment.status == TREATMENT_STATUS_ACTIVE,
            FindingTreatment.expires_at.isnot(None),
            FindingTreatment.expires_at <= current,
        )
        .distinct()
        .all()
    )
    expired = 0
    for tenant_id, asset_finding_id in due:
        finding = (
            db.query(AssetFinding)
            .filter(AssetFinding.id == asset_finding_id, AssetFinding.tenant_id == tenant_id)
            .with_for_update()
            .first()
        )
        if finding is None:
            continue
        expired += expire_elapsed_treatments_for_finding(db, finding, now=current)
    return expired


def create_compensating_control(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    actor: User,
    name: str,
    description: str = "",
    evidence_notes: str = "",
) -> CompensatingControl:
    label = (name or "").strip()
    if not label:
        raise TreatmentError("Compensating control name is required")
    finding = _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    now = utcnow()
    row = CompensatingControl(
        tenant_id=finding.tenant_id,
        treatment_id=treatment.id,
        name=label,
        description=(description or "").strip(),
        evidence_notes=(evidence_notes or "").strip(),
        status=COMPENSATING_STATUS_ACTIVE,
        created_by_user_id=actor.id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="compensating_control.created",
        object_type="compensating_control",
        object_id=row.id,
        tenant_id=finding.tenant_id,
        details={
            "treatment_id": treatment.id,
            "asset_finding_id": finding.id,
            "name": row.name,
        },
    )
    return row


def update_compensating_control(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    control_id: int,
    actor: User,
    name: str | None = None,
    description: str | None = None,
    evidence_notes: str | None = None,
) -> CompensatingControl:
    _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    row = (
        db.query(CompensatingControl)
        .filter(
            CompensatingControl.id == control_id,
            CompensatingControl.tenant_id == tenant_id,
            CompensatingControl.treatment_id == treatment.id,
        )
        .first()
    )
    if row is None:
        raise TreatmentError("Compensating control not found", 404)
    if row.status != COMPENSATING_STATUS_ACTIVE:
        raise TreatmentError("Retired compensating controls cannot be changed")
    before = {"name": row.name, "description": row.description, "evidence_notes": row.evidence_notes}
    if name is not None:
        label = name.strip()
        if not label:
            raise TreatmentError("Compensating control name is required")
        row.name = label
    if description is not None:
        row.description = description.strip()
    if evidence_notes is not None:
        row.evidence_notes = evidence_notes.strip()
    row.updated_at = utcnow()
    record_audit(
        db,
        actor=actor,
        action="compensating_control.changed",
        object_type="compensating_control",
        object_id=row.id,
        tenant_id=tenant_id,
        details={"before": before, "after": {"name": row.name, "description": row.description, "evidence_notes": row.evidence_notes}},
    )
    return row


def retire_compensating_control(
    db: Session,
    *,
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    control_id: int,
    actor: User,
    reason: str,
) -> CompensatingControl:
    text = (reason or "").strip()
    if not text:
        raise TreatmentError("Retirement reason is required")
    _lock_finding(db, tenant_id, asset_finding_id)
    treatment = _get_treatment(db, tenant_id, asset_finding_id, treatment_id)
    row = (
        db.query(CompensatingControl)
        .filter(
            CompensatingControl.id == control_id,
            CompensatingControl.tenant_id == tenant_id,
            CompensatingControl.treatment_id == treatment.id,
        )
        .first()
    )
    if row is None:
        raise TreatmentError("Compensating control not found", 404)
    if row.status == COMPENSATING_STATUS_RETIRED:
        raise TreatmentError("Compensating control is already retired")
    now = utcnow()
    row.status = COMPENSATING_STATUS_RETIRED
    row.retired_at = now
    row.retired_by_user_id = actor.id
    row.retirement_reason = text
    row.updated_at = now
    record_audit(
        db,
        actor=actor,
        action="compensating_control.retired",
        object_type="compensating_control",
        object_id=row.id,
        tenant_id=tenant_id,
        details={"treatment_id": treatment.id, "name": row.name, "reason": text},
    )
    return row


def merge_finding_treatments(
    db: Session,
    *,
    keeper: AssetFinding,
    donor: AssetFinding,
    now: datetime | None = None,
) -> None:
    current = now or utcnow()
    expire_elapsed_treatments_for_finding(db, keeper, now=current)
    expire_elapsed_treatments_for_finding(db, donor, now=current)
    keeper_active = current_active_treatment(db, keeper.id, lock=True)
    donor_active = current_active_treatment(db, donor.id, lock=True)
    if keeper_active is not None and donor_active is not None:
        for row in (keeper_active, donor_active):
            row.status = TREATMENT_STATUS_SUPERSEDED
            row.updated_at = current
            note = MERGE_COLLISION_REASON
            row.review_notes = f"{row.review_notes}\n{note}".strip() if row.review_notes else note
            record_audit(
                db,
                actor=None,
                action="treatment.superseded",
                object_type="finding_treatment",
                object_id=row.id,
                tenant_id=keeper.tenant_id,
                details={
                    "reason": "merge_active_treatment_collision",
                    "keeper_asset_finding_id": keeper.id,
                    "donor_asset_finding_id": donor.id,
                    "treatment_type": row.treatment_type,
                    "message": MERGE_COLLISION_REASON,
                },
            )
        db.flush()
    db.query(FindingTreatment).filter(FindingTreatment.asset_finding_id == donor.id).update(
        {FindingTreatment.asset_finding_id: keeper.id, FindingTreatment.tenant_id: keeper.tenant_id},
        synchronize_session=False,
    )
    from app.compliance import reassign_asset_finding_control_references

    reassign_asset_finding_control_references(db, keeper=keeper, donor=donor, now=current)
    db.flush()
    if current_active_treatment(db, keeper.id) is None and keeper.treatment_state != donor.treatment_state:
        keeper.treatment_state = TREATMENT_UNADDRESSED
        keeper.updated_at = current
        _recalculate_priority(db, keeper)
        return
    reconcile_treatment_projection(db, keeper)


def list_treatments(db: Session, tenant_id: int, asset_finding_id: int) -> list[FindingTreatment]:
    _lock_finding = (
        db.query(AssetFinding.id)
        .filter(AssetFinding.id == asset_finding_id, AssetFinding.tenant_id == tenant_id)
        .first()
    )
    if _lock_finding is None:
        raise TreatmentError("Asset finding not found", 404)
    return (
        db.query(FindingTreatment)
        .options(selectinload(FindingTreatment.compensating_controls))
        .filter(
            FindingTreatment.tenant_id == tenant_id,
            FindingTreatment.asset_finding_id == asset_finding_id,
        )
        .order_by(FindingTreatment.created_at.asc(), FindingTreatment.id.asc())
        .all()
    )


def treatment_review_overdue_clause():
    now = utcnow()
    return (
        FindingTreatment.status == TREATMENT_STATUS_ACTIVE,
        FindingTreatment.review_due_at.isnot(None),
        FindingTreatment.review_due_at <= now,
        or_(FindingTreatment.expires_at.is_(None), FindingTreatment.expires_at > now),
    )


__all__ = [
    "LEGACY_TREATMENT_RATIONALE",
    "MERGE_COLLISION_REASON",
    "TreatmentError",
    "approve_treatment",
    "create_compensating_control",
    "create_treatment",
    "current_active_treatment",
    "display_status",
    "expire_due_treatments",
    "expire_elapsed_treatments_for_finding",
    "list_treatments",
    "merge_finding_treatments",
    "reconcile_treatment_projection",
    "retire_compensating_control",
    "review_treatment",
    "revoke_treatment",
    "treatment_review_overdue_clause",
    "update_compensating_control",
    "utcnow",
]
