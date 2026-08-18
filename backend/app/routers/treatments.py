from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_any, require_user
from app.database import get_db
from app.models import CompensatingControl, FindingTreatment, Tenant, User
from app.schemas import (
    CompensatingControlIn,
    CompensatingControlOut,
    CompensatingControlRetireIn,
    CompensatingControlUpdateIn,
    FindingTreatmentIn,
    FindingTreatmentOut,
    TreatmentApproveIn,
    TreatmentReviewIn,
    TreatmentRevokeIn,
)
from app.treatments import (
    TreatmentError,
    approve_treatment,
    create_compensating_control,
    create_treatment,
    display_status,
    list_treatments,
    retire_compensating_control,
    review_treatment,
    revoke_treatment,
    update_compensating_control,
)

router = APIRouter(tags=["treatments"])


def _require_tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _usernames(db: Session, *user_ids: int | None) -> dict[int, str]:
    ids = [item for item in user_ids if item]
    if not ids:
        return {}
    rows = db.query(User.id, User.username).filter(User.id.in_(ids)).all()
    return {row.id: row.username for row in rows}


def serialize_compensating_control(db: Session, row: CompensatingControl) -> CompensatingControlOut:
    names = _usernames(db, row.created_by_user_id, row.retired_by_user_id)
    return CompensatingControlOut(
        id=row.id,
        tenant_id=row.tenant_id,
        treatment_id=row.treatment_id,
        name=row.name,
        description=row.description,
        evidence_notes=row.evidence_notes,
        status=row.status,
        created_by_user_id=row.created_by_user_id,
        created_by_username=names.get(row.created_by_user_id) if row.created_by_user_id else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
        retired_at=row.retired_at,
        retired_by_user_id=row.retired_by_user_id,
        retired_by_username=names.get(row.retired_by_user_id) if row.retired_by_user_id else None,
        retirement_reason=row.retirement_reason,
    )


def serialize_treatment(db: Session, row: FindingTreatment) -> FindingTreatmentOut:
    names = _usernames(db, row.created_by_user_id, row.reviewed_by_user_id, row.revoked_by_user_id)
    controls = sorted(row.compensating_controls, key=lambda item: item.id)
    return FindingTreatmentOut(
        id=row.id,
        tenant_id=row.tenant_id,
        asset_finding_id=row.asset_finding_id,
        treatment_type=row.treatment_type,
        status=row.status,
        display_status=display_status(row),
        rationale=row.rationale,
        evidence_notes=row.evidence_notes,
        source=row.source,
        created_by_user_id=row.created_by_user_id,
        created_by_username=names.get(row.created_by_user_id) if row.created_by_user_id else None,
        reviewed_by_user_id=row.reviewed_by_user_id,
        reviewed_by_username=names.get(row.reviewed_by_user_id) if row.reviewed_by_user_id else None,
        revoked_by_user_id=row.revoked_by_user_id,
        revoked_by_username=names.get(row.revoked_by_user_id) if row.revoked_by_user_id else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
        reviewed_at=row.reviewed_at,
        review_due_at=row.review_due_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        revocation_reason=row.revocation_reason,
        review_notes=row.review_notes,
        compensating_controls=[serialize_compensating_control(db, item) for item in controls],
    )


def _run(fn, db: Session):
    try:
        result = fn()
        db.commit()
        return result
    except TreatmentError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments",
    response_model=list[FindingTreatmentOut],
)
def get_treatments(
    tenant_id: int,
    asset_finding_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    try:
        rows = list_treatments(db, tenant_id, asset_finding_id)
    except TreatmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return [serialize_treatment(db, row) for row in rows]


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments",
    response_model=FindingTreatmentOut,
)
def post_treatment(
    tenant_id: int,
    asset_finding_id: int,
    body: FindingTreatmentIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: create_treatment(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_type=body.treatment_type,
            rationale=body.rationale,
            actor=user,
            evidence_notes=body.evidence_notes,
            review_due_at=body.review_due_at,
            expires_at=body.expires_at,
        ),
        db,
    )
    db.refresh(row)
    return serialize_treatment(db, row)


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/approve",
    response_model=FindingTreatmentOut,
)
def post_approve(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    body: TreatmentApproveIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: approve_treatment(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            actor=user,
            review_notes=body.review_notes,
        ),
        db,
    )
    return serialize_treatment(db, row)


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/review",
    response_model=FindingTreatmentOut,
)
def post_review(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    body: TreatmentReviewIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: review_treatment(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            actor=user,
            review_notes=body.review_notes,
            review_due_at=body.review_due_at,
        ),
        db,
    )
    return serialize_treatment(db, row)


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/revoke",
    response_model=FindingTreatmentOut,
)
def post_revoke(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    body: TreatmentRevokeIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: revoke_treatment(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            actor=user,
            reason=body.reason,
        ),
        db,
    )
    return serialize_treatment(db, row)


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/compensating-controls",
    response_model=CompensatingControlOut,
)
def post_compensating(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    body: CompensatingControlIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: create_compensating_control(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            actor=user,
            name=body.name,
            description=body.description,
            evidence_notes=body.evidence_notes,
        ),
        db,
    )
    return serialize_compensating_control(db, row)


@router.patch(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/compensating-controls/{control_id}",
    response_model=CompensatingControlOut,
)
def patch_compensating(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    control_id: int,
    body: CompensatingControlUpdateIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: update_compensating_control(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            control_id=control_id,
            actor=user,
            name=body.name,
            description=body.description,
            evidence_notes=body.evidence_notes,
        ),
        db,
    )
    return serialize_compensating_control(db, row)


@router.post(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/treatments/{treatment_id}/compensating-controls/{control_id}/retire",
    response_model=CompensatingControlOut,
)
def post_retire_compensating(
    tenant_id: int,
    asset_finding_id: int,
    treatment_id: int,
    control_id: int,
    body: CompensatingControlRetireIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    row = _run(
        lambda: retire_compensating_control(
            db,
            tenant_id=tenant_id,
            asset_finding_id=asset_finding_id,
            treatment_id=treatment_id,
            control_id=control_id,
            actor=user,
            reason=body.reason,
        ),
        db,
    )
    return serialize_compensating_control(db, row)
