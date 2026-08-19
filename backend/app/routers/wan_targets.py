from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import require_visible_tenant
from app.audit import record_audit, utcnow
from app.auth import require_any, require_user
from app.database import get_db
from app.locality import get_tenant
from app.models import AuthorizedWanTarget, Subnet, User
from app.schemas import AuthorizedWanTargetIn, AuthorizedWanTargetOut
from app.wan_targets import (
    WanTargetInvalidError,
    assert_wan_target_policy,
    find_active_wan_target_by_normalized,
    normalize_wan_target,
)

router = APIRouter(tags=["wan-targets"])


@router.get("/tenants/{tenant_id}/wan-targets", response_model=list[AuthorizedWanTargetOut])
def list_wan_targets(
    tenant_id: int,
    include_archived: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    require_visible_tenant(db, user, tenant_id)
    q = db.query(AuthorizedWanTarget).filter(AuthorizedWanTarget.tenant_id == tenant_id)
    if not include_archived:
        q = q.filter(AuthorizedWanTarget.archived_at.is_(None))
    return q.order_by(AuthorizedWanTarget.name, AuthorizedWanTarget.id).all()


@router.post("/tenants/{tenant_id}/wan-targets", response_model=AuthorizedWanTargetOut)
def create_wan_target(
    tenant_id: int,
    body: AuthorizedWanTargetIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    try:
        target_type, normalized = normalize_wan_target(body.target_type, body.value)
        assert_wan_target_policy(target_type, normalized)
    except WanTargetInvalidError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    existing = find_active_wan_target_by_normalized(db, tenant_id, normalized)
    if existing:
        raise HTTPException(status_code=400, detail="An active authorized WAN target already uses this value")
    target = AuthorizedWanTarget(
        tenant_id=tenant_id,
        name=body.name.strip() or normalized,
        target_type=target_type,
        value=body.value.strip(),
        normalized_value=normalized,
    )
    db.add(target)
    db.flush()
    _sync_companion_subnet(db, target)
    record_audit(
        db,
        actor=user,
        action="wan_target.create",
        object_type="wan_target",
        object_id=target.id,
        tenant_id=tenant_id,
        details={"type": target.target_type, "normalized": target.normalized_value, "name": target.name},
    )
    from app.events import emit_wan_target_changed

    emit_wan_target_changed(db, target, change="created")
    db.commit()
    db.refresh(target)
    return target


@router.post("/wan-targets/{target_id}/archive", response_model=AuthorizedWanTargetOut)
def archive_wan_target(target_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    target = db.query(AuthorizedWanTarget).filter(AuthorizedWanTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="WAN target not found")
    if target.archived_at is None:
        target.archived_at = utcnow()
        record_audit(
            db,
            actor=user,
            action="wan_target.archive",
            object_type="wan_target",
            object_id=target.id,
            tenant_id=target.tenant_id,
            details={"type": target.target_type, "normalized": target.normalized_value, "name": target.name},
        )
        from app.events import emit_wan_target_changed

        emit_wan_target_changed(db, target, change="archived")
        db.commit()
        db.refresh(target)
    return target


def _sync_companion_subnet(db: Session, target: AuthorizedWanTarget) -> None:
    if target.target_type == "fqdn":
        return
    existing = (
        db.query(Subnet)
        .filter(
            Subnet.tenant_id == target.tenant_id,
            Subnet.scope == "wan",
            Subnet.cidr == target.normalized_value,
        )
        .first()
    )
    if existing:
        return
    db.add(
        Subnet(
            tenant_id=target.tenant_id,
            name=target.name,
            cidr=target.normalized_value,
            scope="wan",
        )
    )
