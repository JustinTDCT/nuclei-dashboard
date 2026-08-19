from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import (
    ACCESS_ALL_TENANTS,
    ACCESS_NONE,
    ACCESS_NOT_APPLICABLE,
    ACCESS_SELECTED,
    clear_viewer_grants,
    dormant_viewer_state,
    has_any_tenant_access,
    is_viewer,
    load_grant_ids,
    load_grant_map,
    normalize_viewer_scope,
    replace_viewer_grants,
    viewer_access_status,
)
from app.audit import record_audit
from app.auth import hash_password, require_admin
from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


def serialize_user(db: Session, user: User, *, grant_ids: list[int] | None = None) -> UserOut:
    grants = grant_ids if grant_ids is not None else (load_grant_ids(db, user.id) if is_viewer(user) else [])
    status = viewer_access_status(user, grant_count=len(grants))
    has_access = True
    if is_viewer(user):
        has_access = status in {ACCESS_ALL_TENANTS, ACCESS_SELECTED} and has_any_tenant_access(db, user)
    elif status == ACCESS_NOT_APPLICABLE:
        has_access = True
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        viewer_all_tenants=bool(user.viewer_all_tenants) if is_viewer(user) else False,
        viewer_expires_at=user.viewer_expires_at if is_viewer(user) else None,
        viewer_tenant_ids=grants if is_viewer(user) else [],
        viewer_access_status=status,
        has_tenant_access=has_access,
    )


def _scope_snapshot(user: User, grant_ids: list[int]) -> dict:
    return {
        "role": user.role,
        "is_active": user.is_active,
        "viewer_all_tenants": bool(user.viewer_all_tenants),
        "viewer_expires_at": user.viewer_expires_at.isoformat() if user.viewer_expires_at else None,
        "viewer_tenant_ids": grant_ids,
    }


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.username).all()
    grants = load_grant_map(db, [user.id for user in users])
    return [serialize_user(db, user, grant_ids=grants.get(user.id, [])) for user in users]


@router.post("", response_model=UserOut)
def create_user(body: UserCreate, actor: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == body.username) | (User.email == body.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    all_tenants, tenant_ids, expires = normalize_viewer_scope(
        role=body.role,
        viewer_all_tenants=body.viewer_all_tenants,
        viewer_tenant_ids=body.viewer_tenant_ids,
        viewer_expires_at=body.viewer_expires_at,
    )
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
        viewer_all_tenants=all_tenants,
        viewer_expires_at=expires,
    )
    db.add(user)
    db.flush()
    if user.role == "viewer":
        tenant_ids = replace_viewer_grants(db, user, tenant_ids, granted_by=actor)
    record_audit(
        db,
        actor=actor,
        action="user.created",
        object_type="user",
        object_id=user.id,
        details={
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "viewer_all_tenants": all_tenants,
            "viewer_tenant_ids": tenant_ids,
            "viewer_expires_at": expires.isoformat() if expires else None,
        },
    )
    db.commit()
    db.refresh(user)
    return serialize_user(db, user, grant_ids=tenant_ids if user.role == "viewer" else [])


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    actor: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    before_grants = load_grant_ids(db, user.id)
    before = _scope_snapshot(user, before_grants)
    previous_role = user.role
    if body.email is not None:
        user.email = body.email
    if body.password:
        user.password_hash = hash_password(body.password)
    if body.role is not None:
        if user.id == actor.id and body.role != "admin":
            raise HTTPException(status_code=400, detail="Cannot demote yourself")
        user.role = body.role
    if body.is_active is not None:
        if user.id == actor.id and not body.is_active:
            raise HTTPException(status_code=400, detail="Cannot disable yourself")
        user.is_active = body.is_active

    role_changed = previous_role != user.role
    scope_supplied = (
        body.viewer_all_tenants is not None
        or body.viewer_tenant_ids is not None
        or body.viewer_expires_at is not None
        or body.clear_viewer_expiration
    )

    if previous_role == "viewer" and user.role != "viewer":
        clear_viewer_grants(db, user)
        dormant_viewer_state(user)
    elif user.role == "viewer":
        if previous_role != "viewer" and not scope_supplied:
            clear_viewer_grants(db, user)
            dormant_viewer_state(user)
        elif scope_supplied or role_changed:
            all_tenants, tenant_ids, expires = normalize_viewer_scope(
                role="viewer",
                viewer_all_tenants=(
                    body.viewer_all_tenants
                    if body.viewer_all_tenants is not None
                    else (False if previous_role != "viewer" else user.viewer_all_tenants)
                ),
                viewer_tenant_ids=(
                    body.viewer_tenant_ids
                    if body.viewer_tenant_ids is not None
                    else ([] if previous_role != "viewer" else before_grants)
                ),
                viewer_expires_at=(
                    None
                    if body.clear_viewer_expiration
                    else (
                        body.viewer_expires_at
                        if body.viewer_expires_at is not None
                        else (None if previous_role != "viewer" else user.viewer_expires_at)
                    )
                ),
            )
            user.viewer_all_tenants = all_tenants
            user.viewer_expires_at = expires
            replace_viewer_grants(db, user, tenant_ids, granted_by=actor)
    else:
        dormant_viewer_state(user)
        clear_viewer_grants(db, user)

    after_grants = load_grant_ids(db, user.id) if user.role == "viewer" else []
    after = _scope_snapshot(user, after_grants)
    details: dict = {"before": before, "after": after}
    if before["role"] != after["role"]:
        record_audit(
            db,
            actor=actor,
            action="user.role_changed",
            object_type="user",
            object_id=user.id,
            details={"before": before["role"], "after": after["role"], **details},
        )
    if before["is_active"] != after["is_active"]:
        record_audit(
            db,
            actor=actor,
            action="user.enabled" if after["is_active"] else "user.disabled",
            object_type="user",
            object_id=user.id,
            details=details,
        )
    if before["viewer_all_tenants"] != after["viewer_all_tenants"]:
        record_audit(
            db,
            actor=actor,
            action="viewer.all_tenants_changed",
            object_type="user",
            object_id=user.id,
            details={
                "before": before["viewer_all_tenants"],
                "after": after["viewer_all_tenants"],
                **details,
            },
        )
    if before["viewer_tenant_ids"] != after["viewer_tenant_ids"]:
        record_audit(
            db,
            actor=actor,
            action="viewer.grants_changed",
            object_type="user",
            object_id=user.id,
            details={
                "added": sorted(set(after["viewer_tenant_ids"]) - set(before["viewer_tenant_ids"])),
                "removed": sorted(set(before["viewer_tenant_ids"]) - set(after["viewer_tenant_ids"])),
                **details,
            },
        )
    if before["viewer_expires_at"] != after["viewer_expires_at"]:
        record_audit(
            db,
            actor=actor,
            action="viewer.expiration_changed",
            object_type="user",
            object_id=user.id,
            details={
                "before": before["viewer_expires_at"],
                "after": after["viewer_expires_at"],
                **details,
            },
        )
    if (
        before["viewer_all_tenants"] != after["viewer_all_tenants"]
        or before["viewer_tenant_ids"] != after["viewer_tenant_ids"]
        or before["viewer_expires_at"] != after["viewer_expires_at"]
        or (previous_role == "viewer") != (user.role == "viewer")
    ):
        record_audit(
            db,
            actor=actor,
            action="viewer.scope_changed",
            object_type="user",
            object_id=user.id,
            details=details,
        )
    db.commit()
    db.refresh(user)
    return serialize_user(db, user, grant_ids=after_grants)
