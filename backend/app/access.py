"""Central Tenant-scope authorization for staff roles, including Viewers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import Select, false, select, true
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from app.locality import get_network, get_site, get_tenant
from app.models import Tenant, User, ViewerTenantGrant

VIEWER_EXPIRED_DETAIL = "Viewer access has expired"
VIEWER_NO_ACCESS_DETAIL = "No tenant access has been assigned to this account."
INTERNAL_ROLES = frozenset({"admin", "user"})
VIEWER_ROLE = "viewer"

ACCESS_NOT_APPLICABLE = "not_applicable"
ACCESS_DISABLED = "disabled"
ACCESS_EXPIRED = "expired"
ACCESS_ALL_TENANTS = "all_tenants"
ACCESS_SELECTED = "selected"
ACCESS_NONE = "none"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_internal_operator(user: User) -> bool:
    return user.role in INTERNAL_ROLES


def is_viewer(user: User) -> bool:
    return user.role == VIEWER_ROLE


def viewer_is_expired(user: User, *, now: datetime | None = None) -> bool:
    if not is_viewer(user) or user.viewer_expires_at is None:
        return False
    expires = _aware(user.viewer_expires_at)
    if expires is None:
        return False
    current = _aware(now) or utcnow()
    return expires <= current


def assert_staff_usable(user: User, *, now: datetime | None = None) -> User:
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or missing")
    if viewer_is_expired(user, now=now):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=VIEWER_EXPIRED_DETAIL)
    return user


def has_all_tenant_access(user: User) -> bool:
    if is_internal_operator(user):
        return True
    return is_viewer(user) and bool(user.viewer_all_tenants)


def grant_subquery(user_id: int) -> Select[tuple[int]]:
    return select(ViewerTenantGrant.tenant_id).where(ViewerTenantGrant.user_id == user_id)


def tenant_scope_clause(
    user: User,
    tenant_column: Any,
    *,
    include_unscoped: bool = False,
) -> ColumnElement[bool]:
    """SQL predicate limiting a Tenant-scoped column to the actor's grants.

    Viewers never receive unscoped (NULL tenant) rows unless include_unscoped
    is explicitly requested, which is reserved for internal operators.
    """
    if is_internal_operator(user):
        return true()
    if not is_viewer(user):
        return false()
    if user.viewer_all_tenants:
        return true() if include_unscoped else tenant_column.isnot(None)
    return tenant_column.in_(grant_subquery(user.id))


def apply_tenant_scope(query, user: User, tenant_column: Any, *, include_unscoped: bool = False):
    return query.filter(tenant_scope_clause(user, tenant_column, include_unscoped=include_unscoped))


def visible_tenant_query(db: Session, user: User):
    return apply_tenant_scope(db.query(Tenant), user, Tenant.id).order_by(Tenant.name, Tenant.id)


def visible_tenant_ids(db: Session, user: User) -> list[int]:
    if has_all_tenant_access(user):
        return [row[0] for row in db.query(Tenant.id).order_by(Tenant.id).all()]
    if not is_viewer(user):
        return []
    rows = (
        db.query(ViewerTenantGrant.tenant_id)
        .filter(ViewerTenantGrant.user_id == user.id)
        .order_by(ViewerTenantGrant.tenant_id)
        .all()
    )
    return [row[0] for row in rows]


def can_access_tenant(db: Session, user: User, tenant_id: int | None) -> bool:
    if tenant_id is None:
        return is_internal_operator(user)
    if is_internal_operator(user):
        return db.query(Tenant.id).filter(Tenant.id == tenant_id).first() is not None
    if not is_viewer(user):
        return False
    if user.viewer_all_tenants:
        return db.query(Tenant.id).filter(Tenant.id == tenant_id).first() is not None
    return (
        db.query(ViewerTenantGrant.tenant_id)
        .filter(ViewerTenantGrant.user_id == user.id, ViewerTenantGrant.tenant_id == tenant_id)
        .first()
        is not None
    )


def require_tenant_access(
    db: Session,
    user: User,
    tenant_id: int | None,
    *,
    detail: str = "Tenant not found",
) -> int:
    if tenant_id is None or not can_access_tenant(db, user, tenant_id):
        raise HTTPException(status_code=404, detail=detail)
    return tenant_id


def require_visible_tenant(db: Session, user: User, tenant_id: int) -> Tenant:
    require_tenant_access(db, user, tenant_id)
    return get_tenant(db, tenant_id)


def require_visible_site(db: Session, user: User, site_id: int, *, tenant_id: int | None = None):
    site = get_site(db, site_id, tenant_id=tenant_id)
    require_tenant_access(db, user, site.tenant_id, detail="Site not found")
    return site


def require_visible_network(db: Session, user: User, network_id: int, *, tenant_id: int | None = None):
    network = get_network(db, network_id, tenant_id=tenant_id)
    require_tenant_access(db, user, network.tenant_id, detail="Network not found")
    return network


def require_object_tenant(
    db: Session,
    user: User,
    obj: Any,
    *,
    tenant_id: int | None,
    detail: str,
):
    if obj is None or not can_access_tenant(db, user, tenant_id):
        raise HTTPException(status_code=404, detail=detail)
    return obj


def viewer_access_status(user: User, *, grant_count: int | None = None, now: datetime | None = None) -> str:
    if not is_viewer(user):
        return ACCESS_NOT_APPLICABLE
    if not user.is_active:
        return ACCESS_DISABLED
    if viewer_is_expired(user, now=now):
        return ACCESS_EXPIRED
    if user.viewer_all_tenants:
        return ACCESS_ALL_TENANTS
    if grant_count is None:
        grant_count = 0
    if grant_count > 0:
        return ACCESS_SELECTED
    return ACCESS_NONE


def has_any_tenant_access(db: Session, user: User) -> bool:
    if is_internal_operator(user):
        return True
    if not is_viewer(user):
        return False
    if user.viewer_all_tenants:
        return db.query(Tenant.id).first() is not None
    return (
        db.query(ViewerTenantGrant.tenant_id).filter(ViewerTenantGrant.user_id == user.id).first()
        is not None
    )


def load_grant_ids(db: Session, user_id: int) -> list[int]:
    rows = (
        db.query(ViewerTenantGrant.tenant_id)
        .filter(ViewerTenantGrant.user_id == user_id)
        .order_by(ViewerTenantGrant.tenant_id)
        .all()
    )
    return [row[0] for row in rows]


def load_grant_map(db: Session, user_ids: list[int]) -> dict[int, list[int]]:
    if not user_ids:
        return {}
    rows = (
        db.query(ViewerTenantGrant.user_id, ViewerTenantGrant.tenant_id)
        .filter(ViewerTenantGrant.user_id.in_(user_ids))
        .order_by(ViewerTenantGrant.user_id, ViewerTenantGrant.tenant_id)
        .all()
    )
    result: dict[int, list[int]] = {user_id: [] for user_id in user_ids}
    for user_id, tenant_id in rows:
        result.setdefault(user_id, []).append(tenant_id)
    return result


def clear_viewer_grants(db: Session, user: User) -> None:
    db.query(ViewerTenantGrant).filter(ViewerTenantGrant.user_id == user.id).delete(synchronize_session=False)


def replace_viewer_grants(db: Session, user: User, tenant_ids: list[int], *, granted_by: User | None) -> list[int]:
    unique_ids = sorted({int(item) for item in tenant_ids})
    if unique_ids:
        existing = {row[0] for row in db.query(Tenant.id).filter(Tenant.id.in_(unique_ids)).all()}
        missing = [item for item in unique_ids if item not in existing]
        if missing:
            raise HTTPException(status_code=400, detail="One or more tenant grants are invalid")
    clear_viewer_grants(db, user)
    for tenant_id in unique_ids:
        db.add(
            ViewerTenantGrant(
                user_id=user.id,
                tenant_id=tenant_id,
                granted_by_user_id=granted_by.id if granted_by else None,
            )
        )
    return unique_ids


def normalize_viewer_scope(
    *,
    role: str,
    viewer_all_tenants: bool | None,
    viewer_tenant_ids: list[int] | None,
    viewer_expires_at: datetime | None,
) -> tuple[bool, list[int], datetime | None]:
    if role != VIEWER_ROLE:
        return False, [], None
    all_tenants = bool(viewer_all_tenants)
    selected = list(viewer_tenant_ids or [])
    if all_tenants and selected:
        raise HTTPException(
            status_code=400,
            detail="All-tenant Viewer access requires an empty selected tenant list",
        )
    expires = _aware(viewer_expires_at)
    return all_tenants, selected, expires


def dormant_viewer_state(user: User) -> None:
    """Clear Viewer grant state so a later role change cannot resurrect it."""
    user.viewer_all_tenants = False
    user.viewer_expires_at = None
