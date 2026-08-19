from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, selectinload

from app.access import apply_tenant_scope, is_internal_operator, require_tenant_access
from app.auth import require_any
from app.database import get_db
from app.models import EVENT_TYPE_LABELS, AuditLog, DomainEvent, Tenant, User

router = APIRouter(tags=["history"])


def _page(items, total: int, limit: int, offset: int) -> dict:
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/audit-history")
def audit_history(
    tenant_id: int | None = None,
    site_id: int | None = None,
    actor: str | None = None,
    action: str | None = None,
    object_type: str | None = None,
    object_id: int | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    if tenant_id is not None:
        require_tenant_access(db, user, tenant_id)
    query = apply_tenant_scope(db.query(AuditLog), user, AuditLog.tenant_id)
    if not is_internal_operator(user):
        query = query.filter(AuditLog.tenant_id.isnot(None))
    if tenant_id is not None:
        query = query.filter(AuditLog.tenant_id == tenant_id)
    if site_id is not None:
        query = query.filter(AuditLog.site_id == site_id)
    if actor:
        query = query.filter(AuditLog.actor_username.ilike(f"%{actor}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    if object_type:
        query = query.filter(AuditLog.object_type == object_type)
    if object_id is not None:
        query = query.filter(AuditLog.object_id == object_id)
    if date_from is not None:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to is not None:
        query = query.filter(AuditLog.created_at <= date_to)
    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(limit).all()
    tenant_ids = {row.tenant_id for row in rows if row.tenant_id}
    names = {item.id: item.name for item in db.query(Tenant).filter(Tenant.id.in_(tenant_ids or {0})).all()}
    items = [
        {
            "id": row.id,
            "created_at": row.created_at,
            "tenant_id": row.tenant_id,
            "tenant_name": names.get(row.tenant_id) if row.tenant_id else None,
            "site_id": row.site_id,
            "actor": row.actor_username,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "summary": f"{row.action} {row.object_type}" + (f" #{row.object_id}" if row.object_id else ""),
            "details": row.details or {},
        }
        for row in rows
    ]
    return _page(items, total, limit, offset)


@router.get("/domain-events")
def domain_event_history(
    tenant_id: int | None = None,
    site_id: int | None = None,
    network_id: int | None = None,
    event_type: str | None = None,
    asset_id: int | None = None,
    finding_id: int | None = None,
    agent_id: int | None = None,
    scan_job_id: int | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    if tenant_id is not None:
        require_tenant_access(db, user, tenant_id)
    query = apply_tenant_scope(
        db.query(DomainEvent).options(selectinload(DomainEvent.site)),
        user,
        DomainEvent.tenant_id,
    )
    if not is_internal_operator(user):
        query = query.filter(DomainEvent.tenant_id.isnot(None))
    if tenant_id is not None:
        query = query.filter(DomainEvent.tenant_id == tenant_id)
    if site_id is not None:
        query = query.filter(DomainEvent.site_id == site_id)
    if network_id is not None:
        query = query.filter(DomainEvent.network_id == network_id)
    if event_type:
        query = query.filter(DomainEvent.event_type == event_type)
    if asset_id is not None:
        query = query.filter(DomainEvent.asset_id == asset_id)
    if finding_id is not None:
        query = query.filter(DomainEvent.asset_finding_id == finding_id)
    if agent_id is not None:
        query = query.filter(DomainEvent.agent_id == agent_id)
    if scan_job_id is not None:
        query = query.filter(DomainEvent.scan_job_id == scan_job_id)
    if date_from is not None:
        query = query.filter(DomainEvent.occurred_at >= date_from)
    if date_to is not None:
        query = query.filter(DomainEvent.occurred_at <= date_to)
    total = query.count()
    rows = query.order_by(DomainEvent.occurred_at.desc(), DomainEvent.id.desc()).offset(offset).limit(limit).all()
    tenant_ids = {row.tenant_id for row in rows if row.tenant_id}
    names = {item.id: item.name for item in db.query(Tenant).filter(Tenant.id.in_(tenant_ids or {0})).all()}
    items = [
        {
            "id": row.id,
            "occurred_at": row.occurred_at,
            "tenant_id": row.tenant_id,
            "tenant_name": names.get(row.tenant_id) if row.tenant_id else None,
            "site_id": row.site_id,
            "site_name": row.site.name if row.site else None,
            "network_id": row.network_id,
            "event_type": row.event_type,
            "event_label": EVENT_TYPE_LABELS.get(row.event_type, row.event_type),
            "asset_id": row.asset_id,
            "asset_finding_id": row.asset_finding_id,
            "agent_id": row.agent_id,
            "scan_job_id": row.scan_job_id,
            "source": row.source,
            "summary": EVENT_TYPE_LABELS.get(row.event_type, row.event_type),
            "details": row.details or {},
        }
        for row in rows
    ]
    return _page(items, total, limit, offset)
