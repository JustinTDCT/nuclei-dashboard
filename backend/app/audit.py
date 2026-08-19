from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def request_source_ip(request: Request | None) -> str:
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def record_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    object_type: str,
    object_id: int | None = None,
    tenant_id: int | None = None,
    site_id: int | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = False,
) -> AuditLog:
    row = AuditLog(
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        action=action,
        object_type=object_type,
        object_id=object_id,
        tenant_id=tenant_id,
        site_id=site_id,
        details=details or {},
        created_at=utcnow(),
    )
    db.add(row)
    if commit:
        db.commit()
        db.refresh(row)
    return row
