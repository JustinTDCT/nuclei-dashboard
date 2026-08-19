from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.access import (
    can_access_tenant,
    has_all_tenant_access,
    require_visible_site,
    require_visible_tenant,
    tenant_scope_clause,
    visible_tenant_ids,
    visible_tenant_query,
)
from app.models import Site, Tenant, User
from app.settings_store import get_settings
from app.timezones import effective_timezone


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass
class ReportContext:
    db: Session
    actor: User
    generated_at: datetime
    display_timezone: str
    requested_tenant_id: int | None = None
    site_id: int | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    filters: dict = field(default_factory=dict)
    authorized_tenant_ids: list[int] = field(default_factory=list)
    all_tenants: bool = False

    def tenant_clause(self, column):
        if self.requested_tenant_id is not None:
            return column == self.requested_tenant_id
        return tenant_scope_clause(self.actor, column)

    def scope_label(self) -> str:
        if self.requested_tenant_id is not None:
            tenant = self.db.get(Tenant, self.requested_tenant_id)
            name = tenant.name if tenant else f"Tenant {self.requested_tenant_id}"
            if self.site_id is not None:
                site = self.db.get(Site, self.site_id)
                site_name = site.name if site else f"Site {self.site_id}"
                return f"{name} / {site_name}"
            return name
        if self.all_tenants:
            return "All authorized tenants"
        if not self.authorized_tenant_ids:
            return "No tenant access"
        if len(self.authorized_tenant_ids) == 1:
            tenant = self.db.get(Tenant, self.authorized_tenant_ids[0])
            return tenant.name if tenant else "Selected tenant"
        return f"{len(self.authorized_tenant_ids)} authorized tenants"


def build_context(
    db: Session,
    actor: User,
    *,
    tenant_id: int | None = None,
    site_id: int | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    require_single_tenant: bool = False,
    extra: dict | None = None,
) -> ReportContext:
    generated_at = datetime.now(timezone.utc)
    settings = get_settings(db)
    global_tz = settings.get("default_timezone") or "UTC"
    site_tz = None
    if tenant_id is not None:
        require_visible_tenant(db, actor, tenant_id)
    if site_id is not None:
        site = require_visible_site(db, actor, site_id)
        if tenant_id is not None and site.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Site not found")
        if tenant_id is None:
            tenant_id = site.tenant_id
        site_tz = site.timezone
    if require_single_tenant and tenant_id is None:
        raise HTTPException(status_code=400, detail="This report requires exactly one tenant")
    start = _aware(date_from)
    end = _aware(date_to)
    if start and end and start > end:
        raise HTTPException(status_code=400, detail="date_from must be before date_to")
    authorized = visible_tenant_ids(db, actor) if not has_all_tenant_access(actor) else []
    return ReportContext(
        db=db,
        actor=actor,
        generated_at=generated_at,
        display_timezone=effective_timezone(site_tz, global_tz),
        requested_tenant_id=tenant_id,
        site_id=site_id,
        date_from=start,
        date_to=end,
        filters=extra or {},
        authorized_tenant_ids=authorized,
        all_tenants=has_all_tenant_access(actor) and tenant_id is None,
    )


def assert_requested_tenant(ctx: ReportContext, tenant_id: int | None) -> None:
    if tenant_id is None:
        return
    if not can_access_tenant(ctx.db, ctx.actor, tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not found")


def visible_tenants(ctx: ReportContext) -> list[Tenant]:
    query = visible_tenant_query(ctx.db, ctx.actor)
    if ctx.requested_tenant_id is not None:
        query = query.filter(Tenant.id == ctx.requested_tenant_id)
    return query.all()
