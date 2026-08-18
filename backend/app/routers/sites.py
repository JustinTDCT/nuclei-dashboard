from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from app.assets import assign_tag, get_or_create_tag, remove_tag
from app.audit import record_audit, utcnow
from app.auth import require_any, require_user
from app.database import get_db
from app.locality import get_site, get_tenant, site_name_taken
from app.models import Agent, Network, Site, Tag, User
from app.schemas import SiteIn, SiteOut, TagAssignIn, TagOut
from app.settings_store import get_settings
from app.timezones import effective_timezone, validate_iana_timezone

router = APIRouter(tags=["sites"])


def serialize_site(db: Session, site: Site, global_timezone: str | None = None) -> SiteOut:
    if global_timezone is None:
        global_timezone = get_settings(db).get("default_timezone")
    out = SiteOut.model_validate(site)
    out.is_archived = site.archived_at is not None
    out.effective_timezone = effective_timezone(site.timezone, global_timezone)
    out.network_count = db.query(Network).filter(Network.site_id == site.id).count()
    out.agent_count = db.query(Agent).filter(Agent.site_id == site.id).count()
    out.tags = [TagOut.model_validate(tag) for tag in site.tags]
    return out


@router.get("/tenants/{tenant_id}/sites", response_model=list[SiteOut])
def list_sites(
    tenant_id: int,
    include_archived: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    q = db.query(Site).options(selectinload(Site.tags)).filter(Site.tenant_id == tenant_id)
    if not include_archived:
        q = q.filter(Site.archived_at.is_(None))
    global_tz = get_settings(db).get("default_timezone")
    return [serialize_site(db, site, global_tz) for site in q.order_by(Site.name).all()]


@router.post("/tenants/{tenant_id}/sites", response_model=SiteOut)
def create_site(
    tenant_id: int,
    body: SiteIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Site name is required")
    if site_name_taken(db, tenant_id, name):
        raise HTTPException(status_code=400, detail="Site name already exists for this tenant")
    timezone = validate_iana_timezone(body.timezone, allow_empty=True)
    site = Site(tenant_id=tenant_id, name=name, timezone=timezone)
    db.add(site)
    db.flush()
    record_audit(
        db,
        actor=user,
        action="site.create",
        object_type="site",
        object_id=site.id,
        tenant_id=tenant_id,
        site_id=site.id,
        details={"name": site.name, "timezone": site.timezone},
    )
    db.commit()
    db.refresh(site)
    return serialize_site(db, site)


@router.get("/sites/{site_id}", response_model=SiteOut)
def read_site(site_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    site = get_site(db, site_id)
    return serialize_site(db, site)


@router.patch("/sites/{site_id}", response_model=SiteOut)
def update_site(
    site_id: int,
    body: SiteIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    site = get_site(db, site_id)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Site name is required")
    if site_name_taken(db, site.tenant_id, name, exclude_id=site.id):
        raise HTTPException(status_code=400, detail="Site name already exists for this tenant")
    timezone = validate_iana_timezone(body.timezone, allow_empty=True)
    before = {"name": site.name, "timezone": site.timezone}
    site.name = name
    site.timezone = timezone
    record_audit(
        db,
        actor=user,
        action="site.update",
        object_type="site",
        object_id=site.id,
        tenant_id=site.tenant_id,
        site_id=site.id,
        details={"before": before, "after": {"name": site.name, "timezone": site.timezone}},
    )
    db.commit()
    db.refresh(site)
    return serialize_site(db, site)


@router.post("/sites/{site_id}/archive", response_model=SiteOut)
def archive_site(site_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    site = get_site(db, site_id)
    if site.archived_at is None:
        site.archived_at = utcnow()
        record_audit(
            db,
            actor=user,
            action="site.archive",
            object_type="site",
            object_id=site.id,
            tenant_id=site.tenant_id,
            site_id=site.id,
            details={"name": site.name},
        )
        db.commit()
        db.refresh(site)
    return serialize_site(db, site)


@router.post("/sites/{site_id}/unarchive", response_model=SiteOut)
def unarchive_site(site_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    site = get_site(db, site_id)
    if site.archived_at is not None:
        site.archived_at = None
        record_audit(
            db,
            actor=user,
            action="site.unarchive",
            object_type="site",
            object_id=site.id,
            tenant_id=site.tenant_id,
            site_id=site.id,
            details={"name": site.name},
        )
        db.commit()
        db.refresh(site)
    return serialize_site(db, site)


@router.post("/sites/{site_id}/tags", response_model=SiteOut)
def add_site_tag(
    site_id: int,
    body: TagAssignIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    site = get_site(db, site_id)
    tag = _resolve_site_tag(db, site.tenant_id, body)
    try:
        assign_tag(site, tag)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        db,
        actor=user,
        action="site.tag_change",
        object_type="site",
        object_id=site.id,
        tenant_id=site.tenant_id,
        site_id=site.id,
        details={"op": "add", "tag_id": tag.id, "name": tag.name},
    )
    db.commit()
    db.refresh(site)
    return serialize_site(db, site)


@router.delete("/sites/{site_id}/tags/{tag_id}", response_model=SiteOut)
def delete_site_tag(
    site_id: int,
    tag_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    site = get_site(db, site_id)
    tag = db.query(Tag).filter(Tag.id == tag_id, Tag.tenant_id == site.tenant_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    remove_tag(site, tag)
    record_audit(
        db,
        actor=user,
        action="site.tag_change",
        object_type="site",
        object_id=site.id,
        tenant_id=site.tenant_id,
        site_id=site.id,
        details={"op": "remove", "tag_id": tag.id, "name": tag.name},
    )
    db.commit()
    db.refresh(site)
    return serialize_site(db, site)


def _resolve_site_tag(db: Session, tenant_id: int, body: TagAssignIn) -> Tag:
    if body.tag_id is not None:
        tag = db.query(Tag).filter(Tag.id == body.tag_id).first()
        if not tag or tag.tenant_id != tenant_id:
            raise HTTPException(status_code=400, detail="Tag does not belong to this tenant")
        return tag
    if body.name:
        try:
            return get_or_create_tag(db, tenant_id, body.name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="tag_id or name is required")
