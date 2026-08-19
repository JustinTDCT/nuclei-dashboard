import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.access import apply_tenant_scope, require_object_tenant, require_visible_site, require_visible_tenant
from app.auth import require_any, require_user
from app.compose_gen import agent_compose, agent_env
from app.database import get_db
from app.locality import drop_cross_site_authorizations, get_agent, get_site, get_tenant, require_active_site
from app.models import Agent, Tenant, User
from app.scan_dispatch import is_agent_healthy
from app.schemas import AgentCreate, AgentHeartbeatIn, AgentOut, AgentUpdate
from app.scanner_versions import agent_version_view, approved_versions_from_settings
from app.settings_store import central_url, get_settings

router = APIRouter(tags=["agents"])


def _online(agent: Agent) -> bool:
    return is_agent_healthy(agent)


def serialize(agent: Agent, include_secret: bool = False, *, approved: dict | None = None) -> AgentOut:
    out = AgentOut.model_validate(agent)
    out.online = _online(agent)
    out.site_name = agent.site.name if agent.site else None
    view = agent_version_view(agent, approved)
    out.runtime_inventory = view["runtime_inventory"]
    out.runtime_inventory_reported_at = view["runtime_inventory_reported_at"]
    out.version_status = view["version_status"]
    out.version_comparison = view["version_comparison"]
    if include_secret and agent.status in ("pending_enrollment", "pending_approval"):
        out.enrollment_secret = agent.enrollment_secret
    else:
        out.enrollment_secret = None
    return out


def _create_agent_row(db: Session, tenant: Tenant, site, name: str, user: User) -> Agent:
    require_active_site(site)
    if site.tenant_id != tenant.id:
        raise HTTPException(status_code=400, detail="Site does not belong to this tenant")
    agent = Agent(
        tenant_id=tenant.id,
        site_id=site.id,
        name=name,
        uuid=str(uuid.uuid4()),
        enrollment_secret=secrets.token_urlsafe(32),
        status="pending_enrollment",
    )
    db.add(agent)
    db.flush()
    record_audit(
        db,
        actor=user,
        action="agent.create",
        object_type="agent",
        object_id=agent.id,
        tenant_id=tenant.id,
        site_id=site.id,
        details={"name": agent.name, "uuid": agent.uuid},
    )
    return agent


def _approved(db: Session) -> dict:
    return approved_versions_from_settings(get_settings(db))


@router.get("/agents", response_model=list[AgentOut])
def list_all_agents(user: User = Depends(require_any), db: Session = Depends(get_db)):
    approved = _approved(db)
    return [
        serialize(a, approved=approved)
        for a in apply_tenant_scope(db.query(Agent), user, Agent.tenant_id).order_by(Agent.created_at.desc()).all()
    ]


@router.get("/tenants/{tenant_id}/agents", response_model=list[AgentOut])
def list_agents(tenant_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    require_visible_tenant(db, user, tenant_id)
    approved = _approved(db)
    return [
        serialize(a, approved=approved)
        for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).order_by(Agent.name).all()
    ]


@router.get("/sites/{site_id}/agents", response_model=list[AgentOut])
def list_site_agents(site_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    site = require_visible_site(db, user, site_id)
    approved = _approved(db)
    return [
        serialize(a, approved=approved)
        for a in db.query(Agent).filter(Agent.site_id == site.id).order_by(Agent.name).all()
    ]


@router.post("/tenants/{tenant_id}/agents", response_model=AgentOut)
def create_agent(
    tenant_id: int, body: AgentCreate, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    tenant = get_tenant(db, tenant_id)
    site = get_site(db, body.site_id, tenant_id=tenant_id)
    agent = _create_agent_row(db, tenant, site, body.name, user)
    db.commit()
    db.refresh(agent)
    return serialize(agent, include_secret=True, approved=_approved(db))


@router.post("/sites/{site_id}/agents", response_model=AgentOut)
def create_site_agent(
    site_id: int, body: AgentCreate, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    site = get_site(db, site_id)
    if body.site_id != site.id:
        raise HTTPException(status_code=400, detail="site_id does not match the path")
    tenant = get_tenant(db, site.tenant_id)
    agent = _create_agent_row(db, tenant, site, body.name, user)
    db.commit()
    db.refresh(agent)
    return serialize(agent, include_secret=True, approved=_approved(db))


@router.patch("/agents/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: int, body: AgentUpdate, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    agent = get_agent(db, agent_id)
    before = {"name": agent.name, "site_id": agent.site_id}
    if body.name is not None:
        agent.name = body.name
    if body.site_id is not None and body.site_id != agent.site_id:
        site = require_active_site(get_site(db, body.site_id, tenant_id=agent.tenant_id))
        agent.site_id = site.id
        drop_cross_site_authorizations(db, agent)
        record_audit(
            db,
            actor=user,
            action="agent.move_site",
            object_type="agent",
            object_id=agent.id,
            tenant_id=agent.tenant_id,
            site_id=site.id,
            details={"before": before, "after": {"name": agent.name, "site_id": agent.site_id}},
        )
    elif body.name is not None:
        record_audit(
            db,
            actor=user,
            action="agent.update",
            object_type="agent",
            object_id=agent.id,
            tenant_id=agent.tenant_id,
            site_id=agent.site_id,
            details={"before": before, "after": {"name": agent.name, "site_id": agent.site_id}},
        )
    db.commit()
    db.refresh(agent)
    return serialize(agent, approved=_approved(db))


@router.post("/agents/{agent_id}/approve", response_model=AgentOut)
def approve_agent(
    agent_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status == "revoked":
        raise HTTPException(status_code=400, detail="Agent is revoked")
    if not agent.public_key:
        raise HTTPException(status_code=400, detail="Agent has not connected yet")
    previous = agent.status
    approved_at = datetime.now(timezone.utc)
    agent.status = "approved"
    agent.approved_at = approved_at
    agent.approved_by_id = user.id
    agent.enrollment_secret = None
    record_audit(
        db,
        actor=user,
        action="agent.approve",
        object_type="agent",
        object_id=agent.id,
        tenant_id=agent.tenant_id,
        site_id=agent.site_id,
        details={
            "before": {"status": previous},
            "after": {"status": agent.status},
            "approved_at": approved_at.isoformat(),
        },
    )
    db.commit()
    db.refresh(agent)
    return serialize(agent, approved=_approved(db))


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
def revoke_agent(agent_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    previous = agent.status
    agent.status = "revoked"
    agent.enrollment_secret = None
    record_audit(
        db,
        actor=user,
        action="agent.revoke",
        object_type="agent",
        object_id=agent.id,
        tenant_id=agent.tenant_id,
        site_id=agent.site_id,
        details={"before": {"status": previous}, "after": {"status": agent.status}},
    )
    db.commit()
    db.refresh(agent)
    return serialize(agent, approved=_approved(db))


@router.get("/agents/{agent_id}", response_model=AgentOut)
def read_agent(agent_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    agent = get_agent(db, agent_id)
    require_object_tenant(db, user, agent, tenant_id=agent.tenant_id, detail="Agent not found")
    return serialize(agent, approved=_approved(db))


def _includes_active_enrollment_secret(agent: Agent, include_secret: bool) -> bool:
    return bool(include_secret and agent.enrollment_secret)


def _audit_deployment_material(db: Session, user: User, agent: Agent, *, fmt: str, include_secret: bool) -> None:
    record_audit(
        db,
        actor=user,
        action="agent.deployment_material_access",
        object_type="agent",
        object_id=agent.id,
        tenant_id=agent.tenant_id,
        site_id=agent.site_id,
        details={
            "format": fmt,
            "included_active_enrollment_secret": _includes_active_enrollment_secret(agent, include_secret),
        },
        commit=True,
    )


@router.get("/agents/{agent_id}/compose", response_class=PlainTextResponse)
def download_compose(agent_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    include = agent.status in ("pending_enrollment", "pending_approval")
    body = agent_compose(agent, central_url(db), include_secret=include)
    _audit_deployment_material(db, user, agent, fmt="compose", include_secret=include)
    return PlainTextResponse(body, media_type="text/yaml")


@router.get("/agents/{agent_id}/env", response_class=PlainTextResponse)
def download_env(agent_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    include = agent.status in ("pending_enrollment", "pending_approval")
    body = agent_env(agent, central_url(db), include_secret=include)
    _audit_deployment_material(db, user, agent, fmt="env", include_secret=include)
    return PlainTextResponse(body, media_type="text/plain")
