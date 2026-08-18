import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth import require_any, require_user
from app.compose_gen import agent_compose, agent_env
from app.database import get_db
from app.settings_store import central_url
from app.models import Agent, Tenant, User
from app.schemas import AgentCreate, AgentOut

router = APIRouter(tags=["agents"])
ONLINE_SECONDS = 90


def _tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _online(agent: Agent) -> bool:
    if not agent.last_heartbeat:
        return False
    hb = agent.last_heartbeat
    if hb.tzinfo is None:
        hb = hb.replace(tzinfo=timezone.utc)
    return hb >= datetime.now(timezone.utc) - timedelta(seconds=ONLINE_SECONDS)


def serialize(agent: Agent, include_secret: bool = False) -> AgentOut:
    out = AgentOut.model_validate(agent)
    out.online = _online(agent)
    if include_secret and agent.status in ("pending_enrollment", "pending_approval"):
        out.enrollment_secret = agent.enrollment_secret
    else:
        out.enrollment_secret = None
    return out


@router.get("/agents", response_model=list[AgentOut])
def list_all_agents(_: User = Depends(require_any), db: Session = Depends(get_db)):
    return [serialize(a) for a in db.query(Agent).order_by(Agent.created_at.desc()).all()]


@router.get("/tenants/{tenant_id}/agents", response_model=list[AgentOut])
def list_agents(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    _tenant(db, tenant_id)
    return [
        serialize(a)
        for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).order_by(Agent.name).all()
    ]


@router.post("/tenants/{tenant_id}/agents", response_model=AgentOut)
def create_agent(
    tenant_id: int, body: AgentCreate, _: User = Depends(require_user), db: Session = Depends(get_db)
):
    _tenant(db, tenant_id)
    agent = Agent(
        tenant_id=tenant_id,
        name=body.name,
        uuid=str(uuid.uuid4()),
        enrollment_secret=secrets.token_urlsafe(32),
        status="pending_enrollment",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return serialize(agent, include_secret=True)


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
    agent.status = "approved"
    agent.approved_at = datetime.now(timezone.utc)
    agent.approved_by_id = user.id
    agent.enrollment_secret = None
    db.commit()
    db.refresh(agent)
    return serialize(agent)


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
def revoke_agent(agent_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.status = "revoked"
    agent.enrollment_secret = None
    db.commit()
    db.refresh(agent)
    return serialize(agent)


@router.get("/agents/{agent_id}/compose", response_class=PlainTextResponse)
def download_compose(agent_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    include = agent.status in ("pending_enrollment", "pending_approval")
    return PlainTextResponse(
        agent_compose(agent, central_url(db), include_secret=include), media_type="text/yaml"
    )


@router.get("/agents/{agent_id}/env", response_class=PlainTextResponse)
def download_env(agent_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    include = agent.status in ("pending_enrollment", "pending_approval")
    return PlainTextResponse(
        agent_env(agent, central_url(db), include_secret=include), media_type="text/plain"
    )
