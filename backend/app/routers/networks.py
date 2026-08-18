from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import record_audit, utcnow
from app.auth import require_any, require_user
from app.database import get_db
from app.locality import (
    authorize_agent,
    authorized_agent_ids,
    companion_subnet,
    deauthorize_agent,
    get_agent,
    get_network,
    get_site,
    network_name_taken,
    require_active_site,
    set_dispatch,
    sync_lan_subnet,
    valid_cidr,
)
from app.models import DISPATCH_ANY_AVAILABLE, Network, User
from app.schemas import NetworkAuthorizationIn, NetworkIn, NetworkOut

router = APIRouter(tags=["networks"])


def serialize_network(db: Session, network: Network) -> NetworkOut:
    out = NetworkOut.model_validate(network)
    out.is_archived = network.archived_at is not None
    subnet = companion_subnet(db, network)
    out.subnet_id = subnet.id if subnet else None
    out.authorized_agent_ids = sorted(authorized_agent_ids(db, network.id))
    return out


@router.get("/sites/{site_id}/networks", response_model=list[NetworkOut])
def list_networks(
    site_id: int,
    include_archived: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    site = get_site(db, site_id)
    q = db.query(Network).filter(Network.site_id == site.id)
    if not include_archived:
        q = q.filter(Network.archived_at.is_(None))
    return [serialize_network(db, n) for n in q.order_by(Network.name).all()]


@router.get("/tenants/{tenant_id}/networks", response_model=list[NetworkOut])
def list_tenant_networks(
    tenant_id: int,
    include_archived: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    q = db.query(Network).filter(Network.tenant_id == tenant_id)
    if not include_archived:
        q = q.filter(Network.archived_at.is_(None))
    return [serialize_network(db, n) for n in q.order_by(Network.name).all()]


@router.post("/sites/{site_id}/networks", response_model=NetworkOut)
def create_network(
    site_id: int,
    body: NetworkIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    site = require_active_site(get_site(db, site_id))
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Network name is required")
    if network_name_taken(db, site.id, name):
        raise HTTPException(status_code=400, detail="Network name already exists for this site")
    cidr = valid_cidr(body.cidr)
    network = Network(
        tenant_id=site.tenant_id,
        site_id=site.id,
        name=name,
        cidr=cidr,
        dispatch_mode=DISPATCH_ANY_AVAILABLE,
        preferred_agent_id=None,
    )
    db.add(network)
    db.flush()
    sync_lan_subnet(db, network)
    set_dispatch(db, network, body.dispatch_mode, body.preferred_agent_id)
    record_audit(
        db,
        actor=user,
        action="network.create",
        object_type="network",
        object_id=network.id,
        tenant_id=site.tenant_id,
        site_id=site.id,
        details={
            "name": network.name,
            "cidr": network.cidr,
            "dispatch_mode": network.dispatch_mode,
            "preferred_agent_id": network.preferred_agent_id,
        },
    )
    db.commit()
    db.refresh(network)
    return serialize_network(db, network)


@router.get("/networks/{network_id}", response_model=NetworkOut)
def read_network(network_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    return serialize_network(db, get_network(db, network_id))


@router.patch("/networks/{network_id}", response_model=NetworkOut)
def update_network(
    network_id: int,
    body: NetworkIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    network = get_network(db, network_id)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Network name is required")
    if network_name_taken(db, network.site_id, name, exclude_id=network.id):
        raise HTTPException(status_code=400, detail="Network name already exists for this site")
    before = {
        "name": network.name,
        "cidr": network.cidr,
        "dispatch_mode": network.dispatch_mode,
        "preferred_agent_id": network.preferred_agent_id,
    }
    network.name = name
    network.cidr = valid_cidr(body.cidr)
    set_dispatch(db, network, body.dispatch_mode, body.preferred_agent_id)
    sync_lan_subnet(db, network)
    record_audit(
        db,
        actor=user,
        action="network.update",
        object_type="network",
        object_id=network.id,
        tenant_id=network.tenant_id,
        site_id=network.site_id,
        details={
            "before": before,
            "after": {
                "name": network.name,
                "cidr": network.cidr,
                "dispatch_mode": network.dispatch_mode,
                "preferred_agent_id": network.preferred_agent_id,
            },
        },
    )
    db.commit()
    db.refresh(network)
    return serialize_network(db, network)


@router.post("/networks/{network_id}/archive", response_model=NetworkOut)
def archive_network(network_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    network = get_network(db, network_id)
    if network.archived_at is None:
        network.archived_at = utcnow()
        record_audit(
            db,
            actor=user,
            action="network.archive",
            object_type="network",
            object_id=network.id,
            tenant_id=network.tenant_id,
            site_id=network.site_id,
            details={"name": network.name, "cidr": network.cidr},
        )
        db.commit()
        db.refresh(network)
    return serialize_network(db, network)


@router.post("/networks/{network_id}/unarchive", response_model=NetworkOut)
def unarchive_network(network_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    network = get_network(db, network_id)
    site = get_site(db, network.site_id)
    if site.archived_at is not None:
        raise HTTPException(status_code=400, detail="Cannot unarchive a network on an archived site")
    if network.archived_at is not None:
        network.archived_at = None
        record_audit(
            db,
            actor=user,
            action="network.unarchive",
            object_type="network",
            object_id=network.id,
            tenant_id=network.tenant_id,
            site_id=network.site_id,
            details={"name": network.name, "cidr": network.cidr},
        )
        db.commit()
        db.refresh(network)
    return serialize_network(db, network)


@router.put("/networks/{network_id}/authorized-agents", response_model=NetworkOut)
def replace_authorized_agents(
    network_id: int,
    body: NetworkAuthorizationIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    network = get_network(db, network_id)
    current = authorized_agent_ids(db, network.id)
    desired = set(body.agent_ids)
    added: list[int] = []
    removed: list[int] = []
    for agent_id in sorted(desired - current):
        authorize_agent(db, network, get_agent(db, agent_id))
        added.append(agent_id)
    for agent_id in sorted(current - desired):
        deauthorize_agent(db, network, agent_id)
        removed.append(agent_id)
    if added or removed:
        record_audit(
            db,
            actor=user,
            action="network.authorization",
            object_type="network",
            object_id=network.id,
            tenant_id=network.tenant_id,
            site_id=network.site_id,
            details={"added_agent_ids": added, "removed_agent_ids": removed, "agent_ids": sorted(desired)},
        )
    db.commit()
    db.refresh(network)
    return serialize_network(db, network)
