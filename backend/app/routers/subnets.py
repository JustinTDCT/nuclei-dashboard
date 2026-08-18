from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.auth import require_any, require_user
from app.database import get_db
from app.locality import (
    get_site,
    get_tenant,
    network_name_taken,
    require_active_site,
    sync_lan_subnet,
    valid_cidr,
)
from app.models import DISPATCH_ANY_AVAILABLE, Network, Subnet, User
from app.schemas import SubnetIn, SubnetOut

router = APIRouter(tags=["subnets"])


@router.get("/tenants/{tenant_id}/subnets", response_model=list[SubnetOut])
def list_subnets(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    get_tenant(db, tenant_id)
    return db.query(Subnet).filter(Subnet.tenant_id == tenant_id).order_by(Subnet.scope, Subnet.name).all()


@router.post("/tenants/{tenant_id}/subnets", response_model=SubnetOut)
def create_subnet(
    tenant_id: int,
    body: SubnetIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    cidr = valid_cidr(body.cidr)
    if body.scope == "wan":
        subnet = Subnet(tenant_id=tenant_id, name=body.name, cidr=cidr, scope="wan")
        db.add(subnet)
        db.commit()
        db.refresh(subnet)
        return subnet

    if not body.site_id:
        raise HTTPException(status_code=400, detail="LAN subnets require a site_id")
    site = require_active_site(get_site(db, body.site_id, tenant_id=tenant_id))
    if network_name_taken(db, site.id, body.name):
        raise HTTPException(status_code=400, detail="Network name already exists for this site")
    network = Network(
        tenant_id=tenant_id,
        site_id=site.id,
        name=body.name,
        cidr=cidr,
        dispatch_mode=DISPATCH_ANY_AVAILABLE,
    )
    db.add(network)
    db.flush()
    subnet = sync_lan_subnet(db, network)
    record_audit(
        db,
        actor=user,
        action="network.create",
        object_type="network",
        object_id=network.id,
        tenant_id=tenant_id,
        site_id=site.id,
        details={"name": network.name, "cidr": network.cidr, "via": "subnet_api"},
    )
    db.commit()
    db.refresh(subnet)
    return subnet


@router.patch("/subnets/{subnet_id}", response_model=SubnetOut)
def update_subnet(
    subnet_id: int, body: SubnetIn, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    subnet = db.query(Subnet).filter(Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")
    cidr = valid_cidr(body.cidr)
    if subnet.scope == "wan":
        if body.scope != "wan":
            raise HTTPException(status_code=400, detail="Cannot convert a WAN target into a LAN network")
        subnet.name = body.name
        subnet.cidr = cidr
        db.commit()
        db.refresh(subnet)
        return subnet

    if body.scope != "lan":
        raise HTTPException(status_code=400, detail="Cannot convert a LAN network into a WAN target")
    if not subnet.network_id:
        raise HTTPException(status_code=400, detail="LAN subnet is not mapped to a site network")
    network = db.query(Network).filter(Network.id == subnet.network_id).first()
    if not network:
        raise HTTPException(status_code=400, detail="LAN subnet is not mapped to a site network")
    if network_name_taken(db, network.site_id, body.name, exclude_id=network.id):
        raise HTTPException(status_code=400, detail="Network name already exists for this site")
    before = {"name": network.name, "cidr": network.cidr}
    network.name = body.name
    network.cidr = cidr
    sync_lan_subnet(db, network)
    record_audit(
        db,
        actor=user,
        action="network.update",
        object_type="network",
        object_id=network.id,
        tenant_id=network.tenant_id,
        site_id=network.site_id,
        details={"before": before, "after": {"name": network.name, "cidr": network.cidr}, "via": "subnet_api"},
    )
    db.commit()
    db.refresh(subnet)
    return subnet


@router.delete("/subnets/{subnet_id}")
def delete_subnet(subnet_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    subnet = db.query(Subnet).filter(Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")
    if subnet.scope == "lan":
        raise HTTPException(
            status_code=400,
            detail="LAN networks cannot be deleted; archive the Network instead",
        )
    db.delete(subnet)
    db.commit()
    return {"ok": True}
