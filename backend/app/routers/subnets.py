from ipaddress import ip_network

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_any, require_user
from app.database import get_db
from app.models import Subnet, Tenant, User
from app.schemas import SubnetIn, SubnetOut

router = APIRouter(tags=["subnets"])


def _tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _valid_cidr(cidr: str) -> str:
    try:
        return str(ip_network(cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid CIDR") from exc


@router.get("/tenants/{tenant_id}/subnets", response_model=list[SubnetOut])
def list_subnets(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    _tenant(db, tenant_id)
    return db.query(Subnet).filter(Subnet.tenant_id == tenant_id).order_by(Subnet.scope, Subnet.name).all()


@router.post("/tenants/{tenant_id}/subnets", response_model=SubnetOut)
def create_subnet(
    tenant_id: int, body: SubnetIn, _: User = Depends(require_user), db: Session = Depends(get_db)
):
    _tenant(db, tenant_id)
    subnet = Subnet(tenant_id=tenant_id, name=body.name, cidr=_valid_cidr(body.cidr), scope=body.scope)
    db.add(subnet)
    db.commit()
    db.refresh(subnet)
    return subnet


@router.patch("/subnets/{subnet_id}", response_model=SubnetOut)
def update_subnet(
    subnet_id: int, body: SubnetIn, _: User = Depends(require_user), db: Session = Depends(get_db)
):
    subnet = db.query(Subnet).filter(Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")
    subnet.name = body.name
    subnet.cidr = _valid_cidr(body.cidr)
    subnet.scope = body.scope
    db.commit()
    db.refresh(subnet)
    return subnet


@router.delete("/subnets/{subnet_id}")
def delete_subnet(subnet_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    subnet = db.query(Subnet).filter(Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")
    db.delete(subnet)
    db.commit()
    return {"ok": True}
