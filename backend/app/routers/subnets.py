from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import require_visible_tenant
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
from app.models import DISPATCH_ANY_AVAILABLE, AuthorizedWanTarget, Network, Subnet, User
from app.schemas import SubnetIn, SubnetOut
from app.wan_targets import normalize_wan_target

router = APIRouter(tags=["subnets"])


@router.get("/tenants/{tenant_id}/subnets", response_model=list[SubnetOut])
def list_subnets(tenant_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    require_visible_tenant(db, user, tenant_id)
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
        db.flush()
        _upsert_wan_target_from_subnet(db, subnet, user, previous_name=None, previous_cidr=None)
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
        previous_name = subnet.name
        previous_cidr = subnet.cidr
        subnet.name = body.name
        subnet.cidr = cidr
        _upsert_wan_target_from_subnet(
            db,
            subnet,
            user,
            previous_name=previous_name,
            previous_cidr=previous_cidr,
        )
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
    _archive_wan_target_for_subnet(db, subnet, user)
    db.delete(subnet)
    db.commit()
    return {"ok": True}


def _upsert_wan_target_from_subnet(
    db: Session,
    subnet: Subnet,
    user: User,
    *,
    previous_name: str | None,
    previous_cidr: str | None,
) -> None:
    from app.audit import record_audit, utcnow

    target_type, normalized = normalize_wan_target("cidr", subnet.cidr)
    if previous_cidr:
        try:
            _, previous_normalized = normalize_wan_target("cidr", previous_cidr)
        except Exception:
            previous_normalized = None
        if previous_normalized and previous_normalized != normalized:
            previous = (
                db.query(AuthorizedWanTarget)
                .filter(
                    AuthorizedWanTarget.tenant_id == subnet.tenant_id,
                    AuthorizedWanTarget.archived_at.is_(None),
                    AuthorizedWanTarget.normalized_value == previous_normalized,
                )
                .all()
            )
            for row in previous:
                row.archived_at = utcnow()
                record_audit(
                    db,
                    actor=user,
                    action="wan_target.archive",
                    object_type="wan_target",
                    object_id=row.id,
                    tenant_id=subnet.tenant_id,
                    details={"via": "subnet_api", "normalized": row.normalized_value, "replaced_by": normalized},
                )
    existing = (
        db.query(AuthorizedWanTarget)
        .filter(
            AuthorizedWanTarget.tenant_id == subnet.tenant_id,
            AuthorizedWanTarget.normalized_value == normalized,
            AuthorizedWanTarget.archived_at.is_(None),
        )
        .first()
    )
    if existing:
        existing.name = subnet.name
        return
    _ = previous_name
    target = AuthorizedWanTarget(
        tenant_id=subnet.tenant_id,
        name=subnet.name,
        target_type=target_type,
        value=subnet.cidr,
        normalized_value=normalized,
    )
    db.add(target)
    db.flush()
    record_audit(
        db,
        actor=user,
        action="wan_target.create",
        object_type="wan_target",
        object_id=target.id,
        tenant_id=subnet.tenant_id,
        details={"via": "subnet_api", "normalized": normalized, "name": subnet.name},
    )


def _archive_wan_target_for_subnet(db: Session, subnet: Subnet, user: User) -> None:
    from app.audit import record_audit, utcnow

    try:
        _, normalized = normalize_wan_target("cidr", subnet.cidr)
    except Exception:
        return
    rows = (
        db.query(AuthorizedWanTarget)
        .filter(
            AuthorizedWanTarget.tenant_id == subnet.tenant_id,
            AuthorizedWanTarget.normalized_value == normalized,
            AuthorizedWanTarget.archived_at.is_(None),
        )
        .all()
    )
    for row in rows:
        row.archived_at = utcnow()
        record_audit(
            db,
            actor=user,
            action="wan_target.archive",
            object_type="wan_target",
            object_id=row.id,
            tenant_id=subnet.tenant_id,
            details={"via": "subnet_api", "normalized": normalized},
        )
