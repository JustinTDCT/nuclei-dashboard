from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.access import require_visible_tenant, visible_tenant_query
from app.auth import require_any, require_user
from app.database import get_db
from app.finding_lifecycle import open_finding_severity_counts
from app.intel.priority import open_finding_priority_counts
from app.models import Agent, Alert, Asset, Device, ScanJob, Tenant, User
from app.schemas import TenantIn, TenantOut

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("", response_model=list[TenantOut])
def list_tenants(user: User = Depends(require_any), db: Session = Depends(get_db)):
    return visible_tenant_query(db, user).all()


@router.post("", response_model=TenantOut)
def create_tenant(body: TenantIn, _: User = Depends(require_user), db: Session = Depends(get_db)):
    if db.query(Tenant).filter(Tenant.name == body.name).first():
        raise HTTPException(status_code=400, detail="Tenant name already exists")
    tenant = Tenant(name=body.name, notes=body.notes)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.get("/{tenant_id}", response_model=TenantOut)
def get_tenant(tenant_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    return require_visible_tenant(db, user, tenant_id)


@router.patch("/{tenant_id}", response_model=TenantOut)
def update_tenant(
    tenant_id: int, body: TenantIn, _: User = Depends(require_user), db: Session = Depends(get_db)
):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.name = body.name
    tenant.notes = body.notes
    db.commit()
    db.refresh(tenant)
    return tenant


@router.delete("/{tenant_id}")
def delete_tenant(tenant_id: int, _: User = Depends(require_user), db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    db.delete(tenant)
    db.commit()
    return {"ok": True}


@router.get("/{tenant_id}/summary")
def tenant_summary(tenant_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    require_visible_tenant(db, user, tenant_id)
    online_cut = datetime.now(timezone.utc) - timedelta(seconds=90)
    devices = dict(
        db.query(Device.status, func.count(Device.id))
        .filter(Device.tenant_id == tenant_id)
        .group_by(Device.status)
        .all()
    )
    findings = open_finding_severity_counts(db, tenant_id)
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    assets = dict(
        db.query(Asset.disposition, func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id)
        .group_by(Asset.disposition)
        .all()
    )
    expected = (
        db.query(func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id, Asset.is_expected.is_(True), Asset.first_seen.is_(None))
        .scalar()
        or 0
    )
    return {
        "devices": {k: devices.get(k, 0) for k in ("new", "known", "stale")},
        "assets": {
            "total": db.query(func.count(Asset.id)).filter(Asset.tenant_id == tenant_id).scalar() or 0,
            "unreviewed": assets.get("unreviewed", 0),
            "expected": expected,
        },
        "findings": {k: findings.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "priorities": open_finding_priority_counts(db, tenant_id),
        "agents": {
            "total": len(agents),
            "pending": sum(1 for a in agents if a.status == "pending_approval"),
            "approved": sum(1 for a in agents if a.status == "approved"),
            "online": sum(
                1
                for a in agents
                if a.last_heartbeat and a.last_heartbeat.replace(tzinfo=a.last_heartbeat.tzinfo or timezone.utc) >= online_cut
            ),
        },
        "open_alerts": db.query(func.count(Alert.id))
        .filter(Alert.tenant_id == tenant_id, Alert.is_acknowledged.is_(False))
        .scalar()
        or 0,
        "recent_jobs": [
            {
                "id": j.id,
                "scan_id": j.scan_id,
                "status": j.status,
                "hosts_found": j.hosts_found,
                "findings_count": j.findings_count,
                "created_at": j.created_at,
                "finished_at": j.finished_at,
            }
            for j in db.query(ScanJob)
            .filter(ScanJob.tenant_id == tenant_id)
            .order_by(ScanJob.created_at.desc())
            .limit(8)
            .all()
        ],
    }
