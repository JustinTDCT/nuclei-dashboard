from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.auth import require_any, require_user
from app.database import get_db
from app.models import Asset, Device, Finding, Tenant, User
from app.schemas import DEVICE_CLASSES, DeviceDetail, DeviceOut, DeviceUpdate, FindingOut

router = APIRouter(tags=["devices"])


def _tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _finding_out(finding: Finding, device: Device | None = None) -> FindingOut:
    host = device or finding.device
    return FindingOut(
        id=finding.id,
        tenant_id=finding.tenant_id,
        scan_job_id=finding.scan_job_id,
        device_id=finding.device_id,
        asset_id=finding.asset_id,
        asset_finding_id=finding.asset_finding_id,
        detector_type=finding.detector_type or "",
        detector_key=finding.detector_key or "",
        hostname=(host.hostname if host else "") or finding.hostname or "",
        ip=(host.ip if host else "") or "",
        template_id=finding.template_id,
        name=finding.name,
        severity=finding.severity,
        host=finding.host,
        matched_at=finding.matched_at,
        tags=finding.tags,
        found_at=finding.found_at,
        raw_json=finding.raw_json or {},
    )


def _with_counts(db: Session, devices: list[Device]) -> list[DeviceOut]:
    if not devices:
        return []
    ids = [d.id for d in devices]
    counts = dict(
        db.query(Finding.device_id, func.count(Finding.id))
        .filter(Finding.device_id.in_(ids))
        .group_by(Finding.device_id)
        .all()
    )
    rows = []
    for device in devices:
        item = DeviceOut.model_validate(device)
        item.findings_count = int(counts.get(device.id) or 0)
        rows.append(item)
    return rows


@router.get("/tenants/{tenant_id}/devices", response_model=list[DeviceOut])
def list_devices(
    tenant_id: int,
    status: str | None = None,
    scope: str | None = None,
    q: str | None = None,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _tenant(db, tenant_id)
    query = db.query(Device).filter(Device.tenant_id == tenant_id)
    if status:
        query = query.filter(Device.status == status)
    if scope:
        query = query.filter(Device.scope == scope)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Device.ip.ilike(like))
            | (Device.classification.ilike(like))
            | (Device.hostname.ilike(like))
            | (Device.auto_label.ilike(like))
            | (Device.title.ilike(like))
            | (Device.description.ilike(like))
        )
    return _with_counts(db, query.order_by(Device.last_seen.desc()).limit(1000).all())


@router.get("/devices/{device_id}", response_model=DeviceDetail)
def get_device(device_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    findings = (
        db.query(Finding)
        .filter(Finding.device_id == device.id)
        .order_by(Finding.found_at.desc())
        .limit(2000)
        .all()
    )
    item = DeviceDetail.model_validate(device)
    item.findings = [_finding_out(f, device) for f in findings]
    item.findings_count = len(item.findings)
    return item


@router.patch("/devices/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int, body: DeviceUpdate, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if body.classification is not None:
        if body.classification not in DEVICE_CLASSES:
            raise HTTPException(status_code=400, detail="Invalid classification")
        device.classification = body.classification
    if body.description is not None:
        device.description = body.description
    if body.status is not None:
        device.status = body.status
    if device.asset_id and (body.classification is not None or body.description is not None):
        asset = db.get(Asset, device.asset_id)
        if asset is not None:
            before = {"classification": asset.classification, "description": asset.description}
            if body.classification is not None:
                asset.classification = body.classification
            if body.description is not None:
                asset.description = body.description
            record_audit(
                db,
                actor=user,
                action="asset.metadata_update",
                object_type="asset",
                object_id=asset.id,
                tenant_id=asset.tenant_id,
                site_id=asset.site_id,
                details={"before": before, "after": {
                    "classification": asset.classification,
                    "description": asset.description,
                }, "via": "device"},
            )
    db.commit()
    db.refresh(device)
    return _with_counts(db, [device])[0]


@router.get("/tenants/{tenant_id}/devices/export")
def export_devices(
    tenant_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _tenant(db, tenant_id)
    rows = db.query(Device).filter(Device.tenant_id == tenant_id).order_by(Device.hostname, Device.ip).all()
    lines = ["hostname,ip,scope,status,classification,description,auto_label,title,ports,first_seen,last_seen"]
    for d in rows:
        ports = ";".join(str(p) for p in (d.ports or []))
        lines.append(
            ",".join(
                [
                    _csv(d.hostname),
                    d.ip,
                    d.scope,
                    d.status,
                    _csv(d.classification),
                    _csv(d.description),
                    _csv(d.auto_label),
                    _csv(d.title),
                    _csv(ports),
                    d.first_seen.isoformat() if d.first_seen else "",
                    d.last_seen.isoformat() if d.last_seen else "",
                ]
            )
        )
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/csv")


def _csv(value: str) -> str:
    text = (value or "").replace('"', '""')
    return f'"{text}"'
