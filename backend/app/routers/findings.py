from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, joinedload

from app.auth import require_any
from app.database import get_db
from app.models import Device, Finding, Tenant, User
from app.routers.devices import _finding_out
from app.schemas import FindingOut

router = APIRouter(tags=["findings"])


@router.get("/tenants/{tenant_id}/findings", response_model=list[FindingOut])
def list_findings(
    tenant_id: int,
    severity: str | None = None,
    host: str | None = None,
    hostname: str | None = None,
    device_id: int | None = None,
    template_id: str | None = None,
    scan_job_id: int | None = None,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    if not db.query(Tenant).filter(Tenant.id == tenant_id).first():
        raise HTTPException(status_code=404, detail="Tenant not found")
    query = db.query(Finding).options(joinedload(Finding.device)).filter(Finding.tenant_id == tenant_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if device_id:
        query = query.filter(Finding.device_id == device_id)
    if hostname:
        like = f"%{hostname}%"
        query = query.outerjoin(Device, Finding.device_id == Device.id).filter(
            (Finding.hostname.ilike(like)) | (Device.hostname.ilike(like)) | (Device.ip.ilike(like))
        )
    if host:
        query = query.filter(Finding.host.ilike(f"%{host}%"))
    if template_id:
        query = query.filter(Finding.template_id.ilike(f"%{template_id}%"))
    if scan_job_id:
        query = query.filter(Finding.scan_job_id == scan_job_id)
    rows = query.order_by(Finding.found_at.desc()).limit(2000).all()
    return [_finding_out(f) for f in rows]


@router.get("/tenants/{tenant_id}/findings/export")
def export_findings(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    if not db.query(Tenant).filter(Tenant.id == tenant_id).first():
        raise HTTPException(status_code=404, detail="Tenant not found")
    rows = (
        db.query(Finding)
        .options(joinedload(Finding.device))
        .filter(Finding.tenant_id == tenant_id)
        .order_by(Finding.found_at.desc())
        .all()
    )
    lines = ["found_at,severity,hostname,ip,template_id,name,host,matched_at,tags"]
    for f in rows:
        item = _finding_out(f)
        lines.append(
            ",".join(
                [
                    f.found_at.isoformat() if f.found_at else "",
                    f.severity,
                    _csv(item.hostname),
                    _csv(item.ip),
                    _csv(f.template_id),
                    _csv(f.name),
                    _csv(f.host),
                    _csv(f.matched_at),
                    _csv(f.tags),
                ]
            )
        )
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/csv")


def _csv(value: str) -> str:
    text = (value or "").replace('"', '""')
    return f'"{text}"'
