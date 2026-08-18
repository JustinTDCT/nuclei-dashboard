from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth import require_any
from app.database import get_db
from app.finding_lifecycle import display_severity, identity_label, nuclei_mapping_for
from app.models import (
    Asset,
    AssetFinding,
    AssetFindingHistory,
    Device,
    Finding,
    Tenant,
    User,
    Vulnerability,
)
from app.routers.assets import _current_hostname
from app.routers.devices import _finding_out
from app.schemas import AssetFindingDetail, AssetFindingHistoryOut, AssetFindingOut, FindingOut

router = APIRouter(tags=["findings"])


def _require_tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _serialize_asset_finding(db: Session, row: AssetFinding) -> AssetFindingOut:
    vulnerability = row.vulnerability
    mapping = nuclei_mapping_for(db, vulnerability.id)
    asset = row.asset
    return AssetFindingOut(
        id=row.id,
        tenant_id=row.tenant_id,
        asset_id=row.asset_id,
        asset_hostname=_current_hostname(asset) or "",
        asset_display_name=asset.display_name if asset else "",
        vulnerability_id=vulnerability.id,
        canonical_key=vulnerability.canonical_key,
        cve_id=vulnerability.cve_id,
        title=vulnerability.title or (mapping.detector_key if mapping else ""),
        identity_label=identity_label(vulnerability, mapping),
        severity=display_severity(db, row),
        technical_state=row.technical_state,
        treatment_state=row.treatment_state,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        resolved_at=row.resolved_at,
        consecutive_clean_scans=row.consecutive_clean_scans,
        reopened_count=row.reopened_count,
        evidence_count=len(row.evidence) if row.evidence is not None else 0,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _get_tenant_asset_finding(db: Session, tenant_id: int, asset_finding_id: int) -> AssetFinding:
    _require_tenant(db, tenant_id)
    row = (
        db.query(AssetFinding)
        .options(
            selectinload(AssetFinding.vulnerability),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
            selectinload(AssetFinding.evidence),
            selectinload(AssetFinding.history),
        )
        .filter(AssetFinding.id == asset_finding_id, AssetFinding.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    return row


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
    _require_tenant(db, tenant_id)
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
    _require_tenant(db, tenant_id)
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


@router.get("/tenants/{tenant_id}/asset-findings", response_model=list[AssetFindingOut])
def list_asset_findings(
    tenant_id: int,
    technical_state: str | None = None,
    severity: str | None = None,
    asset_id: int | None = None,
    vulnerability_id: int | None = None,
    canonical_key: str | None = None,
    cve_id: str | None = None,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    query = (
        db.query(AssetFinding)
        .options(
            selectinload(AssetFinding.vulnerability),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
            selectinload(AssetFinding.evidence),
        )
        .filter(AssetFinding.tenant_id == tenant_id)
    )
    if technical_state:
        query = query.filter(AssetFinding.technical_state == technical_state)
    if asset_id:
        query = query.filter(AssetFinding.asset_id == asset_id)
    if vulnerability_id:
        query = query.filter(AssetFinding.vulnerability_id == vulnerability_id)
    if canonical_key or cve_id:
        query = query.join(Vulnerability, AssetFinding.vulnerability_id == Vulnerability.id)
        if canonical_key:
            query = query.filter(Vulnerability.canonical_key == canonical_key)
        if cve_id:
            query = query.filter(Vulnerability.cve_id == cve_id.upper())
    rows = query.order_by(AssetFinding.last_seen.desc(), AssetFinding.id.desc()).limit(2000).all()
    items = [_serialize_asset_finding(db, row) for row in rows]
    if severity:
        items = [item for item in items if item.severity == severity]
    return items


@router.get("/tenants/{tenant_id}/asset-findings/{asset_finding_id}", response_model=AssetFindingDetail)
def get_tenant_asset_finding(
    tenant_id: int,
    asset_finding_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    return _asset_finding_detail(db, _get_tenant_asset_finding(db, tenant_id, asset_finding_id))


@router.get("/tenants/{tenant_id}/asset-findings/{asset_finding_id}/evidence", response_model=list[FindingOut])
def list_tenant_asset_finding_evidence(
    tenant_id: int,
    asset_finding_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = _get_tenant_asset_finding(db, tenant_id, asset_finding_id)
    evidence = sorted(row.evidence, key=lambda item: (item.found_at, item.id), reverse=True)
    return [_finding_out(item) for item in evidence]


@router.get(
    "/tenants/{tenant_id}/asset-findings/{asset_finding_id}/history",
    response_model=list[AssetFindingHistoryOut],
)
def list_tenant_asset_finding_history(
    tenant_id: int,
    asset_finding_id: int,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = _get_tenant_asset_finding(db, tenant_id, asset_finding_id)
    history = sorted(row.history, key=lambda item: (item.occurred_at, item.id))
    return [AssetFindingHistoryOut.model_validate(item) for item in history]


@router.get("/asset-findings/{asset_finding_id}", response_model=AssetFindingDetail)
def get_asset_finding(
    asset_finding_id: int,
    tenant_id: int | None = Query(default=None),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = _load_asset_finding(db, asset_finding_id)
    if tenant_id is not None and row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    _require_tenant(db, row.tenant_id)
    return _asset_finding_detail(db, row)


@router.get("/asset-findings/{asset_finding_id}/evidence", response_model=list[FindingOut])
def list_asset_finding_evidence(
    asset_finding_id: int,
    tenant_id: int | None = Query(default=None),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = _load_asset_finding(db, asset_finding_id)
    if tenant_id is not None and row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    _require_tenant(db, row.tenant_id)
    evidence = sorted(row.evidence, key=lambda item: (item.found_at, item.id), reverse=True)
    return [_finding_out(item) for item in evidence]


@router.get("/asset-findings/{asset_finding_id}/history", response_model=list[AssetFindingHistoryOut])
def list_asset_finding_history(
    asset_finding_id: int,
    tenant_id: int | None = Query(default=None),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    row = _load_asset_finding(db, asset_finding_id)
    if tenant_id is not None and row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    _require_tenant(db, row.tenant_id)
    history = sorted(row.history, key=lambda item: (item.occurred_at, item.id))
    return [AssetFindingHistoryOut.model_validate(item) for item in history]


def _load_asset_finding(db: Session, asset_finding_id: int) -> AssetFinding:
    row = (
        db.query(AssetFinding)
        .options(
            selectinload(AssetFinding.vulnerability),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
            selectinload(AssetFinding.evidence),
            selectinload(AssetFinding.history),
        )
        .filter(AssetFinding.id == asset_finding_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    return row


def _asset_finding_detail(db: Session, row: AssetFinding) -> AssetFindingDetail:
    mapping = nuclei_mapping_for(db, row.vulnerability_id)
    base = _serialize_asset_finding(db, row)
    history = sorted(row.history, key=lambda item: (item.occurred_at, item.id))
    evidence = sorted(row.evidence, key=lambda item: (item.found_at, item.id), reverse=True)
    return AssetFindingDetail(
        **base.model_dump(),
        description=row.vulnerability.description or "",
        detector_type=mapping.detector_type if mapping else "",
        detector_key=mapping.detector_key if mapping else "",
        history=[AssetFindingHistoryOut.model_validate(item) for item in history],
        evidence=[_finding_out(item) for item in evidence],
    )


def _csv(value: str) -> str:
    text = (value or "").replace('"', '""')
    return f'"{text}"'
