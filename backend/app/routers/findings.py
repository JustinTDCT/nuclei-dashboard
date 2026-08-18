from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import exists, or_
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth import require_any
from app.compliance import COMPLIANCE_MAPPING_DISCLAIMER, list_asset_finding_control_references
from app.database import get_db
from app.finding_lifecycle import (
    apply_severity_filter,
    display_severity,
    identity_label,
    load_asset_finding_display,
    nuclei_mapping_for,
)
from app.intel.priority import (
    apply_kev_filter,
    apply_priority_filter,
    load_finding_intelligence,
    priority_sort_sql,
    real_cwe_ids,
)
from app.models import (
    TREATMENT_STATUS_ACTIVE,
    TREATMENT_UNADDRESSED,
    Asset,
    AssetFinding,
    AssetFindingHistory,
    Device,
    Finding,
    FindingTreatment,
    Tenant,
    User,
    Vulnerability,
    VulnerabilityIntelligence,
    VulnerabilityReference,
)
from app.routers.assets import _current_hostname
from app.routers.compliance import serialize_reference
from app.routers.devices import _finding_out
from app.routers.treatments import serialize_treatment
from app.schemas import (
    AssetFindingDetail,
    AssetFindingHistoryOut,
    AssetFindingOut,
    FindingOut,
    VulnerabilityIntelligenceOut,
)
from app.treatments import display_status, utcnow as treatment_utcnow

router = APIRouter(tags=["findings"])


def _require_tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _num(value):
    return float(value) if value is not None else None


def _serialize_asset_finding(
    db: Session,
    row: AssetFinding,
    *,
    display: dict | None = None,
    intel_map: dict | None = None,
    active_treatments: dict[int, FindingTreatment] | None = None,
) -> AssetFindingOut:
    vulnerability = row.vulnerability
    info = (display or {}).get(row.id) if display is not None else None
    mapping = info["mapping"] if info else nuclei_mapping_for(db, vulnerability.id)
    severity = info["severity"] if info else display_severity(db, row)
    evidence_count = info["evidence_count"] if info else (len(row.evidence) if row.evidence is not None else 0)
    packed = (intel_map or {}).get(row.id) or {}
    intel = packed.get("intel")
    cwe_ids = packed.get("cwe_ids") or []
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
        severity=severity,
        technical_state=row.technical_state,
        treatment_state=row.treatment_state,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        resolved_at=row.resolved_at,
        consecutive_clean_scans=row.consecutive_clean_scans,
        reopened_count=row.reopened_count,
        evidence_count=evidence_count,
        priority=row.priority,
        priority_score=row.priority_score,
        priority_model_version=row.priority_model_version,
        cvss_version=intel.cvss_version if intel else None,
        cvss_base_score=_num(intel.cvss_base_score) if intel else None,
        cvss_base_severity=intel.cvss_base_severity if intel else None,
        epss_score=_num(intel.epss_score) if intel else None,
        epss_percentile=_num(intel.epss_percentile) if intel else None,
        epss_score_date=intel.epss_score_date if intel else None,
        kev=intel.kev if intel else None,
        kev_date_added=intel.kev_date_added if intel else None,
        cwe_ids=cwe_ids,
        treatment_display_status=_treatment_display(row, active_treatments),
        treatment_review_due_at=(active_treatments or {}).get(row.id).review_due_at if (active_treatments or {}).get(row.id) else None,
        treatment_expires_at=(active_treatments or {}).get(row.id).expires_at if (active_treatments or {}).get(row.id) else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _treatment_display(row: AssetFinding, active_treatments: dict[int, FindingTreatment] | None) -> str:
    current = (active_treatments or {}).get(row.id)
    if current is not None:
        return display_status(current)
    return row.treatment_state or TREATMENT_UNADDRESSED


def _active_treatments_for(db: Session, rows: list[AssetFinding]) -> dict[int, FindingTreatment]:
    ids = [row.id for row in rows]
    if not ids:
        return {}
    found = (
        db.query(FindingTreatment)
        .filter(FindingTreatment.asset_finding_id.in_(ids), FindingTreatment.status == TREATMENT_STATUS_ACTIVE)
        .all()
    )
    return {item.asset_finding_id: item for item in found}


def _get_tenant_asset_finding(db: Session, tenant_id: int, asset_finding_id: int) -> AssetFinding:
    _require_tenant(db, tenant_id)
    row = (
        db.query(AssetFinding)
        .options(
            selectinload(AssetFinding.vulnerability).selectinload(Vulnerability.intelligence),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
            selectinload(AssetFinding.evidence),
            selectinload(AssetFinding.history),
            selectinload(AssetFinding.treatments).selectinload(FindingTreatment.compensating_controls),
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
    priority: str | None = None,
    kev: bool | None = None,
    treatment_state: str | None = None,
    treatment_review_overdue: bool | None = None,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    query = (
        db.query(AssetFinding)
        .options(
            selectinload(AssetFinding.vulnerability).selectinload(Vulnerability.intelligence),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
        )
        .filter(AssetFinding.tenant_id == tenant_id)
    )
    if technical_state:
        query = query.filter(AssetFinding.technical_state == technical_state)
    if treatment_state:
        query = query.filter(AssetFinding.treatment_state == treatment_state)
    if treatment_review_overdue:
        now = treatment_utcnow()
        query = query.filter(
            exists().where(
                FindingTreatment.asset_finding_id == AssetFinding.id,
                FindingTreatment.status == TREATMENT_STATUS_ACTIVE,
                FindingTreatment.review_due_at.isnot(None),
                FindingTreatment.review_due_at <= now,
                or_(FindingTreatment.expires_at.is_(None), FindingTreatment.expires_at > now),
            )
        )
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
    query = apply_priority_filter(query, priority)
    query = apply_kev_filter(query, kev)
    query = apply_severity_filter(query, db, severity)
    rows = (
        query.order_by(priority_sort_sql(), AssetFinding.last_seen.desc(), AssetFinding.id.desc())
        .limit(2000)
        .all()
    )
    display = load_asset_finding_display(db, rows)
    intel_map = load_finding_intelligence(db, rows)
    active_treatments = _active_treatments_for(db, rows)
    return [
        _serialize_asset_finding(db, row, display=display, intel_map=intel_map, active_treatments=active_treatments)
        for row in rows
    ]


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
            selectinload(AssetFinding.vulnerability).selectinload(Vulnerability.intelligence),
            selectinload(AssetFinding.asset).selectinload(Asset.identifiers),
            selectinload(AssetFinding.evidence),
            selectinload(AssetFinding.history),
            selectinload(AssetFinding.treatments).selectinload(FindingTreatment.compensating_controls),
        )
        .filter(AssetFinding.id == asset_finding_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    return row


def _asset_finding_detail(db: Session, row: AssetFinding) -> AssetFindingDetail:
    mapping = nuclei_mapping_for(db, row.vulnerability_id)
    intel_map = load_finding_intelligence(db, [row])
    treatments = sorted(row.treatments, key=lambda item: (item.created_at, item.id))
    active = {item.asset_finding_id: item for item in treatments if item.status == TREATMENT_STATUS_ACTIVE}
    base = _serialize_asset_finding(db, row, intel_map=intel_map, active_treatments=active)
    intel = (intel_map.get(row.id) or {}).get("intel")
    history = sorted(row.history, key=lambda item: (item.occurred_at, item.id))
    evidence = sorted(row.evidence, key=lambda item: (item.found_at, item.id), reverse=True)
    current = active.get(row.id)
    refs = list_asset_finding_control_references(db, tenant_id=row.tenant_id, asset_finding=row)
    return AssetFindingDetail(
        **base.model_dump(),
        description=row.vulnerability.description or "",
        detector_type=mapping.detector_type if mapping else "",
        detector_key=mapping.detector_key if mapping else "",
        cvss_vector=intel.cvss_vector if intel else None,
        cvss_source=intel.cvss_source if intel else None,
        epss_model_version=intel.epss_model_version if intel else None,
        kev_due_date=intel.kev_due_date if intel else None,
        kev_required_action=intel.kev_required_action if intel else None,
        kev_known_ransomware_campaign_use=intel.kev_known_ransomware_campaign_use if intel else None,
        nvd_status=intel.nvd_status if intel else None,
        nvd_fetched_at=intel.nvd_fetched_at if intel else None,
        epss_fetched_at=intel.epss_fetched_at if intel else None,
        kev_fetched_at=intel.kev_fetched_at if intel else None,
        priority_explanation=row.priority_explanation,
        history=[AssetFindingHistoryOut.model_validate(item) for item in history],
        evidence=[_finding_out(item) for item in evidence],
        current_treatment=serialize_treatment(db, current) if current else None,
        treatments=[serialize_treatment(db, item) for item in treatments],
        control_references=[serialize_reference(db, item) for item in refs],
        mapping_disclaimer=COMPLIANCE_MAPPING_DISCLAIMER,
    )


NVD_ATTRIBUTION = (
    "This product uses the NVD API but is not endorsed or certified by the NVD."
)
EPSS_ATTRIBUTION = (
    "EPSS scores are published by FIRST and measure exploit likelihood, not severity."
)
KEV_ATTRIBUTION = "KEV membership is taken only from CISA's Known Exploited Vulnerabilities catalog."


def _serialize_vulnerability(db: Session, vulnerability: Vulnerability) -> VulnerabilityIntelligenceOut:
    intel = vulnerability.intelligence or db.get(VulnerabilityIntelligence, vulnerability.id)
    refs = (
        db.query(VulnerabilityReference)
        .filter(VulnerabilityReference.vulnerability_id == vulnerability.id)
        .order_by(VulnerabilityReference.id.asc())
        .all()
    )
    cwes = real_cwe_ids(db, [vulnerability.id]).get(vulnerability.id, [])
    return VulnerabilityIntelligenceOut(
        vulnerability_id=vulnerability.id,
        canonical_key=vulnerability.canonical_key,
        cve_id=vulnerability.cve_id,
        title=vulnerability.title,
        description=vulnerability.description,
        nvd_status=intel.nvd_status if intel else None,
        nvd_published_at=intel.nvd_published_at if intel else None,
        nvd_last_modified_at=intel.nvd_last_modified_at if intel else None,
        cvss_version=intel.cvss_version if intel else None,
        cvss_base_score=_num(intel.cvss_base_score) if intel else None,
        cvss_base_severity=intel.cvss_base_severity if intel else None,
        cvss_vector=intel.cvss_vector if intel else None,
        cvss_source=intel.cvss_source if intel else None,
        epss_score=_num(intel.epss_score) if intel else None,
        epss_percentile=_num(intel.epss_percentile) if intel else None,
        epss_score_date=intel.epss_score_date if intel else None,
        epss_model_version=intel.epss_model_version if intel else None,
        kev=intel.kev if intel else None,
        kev_date_added=intel.kev_date_added if intel else None,
        kev_due_date=intel.kev_due_date if intel else None,
        kev_required_action=intel.kev_required_action if intel else None,
        kev_known_ransomware_campaign_use=intel.kev_known_ransomware_campaign_use if intel else None,
        kev_vendor_project=intel.kev_vendor_project if intel else None,
        kev_product=intel.kev_product if intel else None,
        cwe_ids=cwes,
        references=[{"url": item.url, "source": item.source, "tags": item.tags or []} for item in refs],
        nvd_fetched_at=intel.nvd_fetched_at if intel else None,
        epss_fetched_at=intel.epss_fetched_at if intel else None,
        kev_fetched_at=intel.kev_fetched_at if intel else None,
        attribution={
            "nvd": NVD_ATTRIBUTION,
            "epss": EPSS_ATTRIBUTION,
            "kev": KEV_ATTRIBUTION,
            "priority": "P1–P4 is Nuclei Dashboard operational priority, not an NVD, FIRST, or CISA risk rating.",
        },
    )


@router.get("/vulnerabilities/{vulnerability_id}", response_model=VulnerabilityIntelligenceOut)
def get_vulnerability(
    vulnerability_id: int,
    tenant_id: int = Query(..., description="Tenant that has a linked Asset Finding for this vulnerability"),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    _require_tenant(db, tenant_id)
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    linked = (
        db.query(AssetFinding.id)
        .filter(AssetFinding.vulnerability_id == vulnerability.id, AssetFinding.tenant_id == tenant_id)
        .first()
    )
    if linked is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return _serialize_vulnerability(db, vulnerability)


def _csv(value: str) -> str:
    text = (value or "").replace('"', '""')
    return f'"{text}"'
