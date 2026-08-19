from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import is_internal_operator, require_visible_tenant
from app.audit import record_audit, utcnow
from app.auth import require_admin, require_any, require_user
from app.database import get_db
from app.locality import get_network, get_site, get_tenant
from app.models import EXCLUSION_SCOPE_GLOBAL, Scan, ScanExclusion, User
from app.scan_exclusions import ExclusionError, assert_scope_keys, normalize_exclusion
from app.schemas import ScanExclusionIn, ScanExclusionOut

router = APIRouter(tags=["scan-exclusions"])


@router.get("/scan-exclusions", response_model=list[ScanExclusionOut])
def list_global_exclusions(
    include_archived: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    if not is_internal_operator(user):
        return []
    q = db.query(ScanExclusion).filter(ScanExclusion.scope == EXCLUSION_SCOPE_GLOBAL)
    if not include_archived:
        q = q.filter(ScanExclusion.archived_at.is_(None))
    return q.order_by(ScanExclusion.id).all()


@router.get("/tenants/{tenant_id}/scan-exclusions", response_model=list[ScanExclusionOut])
def list_tenant_exclusions(
    tenant_id: int,
    include_archived: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    require_visible_tenant(db, user, tenant_id)
    q = db.query(ScanExclusion).filter(ScanExclusion.tenant_id == tenant_id)
    if is_internal_operator(user):
        q = db.query(ScanExclusion).filter(
            (ScanExclusion.scope == EXCLUSION_SCOPE_GLOBAL)
            | (ScanExclusion.tenant_id == tenant_id)
        )
    if not include_archived:
        q = q.filter(ScanExclusion.archived_at.is_(None))
    return q.order_by(ScanExclusion.scope, ScanExclusion.id).all()


@router.post("/scan-exclusions", response_model=ScanExclusionOut)
def create_exclusion(body: ScanExclusionIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if body.scope == EXCLUSION_SCOPE_GLOBAL and user.role != "admin":
        raise HTTPException(status_code=403, detail="Insufficient role")
    try:
        exclusion_type, normalized = normalize_exclusion(body.exclusion_type, body.value)
        tenant_id, site_id, network_id, scan_id = _bound_scope(db, body)
        assert_scope_keys(
            body.scope,
            tenant_id=tenant_id,
            site_id=site_id,
            network_id=network_id,
            scan_id=scan_id,
        )
    except ExclusionError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    row = ScanExclusion(
        scope=body.scope,
        exclusion_type=exclusion_type,
        value=body.value.strip(),
        normalized_value=normalized,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        scan_id=scan_id,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        actor=user,
        action="scan_exclusion.create",
        object_type="scan_exclusion",
        object_id=row.id,
        tenant_id=tenant_id,
        site_id=site_id,
        details={"scope": row.scope, "type": row.exclusion_type, "normalized": row.normalized_value},
    )
    db.commit()
    db.refresh(row)
    return row


@router.post("/scan-exclusions/{exclusion_id}/archive", response_model=ScanExclusionOut)
def archive_exclusion(exclusion_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    row = db.query(ScanExclusion).filter(ScanExclusion.id == exclusion_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    if row.scope == EXCLUSION_SCOPE_GLOBAL and user.role != "admin":
        raise HTTPException(status_code=403, detail="Insufficient role")
    if row.archived_at is None:
        row.archived_at = utcnow()
        record_audit(
            db,
            actor=user,
            action="scan_exclusion.archive",
            object_type="scan_exclusion",
            object_id=row.id,
            tenant_id=row.tenant_id,
            site_id=row.site_id,
            details={"scope": row.scope, "normalized": row.normalized_value},
        )
        db.commit()
        db.refresh(row)
    return row


def create_global_exclusion(body: ScanExclusionIn, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    body.scope = EXCLUSION_SCOPE_GLOBAL
    return create_exclusion(body, user, db)


def _bound_scope(db: Session, body: ScanExclusionIn) -> tuple[int | None, int | None, int | None, int | None]:
    if body.scope == EXCLUSION_SCOPE_GLOBAL:
        return None, None, None, None
    if body.tenant_id is None:
        raise ExclusionError("tenant_id is required")
    tenant = get_tenant(db, body.tenant_id)
    site_id = body.site_id
    network_id = body.network_id
    scan_id = body.scan_id
    if site_id is not None:
        site = get_site(db, site_id, tenant_id=tenant.id)
        if site.tenant_id != tenant.id:
            raise ExclusionError("Cross-tenant exclusion reference is not allowed")
        site_id = site.id
    if network_id is not None:
        network = get_network(db, network_id, tenant_id=tenant.id)
        if network.tenant_id != tenant.id:
            raise ExclusionError("Cross-tenant exclusion reference is not allowed")
        if site_id is None:
            site_id = network.site_id
        elif network.site_id != site_id:
            raise ExclusionError("Network does not belong to the selected site")
        network_id = network.id
    if scan_id is not None:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.tenant_id != tenant.id:
            raise ExclusionError("Cross-tenant exclusion reference is not allowed")
        scan_id = scan.id
        if scan.site_id and site_id is None:
            site_id = scan.site_id
    return tenant.id, site_id, network_id, scan_id
