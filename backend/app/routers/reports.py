from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.auth import require_any
from app.database import get_db
from app.models import User
from app.reporting.catalog import assert_supported_filters, get_spec, scoped_filters, supported_filter_keys
from app.reporting.scope import build_context
from app.reporting.service import export_report, preview_report, report_catalog

router = APIRouter(prefix="/reports", tags=["reports"])


def _context(
    request: Request,
    report_key: str,
    *,
    tenant_id: int | None,
    site_id: int | None,
    date_from: datetime | None,
    date_to: datetime | None,
    extra: dict,
    user: User,
    db: Session,
):
    spec = get_spec(report_key)
    assert_supported_filters(spec, request.query_params)
    allowed = supported_filter_keys(spec)
    return spec, build_context(
        db,
        user,
        tenant_id=tenant_id if "tenant_id" in allowed else None,
        site_id=site_id if "site_id" in allowed else None,
        date_from=date_from if "date_from" in allowed else None,
        date_to=date_to if "date_to" in allowed else None,
        require_single_tenant=spec.require_single_tenant,
        extra=scoped_filters(spec, extra),
    )


@router.get("/catalog")
def catalog(_: User = Depends(require_any)):
    return report_catalog()


@router.get("/{report_key}/preview")
def preview(
    request: Request,
    report_key: str,
    tenant_id: int | None = None,
    site_id: int | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    severity: str | None = None,
    priority: str | None = None,
    kev: bool | None = None,
    lifecycle_state: str | None = None,
    disposition: str | None = None,
    criticality: str | None = None,
    include_merged: bool = False,
    treatment_type: str | None = None,
    treatment_status: str | None = None,
    include_false_positives: bool = False,
    framework_id: int | None = None,
    include_removed: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    spec, ctx = _context(
        request,
        report_key,
        tenant_id=tenant_id,
        site_id=site_id,
        date_from=date_from,
        date_to=date_to,
        extra={
            "severity": severity,
            "priority": priority,
            "kev": kev,
            "lifecycle_state": lifecycle_state,
            "disposition": disposition,
            "criticality": criticality,
            "include_merged": include_merged,
            "treatment_type": treatment_type,
            "treatment_status": treatment_status,
            "include_false_positives": include_false_positives,
            "framework_id": framework_id,
            "include_removed": include_removed,
        },
        user=user,
        db=db,
    )
    return preview_report(ctx, spec.key, page=page, page_size=page_size)


@router.get("/{report_key}/export")
def export(
    request: Request,
    report_key: str,
    format: str = Query(default="csv", alias="format"),
    tenant_id: int | None = None,
    site_id: int | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    severity: str | None = None,
    priority: str | None = None,
    kev: bool | None = None,
    lifecycle_state: str | None = None,
    disposition: str | None = None,
    criticality: str | None = None,
    include_merged: bool = False,
    treatment_type: str | None = None,
    treatment_status: str | None = None,
    include_false_positives: bool = False,
    framework_id: int | None = None,
    include_removed: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    spec, ctx = _context(
        request,
        report_key,
        tenant_id=tenant_id,
        site_id=site_id,
        date_from=date_from,
        date_to=date_to,
        extra={
            "severity": severity,
            "priority": priority,
            "kev": kev,
            "lifecycle_state": lifecycle_state,
            "disposition": disposition,
            "criticality": criticality,
            "include_merged": include_merged,
            "treatment_type": treatment_type,
            "treatment_status": treatment_status,
            "include_false_positives": include_false_positives,
            "framework_id": framework_id,
            "include_removed": include_removed,
        },
        user=user,
        db=db,
    )
    return export_report(ctx, spec.key, format.lower())
