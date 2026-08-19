from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth import require_any
from app.database import get_db
from app.models import User
from app.reporting.catalog import get_spec
from app.reporting.scope import build_context
from app.reporting.service import export_report, preview_report, report_catalog

router = APIRouter(prefix="/reports", tags=["reports"])


def _bool(value: bool | None) -> bool | None:
    return value


@router.get("/catalog")
def catalog(_: User = Depends(require_any)):
    return report_catalog()


@router.get("/{report_key}/preview")
def preview(
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
    spec = get_spec(report_key)
    ctx = build_context(
        db,
        user,
        tenant_id=tenant_id,
        site_id=site_id,
        date_from=date_from,
        date_to=date_to,
        require_single_tenant=spec.require_single_tenant,
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
    )
    return preview_report(ctx, report_key, page=page, page_size=page_size)


@router.get("/{report_key}/export")
def export(
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
    spec = get_spec(report_key)
    ctx = build_context(
        db,
        user,
        tenant_id=tenant_id,
        site_id=site_id,
        date_from=date_from,
        date_to=date_to,
        require_single_tenant=spec.require_single_tenant,
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
    )
    return export_report(ctx, report_key, format.lower())
