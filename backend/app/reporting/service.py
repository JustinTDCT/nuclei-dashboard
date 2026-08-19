from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.audit import record_audit
from app.reporting.catalog import catalog, get_spec
from app.reporting.csv_export import csv_response_from_spool, spool_csv
from app.reporting.pdf_export import build_pdf_bytes, pdf_response
from app.reporting.queries import (
    agent_health_query,
    agent_health_rows,
    asset_change_iter,
    asset_change_rows,
    asset_inventory_iter,
    asset_inventory_query,
    asset_inventory_rows,
    control_evidence_iter,
    control_evidence_rows,
    control_evidence_summary,
    executive_count,
    executive_iter,
    executive_rows,
    executive_summary,
    finding_count,
    finding_iter,
    finding_rows,
    resolved_extra,
    scan_history_query,
    scan_history_rows,
    serialize_agent_row,
    serialize_scan_row,
    serialize_treatment_row,
    treatment_query,
    treatment_rows,
)
from app.reporting.scope import ReportContext
from app.models import Tenant
from app.treatments import display_status
from app.usernames import load_usernames

COLUMNS = {
    "executive": [
        "asset_id",
        "tenant",
        "site",
        "display_name",
        "criticality",
        "open_finding_count",
        "lifecycle_state",
        "disposition",
    ],
    "asset_inventory": [
        "asset_id",
        "tenant",
        "site",
        "display_name",
        "hostname",
        "addresses",
        "classification",
        "lifecycle_state",
        "disposition",
        "criticality",
        "expected",
        "first_seen",
        "last_seen",
        "tags",
        "open_finding_count",
    ],
    "asset_changes": ["occurred_at", "source", "change_type", "tenant_id", "site_id", "asset_id", "actor", "summary"],
    "open_findings": [
        "asset_finding_id",
        "asset",
        "site",
        "cve_id",
        "title",
        "severity",
        "priority",
        "cvss",
        "epss",
        "kev",
        "first_seen",
        "age_days",
        "treatment_state",
        "treatment_display_status",
        "treatment_expires_at",
        "evidence_count",
    ],
    "resolved_findings": [
        "asset_finding_id",
        "asset",
        "site",
        "cve_id",
        "title",
        "severity",
        "first_seen",
        "last_seen",
        "resolved_at",
        "reopened_count",
        "latest_resolution_transition",
        "resolution_scan_job_id",
        "resolution_threshold",
        "resolution_policy",
    ],
    "treatments": [
        "treatment_id",
        "asset_finding_id",
        "asset",
        "technical_state",
        "treatment_type",
        "status",
        "display_status",
        "rationale",
        "compensating_controls",
        "created_by",
        "reviewed_by",
        "created_at",
        "expires_at",
    ],
    "cve_aging": [
        "cve_id",
        "asset",
        "site",
        "severity",
        "priority",
        "cvss",
        "epss",
        "kev",
        "first_seen",
        "age_days",
        "age_bucket",
        "treatment_display_status",
    ],
    "scan_history": [
        "job_id",
        "tenant",
        "site",
        "scan_name",
        "trigger_type",
        "scheduled_for",
        "started_at",
        "finished_at",
        "status",
        "hosts_found",
        "findings_count",
        "definition_revision",
        "snapshot_version",
        "execution_scope",
        "error",
        "agent",
        "nuclei_version",
        "nuclei_templates",
        "naabu_version",
        "httpx_version",
    ],
    "agent_health": [
        "agent_id",
        "tenant",
        "site",
        "name",
        "status",
        "healthy",
        "last_heartbeat",
        "last_ip",
        "approved_at",
        "hostname",
        "container_id",
        "agent_version",
    ],
    "control_evidence": [
        "framework",
        "framework_version",
        "control_key",
        "family",
        "title",
        "mapped_evidence_count",
        "evidence_status",
        "subject_type",
        "subject_id",
        "subject_summary",
        "reference_type",
        "notes",
        "created_by",
        "created_at",
        "removed",
        "removal_reason",
    ],
}


def report_catalog() -> list[dict[str, Any]]:
    return [
        {
            "key": spec.key,
            "display_name": spec.title,
            "description": spec.description,
            "supported_formats": list(spec.formats),
            "supported_filters": [
                {"key": item.key, "label": item.label, "kind": item.kind, "required": item.required}
                for item in spec.filters
            ],
        }
        for spec in catalog()
    ]


def _dataset(ctx: ReportContext, report_key: str, *, offset: int | None = None, limit: int | None = None):
    spec = get_spec(report_key)
    summary: dict[str, Any] = {}
    total = 0
    rows: list[dict[str, Any]]
    if report_key == "executive":
        summary = executive_summary(ctx)
        total = executive_count(ctx)
        rows = executive_rows(ctx, offset=offset, limit=limit)
    elif report_key == "asset_inventory":
        query = asset_inventory_query(ctx)
        total = query.count()
        rows = asset_inventory_rows(ctx, offset=offset, limit=limit)
    elif report_key == "asset_changes":
        total, rows = asset_change_rows(ctx, offset=offset, limit=limit)
        summary = {"service_change_history": "Not implemented. Service open/close transitions are not currently recorded."}
    elif report_key == "open_findings":
        total = finding_count(ctx, technical_state="open")
        rows = finding_rows(ctx, technical_state="open", offset=offset, limit=limit)
    elif report_key == "resolved_findings":
        total = finding_count(ctx, technical_state="resolved")
        rows = resolved_extra(ctx, finding_rows(ctx, technical_state="resolved", offset=offset, limit=limit))
    elif report_key == "treatments":
        query = treatment_query(ctx)
        total = query.count()
        rows = treatment_rows(ctx, offset=offset, limit=limit)
    elif report_key == "cve_aging":
        total = finding_count(ctx, technical_state="open", require_cve=True)
        rows = finding_rows(ctx, technical_state="open", require_cve=True, offset=offset, limit=limit)
        summary = {"age_basis": "AssetFinding.first_seen", "risk_model": "Existing P1-P4 only. No additional score."}
    elif report_key == "scan_history":
        query = scan_history_query(ctx)
        total = query.count()
        rows = scan_history_rows(ctx, offset=offset, limit=limit)
    elif report_key == "agent_health":
        query = agent_health_query(ctx)
        total = query.count()
        rows = agent_health_rows(ctx, offset=offset, limit=limit)
        summary = {"enrollment_secret": "never included"}
    elif report_key == "control_evidence":
        rows, summary, total = control_evidence_rows(ctx, offset=offset, limit=limit)
    else:
        raise HTTPException(status_code=404, detail="Report not found")
    return spec, summary, rows, total


def preview_report(ctx: ReportContext, report_key: str, *, page: int, page_size: int) -> dict[str, Any]:
    spec = get_spec(report_key)
    page_size = min(max(page_size, 1), spec.max_page_size)
    page = max(page, 1)
    offset = (page - 1) * page_size
    spec, summary, rows, total = _dataset(ctx, report_key, offset=offset, limit=page_size)
    return {
        "key": spec.key,
        "title": spec.title,
        "description": spec.description,
        "generated_at": ctx.generated_at.isoformat(),
        "timezone": ctx.display_timezone,
        "scope": ctx.scope_label(),
        "effective_tenant_ids": (
            [ctx.requested_tenant_id]
            if ctx.requested_tenant_id is not None
            else ctx.authorized_tenant_ids
            or ([tid for (tid,) in ctx.db.query(Tenant.id).all()] if ctx.all_tenants else [])
        ),
        "filters": {
            "tenant_id": ctx.requested_tenant_id,
            "site_id": ctx.site_id,
            "date_from": ctx.date_from.isoformat() if ctx.date_from else None,
            "date_to": ctx.date_to.isoformat() if ctx.date_to else None,
            **ctx.filters,
        },
        "summary": summary,
        "columns": COLUMNS[report_key],
        "rows": rows,
        "page": page,
        "page_size": page_size,
        "total": total,
    }


def report_summary(ctx: ReportContext, report_key: str) -> dict[str, Any]:
    if report_key == "executive":
        return executive_summary(ctx)
    if report_key == "asset_changes":
        return {"service_change_history": "Not implemented. Service open/close transitions are not currently recorded."}
    if report_key == "cve_aging":
        return {"age_basis": "AssetFinding.first_seen", "risk_model": "Existing P1-P4 only. No additional score."}
    if report_key == "agent_health":
        return {"enrollment_secret": "never included"}
    if report_key == "control_evidence":
        summary, _controls, _counts, _total = control_evidence_summary(ctx)
        return summary
    return {}


def _iter_rows(ctx: ReportContext, report_key: str):
    if report_key == "executive":
        yield from executive_iter(ctx)
        return
    if report_key == "asset_inventory":
        yield from asset_inventory_iter(ctx)
        return
    if report_key == "asset_changes":
        yield from asset_change_iter(ctx)
        return
    if report_key == "open_findings":
        yield from finding_iter(ctx, technical_state="open")
        return
    if report_key == "resolved_findings":
        offset = 0
        while True:
            batch = finding_rows(ctx, technical_state="resolved", offset=offset, limit=200)
            if not batch:
                return
            yield from resolved_extra(ctx, batch)
            if len(batch) < 200:
                return
            offset += 200
    if report_key == "treatments":
        offset = 0
        while True:
            batch = treatment_query(ctx).offset(offset).limit(200).all()
            if not batch:
                return
            names = load_usernames(
                ctx.db,
                [item.created_by_user_id for item in batch] + [item.reviewed_by_user_id for item in batch],
            )
            for item in batch:
                yield serialize_treatment_row(item, names)
            if len(batch) < 200:
                return
            offset += 200
    if report_key == "cve_aging":
        yield from finding_iter(ctx, technical_state="open", require_cve=True)
        return
    if report_key == "scan_history":
        offset = 0
        while True:
            batch = scan_history_query(ctx).offset(offset).limit(200).all()
            if not batch:
                return
            tenant_ids = {item.tenant_id for item in batch}
            tenants = {row.id: row.name for row in ctx.db.query(Tenant).filter(Tenant.id.in_(tenant_ids)).all()}
            for item in batch:
                yield serialize_scan_row(ctx, item, tenants)
            if len(batch) < 200:
                return
            offset += 200
    if report_key == "agent_health":
        offset = 0
        while True:
            batch = agent_health_query(ctx).offset(offset).limit(200).all()
            if not batch:
                return
            for agent in batch:
                yield serialize_agent_row(agent)
            if len(batch) < 200:
                return
            offset += 200
    if report_key == "control_evidence":
        yield from control_evidence_iter(ctx)
        return
    raise HTTPException(status_code=404, detail="Report not found")


def _audit_export(ctx: ReportContext, report_key: str, fmt: str) -> None:
    record_audit(
        ctx.db,
        actor=ctx.actor,
        action="report.export",
        object_type="report",
        tenant_id=ctx.requested_tenant_id,
        site_id=ctx.site_id,
        details={
            "report_key": report_key,
            "format": fmt,
            "tenant_id": ctx.requested_tenant_id,
            "authorized_tenant_ids": ctx.authorized_tenant_ids if not ctx.all_tenants else "all_authorized",
            "site_id": ctx.site_id,
            "filters": ctx.filters,
            "generated_at": ctx.generated_at.isoformat(),
        },
    )
    ctx.db.commit()


def export_report(ctx: ReportContext, report_key: str, fmt: str):
    spec = get_spec(report_key)
    if fmt not in spec.formats:
        raise HTTPException(status_code=400, detail=f"Format {fmt} is not supported for this report")
    columns = COLUMNS[report_key]
    filename = f"{report_key}-{ctx.generated_at.strftime('%Y%m%dT%H%M%SZ')}"
    if fmt == "csv":
        spool = spool_csv(columns, _iter_rows(ctx, report_key))
        _audit_export(ctx, report_key, fmt)
        return csv_response_from_spool(filename, spool)
    summary = report_summary(ctx, report_key)
    disclaimer = summary.get("disclaimer") if report_key in {"control_evidence", "executive"} else None
    content = build_pdf_bytes(
        title=spec.title,
        scope=ctx.scope_label(),
        generated_at=ctx.generated_at.isoformat(),
        timezone_label=ctx.display_timezone,
        filters={
            "tenant_id": ctx.requested_tenant_id,
            "site_id": ctx.site_id,
            "date_from": ctx.date_from.isoformat() if ctx.date_from else None,
            "date_to": ctx.date_to.isoformat() if ctx.date_to else None,
            **ctx.filters,
        },
        summary=summary,
        columns=columns,
        rows=_iter_rows(ctx, report_key),
        disclaimer=disclaimer,
    )
    _audit_export(ctx, report_key, fmt)
    return pdf_response(filename, content)
