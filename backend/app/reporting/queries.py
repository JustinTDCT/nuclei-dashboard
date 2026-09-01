"""Canonical report queries. Preview, CSV, and PDF share these functions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Integer, and_, case, cast, func, literal, or_
from sqlalchemy.orm import Session, selectinload

from app.access import tenant_scope_clause
from app.compliance import COMPLIANCE_MAPPING_DISCLAIMER
from app.finding_lifecycle import apply_severity_filter, load_asset_finding_display, open_finding_severity_counts
from app.intel.priority import open_finding_priority_counts
from app.models import (
    EVENT_ASSET_BECAME_INACTIVE,
    EVENT_ASSET_DISPOSITION_CHANGED,
    EVENT_NEW_ASSET,
    EVENT_PREVIOUSLY_INACTIVE_RETURNED,
    HISTORY_REOPENED,
    HISTORY_RESOLVED,
    IDENTIFIER_HOSTNAME,
    TECHNICAL_OPEN,
    TECHNICAL_RESOLVED,
    TREATMENT_RECORD_ACCEPTED_RISK,
    TREATMENT_RECORD_FALSE_POSITIVE,
    TREATMENT_RECORD_MITIGATED,
    Agent,
    Asset,
    AssetAddress,
    AssetFinding,
    AssetFindingHistory,
    AssetIdentifier,
    AuditLog,
    ComplianceControl,
    ComplianceControlReference,
    DomainEvent,
    FindingTreatment,
    Scan,
    ScanJob,
    Site,
    Tenant,
    Vulnerability,
    VulnerabilityIntelligence,
)
from app.reporting.keyset import KeyCol, export_batch_size, map_keyset
from app.reporting.scope import ReportContext
from app.scan_dispatch import is_agent_healthy
from app.treatments import display_status

NOT_RECORDED = "Not Recorded"
AGE_BUCKETS = (
    ("0-30", 0, 30),
    ("31-60", 31, 60),
    ("61-90", 61, 90),
    ("91-180", 91, 180),
    ("181-365", 181, 365),
    ("365+", 366, None),
)
ASSET_AUDIT_ACTIONS = frozenset(
    {
        "asset.manual_create",
        "asset.merge",
        "asset.split",
        "asset.identifier_correct",
        "asset.move_site",
        "asset.disposition_change",
        "asset.criticality_change",
        "asset.metadata_update",
        "asset.tag_change",
        "asset.policy_classification_changed",
        "asset.policy_disposition_changed",
    }
)
CHANGE_EVENTS = frozenset(
    {
        EVENT_NEW_ASSET,
        EVENT_PREVIOUSLY_INACTIVE_RETURNED,
        EVENT_ASSET_BECAME_INACTIVE,
        EVENT_ASSET_DISPOSITION_CHANGED,
    }
)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _age_days(first_seen: datetime | None, now: datetime) -> int | None:
    if first_seen is None:
        return None
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    return max(0, int((now - first_seen.astimezone(timezone.utc)).total_seconds() // 86400))


def age_bucket(days: int | None) -> str | None:
    if days is None:
        return None
    for label, low, high in AGE_BUCKETS:
        if high is None and days >= low:
            return label
        if high is not None and low <= days <= high:
            return label
    return "365+"


def apply_common(query, ctx: ReportContext, tenant_column, site_column=None, time_column=None):
    query = query.filter(ctx.tenant_clause(tenant_column))
    if ctx.site_id is not None and site_column is not None:
        query = query.filter(site_column == ctx.site_id)
    if ctx.date_from is not None and time_column is not None:
        query = query.filter(time_column >= ctx.date_from)
    if ctx.date_to is not None and time_column is not None:
        query = query.filter(time_column <= ctx.date_to)
    return query


def _asset_base(ctx: ReportContext):
    query = ctx.db.query(Asset).options(
        selectinload(Asset.site),
        selectinload(Asset.tags),
        selectinload(Asset.addresses),
        selectinload(Asset.identifiers),
        selectinload(Asset.tenant),
    )
    query = apply_common(query, ctx, Asset.tenant_id, Asset.site_id)
    if not ctx.filters.get("include_merged"):
        query = query.filter(Asset.merged_into_asset_id.is_(None))
    lifecycle = ctx.filters.get("lifecycle_state")
    if lifecycle:
        query = query.filter(Asset.lifecycle_state == lifecycle)
    disposition = ctx.filters.get("disposition")
    if disposition:
        query = query.filter(Asset.disposition == disposition)
    criticality = ctx.filters.get("criticality")
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    return query


def _open_finding_counts(db: Session, asset_ids: list[int]) -> dict[int, int]:
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetFinding.asset_id, func.count(AssetFinding.id))
        .filter(AssetFinding.asset_id.in_(asset_ids), AssetFinding.technical_state == TECHNICAL_OPEN)
        .group_by(AssetFinding.asset_id)
        .all()
    )
    return {asset_id: int(count) for asset_id, count in rows}


def _hostname(asset: Asset) -> str | None:
    hostnames = [
        row
        for row in asset.identifiers
        if row.identifier_type == IDENTIFIER_HOSTNAME and getattr(row, "validity", "active") == "active"
    ]
    hostnames.sort(key=lambda row: row.last_seen or row.created_at, reverse=True)
    if hostnames:
        return hostnames[0].value
    return asset.display_name or None


def _addresses(asset: Asset) -> str:
    rows = sorted(asset.addresses, key=lambda row: row.last_seen or row.created_at, reverse=True)
    return ";".join(row.ip for row in rows if row.ip)


def asset_inventory_query(ctx: ReportContext):
    return _asset_base(ctx).order_by(Asset.display_name, Asset.id)


def serialize_asset_row(asset: Asset, open_count: int) -> dict[str, Any]:
    return {
        "asset_id": asset.id,
        "tenant": asset.tenant.name if asset.tenant else "",
        "tenant_id": asset.tenant_id,
        "site": asset.site.name if asset.site else "",
        "display_name": asset.display_name,
        "hostname": _hostname(asset) or "",
        "addresses": _addresses(asset),
        "classification": asset.classification,
        "lifecycle_state": asset.lifecycle_state or "",
        "disposition": asset.disposition,
        "criticality": asset.criticality,
        "expected": bool(asset.is_expected and asset.first_seen is None),
        "first_seen": _iso(asset.first_seen),
        "last_seen": _iso(asset.last_seen),
        "tags": ",".join(sorted(tag.name for tag in asset.tags)),
        "open_finding_count": open_count,
    }


def asset_inventory_rows(ctx: ReportContext, *, offset: int | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    query = asset_inventory_query(ctx)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    assets = query.all()
    counts = _open_finding_counts(ctx.db, [asset.id for asset in assets])
    return [serialize_asset_row(asset, counts.get(asset.id, 0)) for asset in assets]


def asset_inventory_keys():
    return (KeyCol(Asset.display_name), KeyCol(Asset.id))


def asset_inventory_iter(ctx: ReportContext):
    def pack(batch: list[Asset]):
        counts = _open_finding_counts(ctx.db, [item.id for item in batch])
        return [serialize_asset_row(item, counts.get(item.id, 0)) for item in batch]

    yield from map_keyset(
        asset_inventory_query(ctx),
        asset_inventory_keys(),
        session=ctx.db,
        serialize_batch=pack,
    )


def _finding_base_query(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False):
    query = (
        ctx.db.query(AssetFinding)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .join(Vulnerability, Vulnerability.id == AssetFinding.vulnerability_id)
        .outerjoin(VulnerabilityIntelligence, VulnerabilityIntelligence.vulnerability_id == Vulnerability.id)
        .options(
            selectinload(AssetFinding.asset).selectinload(Asset.site),
            selectinload(AssetFinding.asset).selectinload(Asset.tenant),
            selectinload(AssetFinding.vulnerability).selectinload(Vulnerability.intelligence),
        )
    )
    time_column = AssetFinding.first_seen
    if technical_state == TECHNICAL_RESOLVED:
        latest_resolved = (
            ctx.db.query(
                AssetFindingHistory.asset_finding_id.label("asset_finding_id"),
                func.max(AssetFindingHistory.occurred_at).label("resolved_at"),
            )
            .filter(AssetFindingHistory.transition_type == HISTORY_RESOLVED)
            .group_by(AssetFindingHistory.asset_finding_id)
            .subquery()
        )
        query = query.outerjoin(latest_resolved, latest_resolved.c.asset_finding_id == AssetFinding.id)
        time_column = func.coalesce(AssetFinding.resolved_at, latest_resolved.c.resolved_at)
    query = apply_common(query, ctx, AssetFinding.tenant_id, Asset.site_id, time_column)
    if technical_state:
        query = query.filter(AssetFinding.technical_state == technical_state)
    if require_cve:
        query = query.filter(Vulnerability.cve_id.isnot(None), Vulnerability.cve_id != "")
    query = apply_severity_filter(query, ctx.db, ctx.filters.get("severity"))
    priority = ctx.filters.get("priority")
    if priority:
        query = query.filter(AssetFinding.priority == priority)
    if ctx.filters.get("kev") is True:
        query = query.filter(VulnerabilityIntelligence.kev.is_(True))
    if ctx.filters.get("kev") is False:
        query = query.filter(or_(VulnerabilityIntelligence.kev.is_(False), VulnerabilityIntelligence.kev.is_(None)))
    return query, time_column


def _finding_query(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False):
    query, time_column = _finding_base_query(ctx, technical_state=technical_state, require_cve=require_cve)
    if technical_state == TECHNICAL_RESOLVED:
        return query.order_by(time_column.asc().nulls_last(), AssetFinding.id.asc())
    return query.order_by(AssetFinding.first_seen.asc(), AssetFinding.id.asc())


def _finding_export_query_and_keys(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False):
    query, time_column = _finding_base_query(ctx, technical_state=technical_state, require_cve=require_cve)
    if technical_state == TECHNICAL_RESOLVED:
        sort_at = time_column.label("sort_at")
        ordered = query.add_columns(sort_at).order_by(sort_at.asc().nulls_last(), AssetFinding.id.asc())
        keys = (
            KeyCol(time_column, value=lambda row: row.sort_at),
            KeyCol(AssetFinding.id, value=lambda row: row[0].id),
        )
        return ordered, keys
    keys = (KeyCol(AssetFinding.first_seen), KeyCol(AssetFinding.id))
    return query.order_by(AssetFinding.first_seen.asc(), AssetFinding.id.asc()), keys


def _active_treatments(db: Session, finding_ids: list[int]) -> dict[int, FindingTreatment]:
    if not finding_ids:
        return {}
    rows = (
        db.query(FindingTreatment)
        .filter(FindingTreatment.asset_finding_id.in_(finding_ids))
        .order_by(FindingTreatment.created_at.desc(), FindingTreatment.id.desc())
        .all()
    )
    latest: dict[int, FindingTreatment] = {}
    for row in rows:
        latest.setdefault(row.asset_finding_id, row)
    return latest


def serialize_finding_row(
    ctx: ReportContext,
    row: AssetFinding,
    *,
    evidence_count: int,
    treatment: FindingTreatment | None,
    severity: str = "info",
) -> dict[str, Any]:
    vuln = row.vulnerability
    intel = vuln.intelligence if vuln else None
    asset = row.asset
    days = _age_days(row.first_seen, ctx.generated_at)
    return {
        "asset_finding_id": row.id,
        "asset_id": row.asset_id,
        "asset": asset.display_name if asset else "",
        "site": asset.site.name if asset and asset.site else "",
        "tenant": asset.tenant.name if asset and asset.tenant else "",
        "canonical_key": vuln.canonical_key if vuln else "",
        "cve_id": vuln.cve_id if vuln else "",
        "title": vuln.title if vuln else "",
        "severity": severity,
        "priority": row.priority or "",
        "priority_sources": ",".join(
            str(item.get("factor") or item.get("source") or "")
            for item in ((row.priority_explanation or {}).get("factors") or [])
            if item
        ),
        "cvss": float(intel.cvss_base_score) if intel and intel.cvss_base_score is not None else "",
        "epss": float(intel.epss_score) if intel and intel.epss_score is not None else "",
        "kev": bool(intel.kev) if intel and intel.kev is not None else False,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "resolved_at": _iso(row.resolved_at),
        "age_days": days if days is not None else "",
        "age_bucket": age_bucket(days) or "",
        "technical_state": row.technical_state,
        "treatment_state": row.treatment_state,
        "treatment_display_status": display_status(treatment) if treatment else row.treatment_state,
        "treatment_expires_at": _iso(treatment.expires_at) if treatment else "",
        "treatment_review_due_at": _iso(treatment.review_due_at) if treatment else "",
        "evidence_count": evidence_count,
        "reopened_count": row.reopened_count,
    }


def finding_count(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False) -> int:
    return int(_finding_query(ctx, technical_state=technical_state, require_cve=require_cve).count())


def finding_rows(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False, offset=None, limit=None):
    query = _finding_query(ctx, technical_state=technical_state, require_cve=require_cve)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    rows = query.all()
    display = load_asset_finding_display(ctx.db, rows)
    treatments = _active_treatments(ctx.db, [row.id for row in rows])
    out = []
    for row in rows:
        packed = serialize_finding_row(
            ctx,
            row,
            evidence_count=int(display.get(row.id, {}).get("evidence_count") or 0),
            treatment=treatments.get(row.id),
            severity=str(display.get(row.id, {}).get("severity") or "info"),
        )
        if packed:
            out.append(packed)
    return out


def finding_iter(ctx: ReportContext, *, technical_state: str | None, require_cve: bool = False):
    def pack(batch):
        findings = [row[0] for row in batch] if technical_state == TECHNICAL_RESOLVED else list(batch)
        packed = list(_pack_findings(ctx, findings))
        if technical_state == TECHNICAL_RESOLVED:
            return resolved_extra(ctx, packed)
        return packed

    query, keys = _finding_export_query_and_keys(ctx, technical_state=technical_state, require_cve=require_cve)
    yield from map_keyset(
        query,
        keys,
        session=ctx.db,
        serialize_batch=pack,
    )


def _pack_findings(ctx: ReportContext, rows: list[AssetFinding]):
    display = load_asset_finding_display(ctx.db, rows)
    treatments = _active_treatments(ctx.db, [row.id for row in rows])
    for row in rows:
        packed = serialize_finding_row(
            ctx,
            row,
            evidence_count=int(display.get(row.id, {}).get("evidence_count") or 0),
            treatment=treatments.get(row.id),
            severity=str(display.get(row.id, {}).get("severity") or "info"),
        )
        if packed:
            yield packed


def resolved_extra(ctx: ReportContext, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ids = [row["asset_finding_id"] for row in rows]
    if not ids:
        return rows
    history = (
        ctx.db.query(AssetFindingHistory)
        .filter(AssetFindingHistory.asset_finding_id.in_(ids), AssetFindingHistory.transition_type == HISTORY_RESOLVED)
        .order_by(AssetFindingHistory.occurred_at.desc(), AssetFindingHistory.id.desc())
        .all()
    )
    latest: dict[int, AssetFindingHistory] = {}
    for item in history:
        latest.setdefault(item.asset_finding_id, item)
    for row in rows:
        item = latest.get(row["asset_finding_id"])
        details = item.details if item else {}
        row["latest_resolution_transition"] = item.transition_type if item else ""
        row["resolution_scan_job_id"] = item.scan_job_id if item else ""
        row["resolution_threshold"] = (details or {}).get("required_clean_scans") or (details or {}).get("threshold") or ""
        row["resolution_policy"] = (details or {}).get("policy") or (details or {}).get("source") or ""
    return rows


def _open_age_buckets(ctx: ReportContext) -> dict[str, int]:
    generated_at = ctx.generated_at
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    age_days = func.greatest(
        0,
        func.floor(func.extract("epoch", generated_at - AssetFinding.first_seen) / 86400.0),
    )
    bucket = case(
        (age_days <= 30, literal("0-30")),
        (age_days <= 60, literal("31-60")),
        (age_days <= 90, literal("61-90")),
        (age_days <= 180, literal("91-180")),
        (age_days <= 365, literal("181-365")),
        else_=literal("365+"),
    )
    labeled = bucket.label("age_bucket")
    rows = (
        apply_common(
            ctx.db.query(labeled, func.count(AssetFinding.id)).join(Asset, Asset.id == AssetFinding.asset_id),
            ctx,
            AssetFinding.tenant_id,
            Asset.site_id,
        )
        .filter(AssetFinding.technical_state == TECHNICAL_OPEN, AssetFinding.first_seen.isnot(None))
        .group_by(labeled)
        .all()
    )
    buckets = {label: 0 for label, _low, _high in AGE_BUCKETS}
    for name, count in rows:
        if name in buckets:
            buckets[name] = int(count)
    return buckets


def executive_summary(ctx: ReportContext) -> dict[str, Any]:
    assets = apply_common(ctx.db.query(func.count(Asset.id)), ctx, Asset.tenant_id, Asset.site_id)
    assets = assets.filter(Asset.merged_into_asset_id.is_(None))
    open_q = apply_common(
        ctx.db.query(func.count(AssetFinding.id)).join(Asset, Asset.id == AssetFinding.asset_id),
        ctx,
        AssetFinding.tenant_id,
        Asset.site_id,
    ).filter(AssetFinding.technical_state == TECHNICAL_OPEN)
    resolved_history = apply_common(
        ctx.db.query(func.count(AssetFindingHistory.id))
        .join(AssetFinding, AssetFinding.id == AssetFindingHistory.asset_finding_id)
        .join(Asset, Asset.id == AssetFinding.asset_id),
        ctx,
        AssetFindingHistory.tenant_id,
        Asset.site_id,
        AssetFindingHistory.occurred_at,
    ).filter(AssetFindingHistory.transition_type == HISTORY_RESOLVED)
    reopened = apply_common(
        ctx.db.query(func.count(AssetFindingHistory.id))
        .join(AssetFinding, AssetFinding.id == AssetFindingHistory.asset_finding_id)
        .join(Asset, Asset.id == AssetFinding.asset_id),
        ctx,
        AssetFindingHistory.tenant_id,
        Asset.site_id,
        AssetFindingHistory.occurred_at,
    ).filter(AssetFindingHistory.transition_type == HISTORY_REOPENED)
    kev = (
        apply_common(
            ctx.db.query(func.count(AssetFinding.id))
            .join(Asset, Asset.id == AssetFinding.asset_id)
            .join(Vulnerability, Vulnerability.id == AssetFinding.vulnerability_id)
            .join(VulnerabilityIntelligence, VulnerabilityIntelligence.vulnerability_id == Vulnerability.id),
            ctx,
            AssetFinding.tenant_id,
            Asset.site_id,
        )
        .filter(AssetFinding.technical_state == TECHNICAL_OPEN, VulnerabilityIntelligence.kev.is_(True))
        .scalar()
        or 0
    )
    cve = (
        apply_common(
            ctx.db.query(func.count(AssetFinding.id))
            .join(Asset, Asset.id == AssetFinding.asset_id)
            .join(Vulnerability, Vulnerability.id == AssetFinding.vulnerability_id),
            ctx,
            AssetFinding.tenant_id,
            Asset.site_id,
        )
        .filter(AssetFinding.technical_state == TECHNICAL_OPEN, Vulnerability.cve_id.isnot(None), Vulnerability.cve_id != "")
        .scalar()
        or 0
    )
    open_total = open_q.scalar() or 0
    treatments = dict(
        apply_common(
            ctx.db.query(AssetFinding.treatment_state, func.count(AssetFinding.id)).join(Asset, Asset.id == AssetFinding.asset_id),
            ctx,
            AssetFinding.tenant_id,
            Asset.site_id,
        )
        .filter(AssetFinding.technical_state == TECHNICAL_OPEN)
        .group_by(AssetFinding.treatment_state)
        .all()
    )
    buckets = _open_age_buckets(ctx)
    critical_assets = (
        apply_common(
            ctx.db.query(func.count(func.distinct(Asset.id)))
            .join(AssetFinding, AssetFinding.asset_id == Asset.id),
            ctx,
            Asset.tenant_id,
            Asset.site_id,
        )
        .filter(
            Asset.criticality.in_(("high", "critical")),
            AssetFinding.technical_state == TECHNICAL_OPEN,
            Asset.merged_into_asset_id.is_(None),
        )
        .scalar()
        or 0
    )
    tenant_id = ctx.requested_tenant_id
    return {
        "assets_in_scope": assets.scalar() or 0,
        "open_asset_findings": open_total,
        "open_by_severity": open_finding_severity_counts(
            ctx.db,
            tenant_id,
            tenant_filter=ctx.tenant_clause(AssetFinding.tenant_id) if tenant_id is None else None,
            site_id=ctx.site_id,
        ),
        "open_by_priority": open_finding_priority_counts(
            ctx.db,
            tenant_id,
            tenant_filter=ctx.tenant_clause(AssetFinding.tenant_id) if tenant_id is None else None,
            site_id=ctx.site_id,
        ),
        "open_kev": kev,
        "open_cve": cve,
        "open_non_cve": max(0, open_total - cve),
        "open_treatment_status": {str(key): int(value) for key, value in treatments.items()},
        "open_age_buckets": buckets,
        "high_criticality_assets_with_open_findings": critical_assets,
        "resolved_in_period": resolved_history.scalar() or 0,
        "reopened_in_period": reopened.scalar() or 0,
        "disclaimer": "These metrics describe recorded technical state. They do not rate posture, certify a framework, or invent a risk score.",
    }


def _executive_assets(ctx: ReportContext):
    return (
        apply_common(
            ctx.db.query(Asset).join(AssetFinding, AssetFinding.asset_id == Asset.id),
            ctx,
            Asset.tenant_id,
            Asset.site_id,
        )
        .filter(
            Asset.criticality.in_(("high", "critical")),
            AssetFinding.technical_state == TECHNICAL_OPEN,
            Asset.merged_into_asset_id.is_(None),
        )
        .distinct()
    )


def executive_count(ctx: ReportContext) -> int:
    return int(
        apply_common(
            ctx.db.query(func.count(func.distinct(Asset.id))).join(AssetFinding, AssetFinding.asset_id == Asset.id),
            ctx,
            Asset.tenant_id,
            Asset.site_id,
        )
        .filter(
            Asset.criticality.in_(("high", "critical")),
            AssetFinding.technical_state == TECHNICAL_OPEN,
            Asset.merged_into_asset_id.is_(None),
        )
        .scalar()
        or 0
    )


def executive_rows(ctx: ReportContext, *, offset=None, limit=None):
    query = _executive_assets(ctx).options(
        selectinload(Asset.site),
        selectinload(Asset.tenant),
        selectinload(Asset.tags),
        selectinload(Asset.addresses),
        selectinload(Asset.identifiers),
    ).order_by(Asset.criticality.desc(), Asset.display_name, Asset.id)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    assets = query.all()
    counts = _open_finding_counts(ctx.db, [asset.id for asset in assets])
    return [serialize_asset_row(asset, counts.get(asset.id, 0)) for asset in assets]


def executive_keys():
    return (
        KeyCol(Asset.criticality, descending=True),
        KeyCol(Asset.display_name),
        KeyCol(Asset.id),
    )


def executive_iter(ctx: ReportContext, *, chunk: int | None = None):
    def pack(batch: list[Asset]):
        counts = _open_finding_counts(ctx.db, [asset.id for asset in batch])
        return [serialize_asset_row(asset, counts.get(asset.id, 0)) for asset in batch]

    query = _executive_assets(ctx).options(
        selectinload(Asset.site),
        selectinload(Asset.tenant),
        selectinload(Asset.tags),
        selectinload(Asset.addresses),
        selectinload(Asset.identifiers),
    ).order_by(Asset.criticality.desc(), Asset.display_name, Asset.id)
    yield from map_keyset(
        query,
        executive_keys(),
        session=ctx.db,
        serialize_batch=pack,
        batch_size=chunk,
    )


def _asset_change_event_query(ctx: ReportContext):
    return apply_common(
        ctx.db.query(
            DomainEvent.occurred_at.label("sort_at"),
            DomainEvent.id.label("sort_id"),
            literal("domain_event").label("source"),
            DomainEvent.event_type.label("change_type"),
            DomainEvent.tenant_id.label("tenant_id"),
            DomainEvent.site_id.label("site_id"),
            DomainEvent.asset_id.label("asset_id"),
            DomainEvent.source.label("actor"),
            DomainEvent.details.label("details"),
        ),
        ctx,
        DomainEvent.tenant_id,
        DomainEvent.site_id,
        DomainEvent.occurred_at,
    ).filter(DomainEvent.event_type.in_(CHANGE_EVENTS))


def _asset_change_audit_query(ctx: ReportContext):
    return apply_common(
        ctx.db.query(
            AuditLog.created_at.label("sort_at"),
            AuditLog.id.label("sort_id"),
            literal("audit").label("source"),
            AuditLog.action.label("change_type"),
            AuditLog.tenant_id.label("tenant_id"),
            AuditLog.site_id.label("site_id"),
            AuditLog.object_id.label("asset_id"),
            AuditLog.actor_username.label("actor"),
            AuditLog.details.label("details"),
        ),
        ctx,
        AuditLog.tenant_id,
        AuditLog.site_id,
        AuditLog.created_at,
    ).filter(AuditLog.action.in_(ASSET_AUDIT_ACTIONS), AuditLog.object_type == "asset")


def _asset_change_subquery(ctx: ReportContext):
    events = _asset_change_event_query(ctx)
    audits = _asset_change_audit_query(ctx)
    return events.union_all(audits).subquery()


def asset_change_count(ctx: ReportContext) -> int:
    stmt = _asset_change_subquery(ctx)
    return int(ctx.db.query(func.count()).select_from(stmt).scalar() or 0)


def _serialize_asset_change(row) -> dict[str, Any]:
    details = row.details or {}
    summary = details.get("display_name") if row.source == "domain_event" and isinstance(details, dict) else None
    return {
        "source": row.source,
        "occurred_at": _iso(row.sort_at),
        "change_type": row.change_type,
        "tenant_id": row.tenant_id,
        "site_id": row.site_id,
        "asset_id": row.asset_id,
        "actor": row.actor or "",
        "summary": summary or row.change_type,
    }


def asset_change_rows(ctx: ReportContext, *, offset=None, limit=None) -> tuple[int, list[dict[str, Any]]]:
    stmt = _asset_change_subquery(ctx)
    total = int(ctx.db.query(func.count()).select_from(stmt).scalar() or 0)
    query = ctx.db.query(stmt).order_by(stmt.c.sort_at.desc(), stmt.c.sort_id.desc())
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return total, [_serialize_asset_change(row) for row in query.all()]


def asset_change_keys(stmt):
    return (
        KeyCol(stmt.c.sort_at, descending=True, value=lambda row: row.sort_at),
        KeyCol(stmt.c.sort_id, descending=True, value=lambda row: row.sort_id),
    )


def asset_change_iter(ctx: ReportContext, *, chunk: int | None = None):
    stmt = _asset_change_subquery(ctx)
    query = ctx.db.query(stmt).order_by(stmt.c.sort_at.desc(), stmt.c.sort_id.desc())

    def pack(batch):
        return [_serialize_asset_change(row) for row in batch]

    yield from map_keyset(
        query,
        asset_change_keys(stmt),
        session=ctx.db,
        serialize_batch=pack,
        batch_size=chunk,
    )


def treatment_query(ctx: ReportContext):
    types = [TREATMENT_RECORD_MITIGATED, TREATMENT_RECORD_ACCEPTED_RISK]
    if ctx.filters.get("include_false_positives"):
        types.append(TREATMENT_RECORD_FALSE_POSITIVE)
    query = (
        ctx.db.query(FindingTreatment)
        .join(AssetFinding, AssetFinding.id == FindingTreatment.asset_finding_id)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .options(
            selectinload(FindingTreatment.compensating_controls),
            selectinload(FindingTreatment.asset_finding).selectinload(AssetFinding.asset).selectinload(Asset.site),
            selectinload(FindingTreatment.asset_finding).selectinload(AssetFinding.vulnerability),
        )
    )
    query = apply_common(query, ctx, FindingTreatment.tenant_id, Asset.site_id, FindingTreatment.created_at)
    query = query.filter(FindingTreatment.treatment_type.in_(types))
    treatment_type = ctx.filters.get("treatment_type")
    if treatment_type:
        query = query.filter(FindingTreatment.treatment_type == treatment_type)
    status = ctx.filters.get("treatment_status")
    if status:
        query = query.filter(FindingTreatment.status == status)
    return query.order_by(FindingTreatment.created_at.desc(), FindingTreatment.id.desc())


def treatment_keys():
    return (
        KeyCol(FindingTreatment.created_at, descending=True),
        KeyCol(FindingTreatment.id, descending=True),
    )


def serialize_treatment_row(row: FindingTreatment, names: dict[int, str]) -> dict[str, Any]:
    finding = row.asset_finding
    asset = finding.asset if finding else None
    vuln = finding.vulnerability if finding else None
    controls = [item.name for item in row.compensating_controls]
    return {
        "treatment_id": row.id,
        "asset_finding_id": row.asset_finding_id,
        "asset": asset.display_name if asset else "",
        "site": asset.site.name if asset and asset.site else "",
        "title": vuln.title if vuln else "",
        "cve_id": vuln.cve_id if vuln else "",
        "technical_state": finding.technical_state if finding else "",
        "treatment_type": row.treatment_type,
        "status": row.status,
        "display_status": display_status(row),
        "rationale": row.rationale,
        "compensating_controls": "; ".join(controls),
        "created_by": names.get(row.created_by_user_id or 0, ""),
        "reviewed_by": names.get(row.reviewed_by_user_id or 0, ""),
        "created_at": _iso(row.created_at),
        "review_due_at": _iso(row.review_due_at),
        "expires_at": _iso(row.expires_at),
    }


def treatment_rows(ctx: ReportContext, *, offset=None, limit=None):
    query = treatment_query(ctx)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    rows = query.all()
    from app.usernames import load_usernames

    names = load_usernames(
        ctx.db,
        [row.created_by_user_id for row in rows] + [row.reviewed_by_user_id for row in rows],
    )
    return [serialize_treatment_row(row, names) for row in rows]


def treatment_iter(ctx: ReportContext):
    from app.usernames import load_usernames

    def pack(batch: list[FindingTreatment]):
        names = load_usernames(
            ctx.db,
            [row.created_by_user_id for row in batch] + [row.reviewed_by_user_id for row in batch],
        )
        return [serialize_treatment_row(row, names) for row in batch]

    yield from map_keyset(
        treatment_query(ctx),
        treatment_keys(),
        session=ctx.db,
        serialize_batch=pack,
    )


def _provenance(job: ScanJob, key: str) -> str:
    from app.scanner_versions import provenance_version

    payload = job.runtime_provenance or {}
    snapshot = job.execution_snapshot or {}
    for source in (payload, snapshot.get("runtime_provenance") or {}, snapshot.get("tool_versions") or {}, snapshot):
        if isinstance(source, dict):
            value = provenance_version(source, key)
            if value:
                return value
    return NOT_RECORDED


def _snapshot_site(snapshot: dict | None) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        return {}
    site = snapshot.get("site")
    return site if isinstance(site, dict) else {}


def scan_history_query(ctx: ReportContext):
    query = (
        ctx.db.query(ScanJob)
        .outerjoin(Scan, Scan.id == ScanJob.scan_id)
        .options(selectinload(ScanJob.scan).selectinload(Scan.site), selectinload(ScanJob.claimed_agent))
    )
    query = apply_common(query, ctx, ScanJob.tenant_id, None, ScanJob.created_at)
    if ctx.site_id is not None:
        snapshot_site_id = ScanJob.execution_snapshot["site"]["id"].astext
        has_snapshot_site = and_(
            ScanJob.execution_snapshot.isnot(None),
            snapshot_site_id.isnot(None),
            snapshot_site_id != "",
            snapshot_site_id != "null",
        )
        query = query.filter(
            or_(
                and_(has_snapshot_site, cast(snapshot_site_id, Integer) == ctx.site_id),
                and_(~has_snapshot_site, Scan.site_id == ctx.site_id),
            )
        )
    return query.order_by(ScanJob.created_at.desc(), ScanJob.id.desc())


def scan_history_keys():
    return (
        KeyCol(ScanJob.created_at, descending=True),
        KeyCol(ScanJob.id, descending=True),
    )


def serialize_scan_row(ctx: ReportContext, job: ScanJob, tenants: dict[int, str]) -> dict[str, Any]:
    scan = job.scan
    snapshot = job.execution_snapshot or {}
    snap_site = _snapshot_site(snapshot)
    site_name = snap_site.get("name") or (scan.site.name if scan and getattr(scan, "site", None) else "")
    return {
        "job_id": job.id,
        "tenant": tenants.get(job.tenant_id, ""),
        "tenant_id": job.tenant_id,
        "site": site_name,
        "scan_name": scan.name if scan else "",
        "trigger_type": job.trigger_type or NOT_RECORDED,
        "scheduled_for": _iso(job.scheduled_for) or NOT_RECORDED,
        "started_at": _iso(job.started_at) or NOT_RECORDED,
        "finished_at": _iso(job.finished_at) or NOT_RECORDED,
        "status": job.status,
        "hosts_found": job.hosts_found,
        "findings_count": job.findings_count,
        "definition_revision": job.definition_revision if job.definition_revision is not None else NOT_RECORDED,
        "snapshot_version": job.snapshot_version or NOT_RECORDED,
        "execution_scope": snapshot.get("scope") or (scan.scope if scan else NOT_RECORDED),
        "error": job.error or "",
        "agent": job.claimed_by or (job.claimed_agent.name if job.claimed_agent else NOT_RECORDED),
        "runtime_provenance": "recorded" if job.runtime_provenance else NOT_RECORDED,
        "runtime_version": _provenance(job, "runtime_version"),
        "nuclei_version": _provenance(job, "nuclei_version"),
        "nuclei_templates_version": _provenance(job, "nuclei_templates_version"),
        "nuclei_templates": _provenance(job, "nuclei_templates_version"),
        "naabu_version": _provenance(job, "naabu_version"),
        "httpx_version": _provenance(job, "httpx_version"),
    }


def scan_history_rows(ctx: ReportContext, *, offset=None, limit=None):
    query = scan_history_query(ctx)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    jobs = query.all()
    tenant_ids = {job.tenant_id for job in jobs}
    tenants = {row.id: row.name for row in ctx.db.query(Tenant).filter(Tenant.id.in_(tenant_ids or {0})).all()}
    return [serialize_scan_row(ctx, job, tenants) for job in jobs]


def scan_history_iter(ctx: ReportContext):
    def pack(batch: list[ScanJob]):
        tenant_ids = {job.tenant_id for job in batch}
        tenants = {row.id: row.name for row in ctx.db.query(Tenant).filter(Tenant.id.in_(tenant_ids or {0})).all()}
        return [serialize_scan_row(ctx, job, tenants) for job in batch]

    yield from map_keyset(
        scan_history_query(ctx),
        scan_history_keys(),
        session=ctx.db,
        serialize_batch=pack,
    )


def agent_health_query(ctx: ReportContext):
    query = ctx.db.query(Agent).options(selectinload(Agent.site), selectinload(Agent.tenant))
    query = apply_common(query, ctx, Agent.tenant_id, Agent.site_id)
    return query.order_by(Agent.name, Agent.id)


def agent_health_keys():
    return (KeyCol(Agent.name), KeyCol(Agent.id))


def serialize_agent_row(agent: Agent, approved: dict[str, str] | None = None) -> dict[str, Any]:
    from app.scanner_versions import INVENTORY_FIELDS, STATUS_LABELS, agent_version_view

    view = agent_version_view(agent, approved)
    inventory = view["runtime_inventory"] or {}
    reported = _iso(view["runtime_inventory_reported_at"]) or "Not Reported"
    versions = {field: inventory.get(field) or "Not Reported" for field in INVENTORY_FIELDS}
    return {
        "agent_id": agent.id,
        "tenant": agent.tenant.name if agent.tenant else "",
        "site": agent.site.name if agent.site else "",
        "name": agent.name,
        "status": agent.status,
        "healthy": is_agent_healthy(agent),
        "last_heartbeat": _iso(agent.last_heartbeat) or NOT_RECORDED,
        "last_ip": agent.last_ip or NOT_RECORDED,
        "approved_at": _iso(agent.approved_at) or NOT_RECORDED,
        "hostname": agent.hostname or NOT_RECORDED,
        "container_id": agent.container_id or NOT_RECORDED,
        "agent_version": versions["runtime_version"],
        "runtime_version": versions["runtime_version"],
        "nuclei_version": versions["nuclei_version"],
        "nuclei_templates_version": versions["nuclei_templates_version"],
        "naabu_version": versions["naabu_version"],
        "httpx_version": versions["httpx_version"],
        "version_status": STATUS_LABELS.get(view["version_status"], view["version_status"]),
        "runtime_inventory_reported_at": reported,
    }


def agent_health_rows(ctx: ReportContext, *, offset=None, limit=None):
    from app.scanner_versions import approved_versions_from_settings
    from app.settings_store import get_settings

    query = agent_health_query(ctx)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    approved = approved_versions_from_settings(get_settings(ctx.db))
    return [serialize_agent_row(agent, approved) for agent in query.all()]


def agent_health_iter(ctx: ReportContext):
    from app.scanner_versions import approved_versions_from_settings
    from app.settings_store import get_settings

    approved = approved_versions_from_settings(get_settings(ctx.db))

    def pack(batch: list[Agent]):
        return [serialize_agent_row(agent, approved) for agent in batch]

    yield from map_keyset(
        agent_health_query(ctx),
        agent_health_keys(),
        session=ctx.db,
        serialize_batch=pack,
    )


def control_evidence_controls(ctx: ReportContext) -> list[ComplianceControl]:
    framework_id = ctx.filters.get("framework_id")
    if not framework_id:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="framework_id is required")
    return (
        ctx.db.query(ComplianceControl)
        .options(selectinload(ComplianceControl.framework))
        .filter(ComplianceControl.framework_id == int(framework_id), ComplianceControl.archived_at.is_(None))
        .order_by(ComplianceControl.sort_order.asc().nulls_last(), ComplianceControl.control_key.asc())
        .all()
    )


def _subject_lookups(db: Session, refs: list[ComplianceControlReference]) -> dict[str, dict[int, str]]:
    asset_ids = [row.asset_id for row in refs if row.asset_id]
    finding_ids = [row.asset_finding_id for row in refs if row.asset_finding_id]
    assets = {
        row.id: row.display_name
        for row in db.query(Asset.id, Asset.display_name).filter(Asset.id.in_(asset_ids or {0})).all()
    }
    findings = {
        row.id: (row.vulnerability.title if row.vulnerability else "Asset finding")
        for row in db.query(AssetFinding)
        .options(selectinload(AssetFinding.vulnerability))
        .filter(AssetFinding.id.in_(finding_ids or {0}))
        .all()
    }
    return {"asset": assets, "asset_finding": findings}


def _subject_summary(row: ComplianceControlReference, lookups: dict[str, dict[int, str]]) -> str:
    if row.asset_id:
        return lookups["asset"].get(row.asset_id) or f"Asset {row.asset_id}"
    if row.asset_finding_id:
        title = lookups["asset_finding"].get(row.asset_finding_id) or "Asset finding"
        return f"{title} #{row.asset_finding_id}"
    if row.finding_id:
        return f"Finding evidence #{row.finding_id}"
    if row.treatment_id:
        return f"Treatment #{row.treatment_id}"
    if row.scan_job_id:
        return f"Scan job #{row.scan_job_id}"
    return "Unknown subject"


def _control_ref_query(ctx: ReportContext):
    query = ctx.db.query(ComplianceControlReference).filter(ComplianceControlReference.tenant_id == ctx.requested_tenant_id)
    if not ctx.filters.get("include_removed"):
        query = query.filter(ComplianceControlReference.removed_at.is_(None))
    return query


def control_evidence_summary(ctx: ReportContext) -> tuple[dict[str, Any], list[ComplianceControl], dict[int, int], int]:
    controls = control_evidence_controls(ctx)
    counts = dict(
        _control_ref_query(ctx)
        .with_entities(ComplianceControlReference.control_id, func.count(ComplianceControlReference.id))
        .group_by(ComplianceControlReference.control_id)
        .all()
    )
    mapped_counts = {control.id: int(counts.get(control.id, 0)) for control in controls}
    mapped = sum(1 for control in controls if mapped_counts.get(control.id))
    total_rows = sum(mapped_counts.get(control.id, 0) or 1 for control in controls)
    summary = {
        "controls": len(controls),
        "mapped_controls": mapped,
        "unmapped_controls": len(controls) - mapped,
        "disclaimer": COMPLIANCE_MAPPING_DISCLAIMER,
    }
    return summary, controls, mapped_counts, total_rows


def _control_placeholder(control: ComplianceControl) -> dict[str, Any]:
    return {
        "framework": control.framework.name if control.framework else "",
        "framework_version": control.framework.version if control.framework else "",
        "control_key": control.control_key,
        "family": control.family or "",
        "title": control.title,
        "description": control.description,
        "mapped_evidence_count": 0,
        "evidence_status": "No mapped evidence in the application",
        "subject_type": "",
        "subject_id": "",
        "subject_summary": "",
        "reference_type": "",
        "notes": "",
        "created_by": "",
        "created_at": "",
        "removed": False,
        "removal_reason": "",
    }


def _serialize_control_ref(
    control: ComplianceControl,
    ref: ComplianceControlReference,
    mapped_count: int,
    names: dict[int, str],
    lookups: dict[str, dict[int, str]],
) -> dict[str, Any]:
    subject_type = (
        "asset"
        if ref.asset_id
        else "asset_finding"
        if ref.asset_finding_id
        else "finding"
        if ref.finding_id
        else "treatment"
        if ref.treatment_id
        else "scan_job"
    )
    subject_id = ref.asset_id or ref.asset_finding_id or ref.finding_id or ref.treatment_id or ref.scan_job_id
    return {
        "framework": control.framework.name if control.framework else "",
        "framework_version": control.framework.version if control.framework else "",
        "control_key": control.control_key,
        "family": control.family or "",
        "title": control.title,
        "description": control.description,
        "mapped_evidence_count": mapped_count,
        "evidence_status": "Evidence/reference is mapped",
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_summary": _subject_summary(ref, lookups),
        "reference_type": ref.reference_type,
        "notes": ref.notes or "",
        "created_by": names.get(ref.created_by_user_id or 0, ""),
        "created_at": _iso(ref.created_at),
        "removed": ref.removed_at is not None,
        "removal_reason": ref.removal_reason or "",
    }


def _control_ref_page(ctx: ReportContext, control_id: int, *, offset: int, limit: int):
    from app.usernames import load_usernames

    refs = (
        _control_ref_query(ctx)
        .filter(ComplianceControlReference.control_id == control_id)
        .order_by(ComplianceControlReference.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    names = load_usernames(ctx.db, [row.created_by_user_id for row in refs])
    lookups = _subject_lookups(ctx.db, refs)
    return refs, names, lookups


def control_evidence_rows(ctx: ReportContext, *, offset=None, limit=None) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    summary, controls, counts, total = control_evidence_summary(ctx)
    start = 0 if offset is None else offset
    end = total if limit is None else start + limit
    rows: list[dict[str, Any]] = []
    pos = 0
    for control in controls:
        mapped_count = counts.get(control.id, 0)
        span = mapped_count if mapped_count else 1
        if pos + span <= start:
            pos += span
            continue
        if pos >= end:
            break
        skip = max(0, start - pos)
        take = min(span - skip, end - max(pos, start))
        if mapped_count == 0:
            rows.append(_control_placeholder(control))
        else:
            refs, names, lookups = _control_ref_page(ctx, control.id, offset=skip, limit=take)
            for ref in refs:
                rows.append(_serialize_control_ref(control, ref, mapped_count, names, lookups))
        pos += span
    return rows, summary, total


def control_evidence_iter(ctx: ReportContext, *, chunk: int | None = None):
    _summary, controls, counts, _total = control_evidence_summary(ctx)
    size = chunk if chunk is not None else export_batch_size()
    from app.usernames import load_usernames

    for control in controls:
        mapped_count = counts.get(control.id, 0)
        if not mapped_count:
            yield _control_placeholder(control)
            continue
        cursor_id = 0
        while True:
            refs = (
                _control_ref_query(ctx)
                .filter(
                    ComplianceControlReference.control_id == control.id,
                    ComplianceControlReference.id > cursor_id,
                )
                .order_by(ComplianceControlReference.id)
                .limit(size)
                .all()
            )
            if not refs:
                break
            names = load_usernames(ctx.db, [row.created_by_user_id for row in refs])
            lookups = _subject_lookups(ctx.db, refs)
            for ref in refs:
                yield _serialize_control_ref(control, ref, mapped_count, names, lookups)
                ctx.db.expunge(ref)
            if len(refs) < size:
                break
            cursor_id = refs[-1].id
