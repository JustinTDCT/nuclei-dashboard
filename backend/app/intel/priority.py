"""Transparent AssetFinding operational priority model 2b.1."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable

from sqlalchemy import and_, case, func
from sqlalchemy.orm import Session, selectinload

from app.models import (
    CRITICALITY_CRITICAL,
    CRITICALITY_HIGH,
    CRITICALITY_LOW,
    CRITICALITY_NORMAL,
    CUI_TAG_NORMALIZED,
    PRIORITY_MODEL_VERSION,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    Asset,
    AssetFinding,
    AssetObservation,
    Finding,
    ScanJob,
    Tag,
    Vulnerability,
    VulnerabilityCwe,
    VulnerabilityIntelligence,
    tag_assets,
)

PRIORITY_ORDER = {PRIORITY_P1: 1, PRIORITY_P2: 2, PRIORITY_P3: 3, PRIORITY_P4: 4}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_decimal(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except Exception:  # noqa: BLE001
        return None


def _age_days(first_seen: datetime | None, now: datetime) -> int:
    if first_seen is None:
        return 0
    stamp = first_seen
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    delta = now - stamp.astimezone(timezone.utc)
    return max(0, int(delta.total_seconds() // 86400))


def _impact_points(cvss: float | None, detector_severity: str | None) -> tuple[int, dict[str, Any]]:
    if cvss is not None:
        if cvss >= 9.0:
            points = 40
        elif cvss >= 7.0:
            points = 30
        elif cvss >= 4.0:
            points = 20
        elif cvss > 0:
            points = 10
        else:
            points = 0
        return points, {
            "factor": "cvss",
            "value": cvss,
            "points": points,
            "source": "nvd",
        }
    severity = (detector_severity or "").strip().lower() or "unknown"
    points = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(severity, 0)
    return points, {
        "factor": "detector_severity",
        "value": severity,
        "points": points,
        "source": "detector",
    }


def _epss_points(percentile: float | None, score: float | None) -> tuple[int, dict[str, Any]]:
    points = 0
    if percentile is not None:
        if percentile >= 0.98:
            points = 25
        elif percentile >= 0.95:
            points = 20
        elif percentile >= 0.90:
            points = 15
        elif percentile >= 0.75:
            points = 10
        elif percentile >= 0.50:
            points = 5
    return points, {
        "factor": "epss_percentile",
        "value": percentile,
        "epss_score": score,
        "points": points,
        "source": "first_epss",
        "note": (
            "EPSS is exploit likelihood/probability, not severity. "
            "Percentile thresholds are Nuclei Dashboard product prioritization "
            "thresholds, not a FIRST standard."
        ),
    }


def _criticality_points(criticality: str | None) -> tuple[int, dict[str, Any]]:
    value = (criticality or CRITICALITY_NORMAL).strip().lower()
    points = {
        CRITICALITY_CRITICAL: 20,
        CRITICALITY_HIGH: 12,
        CRITICALITY_NORMAL: 5,
        CRITICALITY_LOW: 0,
    }.get(value, 0)
    return points, {"factor": "asset_criticality", "value": value, "points": points}


def _exposure_points(proven: bool) -> tuple[int, dict[str, Any]]:
    if proven:
        return 15, {"factor": "internet_exposure", "value": "proven", "points": 15}
    return 0, {
        "factor": "internet_exposure",
        "value": "unknown",
        "points": 0,
        "note": "WAN/Internet exposure was not proven from Scan Run or Detection Evidence.",
    }


def _cui_points(has_cui: bool) -> tuple[int, dict[str, Any]]:
    points = 10 if has_cui else 0
    return points, {"factor": "cui_tag", "value": has_cui, "points": points}


def _age_points(days: int) -> tuple[int, dict[str, Any]]:
    if days >= 180:
        points = 10
    elif days >= 90:
        points = 7
    elif days >= 30:
        points = 4
    else:
        points = 0
    return points, {"factor": "finding_age_days", "value": days, "points": points}


def _band(score: int) -> str:
    if score >= 75:
        return PRIORITY_P1
    if score >= 50:
        return PRIORITY_P2
    if score >= 25:
        return PRIORITY_P3
    return PRIORITY_P4


def _higher(left: str, right: str) -> str:
    return left if PRIORITY_ORDER[left] <= PRIORITY_ORDER[right] else right


@dataclass
class PriorityInput:
    cvss_base_score: float | None = None
    detector_severity: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool | None = None
    asset_criticality: str = CRITICALITY_NORMAL
    proven_wan_exposure: bool = False
    has_cui_tag: bool = False
    first_seen: datetime | None = None
    treatment_state: str | None = None
    now: datetime | None = None
    data_freshness: dict[str, Any] = field(default_factory=dict)


def calculate_asset_finding_priority(data: PriorityInput | dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, dict):
        payload = PriorityInput(**{key: data.get(key) for key in PriorityInput.__dataclass_fields__})
    else:
        payload = data
    now = payload.now or utcnow()
    factors: list[dict[str, Any]] = []
    overrides: list[dict[str, Any]] = []
    score = 0

    impact, impact_factor = _impact_points(_as_float(payload.cvss_base_score), payload.detector_severity)
    score += impact
    factors.append(impact_factor)

    epss, epss_factor = _epss_points(_as_float(payload.epss_percentile), _as_float(payload.epss_score))
    score += epss
    factors.append(epss_factor)

    kev = payload.kev
    if kev is True:
        kev_points = 35
        kev_note = "CISA KEV — known exploited vulnerability"
    elif kev is False:
        kev_points = 0
        kev_note = "Not listed in the official CISA KEV catalog."
    else:
        kev_points = 0
        kev_note = "Unknown / not synchronized"
    factors.append(
        {
            "factor": "cisa_kev",
            "value": kev,
            "points": kev_points,
            "source": "cisa_kev",
            "note": kev_note,
        }
    )
    score += kev_points

    crit, crit_factor = _criticality_points(payload.asset_criticality)
    score += crit
    factors.append(crit_factor)

    exposure, exposure_factor = _exposure_points(payload.proven_wan_exposure)
    score += exposure
    factors.append(exposure_factor)

    cui, cui_factor = _cui_points(payload.has_cui_tag)
    score += cui
    factors.append(cui_factor)

    age_days = _age_days(payload.first_seen, now)
    age, age_factor = _age_points(age_days)
    score += age
    factors.append(age_factor)

    factors.append(
        {
            "factor": "treatment",
            "value": payload.treatment_state,
            "points": 0,
            "note": "Treatment does not change operational priority in model 2b.1.",
        }
    )

    if score > 100:
        factors.append({"factor": "score_cap", "value": score, "points": 100 - score})
        score = 100

    priority = _band(score)
    if kev is True:
        if priority != PRIORITY_P1:
            overrides.append(
                {
                    "type": "kev_minimum",
                    "priority": PRIORITY_P1,
                    "reason": "CISA KEV — known exploited vulnerability",
                }
            )
        else:
            overrides.append(
                {
                    "type": "kev_minimum",
                    "priority": PRIORITY_P1,
                    "reason": "CISA KEV — known exploited vulnerability",
                }
            )
        priority = PRIORITY_P1

    cvss = _as_float(payload.cvss_base_score)
    detector = (payload.detector_severity or "").strip().lower()
    # Detector severity is a fallback only. When normalized CVSS exists it
    # owns both the impact points and the severity floor.
    if cvss is not None:
        critical_floor = cvss >= 9.0
        high_floor = cvss >= 7.0
        floor_reason = "Critical CVSS severity floor" if critical_floor else "High CVSS severity floor"
    else:
        critical_floor = detector == "critical"
        high_floor = detector == "high"
        floor_reason = (
            "Critical detector severity floor" if critical_floor else "High detector severity floor"
        )
    if critical_floor:
        if PRIORITY_ORDER[priority] > PRIORITY_ORDER[PRIORITY_P2]:
            overrides.append(
                {
                    "type": "severity_floor",
                    "priority": PRIORITY_P2,
                    "reason": floor_reason,
                }
            )
        priority = _higher(priority, PRIORITY_P2)
    elif high_floor:
        if PRIORITY_ORDER[priority] > PRIORITY_ORDER[PRIORITY_P3]:
            overrides.append(
                {
                    "type": "severity_floor",
                    "priority": PRIORITY_P3,
                    "reason": floor_reason,
                }
            )
        priority = _higher(priority, PRIORITY_P3)

    explanation = {
        "model_version": PRIORITY_MODEL_VERSION,
        "score": score,
        "priority": priority,
        "overrides": overrides,
        "factors": factors,
        "data_freshness": payload.data_freshness or {},
        "label": "Nuclei Dashboard operational priority",
    }
    factor_sum = sum(int(item.get("points") or 0) for item in factors)
    explanation["factor_sum"] = factor_sum
    return {
        "priority": priority,
        "score": score,
        "model_version": PRIORITY_MODEL_VERSION,
        "factors": factors,
        "overrides": overrides,
        "calculated_at": now,
        "explanation": explanation,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _display_severity(finding: AssetFinding, latest: Finding | None) -> str:
    if latest and latest.severity:
        return latest.severity
    return "info"


def _cui_tag_ids(db: Session, asset_ids: Iterable[int]) -> set[int]:
    ids = list(asset_ids)
    if not ids:
        return set()
    rows = (
        db.query(tag_assets.c.asset_id)
        .join(Tag, Tag.id == tag_assets.c.tag_id)
        .filter(tag_assets.c.asset_id.in_(ids), Tag.normalized_name == CUI_TAG_NORMALIZED)
        .all()
    )
    return {int(row[0]) for row in rows}


def _proven_wan_finding_ids(db: Session, finding_ids: Iterable[int]) -> set[int]:
    ids = list(finding_ids)
    if not ids:
        return set()
    snapshot_ids = {
        int(row[0])
        for row in db.query(Finding.asset_finding_id)
        .join(ScanJob, ScanJob.id == Finding.scan_job_id)
        .filter(
            Finding.asset_finding_id.in_(ids),
            Finding.scan_job_id.isnot(None),
            ScanJob.execution_snapshot["scope"].astext == "wan",
        )
        .all()
        if row[0] is not None
    }
    observation_ids = {
        int(row[0])
        for row in db.query(Finding.asset_finding_id)
        .join(
            AssetObservation,
            and_(
                AssetObservation.scan_job_id == Finding.scan_job_id,
                AssetObservation.asset_id == Finding.asset_id,
            ),
        )
        .filter(
            Finding.asset_finding_id.in_(ids),
            Finding.scan_job_id.isnot(None),
            AssetObservation.scope == "wan",
        )
        .all()
        if row[0] is not None
    }
    return snapshot_ids | observation_ids


def _latest_evidence_map(db: Session, finding_ids: Iterable[int]) -> dict[int, Finding]:
    ids = list(finding_ids)
    if not ids:
        return {}
    rows = (
        db.query(Finding)
        .distinct(Finding.asset_finding_id)
        .filter(Finding.asset_finding_id.in_(ids))
        .order_by(Finding.asset_finding_id, Finding.found_at.desc(), Finding.id.desc())
        .all()
    )
    return {row.asset_finding_id: row for row in rows if row.asset_finding_id is not None}


def recalculate_asset_finding_priorities(
    db: Session,
    asset_findings: list[AssetFinding] | None = None,
    *,
    asset_finding_ids: list[int] | None = None,
    now: datetime | None = None,
) -> int:
    now = now or utcnow()
    if asset_findings is None:
        query = db.query(AssetFinding).options(
            selectinload(AssetFinding.asset),
            selectinload(AssetFinding.vulnerability).selectinload(Vulnerability.intelligence),
        )
        if asset_finding_ids is not None:
            if not asset_finding_ids:
                return 0
            query = query.filter(AssetFinding.id.in_(asset_finding_ids))
        asset_findings = query.all()
    if not asset_findings:
        return 0
    ids = [row.id for row in asset_findings]
    asset_ids = {row.asset_id for row in asset_findings}
    latest = _latest_evidence_map(db, ids)
    cui_assets = _cui_tag_ids(db, asset_ids)
    wan_ids = _proven_wan_finding_ids(db, ids)
    vuln_ids = {row.vulnerability_id for row in asset_findings}
    intel_rows = (
        db.query(VulnerabilityIntelligence)
        .filter(VulnerabilityIntelligence.vulnerability_id.in_(vuln_ids))
        .all()
        if vuln_ids
        else []
    )
    intel_by_id = {row.vulnerability_id: row for row in intel_rows}
    updated = 0
    for finding in asset_findings:
        intel = intel_by_id.get(finding.vulnerability_id)
        if intel is None and finding.vulnerability is not None:
            intel = finding.vulnerability.intelligence
        evidence = latest.get(finding.id)
        asset = finding.asset
        result = calculate_asset_finding_priority(
            PriorityInput(
                cvss_base_score=_as_float(getattr(intel, "cvss_base_score", None)),
                detector_severity=_display_severity(finding, evidence),
                epss_score=_as_float(getattr(intel, "epss_score", None)),
                epss_percentile=_as_float(getattr(intel, "epss_percentile", None)),
                kev=getattr(intel, "kev", None),
                asset_criticality=asset.criticality if asset else CRITICALITY_NORMAL,
                proven_wan_exposure=finding.id in wan_ids,
                has_cui_tag=finding.asset_id in cui_assets,
                first_seen=finding.first_seen,
                treatment_state=finding.treatment_state,
                now=now,
                data_freshness={
                    "nvd": _iso(getattr(intel, "nvd_fetched_at", None)),
                    "epss": _iso(getattr(intel, "epss_fetched_at", None)),
                    "kev": _iso(getattr(intel, "kev_fetched_at", None)),
                },
            )
        )
        finding.priority = result["priority"]
        finding.priority_score = result["score"]
        finding.priority_model_version = result["model_version"]
        finding.priority_explanation = result["explanation"]
        finding.priority_calculated_at = result["calculated_at"]
        finding.updated_at = now
        updated += 1
    db.flush()
    return updated


def recalculate_priorities_for_vulnerabilities(db: Session, vulnerability_ids: Iterable[int]) -> int:
    ids = [int(item) for item in vulnerability_ids]
    if not ids:
        return 0
    rows = (
        db.query(AssetFinding)
        .options(selectinload(AssetFinding.asset), selectinload(AssetFinding.vulnerability))
        .filter(AssetFinding.vulnerability_id.in_(ids))
        .all()
    )
    return recalculate_asset_finding_priorities(db, rows)


def recalculate_priorities_for_assets(db: Session, asset_ids: Iterable[int]) -> int:
    ids = [int(item) for item in asset_ids]
    if not ids:
        return 0
    rows = (
        db.query(AssetFinding)
        .options(selectinload(AssetFinding.asset), selectinload(AssetFinding.vulnerability))
        .filter(AssetFinding.asset_id.in_(ids))
        .all()
    )
    return recalculate_asset_finding_priorities(db, rows)


def recalculate_age_bucket_changes(db: Session, *, now: datetime | None = None) -> int:
    now = now or utcnow()
    rows = (
        db.query(AssetFinding)
        .options(selectinload(AssetFinding.asset), selectinload(AssetFinding.vulnerability))
        .all()
    )
    return recalculate_asset_finding_priorities(db, rows, now=now)


def real_cwe_ids(db: Session, vulnerability_ids: Iterable[int]) -> dict[int, list[str]]:
    ids = list(vulnerability_ids)
    if not ids:
        return {}
    rows = (
        db.query(VulnerabilityCwe)
        .filter(VulnerabilityCwe.vulnerability_id.in_(ids), ~VulnerabilityCwe.cwe_id.ilike("NVD-CWE-%"))
        .order_by(VulnerabilityCwe.cwe_id.asc(), VulnerabilityCwe.id.asc())
        .all()
    )
    mapped: dict[int, list[str]] = {vid: [] for vid in ids}
    for row in rows:
        if row.cwe_id not in mapped[row.vulnerability_id]:
            mapped[row.vulnerability_id].append(row.cwe_id)
    return mapped


def _float(value: Any) -> float | None:
    number = _as_float(value)
    return number


def load_finding_intelligence(db: Session, rows: list[AssetFinding]) -> dict[int, dict[str, Any]]:
    vuln_ids = {row.vulnerability_id for row in rows}
    intel_rows = (
        db.query(VulnerabilityIntelligence)
        .filter(VulnerabilityIntelligence.vulnerability_id.in_(vuln_ids))
        .all()
        if vuln_ids
        else []
    )
    intel_by_vuln = {row.vulnerability_id: row for row in intel_rows}
    cwes = real_cwe_ids(db, vuln_ids)
    payload: dict[int, dict[str, Any]] = {}
    for row in rows:
        intel = intel_by_vuln.get(row.vulnerability_id)
        payload[row.id] = {
            "intel": intel,
            "cwe_ids": cwes.get(row.vulnerability_id, []),
        }
    return payload


def apply_priority_filter(query, priority: str | None):
    if not priority:
        return query
    return query.filter(AssetFinding.priority == priority.strip().lower())


def apply_kev_filter(query, kev: bool | None):
    if kev is None:
        return query
    query = query.outerjoin(
        VulnerabilityIntelligence,
        VulnerabilityIntelligence.vulnerability_id == AssetFinding.vulnerability_id,
    )
    if kev:
        return query.filter(VulnerabilityIntelligence.kev.is_(True))
    return query.filter(VulnerabilityIntelligence.kev.is_(False))


def priority_sort_sql():
    return case(
        (AssetFinding.priority == "p1", 1),
        (AssetFinding.priority == "p2", 2),
        (AssetFinding.priority == "p3", 3),
        (AssetFinding.priority == "p4", 4),
        else_=5,
    )


def open_finding_priority_counts(
    db: Session,
    tenant_id: int | None = None,
    *,
    tenant_filter=None,
) -> dict[str, int]:
    query = db.query(AssetFinding.priority, func.count(AssetFinding.id)).filter(
        AssetFinding.technical_state == "open"
    )
    if tenant_id is not None:
        query = query.filter(AssetFinding.tenant_id == tenant_id)
    elif tenant_filter is not None:
        query = query.filter(tenant_filter)
    counts = {"p1": 0, "p2": 0, "p3": 0, "p4": 0, "uncalculated": 0}
    for priority, total in query.group_by(AssetFinding.priority).all():
        key = priority if priority in counts else "uncalculated"
        counts[key] += int(total)
    return counts
