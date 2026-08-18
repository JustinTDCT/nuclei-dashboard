"""Scanner-independent finding identity and lifecycle.

Phase 2A owns catalog identity, Detection Evidence, and consecutive
clean-scan resolution. Treatment workflows are Phase 2C.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from app.classify import identity_name, is_ip, normalize_hostname
from app.correlation import canonical_asset_id
from app.events import emit_domain_event
from app.models import (
    DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS,
    DETECTOR_NUCLEI,
    EVALUATION_CLEAN,
    EVALUATION_DETECTED,
    EVENT_NEW_FINDING,
    EVENT_VULNERABILITY_REOPENED,
    EVENT_VULNERABILITY_RESOLVED,
    HISTORY_OPENED,
    HISTORY_REOPENED,
    HISTORY_RESOLVED,
    JOB_DONE,
    JOB_FAILED,
    SOURCE_SCANNER,
    TECHNICAL_OPEN,
    TECHNICAL_RESOLVED,
    TREATMENT_UNADDRESSED,
    Asset,
    AssetFinding,
    AssetFindingHistory,
    AssetFindingRunEvaluation,
    AssetObservation,
    Device,
    Finding,
    ScanJob,
    Vulnerability,
    VulnerabilityDetectorMapping,
)
from app.scan_execution import execution_context
from app.scan_security import ExecutionBlocked
from app.schemas import FindingReport
from app.settings_store import get_settings

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class FindingLifecycleError(Exception):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class DetectorIdentity:
    detector_type: str
    detector_key: str
    cve_id: str | None
    canonical_key: str
    title: str
    description: str
    severity: str
    tags: str
    host: str
    matched_at: str
    hostname: str
    ip: str
    raw: dict[str, Any]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_csv_tokens(raw: str | None) -> list[str]:
    return [part.strip().lower() for part in (raw or "").split(",") if part.strip()]


def normalize_cve(value: str | None) -> str | None:
    token = (value or "").strip().upper()
    if CVE_RE.match(token):
        return token
    return None


def _classification_cves(raw: dict[str, Any]) -> list[str]:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    candidates: list[str] = []
    for key in ("cve-id", "cve_id", "cve"):
        value = classification.get(key)
        if isinstance(value, list):
            candidates.extend(str(item) for item in value if item)
        elif value:
            candidates.append(str(value))
    return candidates


def extract_explicit_cve(raw: dict[str, Any]) -> str | None:
    for item in _classification_cves(raw):
        cve = normalize_cve(item)
        if cve:
            return cve
    return None


def catalog_identity(detector_type: str, detector_key: str, cve_id: str | None) -> str:
    if cve_id:
        return f"cve:{cve_id}"
    return f"{detector_type}:{detector_key}"


def evidence_identity_key(
    *,
    scan_job_id: int,
    detector_type: str,
    detector_key: str,
    host: str,
    matched_at: str,
) -> str:
    material = "|".join(
        [
            str(scan_job_id),
            detector_type,
            detector_key,
            (host or "").strip(),
            (matched_at or "").strip(),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{scan_job_id}:{detector_type}:{digest}"


def parse_detector_identity(report: FindingReport) -> DetectorIdentity:
    raw = report.raw or {}
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    detector_type = DETECTOR_NUCLEI
    detector_key = (report.template_id or raw.get("template-id") or "").strip()
    title = (report.name or info.get("name") or "").strip()
    description = str(info.get("description") or "").strip()
    severity = (report.severity or info.get("severity") or "info").strip().lower() or "info"
    tags = report.tags or ",".join(info.get("tags") or [])
    host = (report.host or raw.get("host") or "").strip()
    matched_at = (report.matched_at or raw.get("matched-at") or "").strip()
    raw_host = (host or matched_at or "").strip()
    from app.inventory import host_to_ip

    parsed = urlparse(raw_host).hostname if "://" in raw_host else raw_host.split("/")[0].split(":")[0]
    parsed = normalize_hostname(parsed or "")
    ip = host_to_ip(host or matched_at) or ""
    hostname = identity_name(parsed, ip)
    cve_id = extract_explicit_cve(raw)
    return DetectorIdentity(
        detector_type=detector_type,
        detector_key=detector_key,
        cve_id=cve_id,
        canonical_key=catalog_identity(detector_type, detector_key, cve_id) if detector_key or cve_id else "",
        title=title,
        description=description,
        severity=severity,
        tags=tags or "",
        host=host,
        matched_at=matched_at,
        hostname=hostname,
        ip=ip,
        raw=raw,
    )


def resolve_trusted_asset(
    db: Session,
    *,
    tenant_id: int,
    job: ScanJob,
    device: Device | None,
) -> Asset | None:
    if device is None or device.asset_id is None:
        return None
    if device.tenant_id != tenant_id or device.tenant_id != job.tenant_id:
        return None
    asset = db.get(Asset, device.asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        return None
    canonical_id = canonical_asset_id(db, asset.id)
    if canonical_id != asset.id:
        asset = db.get(Asset, canonical_id)
        if asset is None or asset.tenant_id != tenant_id:
            return None
    return asset


def get_or_create_vulnerability(db: Session, identity: DetectorIdentity) -> Vulnerability | None:
    if not identity.canonical_key:
        return None
    existing = db.query(Vulnerability).filter(Vulnerability.canonical_key == identity.canonical_key).first()
    if existing is not None:
        if identity.title and not existing.title:
            existing.title = identity.title
        if identity.description and not existing.description:
            existing.description = identity.description
        if identity.cve_id and not existing.cve_id:
            existing.cve_id = identity.cve_id
        existing.updated_at = utcnow()
        return existing
    row = Vulnerability(
        canonical_key=identity.canonical_key,
        cve_id=identity.cve_id,
        title=identity.title,
        description=identity.description,
        updated_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def get_or_create_mapping(
    db: Session,
    vulnerability: Vulnerability,
    identity: DetectorIdentity,
) -> VulnerabilityDetectorMapping:
    existing = (
        db.query(VulnerabilityDetectorMapping)
        .filter(
            VulnerabilityDetectorMapping.detector_type == identity.detector_type,
            VulnerabilityDetectorMapping.detector_key == identity.detector_key,
        )
        .first()
    )
    if existing is not None:
        if existing.vulnerability_id != vulnerability.id:
            raise FindingLifecycleError("Detector mapping already belongs to a different vulnerability")
        if identity.severity:
            existing.last_severity = identity.severity
        if identity.tags:
            existing.last_tags = identity.tags
        return existing
    row = VulnerabilityDetectorMapping(
        vulnerability_id=vulnerability.id,
        detector_type=identity.detector_type,
        detector_key=identity.detector_key,
        last_severity=identity.severity,
        last_tags=identity.tags,
    )
    db.add(row)
    db.flush()
    return row


def _append_history(
    db: Session,
    *,
    asset_finding: AssetFinding,
    transition_type: str,
    previous: str | None,
    new_state: str,
    scan_job_id: int | None,
    occurred_at: datetime,
    details: dict[str, Any],
    idempotence_key: str,
) -> AssetFindingHistory | None:
    existing = (
        db.query(AssetFindingHistory)
        .filter(AssetFindingHistory.idempotence_key == idempotence_key)
        .first()
    )
    if existing is not None:
        return None
    row = AssetFindingHistory(
        asset_finding_id=asset_finding.id,
        tenant_id=asset_finding.tenant_id,
        transition_type=transition_type,
        previous_technical_state=previous,
        new_technical_state=new_state,
        scan_job_id=scan_job_id,
        occurred_at=occurred_at,
        details=details,
        idempotence_key=idempotence_key,
    )
    db.add(row)
    db.flush()
    return row


def _emit_lifecycle_event(
    db: Session,
    *,
    event_type: str,
    asset_finding: AssetFinding,
    vulnerability: Vulnerability,
    scan_job_id: int | None,
    occurred_at: datetime,
    extra: dict[str, Any] | None = None,
) -> None:
    details = {
        "asset_finding_id": asset_finding.id,
        "vulnerability_id": vulnerability.id,
        "canonical_key": vulnerability.canonical_key,
        "cve_id": vulnerability.cve_id,
        "technical_state": asset_finding.technical_state,
        "treatment_state": asset_finding.treatment_state,
        "scan_job_id": scan_job_id,
        **(extra or {}),
    }
    emit_domain_event(
        db,
        event_type=event_type,
        tenant_id=asset_finding.tenant_id,
        site_id=asset_finding.asset.site_id if asset_finding.asset else None,
        asset_id=asset_finding.asset_id,
        idempotence_key=f"{event_type}:{asset_finding.id}:{scan_job_id or 0}",
        details=details,
        source=SOURCE_SCANNER,
        occurred_at=occurred_at,
    )


def apply_detection(
    db: Session,
    *,
    asset: Asset,
    vulnerability: Vulnerability,
    job: ScanJob,
    identity: DetectorIdentity,
    detected_at: datetime,
) -> tuple[AssetFinding, bool]:
    if asset.tenant_id != job.tenant_id:
        raise FindingLifecycleError("Cross-tenant asset/finding relationship is not allowed")
    existing = (
        db.query(AssetFinding)
        .filter(
            AssetFinding.asset_id == asset.id,
            AssetFinding.vulnerability_id == vulnerability.id,
        )
        .first()
    )
    created = False
    reopened = False
    if existing is None:
        existing = AssetFinding(
            tenant_id=job.tenant_id,
            asset_id=asset.id,
            vulnerability_id=vulnerability.id,
            technical_state=TECHNICAL_OPEN,
            treatment_state=TREATMENT_UNADDRESSED,
            first_seen=detected_at,
            last_seen=detected_at,
            resolved_at=None,
            consecutive_clean_scans=0,
            reopened_count=0,
            updated_at=detected_at,
        )
        db.add(existing)
        db.flush()
        created = True
        _append_history(
            db,
            asset_finding=existing,
            transition_type=HISTORY_OPENED,
            previous=None,
            new_state=TECHNICAL_OPEN,
            scan_job_id=job.id,
            occurred_at=detected_at,
            details={"reason": "first_detection", "detector_type": identity.detector_type},
            idempotence_key=f"opened:{existing.id}:{job.id}",
        )
        _emit_lifecycle_event(
            db,
            event_type=EVENT_NEW_FINDING,
            asset_finding=existing,
            vulnerability=vulnerability,
            scan_job_id=job.id,
            occurred_at=detected_at,
        )
    else:
        if existing.tenant_id != job.tenant_id or existing.asset_id != asset.id:
            raise FindingLifecycleError("Asset finding tenant/asset mismatch")
        existing.last_seen = detected_at
        existing.consecutive_clean_scans = 0
        existing.updated_at = detected_at
        if existing.technical_state == TECHNICAL_RESOLVED:
            previous = existing.technical_state
            existing.technical_state = TECHNICAL_OPEN
            existing.resolved_at = None
            existing.reopened_count = (existing.reopened_count or 0) + 1
            reopened = True
            _append_history(
                db,
                asset_finding=existing,
                transition_type=HISTORY_REOPENED,
                previous=previous,
                new_state=TECHNICAL_OPEN,
                scan_job_id=job.id,
                occurred_at=detected_at,
                details={"reason": "detected_after_resolution"},
                idempotence_key=f"reopened:{existing.id}:{job.id}",
            )
            _emit_lifecycle_event(
                db,
                event_type=EVENT_VULNERABILITY_REOPENED,
                asset_finding=existing,
                vulnerability=vulnerability,
                scan_job_id=job.id,
                occurred_at=detected_at,
                extra={"reopened_count": existing.reopened_count},
            )
    db.flush()
    return existing, created or reopened


def _insert_evidence(
    db: Session,
    *,
    tenant_id: int,
    job: ScanJob,
    device: Device | None,
    asset: Asset | None,
    asset_finding: AssetFinding | None,
    identity: DetectorIdentity,
    hostname: str,
) -> tuple[Finding, bool]:
    key = evidence_identity_key(
        scan_job_id=job.id,
        detector_type=identity.detector_type,
        detector_key=identity.detector_key,
        host=identity.host,
        matched_at=identity.matched_at,
    )
    existing = db.query(Finding).filter(Finding.evidence_key == key).first()
    if existing is not None:
        return existing, False
    row = Finding(
        tenant_id=tenant_id,
        scan_job_id=job.id,
        device_id=device.id if device else None,
        asset_id=asset.id if asset else None,
        asset_finding_id=asset_finding.id if asset_finding else None,
        detector_type=identity.detector_type,
        detector_key=identity.detector_key,
        evidence_key=key,
        hostname=hostname,
        template_id=identity.detector_key,
        name=identity.title,
        severity=identity.severity,
        host=identity.host,
        matched_at=identity.matched_at,
        tags=identity.tags,
        raw_json=identity.raw,
        found_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row, True


def ingest_findings(
    db: Session,
    tenant_id: int,
    job_id: int,
    scope: str,
    reports: list[FindingReport],
) -> int:
    from app.inventory import _find_device, _promote_hostname

    job = db.get(ScanJob, job_id)
    if job is None or job.tenant_id != tenant_id:
        raise FindingLifecycleError("Scan run does not belong to this tenant")
    added = 0
    for report in reports:
        identity = parse_detector_identity(report)
        raw_host = (identity.host or identity.matched_at or "").strip()
        parsed = urlparse(raw_host).hostname if "://" in raw_host else raw_host.split("/")[0].split(":")[0]
        parsed = normalize_hostname(parsed or "")
        try:
            context = execution_context(db, job)
            run_scope = context.get("scope") or scope
            site_id = context.get("site_id") if run_scope == "lan" else None
        except ExecutionBlocked:
            run_scope = scope
            site_id = None
        device = _find_device(db, tenant_id, run_scope, identity.hostname, identity.ip, site_id=site_id)
        if device and parsed and not is_ip(parsed):
            device = _promote_hostname(db, device, parsed, tenant_id, run_scope, site_id=site_id)
        if device and identity.ip:
            device.ip = identity.ip
        if device and device.tenant_id != tenant_id:
            raise FindingLifecycleError("Cross-tenant device/finding relationship is not allowed")
        key = evidence_identity_key(
            scan_job_id=job.id,
            detector_type=identity.detector_type,
            detector_key=identity.detector_key,
            host=identity.host,
            matched_at=identity.matched_at,
        )
        if db.query(Finding.id).filter(Finding.evidence_key == key).first() is not None:
            continue
        asset = resolve_trusted_asset(db, tenant_id=tenant_id, job=job, device=device)
        hostname = (device.hostname if device else identity.hostname) or identity.hostname
        asset_finding = None
        if asset is not None and identity.canonical_key:
            vulnerability = get_or_create_vulnerability(db, identity)
            if vulnerability is not None:
                get_or_create_mapping(db, vulnerability, identity)
                asset_finding, _ = apply_detection(
                    db,
                    asset=asset,
                    vulnerability=vulnerability,
                    job=job,
                    identity=identity,
                    detected_at=utcnow(),
                )
        _evidence, created = _insert_evidence(
            db,
            tenant_id=tenant_id,
            job=job,
            device=device,
            asset=asset,
            asset_finding=asset_finding,
            identity=identity,
            hostname=hostname,
        )
        if created:
            added += 1
    db.flush()
    return added


def nuclei_mapping_for(db: Session, vulnerability_id: int) -> VulnerabilityDetectorMapping | None:
    return (
        db.query(VulnerabilityDetectorMapping)
        .filter(
            VulnerabilityDetectorMapping.vulnerability_id == vulnerability_id,
            VulnerabilityDetectorMapping.detector_type == DETECTOR_NUCLEI,
        )
        .order_by(VulnerabilityDetectorMapping.id.asc())
        .first()
    )


def asset_observed_in_run(db: Session, job: ScanJob, asset_id: int) -> bool:
    return (
        db.query(AssetObservation.id)
        .filter(
            AssetObservation.scan_job_id == job.id,
            AssetObservation.asset_id == asset_id,
            AssetObservation.tenant_id == job.tenant_id,
        )
        .first()
        is not None
    )


def is_finding_applicable_to_run(db: Session, asset_finding: AssetFinding, job: ScanJob) -> bool:
    snapshot = job.execution_snapshot
    if not snapshot or not isinstance(snapshot, dict):
        return False
    try:
        execution_context(db, job)
    except ExecutionBlocked:
        return False
    stages = snapshot.get("stages") or {}
    if stages.get("vulnerability") is not True:
        return False
    if asset_finding.tenant_id != job.tenant_id:
        return False
    if not asset_observed_in_run(db, job, asset_finding.asset_id):
        return False
    mapping = nuclei_mapping_for(db, asset_finding.vulnerability_id)
    if mapping is None:
        return False
    if mapping.detector_type != DETECTOR_NUCLEI:
        return False
    selected = set(parse_csv_tokens(str(stages.get("nuclei_severities") or "")))
    known_severity = (mapping.last_severity or "").strip().lower()
    if not selected or not known_severity or known_severity not in selected:
        return False
    tag_filter = parse_csv_tokens(str(stages.get("nuclei_tags") or ""))
    if tag_filter:
        known_tags = set(parse_csv_tokens(mapping.last_tags))
        if not known_tags or not known_tags.intersection(tag_filter):
            return False
    return True


def resolution_threshold(db: Session) -> int:
    raw = get_settings(db).get("finding_resolution_clean_scans", DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("finding_resolution_clean_scans must be a positive integer") from exc
    if value < 1:
        raise FindingLifecycleError("finding_resolution_clean_scans must be a positive integer")
    return value


def _record_evaluation(
    db: Session,
    *,
    asset_finding: AssetFinding,
    job: ScanJob,
    outcome: str,
    occurred_at: datetime,
    details: dict[str, Any],
) -> tuple[AssetFindingRunEvaluation, bool]:
    existing = (
        db.query(AssetFindingRunEvaluation)
        .filter(
            AssetFindingRunEvaluation.asset_finding_id == asset_finding.id,
            AssetFindingRunEvaluation.scan_job_id == job.id,
        )
        .first()
    )
    if existing is not None:
        return existing, False
    row = AssetFindingRunEvaluation(
        asset_finding_id=asset_finding.id,
        scan_job_id=job.id,
        tenant_id=job.tenant_id,
        outcome=outcome,
        occurred_at=occurred_at,
        details=details,
    )
    db.add(row)
    db.flush()
    return row, True


def _resolve_if_threshold_reached(
    db: Session,
    *,
    asset_finding: AssetFinding,
    job: ScanJob,
    occurred_at: datetime,
    threshold: int,
) -> None:
    if asset_finding.technical_state != TECHNICAL_OPEN:
        return
    if asset_finding.consecutive_clean_scans < threshold:
        return
    previous = asset_finding.technical_state
    asset_finding.technical_state = TECHNICAL_RESOLVED
    asset_finding.resolved_at = occurred_at
    asset_finding.updated_at = occurred_at
    history = _append_history(
        db,
        asset_finding=asset_finding,
        transition_type=HISTORY_RESOLVED,
        previous=previous,
        new_state=TECHNICAL_RESOLVED,
        scan_job_id=job.id,
        occurred_at=occurred_at,
        details={"reason": "consecutive_clean_scans", "threshold": threshold},
        idempotence_key=f"resolved:{asset_finding.id}:{job.id}",
    )
    if history is not None:
        _emit_lifecycle_event(
            db,
            event_type=EVENT_VULNERABILITY_RESOLVED,
            asset_finding=asset_finding,
            vulnerability=asset_finding.vulnerability,
            scan_job_id=job.id,
            occurred_at=occurred_at,
            extra={"consecutive_clean_scans": asset_finding.consecutive_clean_scans},
        )


def finalize_run_lifecycle(db: Session, job: ScanJob) -> None:
    if not job.execution_snapshot:
        raise FindingLifecycleError("Run has no immutable execution snapshot")
    occurred_at = job.finished_at or utcnow()
    threshold = resolution_threshold(db)
    detected_ids = {
        row[0]
        for row in db.query(Finding.asset_finding_id)
        .filter(
            Finding.scan_job_id == job.id,
            Finding.tenant_id == job.tenant_id,
            Finding.asset_finding_id.isnot(None),
        )
        .all()
    }
    observed_ids = {
        row[0]
        for row in db.query(AssetObservation.asset_id)
        .filter(AssetObservation.scan_job_id == job.id, AssetObservation.tenant_id == job.tenant_id)
        .all()
    }
    conditions = []
    if detected_ids:
        conditions.append(AssetFinding.id.in_(detected_ids))
    if observed_ids:
        conditions.append(AssetFinding.asset_id.in_(observed_ids))
    if not conditions:
        return
    candidates = (
        db.query(AssetFinding)
        .options(selectinload(AssetFinding.vulnerability), selectinload(AssetFinding.asset))
        .filter(AssetFinding.tenant_id == job.tenant_id)
        .filter(or_(*conditions))
        .all()
    )
    for asset_finding in candidates:
        if asset_finding.id in detected_ids:
            _evaluation, created = _record_evaluation(
                db,
                asset_finding=asset_finding,
                job=job,
                outcome=EVALUATION_DETECTED,
                occurred_at=occurred_at,
                details={"reason": "positive_detection"},
            )
            if created:
                asset_finding.consecutive_clean_scans = 0
                asset_finding.updated_at = occurred_at
            continue
        if not is_finding_applicable_to_run(db, asset_finding, job):
            continue
        _evaluation, created = _record_evaluation(
            db,
            asset_finding=asset_finding,
            job=job,
            outcome=EVALUATION_CLEAN,
            occurred_at=occurred_at,
            details={"reason": "applicable_clean_scan"},
        )
        if not created:
            continue
        asset_finding.consecutive_clean_scans = (asset_finding.consecutive_clean_scans or 0) + 1
        asset_finding.updated_at = occurred_at
        _resolve_if_threshold_reached(
            db,
            asset_finding=asset_finding,
            job=job,
            occurred_at=occurred_at,
            threshold=threshold,
        )
    db.flush()


def complete_scan_run(db: Session, job: ScanJob, *, ok: bool, error: str | None = None) -> ScanJob:
    finished = utcnow()
    if not ok:
        job.status = JOB_FAILED
        job.error = error
        job.finished_at = finished
        return job
    if not job.execution_snapshot:
        raise FindingLifecycleError("Successful completion requires an immutable execution snapshot")
    job.finished_at = finished
    finalize_run_lifecycle(db, job)
    job.status = JOB_DONE
    job.error = error
    return job


def display_severity(db: Session, asset_finding: AssetFinding) -> str:
    latest = (
        db.query(Finding)
        .filter(Finding.asset_finding_id == asset_finding.id)
        .order_by(Finding.found_at.desc(), Finding.id.desc())
        .first()
    )
    if latest and latest.severity:
        return latest.severity
    mapping = nuclei_mapping_for(db, asset_finding.vulnerability_id)
    if mapping and mapping.last_severity:
        return mapping.last_severity
    return "info"


def open_finding_severity_counts(db: Session, tenant_id: int | None = None) -> dict[str, int]:
    query = db.query(AssetFinding).filter(AssetFinding.technical_state == TECHNICAL_OPEN)
    if tenant_id is not None:
        query = query.filter(AssetFinding.tenant_id == tenant_id)
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for row in query.all():
        severity = display_severity(db, row)
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def identity_label(vulnerability: Vulnerability, mapping: VulnerabilityDetectorMapping | None) -> str:
    if vulnerability.cve_id:
        return vulnerability.cve_id
    if mapping and mapping.detector_key:
        return f"{mapping.detector_type}:{mapping.detector_key}"
    return vulnerability.canonical_key


def merge_asset_findings(db: Session, *, target: Asset, sources: list[Asset]) -> None:
    if any(source.tenant_id != target.tenant_id for source in sources):
        raise FindingLifecycleError("Cross-tenant asset/finding relationship is not allowed")
    now = utcnow()
    for source in sources:
        rows = (
            db.query(AssetFinding)
            .options(selectinload(AssetFinding.evidence), selectinload(AssetFinding.history), selectinload(AssetFinding.evaluations))
            .filter(AssetFinding.asset_id == source.id)
            .all()
        )
        for donor in rows:
            keeper = (
                db.query(AssetFinding)
                .filter(
                    AssetFinding.asset_id == target.id,
                    AssetFinding.vulnerability_id == donor.vulnerability_id,
                )
                .first()
            )
            if keeper is None:
                donor.asset_id = target.id
                donor.tenant_id = target.tenant_id
                donor.updated_at = now
                db.query(Finding).filter(Finding.asset_finding_id == donor.id).update(
                    {Finding.asset_id: target.id, Finding.tenant_id: target.tenant_id},
                    synchronize_session=False,
                )
                continue
            _merge_duplicate_asset_findings(db, keeper=keeper, donor=donor, now=now)


def _merge_duplicate_asset_findings(
    db: Session,
    *,
    keeper: AssetFinding,
    donor: AssetFinding,
    now: datetime,
) -> None:
    if donor.first_seen and (not keeper.first_seen or donor.first_seen < keeper.first_seen):
        keeper.first_seen = donor.first_seen
    if donor.last_seen and (not keeper.last_seen or donor.last_seen > keeper.last_seen):
        keeper.last_seen = donor.last_seen
    keeper.reopened_count = (keeper.reopened_count or 0) + (donor.reopened_count or 0)
    if keeper.technical_state == TECHNICAL_OPEN or donor.technical_state == TECHNICAL_OPEN:
        keeper.technical_state = TECHNICAL_OPEN
        keeper.resolved_at = None
        keeper.consecutive_clean_scans = min(keeper.consecutive_clean_scans or 0, donor.consecutive_clean_scans or 0)
    else:
        keeper.technical_state = TECHNICAL_RESOLVED
        stamps = [stamp for stamp in (keeper.resolved_at, donor.resolved_at) if stamp]
        keeper.resolved_at = max(stamps) if stamps else keeper.resolved_at
        keeper.consecutive_clean_scans = max(keeper.consecutive_clean_scans or 0, donor.consecutive_clean_scans or 0)
    if keeper.treatment_state != donor.treatment_state:
        keeper.treatment_state = TREATMENT_UNADDRESSED
    keeper.updated_at = now
    db.query(Finding).filter(Finding.asset_finding_id == donor.id).update(
        {
            Finding.asset_finding_id: keeper.id,
            Finding.asset_id: keeper.asset_id,
            Finding.tenant_id: keeper.tenant_id,
        },
        synchronize_session=False,
    )
    db.query(AssetFindingHistory).filter(AssetFindingHistory.asset_finding_id == donor.id).update(
        {AssetFindingHistory.asset_finding_id: keeper.id, AssetFindingHistory.tenant_id: keeper.tenant_id},
        synchronize_session=False,
    )
    donor_evals = (
        db.query(AssetFindingRunEvaluation)
        .filter(AssetFindingRunEvaluation.asset_finding_id == donor.id)
        .all()
    )
    for evaluation in donor_evals:
        collision = (
            db.query(AssetFindingRunEvaluation)
            .filter(
                AssetFindingRunEvaluation.asset_finding_id == keeper.id,
                AssetFindingRunEvaluation.scan_job_id == evaluation.scan_job_id,
            )
            .first()
        )
        if collision is None:
            evaluation.asset_finding_id = keeper.id
            evaluation.tenant_id = keeper.tenant_id
        elif collision.outcome != EVALUATION_DETECTED and evaluation.outcome == EVALUATION_DETECTED:
            db.delete(collision)
            evaluation.asset_finding_id = keeper.id
            evaluation.tenant_id = keeper.tenant_id
        else:
            db.delete(evaluation)
    db.flush()
    db.delete(donor)
    db.flush()


__all__ = [
    "FindingLifecycleError",
    "apply_detection",
    "asset_observed_in_run",
    "catalog_identity",
    "complete_scan_run",
    "display_severity",
    "evidence_identity_key",
    "extract_explicit_cve",
    "finalize_run_lifecycle",
    "identity_label",
    "ingest_findings",
    "is_finding_applicable_to_run",
    "merge_asset_findings",
    "parse_detector_identity",
    "resolution_threshold",
    "resolve_trusted_asset",
]
