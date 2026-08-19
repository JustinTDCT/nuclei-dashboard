"""Scanner-independent finding identity and lifecycle.

Phase 2A owns catalog identity, Detection Evidence, and consecutive
clean-scan resolution. Treatment workflows are Phase 2C.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, selectinload

from app.classify import identity_name, is_ip, normalize_hostname
from app.correlation import canonical_asset_id
from app.events import emit_domain_event, trusted_run_locality
from app.models import (
    COVERAGE_KIND_CIDR,
    COVERAGE_KIND_FQDN,
    COVERAGE_KIND_IP,
    COVERAGE_KIND_IP_PORT,
    COVERAGE_KIND_OTHER,
    COVERAGE_KIND_URL,
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
    HOST_COVERAGE_KINDS,
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
    ScanRunDetectorCoverage,
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


def explicit_cves(raw: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for item in _classification_cves(raw):
        cve = normalize_cve(item)
        if cve and cve not in seen:
            seen.append(cve)
    return seen


def extract_explicit_cve(raw: dict[str, Any]) -> str | None:
    cves = explicit_cves(raw)
    if len(cves) == 1:
        return cves[0]
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


def parse_coverage_target(target: str) -> tuple[str, str]:
    raw = (target or "").strip()
    if not raw:
        return "", COVERAGE_KIND_OTHER
    if "://" in raw:
        host = urlparse(raw).hostname or ""
        return normalize_hostname(host), COVERAGE_KIND_URL
    try:
        network = ipaddress.ip_network(raw, strict=False)
        if "/" in raw or network.num_addresses > 1:
            return "", COVERAGE_KIND_CIDR
        return str(network.network_address), COVERAGE_KIND_IP
    except ValueError:
        pass
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if is_ip(host) and port.isdigit():
            return host, COVERAGE_KIND_IP_PORT
    if is_ip(raw):
        return raw, COVERAGE_KIND_IP
    host = normalize_hostname(raw.split("/")[0])
    if host and not is_ip(host):
        return host, COVERAGE_KIND_FQDN
    return host, COVERAGE_KIND_OTHER


def store_detector_coverage(
    db: Session,
    job: ScanJob,
    *,
    detector_type: str,
    targets: list[str],
) -> int:
    detector = (detector_type or "").strip().lower()
    if not detector:
        raise FindingLifecycleError("detector_type is required")
    if job.tenant_id is None:
        raise FindingLifecycleError("Run tenant is required")
    added = 0
    seen: set[str] = set()
    for raw in targets:
        target = (raw or "").strip()
        if not target or target in seen:
            continue
        seen.add(target)
        existing = (
            db.query(ScanRunDetectorCoverage.id)
            .filter(
                ScanRunDetectorCoverage.scan_job_id == job.id,
                ScanRunDetectorCoverage.detector_type == detector,
                ScanRunDetectorCoverage.target == target,
            )
            .first()
        )
        if existing is not None:
            continue
        host, kind = parse_coverage_target(target)
        db.add(
            ScanRunDetectorCoverage(
                tenant_id=job.tenant_id,
                scan_job_id=job.id,
                detector_type=detector,
                target=target,
                normalized_host=host,
                target_kind=kind,
            )
        )
        added += 1
    db.flush()
    return added


def current_run_observations(db: Session, job: ScanJob) -> list[AssetObservation]:
    return (
        db.query(AssetObservation)
        .filter(
            AssetObservation.scan_job_id == job.id,
            AssetObservation.tenant_id == job.tenant_id,
        )
        .all()
    )


def _observation_identity_tokens(observation: AssetObservation) -> set[str]:
    tokens: set[str] = set()
    if observation.ip:
        tokens.add(observation.ip.strip())
    hostname = normalize_hostname(observation.hostname or "")
    if hostname and not is_ip(hostname):
        tokens.add(hostname)
    snapshot = observation.snapshot if isinstance(observation.snapshot, dict) else {}
    for key in ("ip", "hostname", "fqdn"):
        value = snapshot.get(key)
        if isinstance(value, str) and value.strip():
            token = normalize_hostname(value) if key != "ip" else value.strip()
            if token and (key == "ip" or not is_ip(token)):
                tokens.add(token)
    return tokens


def _identity_tokens(identity: DetectorIdentity) -> set[str]:
    tokens: set[str] = set()
    if identity.ip:
        tokens.add(identity.ip.strip())
    hostname = normalize_hostname(identity.hostname or "")
    if hostname and not is_ip(hostname):
        tokens.add(hostname)
    raw_host = (identity.host or identity.matched_at or "").strip()
    parsed = urlparse(raw_host).hostname if "://" in raw_host else raw_host.split("/")[0].split(":")[0]
    parsed = normalize_hostname(parsed or "")
    if parsed:
        tokens.add(parsed)
    return {token for token in tokens if token}


def resolve_current_run_asset(db: Session, job: ScanJob, identity: DetectorIdentity) -> Asset | None:
    observations = current_run_observations(db, job)
    if not observations:
        return None
    tokens = _identity_tokens(identity)
    if not tokens:
        return None
    asset_ids: set[int] = set()
    for observation in observations:
        if observation.tenant_id != job.tenant_id:
            continue
        if tokens.intersection(_observation_identity_tokens(observation)):
            asset_ids.add(observation.asset_id)
    if len(asset_ids) != 1:
        return None
    asset = db.get(Asset, next(iter(asset_ids)))
    if asset is None or asset.tenant_id != job.tenant_id:
        return None
    canonical_id = canonical_asset_id(db, asset.id)
    if canonical_id != asset.id:
        asset = db.get(Asset, canonical_id)
        if asset is None or asset.tenant_id != job.tenant_id:
            return None
    return asset


def current_run_device(db: Session, job: ScanJob, identity: DetectorIdentity) -> Device | None:
    tokens = _identity_tokens(identity)
    if not tokens:
        return None
    devices = (
        db.query(Device)
        .filter(Device.last_scan_job_id == job.id, Device.tenant_id == job.tenant_id)
        .all()
    )
    matches: list[Device] = []
    for device in devices:
        device_tokens = {part for part in (device.ip or "", normalize_hostname(device.hostname or "")) if part}
        if tokens.intersection(device_tokens):
            matches.append(device)
    if len({row.id for row in matches}) != 1:
        return None
    return matches[0]


def resolve_trusted_asset(
    db: Session,
    *,
    tenant_id: int,
    job: ScanJob,
    device: Device | None,
) -> Asset | None:
    if device is None or device.asset_id is None:
        return None
    if device.last_scan_job_id != job.id:
        return None
    if device.tenant_id != tenant_id or device.tenant_id != job.tenant_id:
        return None
    if not asset_observed_in_run(db, job, device.asset_id):
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


def cve_union(raws: list[dict[str, Any]]) -> set[str]:
    cves: set[str] = set()
    for raw in raws:
        cves.update(explicit_cves(raw if isinstance(raw, dict) else {}))
    return cves


def _known_cves_for_detector(db: Session, identity: DetectorIdentity) -> set[str]:
    raws = [identity.raw or {}]
    rows = (
        db.query(Finding.raw_json)
        .filter(
            Finding.detector_type == identity.detector_type,
            Finding.detector_key == identity.detector_key,
        )
        .all()
    )
    raws.extend(raw if isinstance(raw, dict) else {} for (raw,) in rows)
    return cve_union(raws)


def desired_catalog_identity(db: Session, identity: DetectorIdentity) -> tuple[str, str | None]:
    cves = _known_cves_for_detector(db, identity)
    if len(cves) == 1:
        cve_id = next(iter(cves))
        return f"cve:{cve_id}", cve_id
    return catalog_identity(identity.detector_type, identity.detector_key, None), None


def get_or_create_mapping(
    db: Session,
    vulnerability: Vulnerability,
    identity: DetectorIdentity,
) -> VulnerabilityDetectorMapping:
    vulnerability, mapping = upsert_detector_catalog(db, identity)
    if mapping.vulnerability_id != vulnerability.id:
        raise FindingLifecycleError("Detector mapping already belongs to a different vulnerability")
    return mapping


def upsert_detector_catalog(
    db: Session,
    identity: DetectorIdentity,
) -> tuple[Vulnerability | None, VulnerabilityDetectorMapping | None]:
    if not identity.detector_type or not identity.detector_key:
        return None, None
    canonical_key, cve_id = desired_catalog_identity(db, identity)
    resolved = DetectorIdentity(
        detector_type=identity.detector_type,
        detector_key=identity.detector_key,
        cve_id=cve_id,
        canonical_key=canonical_key,
        title=identity.title,
        description=identity.description,
        severity=identity.severity,
        tags=identity.tags,
        host=identity.host,
        matched_at=identity.matched_at,
        hostname=identity.hostname,
        ip=identity.ip,
        raw=identity.raw,
    )
    vulnerability = get_or_create_vulnerability(db, resolved)
    if vulnerability is None:
        return None, None
    existing = (
        db.query(VulnerabilityDetectorMapping)
        .filter(
            VulnerabilityDetectorMapping.detector_type == identity.detector_type,
            VulnerabilityDetectorMapping.detector_key == identity.detector_key,
        )
        .first()
    )
    if existing is None:
        existing = VulnerabilityDetectorMapping(
            vulnerability_id=vulnerability.id,
            detector_type=identity.detector_type,
            detector_key=identity.detector_key,
            last_severity=identity.severity,
            last_tags=identity.tags,
        )
        db.add(existing)
        db.flush()
        return vulnerability, existing
    if existing.vulnerability_id != vulnerability.id:
        retarget_mapping(db, existing, vulnerability)
    if identity.severity:
        existing.last_severity = identity.severity
    if identity.tags:
        existing.last_tags = identity.tags
    db.flush()
    return vulnerability, existing


def _recompute_asset_finding_seen(db: Session, asset_finding: AssetFinding) -> None:
    bounds = (
        db.query(func.min(Finding.found_at), func.max(Finding.found_at))
        .filter(Finding.asset_finding_id == asset_finding.id)
        .one()
    )
    if bounds[0] is not None:
        asset_finding.first_seen = bounds[0]
        asset_finding.last_seen = bounds[1]
        asset_finding.updated_at = utcnow()


def _other_detector_evidence_exists(
    db: Session,
    *,
    asset_finding_id: int,
    mapping: VulnerabilityDetectorMapping,
) -> bool:
    return (
        db.query(Finding.id)
        .filter(
            Finding.asset_finding_id == asset_finding_id,
            or_(
                Finding.detector_type != mapping.detector_type,
                Finding.detector_key != mapping.detector_key,
            ),
        )
        .first()
        is not None
    )


def partition_asset_finding_for_mapping(
    db: Session,
    *,
    donor: AssetFinding,
    mapping: VulnerabilityDetectorMapping,
    vulnerability: Vulnerability,
) -> AssetFinding:
    now = utcnow()
    supporting = (
        db.query(Finding)
        .filter(
            Finding.asset_finding_id == donor.id,
            Finding.detector_type == mapping.detector_type,
            Finding.detector_key == mapping.detector_key,
        )
        .all()
    )
    if not supporting:
        return donor
    if not _other_detector_evidence_exists(db, asset_finding_id=donor.id, mapping=mapping):
        keeper = (
            db.query(AssetFinding)
            .filter(
                AssetFinding.asset_id == donor.asset_id,
                AssetFinding.vulnerability_id == vulnerability.id,
                AssetFinding.id != donor.id,
            )
            .first()
        )
        if keeper is None:
            donor.vulnerability_id = vulnerability.id
            donor.updated_at = now
            return donor
        _merge_duplicate_asset_findings(db, keeper=keeper, donor=donor, now=now)
        return keeper
    keeper = (
        db.query(AssetFinding)
        .filter(
            AssetFinding.asset_id == donor.asset_id,
            AssetFinding.vulnerability_id == vulnerability.id,
        )
        .first()
    )
    created = False
    if keeper is None:
        first_seen = min(row.found_at for row in supporting if row.found_at is not None)
        last_seen = max(row.found_at for row in supporting if row.found_at is not None)
        keeper = AssetFinding(
            tenant_id=donor.tenant_id,
            asset_id=donor.asset_id,
            vulnerability_id=vulnerability.id,
            technical_state=TECHNICAL_OPEN,
            treatment_state=TREATMENT_UNADDRESSED,
            first_seen=first_seen,
            last_seen=last_seen,
            resolved_at=None,
            consecutive_clean_scans=0,
            reopened_count=0,
            updated_at=now,
        )
        db.add(keeper)
        db.flush()
        created = True
    for row in supporting:
        row.asset_finding_id = keeper.id
        row.asset_id = keeper.asset_id
        row.tenant_id = keeper.tenant_id
    db.flush()
    _recompute_asset_finding_seen(db, keeper)
    _recompute_asset_finding_seen(db, donor)
    if created:
        _append_history(
            db,
            asset_finding=keeper,
            transition_type=HISTORY_OPENED,
            previous=None,
            new_state=TECHNICAL_OPEN,
            scan_job_id=None,
            occurred_at=keeper.first_seen,
            details={
                "reason": "detector_identity_partition",
                "source_asset_finding_id": donor.id,
                "detector_type": mapping.detector_type,
                "detector_key": mapping.detector_key,
            },
            idempotence_key=(
                f"partition-opened:{keeper.id}:{mapping.detector_type}:{mapping.detector_key}"
            ),
        )
    from app.intel.priority import recalculate_asset_finding_priorities

    recalculate_asset_finding_priorities(db, [keeper, donor])
    return keeper


def retarget_mapping(
    db: Session,
    mapping: VulnerabilityDetectorMapping,
    vulnerability: Vulnerability,
) -> None:
    if mapping.vulnerability_id == vulnerability.id:
        return
    previous_id = mapping.vulnerability_id
    mapping.vulnerability_id = vulnerability.id
    db.flush()
    donor_ids = {
        row[0]
        for row in db.query(Finding.asset_finding_id)
        .filter(
            Finding.detector_type == mapping.detector_type,
            Finding.detector_key == mapping.detector_key,
            Finding.asset_finding_id.isnot(None),
        )
        .all()
        if row[0] is not None
    }
    donors = (
        db.query(AssetFinding)
        .filter(AssetFinding.id.in_(donor_ids), AssetFinding.vulnerability_id == previous_id)
        .all()
        if donor_ids
        else []
    )
    for donor in donors:
        partition_asset_finding_for_mapping(
            db,
            donor=donor,
            mapping=mapping,
            vulnerability=vulnerability,
        )
    db.flush()


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
    job: ScanJob,
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
        "scan_job_id": job.id,
        **(extra or {}),
    }
    site_id, network_id = trusted_run_locality(db, job, asset=asset_finding.asset)
    emit_domain_event(
        db,
        event_type=event_type,
        tenant_id=asset_finding.tenant_id,
        site_id=site_id,
        network_id=network_id,
        asset_id=asset_finding.asset_id,
        asset_finding_id=asset_finding.id,
        scan_job_id=job.id,
        idempotence_key=f"{event_type}:{asset_finding.id}:{job.id}",
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
            job=job,
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
                job=job,
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
    job = db.get(ScanJob, job_id)
    if job is None or job.tenant_id != tenant_id:
        raise FindingLifecycleError("Scan run does not belong to this tenant")
    added = 0
    for report in reports:
        identity = parse_detector_identity(report)
        key = evidence_identity_key(
            scan_job_id=job.id,
            detector_type=identity.detector_type,
            detector_key=identity.detector_key,
            host=identity.host,
            matched_at=identity.matched_at,
        )
        if db.query(Finding.id).filter(Finding.evidence_key == key).first() is not None:
            continue
        vulnerability, _mapping = upsert_detector_catalog(db, identity)
        device = current_run_device(db, job, identity)
        if device and device.tenant_id != tenant_id:
            raise FindingLifecycleError("Cross-tenant device/finding relationship is not allowed")
        asset = resolve_current_run_asset(db, job, identity)
        if asset is not None and asset.tenant_id != tenant_id:
            raise FindingLifecycleError("Cross-tenant asset/finding relationship is not allowed")
        hostname = (device.hostname if device else identity.hostname) or identity.hostname
        asset_finding = None
        if asset is not None and vulnerability is not None:
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
        if asset_finding is not None:
            from app.intel.priority import recalculate_asset_finding_priorities

            recalculate_asset_finding_priorities(db, [asset_finding])
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


def supporting_detector_keys(db: Session, asset_finding: AssetFinding) -> list[tuple[str, str]]:
    rows = (
        db.query(Finding.detector_type, Finding.detector_key)
        .filter(
            Finding.asset_finding_id == asset_finding.id,
            Finding.detector_type != "",
            Finding.detector_key != "",
        )
        .distinct()
        .all()
    )
    return [(detector_type, detector_key) for detector_type, detector_key in rows]


def supporting_mappings(db: Session, asset_finding: AssetFinding) -> list[VulnerabilityDetectorMapping]:
    keys = supporting_detector_keys(db, asset_finding)
    if not keys:
        return []
    mappings: list[VulnerabilityDetectorMapping] = []
    for detector_type, detector_key in keys:
        mapping = (
            db.query(VulnerabilityDetectorMapping)
            .filter(
                VulnerabilityDetectorMapping.detector_type == detector_type,
                VulnerabilityDetectorMapping.detector_key == detector_key,
            )
            .first()
        )
        if mapping is None:
            return []
        mappings.append(mapping)
    return mappings


def latest_supporting_evidence(
    db: Session,
    asset_finding: AssetFinding,
    detector_type: str,
    detector_key: str,
) -> Finding | None:
    return (
        db.query(Finding)
        .filter(
            Finding.asset_finding_id == asset_finding.id,
            Finding.detector_type == detector_type,
            Finding.detector_key == detector_key,
        )
        .order_by(Finding.found_at.desc(), Finding.id.desc())
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


def asset_covered_by_detector(db: Session, job: ScanJob, asset_id: int, detector_type: str) -> bool:
    coverage = (
        db.query(ScanRunDetectorCoverage)
        .filter(
            ScanRunDetectorCoverage.scan_job_id == job.id,
            ScanRunDetectorCoverage.tenant_id == job.tenant_id,
            ScanRunDetectorCoverage.detector_type == detector_type,
        )
        .all()
    )
    if not coverage:
        return False
    observations = (
        db.query(AssetObservation)
        .filter(
            AssetObservation.scan_job_id == job.id,
            AssetObservation.asset_id == asset_id,
            AssetObservation.tenant_id == job.tenant_id,
        )
        .all()
    )
    if not observations:
        return False
    tokens: set[str] = set()
    for observation in observations:
        tokens.update(_observation_identity_tokens(observation))
    if not tokens:
        return False
    for row in coverage:
        if row.target_kind not in HOST_COVERAGE_KINDS:
            continue
        host = (row.normalized_host or "").strip()
        if host and host in tokens:
            return True
    return False


def _mapping_included_in_filters(
    *,
    stages: dict[str, Any],
    severity: str,
    tags: str,
) -> bool:
    selected = set(parse_csv_tokens(str(stages.get("nuclei_severities") or "")))
    known_severity = (severity or "").strip().lower()
    if not selected or not known_severity or known_severity not in selected:
        return False
    tag_filter = parse_csv_tokens(str(stages.get("nuclei_tags") or ""))
    if tag_filter:
        known_tags = set(parse_csv_tokens(tags))
        if not known_tags or not known_tags.intersection(tag_filter):
            return False
    return True


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
    if not asset_covered_by_detector(db, job, asset_finding.asset_id, DETECTOR_NUCLEI):
        return False
    mappings = supporting_mappings(db, asset_finding)
    if not mappings:
        return False
    for mapping in mappings:
        if mapping.detector_type != DETECTOR_NUCLEI:
            return False
        evidence = latest_supporting_evidence(db, asset_finding, mapping.detector_type, mapping.detector_key)
        severity = (evidence.severity if evidence else mapping.last_severity) or ""
        tags = (evidence.tags if evidence else mapping.last_tags) or ""
        if not _mapping_included_in_filters(stages=stages, severity=severity, tags=tags):
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
    threshold_details: dict[str, Any] | None = None,
) -> None:
    if asset_finding.technical_state != TECHNICAL_OPEN:
        return
    if asset_finding.consecutive_clean_scans < threshold:
        return
    previous = asset_finding.technical_state
    asset_finding.technical_state = TECHNICAL_RESOLVED
    asset_finding.resolved_at = occurred_at
    asset_finding.updated_at = occurred_at
    details = {"reason": "consecutive_clean_scans", "threshold": threshold}
    if threshold_details:
        details.update(threshold_details)
    history = _append_history(
        db,
        asset_finding=asset_finding,
        transition_type=HISTORY_RESOLVED,
        previous=previous,
        new_state=TECHNICAL_RESOLVED,
        scan_job_id=job.id,
        occurred_at=occurred_at,
        details=details,
        idempotence_key=f"resolved:{asset_finding.id}:{job.id}",
    )
    if history is not None:
        _emit_lifecycle_event(
            db,
            event_type=EVENT_VULNERABILITY_RESOLVED,
            asset_finding=asset_finding,
            vulnerability=asset_finding.vulnerability,
            job=job,
            occurred_at=occurred_at,
            extra={"consecutive_clean_scans": asset_finding.consecutive_clean_scans},
        )


def finalize_run_lifecycle(db: Session, job: ScanJob) -> None:
    if not job.execution_snapshot:
        raise FindingLifecycleError("Run has no immutable execution snapshot")
    occurred_at = job.finished_at or utcnow()
    from app.models import POLICY_CATEGORY_FINDING_LIFECYCLE
    from app.policy import PolicyResolver, context_for_findings, resolution_details

    resolver = PolicyResolver(db)
    fallback_threshold = resolution_threshold(db)
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
    clean_candidates = [row for row in candidates if row.id not in detected_ids]
    unique_assets: list[Asset] = []
    seen_assets: set[int] = set()
    for row in clean_candidates:
        if row.asset is not None and row.asset.id not in seen_assets:
            seen_assets.add(row.asset.id)
            unique_assets.append(row.asset)
    finding_contexts = context_for_findings(db, clean_candidates, assets=unique_assets)
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
        context = finding_contexts.get(asset_finding.id)
        if context is None:
            threshold = fallback_threshold
            details = {"threshold_source": "fallback"}
        else:
            evaluated = resolver.evaluate(context, POLICY_CATEGORY_FINDING_LIFECYCLE)
            explanation = evaluated.actions["resolution_clean_scans"]
            threshold = int(explanation.value)
            details = resolution_details(explanation)
        _resolve_if_threshold_reached(
            db,
            asset_finding=asset_finding,
            job=job,
            occurred_at=occurred_at,
            threshold=threshold,
            threshold_details=details,
        )
    db.flush()


def complete_scan_run(db: Session, job: ScanJob, *, ok: bool, error: str | None = None) -> ScanJob:
    finished = utcnow()
    if not ok:
        from app.jobs import transition_job_to_failed

        transition_job_to_failed(db, job, error or "scan failed")
        job.finished_at = finished
        return job
    if not job.execution_snapshot:
        raise FindingLifecycleError("Successful completion requires an immutable execution snapshot")
    job.finished_at = finished
    finalize_run_lifecycle(db, job)
    job.status = JOB_DONE
    job.error = error
    return job


def latest_evidence_subquery(db: Session):
    return (
        db.query(
            Finding.asset_finding_id.label("asset_finding_id"),
            Finding.severity.label("severity"),
            Finding.detector_type.label("detector_type"),
            Finding.detector_key.label("detector_key"),
        )
        .distinct(Finding.asset_finding_id)
        .filter(Finding.asset_finding_id.isnot(None))
        .order_by(Finding.asset_finding_id, Finding.found_at.desc(), Finding.id.desc())
        .subquery()
    )


def display_severity_sql(latest, mapping):
    return func.lower(func.coalesce(latest.c.severity, mapping.last_severity, "info"))


def apply_severity_filter(query, db: Session, severity: str | None):
    if not severity:
        return query
    latest = latest_evidence_subquery(db)
    mapping = VulnerabilityDetectorMapping
    return (
        query.outerjoin(latest, latest.c.asset_finding_id == AssetFinding.id)
        .outerjoin(
            mapping,
            and_(
                mapping.detector_type == latest.c.detector_type,
                mapping.detector_key == latest.c.detector_key,
            ),
        )
        .filter(display_severity_sql(latest, mapping) == severity.strip().lower())
    )


def display_severity(db: Session, asset_finding: AssetFinding) -> str:
    latest = (
        db.query(Finding)
        .filter(Finding.asset_finding_id == asset_finding.id)
        .order_by(Finding.found_at.desc(), Finding.id.desc())
        .first()
    )
    if latest and latest.severity:
        return latest.severity
    if latest and latest.detector_type and latest.detector_key:
        mapping = (
            db.query(VulnerabilityDetectorMapping)
            .filter(
                VulnerabilityDetectorMapping.detector_type == latest.detector_type,
                VulnerabilityDetectorMapping.detector_key == latest.detector_key,
            )
            .first()
        )
        if mapping and mapping.last_severity:
            return mapping.last_severity
    mapping = nuclei_mapping_for(db, asset_finding.vulnerability_id)
    if mapping and mapping.last_severity:
        return mapping.last_severity
    return "info"


def load_asset_finding_display(db: Session, rows: list[AssetFinding]) -> dict[int, dict[str, Any]]:
    ids = [row.id for row in rows]
    empty: dict[int, dict[str, Any]] = {
        row.id: {"severity": "info", "mapping": None, "evidence_count": 0} for row in rows
    }
    if not ids:
        return empty
    latest_rows = (
        db.query(Finding)
        .distinct(Finding.asset_finding_id)
        .filter(Finding.asset_finding_id.in_(ids))
        .order_by(Finding.asset_finding_id, Finding.found_at.desc(), Finding.id.desc())
        .all()
    )
    latest_by_af = {row.asset_finding_id: row for row in latest_rows if row.asset_finding_id is not None}
    mapping_keys = {
        (row.detector_type, row.detector_key)
        for row in latest_rows
        if row.detector_type and row.detector_key
    }
    mappings = []
    if mapping_keys:
        mappings = (
            db.query(VulnerabilityDetectorMapping)
            .filter(
                or_(
                    *[
                        and_(
                            VulnerabilityDetectorMapping.detector_type == detector_type,
                            VulnerabilityDetectorMapping.detector_key == detector_key,
                        )
                        for detector_type, detector_key in mapping_keys
                    ]
                )
            )
            .all()
        )
    mapping_by_key = {(row.detector_type, row.detector_key): row for row in mappings}
    counts = dict(
        db.query(Finding.asset_finding_id, func.count(Finding.id))
        .filter(Finding.asset_finding_id.in_(ids))
        .group_by(Finding.asset_finding_id)
        .all()
    )
    display = empty
    for asset_finding in rows:
        latest = latest_by_af.get(asset_finding.id)
        mapping = None
        if latest is not None:
            mapping = mapping_by_key.get((latest.detector_type, latest.detector_key))
        severity = (latest.severity if latest and latest.severity else "") or (
            mapping.last_severity if mapping else ""
        ) or "info"
        display[asset_finding.id] = {
            "severity": severity,
            "mapping": mapping,
            "evidence_count": int(counts.get(asset_finding.id) or 0),
        }
    return display


def open_finding_severity_counts(
    db: Session,
    tenant_id: int | None = None,
    *,
    tenant_filter=None,
    site_id: int | None = None,
) -> dict[str, int]:
    latest = latest_evidence_subquery(db)
    mapping = VulnerabilityDetectorMapping
    query = (
        db.query(display_severity_sql(latest, mapping), func.count(AssetFinding.id))
        .select_from(AssetFinding)
        .outerjoin(latest, latest.c.asset_finding_id == AssetFinding.id)
        .outerjoin(
            mapping,
            and_(
                mapping.detector_type == latest.c.detector_type,
                mapping.detector_key == latest.c.detector_key,
            ),
        )
        .filter(AssetFinding.technical_state == TECHNICAL_OPEN)
    )
    if tenant_id is not None:
        query = query.filter(AssetFinding.tenant_id == tenant_id)
    elif tenant_filter is not None:
        query = query.filter(tenant_filter)
    if site_id is not None:
        query = query.join(Asset, Asset.id == AssetFinding.asset_id).filter(Asset.site_id == site_id)
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for severity, total in query.group_by(display_severity_sql(latest, mapping)).all():
        counts[str(severity or "info")] = counts.get(str(severity or "info"), 0) + int(total)
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
    from app.treatments import merge_finding_treatments

    merge_finding_treatments(db, keeper=keeper, donor=donor, now=now)
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
    from app.intel.priority import recalculate_asset_finding_priorities

    recalculate_asset_finding_priorities(db, [keeper])


__all__ = [
    "FindingLifecycleError",
    "apply_detection",
    "apply_severity_filter",
    "asset_covered_by_detector",
    "asset_observed_in_run",
    "catalog_identity",
    "complete_scan_run",
    "cve_union",
    "display_severity",
    "evidence_identity_key",
    "explicit_cves",
    "extract_explicit_cve",
    "finalize_run_lifecycle",
    "identity_label",
    "ingest_findings",
    "is_finding_applicable_to_run",
    "load_asset_finding_display",
    "merge_asset_findings",
    "parse_detector_identity",
    "partition_asset_finding_for_mapping",
    "resolution_threshold",
    "resolve_current_run_asset",
    "resolve_trusted_asset",
    "store_detector_coverage",
    "upsert_detector_catalog",
]
