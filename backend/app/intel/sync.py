"""Source synchronization for NVD, FIRST EPSS, and CISA KEV."""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.intel.epss import EpssDataset, fetch_epss_dataset
from app.intel.http import FetchFn, IntelligenceHttpError, fetch_url
from app.intel.kev import KevCatalog, fetch_kev_catalog
from app.intel.nvd import ParsedNvdCve, fetch_nvd_cves, nvd_rate_delay
from app.intel.priority import recalculate_priorities_for_vulnerabilities
from app.models import (
    INTEL_SOURCE_CISA_KEV,
    INTEL_SOURCE_EPSS,
    INTEL_SOURCE_NVD,
    Vulnerability,
    VulnerabilityCwe,
    VulnerabilityIntelligence,
    VulnerabilityIntelligenceSync,
    VulnerabilityReference,
)
from app.settings_store import get_settings

log = logging.getLogger(__name__)

NVD_FRESHNESS = timedelta(hours=6)
KEV_FRESHNESS = timedelta(hours=6)
EPSS_FRESHNESS = timedelta(hours=24)
NVD_BATCH_SIZE = 50
LOCK_KEYSPACE = 742201


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def nvd_api_key() -> str | None:
    key = (settings.nvd_api_key or "").strip()
    return key or None


def nvd_api_key_configured() -> bool:
    return nvd_api_key() is not None


def _redact(error: Exception | str) -> str:
    text_value = str(error)
    key = nvd_api_key()
    if key:
        text_value = text_value.replace(key, "<redacted>")
    return text_value[:500]


def _get_or_create_sync(db: Session, source: str) -> VulnerabilityIntelligenceSync:
    row = db.get(VulnerabilityIntelligenceSync, source)
    if row is None:
        row = VulnerabilityIntelligenceSync(source=source, extra_metadata={}, updated_at=utcnow())
        db.add(row)
        db.flush()
    return row


def _mark_attempt(db: Session, source: str) -> VulnerabilityIntelligenceSync:
    row = _get_or_create_sync(db, source)
    row.last_attempt_at = utcnow()
    row.updated_at = utcnow()
    db.flush()
    return row


def _mark_success(
    db: Session,
    source: str,
    *,
    records_seen: int,
    records_updated: int,
    source_updated_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    row = _get_or_create_sync(db, source)
    now = utcnow()
    row.last_attempt_at = row.last_attempt_at or now
    row.last_success_at = now
    row.source_updated_at = source_updated_at
    row.records_seen = records_seen
    row.records_updated = records_updated
    row.last_error = None
    if metadata:
        current = dict(row.extra_metadata or {})
        current.update(metadata)
        row.extra_metadata = current
    row.updated_at = now
    db.flush()


def _mark_failure(db: Session, source: str, error: Exception | str) -> None:
    row = _get_or_create_sync(db, source)
    row.last_attempt_at = row.last_attempt_at or utcnow()
    row.last_error = _redact(error)
    row.updated_at = utcnow()
    db.flush()


def _lock_key(source: str) -> int:
    digest = hashlib.sha256(f"vuln-intel:{source}".encode("utf-8")).hexdigest()
    return LOCK_KEYSPACE + int(digest[:8], 16) % 100000


def _try_lock(db: Session, source: str) -> bool:
    acquired = db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": _lock_key(source)}).scalar()
    return bool(acquired)


def _unlock(db: Session, source: str) -> None:
    db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _lock_key(source)})


def _intel_row(db: Session, vulnerability: Vulnerability) -> VulnerabilityIntelligence:
    row = vulnerability.intelligence
    if row is None:
        row = db.get(VulnerabilityIntelligence, vulnerability.id)
    if row is None:
        row = VulnerabilityIntelligence(vulnerability_id=vulnerability.id, updated_at=utcnow())
        db.add(row)
        db.flush()
        vulnerability.intelligence = row
    return row


def _tracked_cve_vulnerabilities(db: Session) -> list[Vulnerability]:
    return (
        db.query(Vulnerability)
        .filter(Vulnerability.cve_id.isnot(None), Vulnerability.cve_id != "")
        .order_by(Vulnerability.id.asc())
        .all()
    )


def apply_nvd_record(db: Session, vulnerability: Vulnerability, parsed: ParsedNvdCve) -> bool:
    row = _intel_row(db, vulnerability)
    changed = False
    now = utcnow()
    if row.nvd_status != parsed.status:
        row.nvd_status = parsed.status
        changed = True
    if row.nvd_published_at != parsed.published_at:
        row.nvd_published_at = parsed.published_at
        changed = True
    if row.nvd_last_modified_at != parsed.last_modified_at:
        row.nvd_last_modified_at = parsed.last_modified_at
        changed = True
    if parsed.rejected:
        if row.cvss_base_score is not None or row.cvss_version is not None:
            row.cvss_version = None
            row.cvss_base_score = None
            row.cvss_base_severity = None
            row.cvss_vector = None
            row.cvss_source = None
            changed = True
    elif parsed.cvss is not None:
        score = parsed.cvss.base_score
        if (
            row.cvss_version != parsed.cvss.version
            or row.cvss_base_score != score
            or row.cvss_base_severity != parsed.cvss.base_severity
            or row.cvss_vector != parsed.cvss.vector
            or row.cvss_source != parsed.cvss.source
        ):
            row.cvss_version = parsed.cvss.version
            row.cvss_base_score = score
            row.cvss_base_severity = parsed.cvss.base_severity
            row.cvss_vector = parsed.cvss.vector
            row.cvss_source = parsed.cvss.source
            changed = True
    if parsed.description and not (vulnerability.description or "").strip():
        vulnerability.description = parsed.description
        changed = True
    if not (vulnerability.title or "").strip():
        vulnerability.title = vulnerability.cve_id or parsed.cve_id
        changed = True
    row.nvd_fetched_at = now
    row.updated_at = now
    vulnerability.updated_at = now

    existing_cwes = {
        (item.cwe_id, item.source): item
        for item in db.query(VulnerabilityCwe).filter(VulnerabilityCwe.vulnerability_id == vulnerability.id).all()
    }
    desired = {(cwe_id, source) for cwe_id, source in parsed.cwes}
    for key, item in existing_cwes.items():
        if key not in desired and not item.cwe_id.upper().startswith("NVD-CWE-"):
            db.delete(item)
            changed = True
    for cwe_id, source in parsed.cwes:
        if (cwe_id, source) not in existing_cwes:
            db.add(VulnerabilityCwe(vulnerability_id=vulnerability.id, cwe_id=cwe_id, source=source))
            changed = True

    existing_refs = {
        (item.url, item.source): item
        for item in db.query(VulnerabilityReference)
        .filter(VulnerabilityReference.vulnerability_id == vulnerability.id)
        .all()
    }
    for ref in parsed.references:
        key = (ref["url"], ref["source"])
        if key not in existing_refs:
            db.add(
                VulnerabilityReference(
                    vulnerability_id=vulnerability.id,
                    url=ref["url"],
                    source=ref["source"],
                    tags=ref.get("tags") or [],
                )
            )
            changed = True
    db.flush()
    return changed


def refresh_nvd(
    db: Session,
    *,
    fetch: FetchFn = fetch_url,
    sleep=time.sleep,
    force: bool = False,
) -> dict[str, Any]:
    sync = _mark_attempt(db, INTEL_SOURCE_NVD)
    if not force and sync.last_success_at and utcnow() - sync.last_success_at < NVD_FRESHNESS:
        return {"source": INTEL_SOURCE_NVD, "skipped": True, "reason": "not_due"}
    rows = _tracked_cve_vulnerabilities(db)
    by_cve: dict[str, list[Vulnerability]] = {}
    for row in rows:
        cve = (row.cve_id or "").upper()
        by_cve.setdefault(cve, []).append(row)
    cves = list(by_cve)
    seen = 0
    updated = 0
    affected: set[int] = set()
    api_key = nvd_api_key()
    delay = nvd_rate_delay(bool(api_key))
    try:
        for offset in range(0, len(cves), NVD_BATCH_SIZE):
            batch = cves[offset : offset + NVD_BATCH_SIZE]
            if offset and delay:
                sleep(delay)
            parsed_rows = fetch_nvd_cves(batch, api_key=api_key, fetch=fetch, sleep=sleep)
            seen += len(parsed_rows)
            parsed_by_cve = {item.cve_id: item for item in parsed_rows}
            for cve in batch:
                parsed = parsed_by_cve.get(cve)
                if parsed is None:
                    continue
                for vulnerability in by_cve[cve]:
                    if apply_nvd_record(db, vulnerability, parsed):
                        updated += 1
                    affected.add(vulnerability.id)
            db.flush()
            db.commit()
        _mark_success(db, INTEL_SOURCE_NVD, records_seen=seen, records_updated=updated)
        if affected:
            recalculate_priorities_for_vulnerabilities(db, affected)
        return {"source": INTEL_SOURCE_NVD, "records_seen": seen, "records_updated": updated}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        _mark_failure(db, INTEL_SOURCE_NVD, exc)
        log.warning("NVD refresh failed: %s", _redact(exc))
        return {"source": INTEL_SOURCE_NVD, "error": _redact(exc)}


def apply_epss_dataset(db: Session, dataset: EpssDataset, tracked: list[Vulnerability]) -> tuple[int, set[int]]:
    now = utcnow()
    updated = 0
    affected: set[int] = set()
    for vulnerability in tracked:
        cve = (vulnerability.cve_id or "").upper()
        row = _intel_row(db, vulnerability)
        record = dataset.records.get(cve)
        if record is None:
            if row.epss_score is not None or row.epss_percentile is not None:
                row.epss_score = None
                row.epss_percentile = None
                row.epss_score_date = None
                row.epss_model_version = None
                updated += 1
                affected.add(vulnerability.id)
        else:
            if (
                row.epss_score != record.score
                or row.epss_percentile != record.percentile
                or row.epss_score_date != dataset.score_date
                or row.epss_model_version != dataset.model_version
            ):
                row.epss_score = record.score
                row.epss_percentile = record.percentile
                row.epss_score_date = dataset.score_date
                row.epss_model_version = dataset.model_version
                updated += 1
                affected.add(vulnerability.id)
        row.epss_fetched_at = now
        row.updated_at = now
    db.flush()
    return updated, affected


def refresh_epss(
    db: Session,
    *,
    fetch: FetchFn = fetch_url,
    sleep=time.sleep,
    force: bool = False,
) -> dict[str, Any]:
    sync = _mark_attempt(db, INTEL_SOURCE_EPSS)
    if not force and sync.last_success_at and utcnow() - sync.last_success_at < EPSS_FRESHNESS:
        return {"source": INTEL_SOURCE_EPSS, "skipped": True, "reason": "not_due"}
    tracked = _tracked_cve_vulnerabilities(db)
    try:
        dataset = fetch_epss_dataset(fetch=fetch, sleep=sleep)
        updated, affected = apply_epss_dataset(db, dataset, tracked)
        _mark_success(
            db,
            INTEL_SOURCE_EPSS,
            records_seen=len(dataset.records),
            records_updated=updated,
            source_updated_at=dataset.source_updated_at,
            metadata={"model_version": dataset.model_version, "score_date": dataset.score_date.isoformat() if dataset.score_date else None},
        )
        if affected:
            recalculate_priorities_for_vulnerabilities(db, affected)
        return {
            "source": INTEL_SOURCE_EPSS,
            "records_seen": len(dataset.records),
            "records_updated": updated,
            "score_date": dataset.score_date.isoformat() if dataset.score_date else None,
            "model_version": dataset.model_version,
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        _mark_failure(db, INTEL_SOURCE_EPSS, exc)
        log.warning("EPSS refresh failed: %s", _redact(exc))
        return {"source": INTEL_SOURCE_EPSS, "error": _redact(exc)}


def apply_kev_catalog(db: Session, catalog: KevCatalog, tracked: list[Vulnerability]) -> tuple[int, set[int]]:
    now = utcnow()
    updated = 0
    affected: set[int] = set()
    for vulnerability in tracked:
        cve = (vulnerability.cve_id or "").upper()
        row = _intel_row(db, vulnerability)
        record = catalog.records.get(cve)
        if record is not None:
            next_state = True
            if (
                row.kev is not True
                or row.kev_date_added != record.date_added
                or row.kev_due_date != record.due_date
                or row.kev_required_action != record.required_action
                or row.kev_known_ransomware_campaign_use != record.known_ransomware_campaign_use
                or row.kev_vendor_project != record.vendor_project
                or row.kev_product != record.product
            ):
                row.kev = next_state
                row.kev_date_added = record.date_added
                row.kev_due_date = record.due_date
                row.kev_required_action = record.required_action
                row.kev_known_ransomware_campaign_use = record.known_ransomware_campaign_use
                row.kev_vendor_project = record.vendor_project
                row.kev_product = record.product
                updated += 1
                affected.add(vulnerability.id)
        elif catalog.complete:
            if row.kev is not False or row.kev_date_added is not None:
                row.kev = False
                row.kev_date_added = None
                row.kev_due_date = None
                row.kev_required_action = None
                row.kev_known_ransomware_campaign_use = None
                row.kev_vendor_project = None
                row.kev_product = None
                updated += 1
                affected.add(vulnerability.id)
        row.kev_fetched_at = now
        row.updated_at = now
    db.flush()
    return updated, affected


def refresh_kev(
    db: Session,
    *,
    fetch: FetchFn = fetch_url,
    sleep=time.sleep,
    force: bool = False,
) -> dict[str, Any]:
    sync = _mark_attempt(db, INTEL_SOURCE_CISA_KEV)
    if not force and sync.last_success_at and utcnow() - sync.last_success_at < KEV_FRESHNESS:
        return {"source": INTEL_SOURCE_CISA_KEV, "skipped": True, "reason": "not_due"}
    tracked = _tracked_cve_vulnerabilities(db)
    try:
        catalog = fetch_kev_catalog(fetch=fetch, sleep=sleep)
        updated, affected = apply_kev_catalog(db, catalog, tracked)
        _mark_success(
            db,
            INTEL_SOURCE_CISA_KEV,
            records_seen=len(catalog.records),
            records_updated=updated,
            source_updated_at=catalog.date_released,
            metadata={"catalog_version": catalog.catalog_version, "complete": catalog.complete},
        )
        if affected:
            recalculate_priorities_for_vulnerabilities(db, affected)
        return {
            "source": INTEL_SOURCE_CISA_KEV,
            "records_seen": len(catalog.records),
            "records_updated": updated,
            "complete": catalog.complete,
            "catalog_version": catalog.catalog_version,
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        _mark_failure(db, INTEL_SOURCE_CISA_KEV, exc)
        log.warning("KEV refresh failed: %s", _redact(exc))
        return {"source": INTEL_SOURCE_CISA_KEV, "error": _redact(exc)}


SOURCE_REFRESHERS = {
    INTEL_SOURCE_NVD: refresh_nvd,
    INTEL_SOURCE_EPSS: refresh_epss,
    INTEL_SOURCE_CISA_KEV: refresh_kev,
}


def refresh_intelligence(
    db: Session,
    *,
    sources: Iterable[str] | None = None,
    fetch: FetchFn = fetch_url,
    sleep=time.sleep,
    force: bool = False,
) -> dict[str, Any]:
    cfg = get_settings(db)
    if not cfg.get("vulnerability_intelligence_enabled", True):
        return {"enabled": False, "results": []}
    selected = list(sources or SOURCE_REFRESHERS)
    results = []
    for source in selected:
        refresher = SOURCE_REFRESHERS.get(source)
        if refresher is None:
            continue
        if not _try_lock(db, source):
            results.append({"source": source, "skipped": True, "reason": "in_progress"})
            continue
        try:
            results.append(refresher(db, fetch=fetch, sleep=sleep, force=force))
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            _mark_failure(db, source, exc)
            db.commit()
            log.exception("Intelligence refresh crashed for %s", source)
            results.append({"source": source, "error": _redact(exc)})
        finally:
            try:
                _unlock(db, source)
            except Exception:  # noqa: BLE001
                log.warning("Failed to release intelligence lock for %s", source)
    return {"enabled": True, "results": results}


def refresh_due_sources(db: Session, *, fetch: FetchFn = fetch_url, sleep=time.sleep) -> dict[str, Any]:
    return refresh_intelligence(db, fetch=fetch, sleep=sleep, force=False)


def source_due(row: VulnerabilityIntelligenceSync | None, freshness: timedelta) -> bool:
    if row is None or row.last_success_at is None:
        return True
    return utcnow() - row.last_success_at >= freshness


def intelligence_status(db: Session) -> dict[str, Any]:
    cfg = get_settings(db)
    enabled = bool(cfg.get("vulnerability_intelligence_enabled", True))
    rows = {row.source: row for row in db.query(VulnerabilityIntelligenceSync).all()}
    freshness = {
        INTEL_SOURCE_NVD: NVD_FRESHNESS,
        INTEL_SOURCE_EPSS: EPSS_FRESHNESS,
        INTEL_SOURCE_CISA_KEV: KEV_FRESHNESS,
    }
    sources = {}
    for source, window in freshness.items():
        row = rows.get(source)
        metadata = dict(row.extra_metadata or {}) if row else {}
        sources[source] = {
            "last_attempt_at": row.last_attempt_at if row else None,
            "last_success_at": row.last_success_at if row else None,
            "source_updated_at": row.source_updated_at if row else None,
            "records_seen": row.records_seen if row else None,
            "records_updated": row.records_updated if row else None,
            "last_error": row.last_error if row else None,
            "metadata": metadata,
            "due": enabled and source_due(row, window),
            "enabled": enabled,
        }
    return {
        "enabled": enabled,
        "nvd_api_key_configured": nvd_api_key_configured(),
        "sources": sources,
    }
