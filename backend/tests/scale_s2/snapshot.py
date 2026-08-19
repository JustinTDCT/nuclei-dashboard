"""Normalize ingest state so surrogate IDs and timestamps drop out of comparison."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    Alert,
    Asset,
    AssetAddress,
    AssetCorrelationDecision,
    AssetFinding,
    AssetFindingHistory,
    AssetFindingRunEvaluation,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
    DomainEvent,
    EventAlertQueue,
    Finding,
    ScanJob,
    ScanRunDetectorCoverage,
    Vulnerability,
    VulnerabilityDetectorMapping,
)
from tests.scale_s2.constants import SNAPSHOT_COLLECTIONS

TIMESTAMP_KEYS = {
    "created_at",
    "updated_at",
    "first_seen",
    "last_seen",
    "found_at",
    "observed_at",
    "occurred_at",
    "resolved_at",
    "finished_at",
    "started_at",
    "corrected_at",
    "merged_at",
    "acknowledged_at",
    "first_event_at",
    "last_event_at",
    "priority_calculated_at",
    "waiting_since",
    "wait_expires_at",
}

ID_KEY_TO_MAP = {
    "asset_id": "assets",
    "selected_asset_id": "assets",
    "merged_into_asset_id": "assets",
    "device_id": "devices",
    "source_device_id": "devices",
    "vulnerability_id": "vulnerabilities",
    "asset_finding_id": "asset_findings",
    "address_id": "addresses",
    "last_scan_job_id": "jobs",
    "scan_job_id": "jobs",
    "domain_event_id": "events",
    "last_domain_event_id": "events",
    "replacement_identifier_id": "identifiers",
}


def _dt(value: Any) -> Any:
    if isinstance(value, datetime):
        return None
    return value


def _sorted(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: json_key(row.get("key") or row))


def json_key(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return "|".join(json_key(item) for item in value)
    if isinstance(value, dict):
        return "{" + ",".join(f"{k}={json_key(value[k])}" for k in sorted(value)) + "}"
    return str(value)


def _strip_volatile(value: Any, maps: dict[str, dict[int, str]]) -> Any:
    if isinstance(value, datetime):
        return None
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in TIMESTAMP_KEYS or str(key).endswith("_at"):
                continue
            if key in ID_KEY_TO_MAP:
                out[key] = _remap(ID_KEY_TO_MAP[key], item, maps)
            else:
                out[key] = _strip_volatile(item, maps)
        return out
    if isinstance(value, list):
        return [_strip_volatile(item, maps) for item in value]
    return value


def _remap(kind: str, value: Any, maps: dict[str, dict[int, str]]) -> Any:
    if value is None:
        return None
    if isinstance(value, int):
        return maps.get(kind, {}).get(value, f"{kind}:{value}")
    return value


def capture_raw_state(db: Session, tenant_id: int) -> dict[str, Any]:
    assets = db.query(Asset).filter(Asset.tenant_id == tenant_id).all()
    asset_ids = [row.id for row in assets]
    identifiers = (
        db.query(AssetIdentifier).filter(AssetIdentifier.tenant_id == tenant_id).all()
        if asset_ids
        else []
    )
    addresses = db.query(AssetAddress).filter(AssetAddress.tenant_id == tenant_id).all() if asset_ids else []
    services = db.query(AssetService).filter(AssetService.tenant_id == tenant_id).all() if asset_ids else []
    observations = (
        db.query(AssetObservation).filter(AssetObservation.tenant_id == tenant_id).all() if asset_ids else []
    )
    decisions = (
        db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.tenant_id == tenant_id).all()
    )
    devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
    findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    asset_findings = db.query(AssetFinding).filter(AssetFinding.tenant_id == tenant_id).all()
    history = db.query(AssetFindingHistory).filter(AssetFindingHistory.tenant_id == tenant_id).all()
    evaluations = (
        db.query(AssetFindingRunEvaluation).filter(AssetFindingRunEvaluation.tenant_id == tenant_id).all()
    )
    coverage = db.query(ScanRunDetectorCoverage).filter(ScanRunDetectorCoverage.tenant_id == tenant_id).all()
    events = db.query(DomainEvent).filter(DomainEvent.tenant_id == tenant_id).all()
    alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).all()
    event_ids = [row.id for row in events]
    queue = (
        db.query(EventAlertQueue).filter(EventAlertQueue.domain_event_id.in_(event_ids)).all()
        if event_ids
        else []
    )
    jobs = db.query(ScanJob).filter(ScanJob.tenant_id == tenant_id).all()
    vuln_ids = {row.vulnerability_id for row in asset_findings}
    vulns = db.query(Vulnerability).filter(Vulnerability.id.in_(vuln_ids)).all() if vuln_ids else []
    mappings = (
        db.query(VulnerabilityDetectorMapping)
        .filter(VulnerabilityDetectorMapping.vulnerability_id.in_(vuln_ids))
        .all()
        if vuln_ids
        else []
    )
    extra_keys = {(row.detector_type, row.detector_key) for row in findings if row.detector_key}
    if extra_keys:
        extra_maps = (
            db.query(VulnerabilityDetectorMapping)
            .filter(
                VulnerabilityDetectorMapping.detector_type.in_({item[0] for item in extra_keys}),
            )
            .all()
        )
        for mapping in extra_maps:
            if (mapping.detector_type, mapping.detector_key) in extra_keys:
                mappings.append(mapping)
                if mapping.vulnerability_id not in {row.id for row in vulns}:
                    vuln = db.get(Vulnerability, mapping.vulnerability_id)
                    if vuln is not None:
                        vulns.append(vuln)
    return {
        "tenant_id": tenant_id,
        "assets": assets,
        "identifiers": identifiers,
        "addresses": addresses,
        "services": services,
        "observations": observations,
        "decisions": decisions,
        "devices": devices,
        "findings": findings,
        "asset_findings": asset_findings,
        "history": history,
        "evaluations": evaluations,
        "coverage": coverage,
        "events": events,
        "alerts": alerts,
        "queue": queue,
        "jobs": jobs,
        "vulnerabilities": vulns,
        "mappings": mappings,
    }


def _asset_key(asset: Asset, identifiers: list[AssetIdentifier], addresses: list[AssetAddress]) -> str:
    ident = tuple(
        sorted(
            (row.identifier_type, row.normalized_value, row.validity)
            for row in identifiers
            if row.asset_id == asset.id
        )
    )
    ips = tuple(sorted(row.ip for row in addresses if row.asset_id == asset.id))
    return json_key(
        (
            asset.display_name or "",
            asset.classification or "",
            asset.lifecycle_state or "",
            asset.disposition or "",
            ident,
            ips,
        )
    )


def normalize_state(raw: dict[str, Any]) -> dict[str, Any]:
    assets: list[Asset] = raw["assets"]
    identifiers: list[AssetIdentifier] = raw["identifiers"]
    addresses: list[AssetAddress] = raw["addresses"]
    maps: dict[str, dict[int, str]] = {
        "assets": {},
        "devices": {},
        "vulnerabilities": {},
        "asset_findings": {},
        "jobs": {},
        "events": {},
        "addresses": {},
        "identifiers": {},
    }
    jobs = list(raw["jobs"])
    if len(jobs) == 1:
        maps["jobs"][jobs[0].id] = "job:primary"
    else:
        for index, job in enumerate(sorted(jobs, key=lambda row: (row.status or "", row.hosts_found or 0, row.id))):
            maps["jobs"][job.id] = f"job:{index}:{job.status}"
    for vuln in raw["vulnerabilities"]:
        maps["vulnerabilities"][vuln.id] = f"vuln:{vuln.canonical_key}"
    for asset in assets:
        maps["assets"][asset.id] = _asset_key(asset, identifiers, addresses)
    for ident in identifiers:
        maps["identifiers"][ident.id] = json_key(
            (maps["assets"].get(ident.asset_id), ident.identifier_type, ident.normalized_value)
        )
    for address in addresses:
        maps["addresses"][address.id] = json_key((maps["assets"].get(address.asset_id), address.ip))
    for device in raw["devices"]:
        maps["devices"][device.id] = json_key((device.scope, device.hostname or "", device.ip or ""))
    for finding in raw["asset_findings"]:
        maps["asset_findings"][finding.id] = json_key(
            (
                maps["assets"].get(finding.asset_id),
                maps["vulnerabilities"].get(finding.vulnerability_id, finding.vulnerability_id),
            )
        )
    for event in raw["events"]:
        maps["events"][event.id] = json_key(
            (
                event.event_type,
                maps["assets"].get(event.asset_id) if event.asset_id else "",
                maps["asset_findings"].get(event.asset_finding_id) if event.asset_finding_id else "",
            )
        )

    normalized = {
        "assets": _sorted(
            [
                {
                    "key": maps["assets"][row.id],
                    "display_name": row.display_name,
                    "classification": row.classification,
                    "description": row.description or "",
                    "lifecycle_state": row.lifecycle_state,
                    "disposition": row.disposition,
                    "criticality": row.criticality,
                    "is_expected": row.is_expected,
                    "merged_into": _remap("assets", row.merged_into_asset_id, maps),
                }
                for row in assets
            ]
        ),
        "asset_identifiers": _sorted(
            [
                {
                    "key": maps["identifiers"][row.id],
                    "asset": _remap("assets", row.asset_id, maps),
                    "identifier_type": row.identifier_type,
                    "value": row.value,
                    "normalized_value": row.normalized_value,
                    "source": row.source,
                    "validity": row.validity,
                    "correction_reason": row.correction_reason or "",
                }
                for row in identifiers
            ]
        ),
        "asset_addresses": _sorted(
            [
                {
                    "key": maps["addresses"][row.id],
                    "asset": _remap("assets", row.asset_id, maps),
                    "ip": row.ip,
                    "address_family": row.address_family,
                    "source": row.source,
                }
                for row in addresses
            ]
        ),
        "asset_services": _sorted(
            [
                {
                    "key": json_key((maps["assets"].get(row.asset_id), row.ip, row.port, row.protocol)),
                    "asset": _remap("assets", row.asset_id, maps),
                    "ip": row.ip,
                    "port": row.port,
                    "protocol": row.protocol,
                    "product": row.product or "",
                    "version": row.version or "",
                    "web_title": row.web_title or "",
                    "tech": row.tech or "",
                    "source": row.source,
                }
                for row in raw["services"]
            ]
        ),
        "asset_observations": _sorted(
            [
                {
                    "key": row.observation_key,
                    "asset": _remap("assets", row.asset_id, maps),
                    "scope": row.scope,
                    "source": row.source,
                    "hostname": row.hostname or "",
                    "ip": row.ip or "",
                    "observation_key": row.observation_key,
                    "snapshot": _strip_volatile(row.snapshot or {}, maps),
                    "provenance": row.provenance,
                }
                for row in raw["observations"]
            ]
        ),
        "asset_correlation_decisions": _sorted(
            [
                {
                    "key": row.observation_key,
                    "observation_key": row.observation_key,
                    "selected_asset": _remap("assets", row.selected_asset_id, maps),
                    "decision": row.decision,
                    "confidence": row.confidence,
                    "score": row.score,
                    "algorithm_version": row.algorithm_version,
                    "evidence": _strip_volatile(row.evidence or [], maps),
                    "candidates": _strip_volatile(row.candidates or [], maps),
                }
                for row in raw["decisions"]
            ]
        ),
        "devices": _sorted(
            [
                {
                    "key": maps["devices"][row.id],
                    "hostname": row.hostname or "",
                    "ip": row.ip or "",
                    "scope": row.scope,
                    "status": row.status,
                    "classification": row.classification,
                    "description": row.description or "",
                    "auto_label": row.auto_label or "",
                    "title": row.title or "",
                    "tech": row.tech or "",
                    "ports": row.ports or [],
                    "asset": _remap("assets", row.asset_id, maps),
                }
                for row in raw["devices"]
            ]
        ),
        "vulnerabilities": _sorted(
            [
                {
                    "key": maps["vulnerabilities"][row.id],
                    "canonical_key": row.canonical_key,
                    "cve_id": row.cve_id,
                    "title": row.title or "",
                    "description": row.description or "",
                }
                for row in raw["vulnerabilities"]
            ]
        ),
        "vulnerability_detector_mappings": _sorted(
            [
                {
                    "key": json_key((row.detector_type, row.detector_key)),
                    "vulnerability": _remap("vulnerabilities", row.vulnerability_id, maps),
                    "detector_type": row.detector_type,
                    "detector_key": row.detector_key,
                    "last_severity": row.last_severity or "",
                    "last_tags": row.last_tags or "",
                }
                for row in raw["mappings"]
            ]
        ),
        "findings": _sorted(
            [
                {
                    "key": json_key((row.detector_type, row.detector_key, row.host, row.matched_at, row.template_id)),
                    "detector_type": row.detector_type,
                    "detector_key": row.detector_key,
                    "template_id": row.template_id,
                    "name": row.name or "",
                    "severity": row.severity,
                    "hostname": row.hostname or "",
                    "host": row.host or "",
                    "matched_at": row.matched_at or "",
                    "tags": row.tags or "",
                    "raw_json": _strip_volatile(row.raw_json or {}, maps),
                    "asset": _remap("assets", row.asset_id, maps),
                    "device": _remap("devices", row.device_id, maps),
                    "asset_finding": _remap("asset_findings", row.asset_finding_id, maps),
                }
                for row in raw["findings"]
                if not (row.evidence_key or "").startswith("s2a-hist:")
            ]
        ),
        "asset_findings": _sorted(
            [
                {
                    "key": maps["asset_findings"][row.id],
                    "asset": _remap("assets", row.asset_id, maps),
                    "vulnerability": _remap("vulnerabilities", row.vulnerability_id, maps),
                    "technical_state": row.technical_state,
                    "treatment_state": row.treatment_state,
                    "consecutive_clean_scans": row.consecutive_clean_scans,
                    "reopened_count": row.reopened_count,
                    "priority": row.priority,
                    "priority_score": row.priority_score,
                    "priority_model_version": row.priority_model_version,
                }
                for row in raw["asset_findings"]
            ]
        ),
        "asset_finding_history": _sorted(
            [
                {
                    "key": json_key(
                        (
                            maps["asset_findings"].get(row.asset_finding_id),
                            row.transition_type,
                            row.previous_technical_state,
                            row.new_technical_state,
                        )
                    ),
                    "asset_finding": _remap("asset_findings", row.asset_finding_id, maps),
                    "transition_type": row.transition_type,
                    "previous_technical_state": row.previous_technical_state,
                    "new_technical_state": row.new_technical_state,
                    "details": _strip_volatile(row.details or {}, maps),
                }
                for row in raw["history"]
            ]
        ),
        "asset_finding_run_evaluations": _sorted(
            [
                {
                    "key": json_key((maps["asset_findings"].get(row.asset_finding_id), row.outcome)),
                    "asset_finding": _remap("asset_findings", row.asset_finding_id, maps),
                    "outcome": row.outcome,
                    "details": _strip_volatile(row.details or {}, maps),
                }
                for row in raw["evaluations"]
            ]
        ),
        "scan_run_detector_coverage": _sorted(
            [
                {
                    "key": json_key((row.detector_type, row.target)),
                    "detector_type": row.detector_type,
                    "target": row.target,
                    "normalized_host": row.normalized_host or "",
                    "target_kind": row.target_kind,
                }
                for row in raw["coverage"]
            ]
        ),
        "domain_events": _sorted(
            [
                {
                    "key": maps["events"][row.id],
                    "event_type": row.event_type,
                    "source": row.source,
                    "asset": _remap("assets", row.asset_id, maps),
                    "asset_finding": _remap("asset_findings", row.asset_finding_id, maps),
                    "details": _strip_volatile(row.details or {}, maps),
                }
                for row in raw["events"]
            ]
        ),
        "alerts": _sorted(
            [
                {
                    "key": json_key((row.type, row.title, row.severity, row.dedupe_key or "")),
                    "type": row.type,
                    "title": row.title,
                    "body": row.body or "",
                    "severity": row.severity,
                    "is_acknowledged": row.is_acknowledged,
                    "dashboard_visible": row.dashboard_visible,
                    "occurrence_count": row.occurrence_count,
                    "asset": _remap("assets", row.asset_id, maps),
                    "asset_finding": _remap("asset_findings", row.asset_finding_id, maps),
                    "dedupe_key": row.dedupe_key,
                }
                for row in raw["alerts"]
            ]
        ),
        "event_alert_queue": _sorted(
            [
                {
                    "key": json_key((maps["events"].get(row.domain_event_id), row.status)),
                    "status": row.status,
                    "attempts": row.attempts,
                    "event": _remap("events", row.domain_event_id, maps),
                }
                for row in raw["queue"]
            ]
        ),
        "scan_jobs": _sorted(
            [
                {
                    "key": maps["jobs"][row.id],
                    "status": row.status,
                    "hosts_found": row.hosts_found,
                    "findings_count": row.findings_count,
                    "error": row.error,
                }
                for row in raw["jobs"]
            ]
        ),
    }
    return {name: normalized[name] for name in SNAPSHOT_COLLECTIONS}


def capture_normalized_state(db: Session, tenant_id: int) -> dict[str, Any]:
    return normalize_state(capture_raw_state(db, tenant_id))


def diff_normalized(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    diffs: dict[str, Any] = {}
    names = set(left) | set(right)
    for name in sorted(names):
        a = left.get(name)
        b = right.get(name)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            a_map = {json_key(row.get("key") if isinstance(row, dict) else row): row for row in a}
            b_map = {json_key(row.get("key") if isinstance(row, dict) else row): row for row in b}
            only_left = sorted(set(a_map) - set(b_map))
            only_right = sorted(set(b_map) - set(a_map))
            changed = []
            for key in sorted(set(a_map) & set(b_map)):
                if a_map[key] != b_map[key]:
                    changed.append({"key": key, "left": a_map[key], "right": b_map[key]})
            diffs[name] = {
                "only_left": only_left[:20],
                "only_right": only_right[:20],
                "changed": changed[:20],
                "left_count": len(a),
                "right_count": len(b),
            }
        else:
            diffs[name] = {"left": a, "right": b}
    return diffs


def assert_equivalent(left: dict[str, Any], right: dict[str, Any], *, label: str = "ingest") -> None:
    diffs = diff_normalized(left, right)
    if diffs:
        summary = ", ".join(f"{name}({value.get('left_count', '?')} vs {value.get('right_count', '?')})" for name, value in diffs.items())
        raise AssertionError(f"{label} semantic mismatch: {summary}; sample={ {k: diffs[k] for k in list(diffs)[:3]} }")
