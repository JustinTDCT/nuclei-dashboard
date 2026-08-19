"""Immutable Phase 1D execution snapshot builder and worker payload."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    SNAPSHOT_VERSION,
    Agent,
    AuthorizedWanTarget,
    Network,
    Scan,
    ScanJob,
    Site,
)
from app.scan_dispatch import CENTRAL_WORKER
from app.scan_exclusions import apply_exclusions_to_cidrs, exclusion_networks_from_rows
from app.scan_intensity import INTENSITY_KEYS
from app.wan_targets import WAN_TARGET_CIDR, WAN_TARGET_FQDN, WAN_TARGET_IP

SECRET_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "enrollment_secret",
        "smtp_password",
        "private_key",
        "api_key",
        "nvd_api_key",
    }
)
_SECRET_KEY_NEEDLES = (
    "password",
    "secret",
    "token",
    "authorization",
    "private_key",
    "api_key",
    "credential",
    "cookie",
    "bearer",
)
PROVENANCE_SCALAR_KEYS = frozenset(
    {
        "runtime_version",
        "naabu_version",
        "httpx_version",
        "nuclei_version",
        "nuclei_templates",
    }
)


class SnapshotError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def build_execution_snapshot(
    *,
    scan: Scan,
    site: Site | None,
    networks: list[Network],
    wan_targets: list[AuthorizedWanTarget],
    stages: dict[str, Any],
    intensity: dict[str, Any],
    exclusions: list[dict[str, Any]],
    dispatch: dict[str, Any],
    eligible_agent_ids: list[int],
    schedule: dict[str, Any],
    timezone_name: str,
    trigger_type: str,
    scheduled_for: datetime | None,
    grace_seconds: int,
    wait_minutes: int,
    created_at: datetime,
    dry_run: bool = False,
) -> dict[str, Any]:
    snapshot = {
        "snapshot_version": SNAPSHOT_VERSION,
        "scan_id": scan.id,
        "definition_revision": scan.definition_revision,
        "tenant_id": scan.tenant_id,
        "scope": scan.scope,
        "site": None
        if site is None
        else {"id": site.id, "name": site.name, "timezone": site.timezone},
        "targets": {
            "networks": [
                {"id": network.id, "name": network.name, "cidr": network.cidr}
                for network in sorted(networks, key=lambda item: item.id)
            ],
            "wan_targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "type": target.target_type,
                    "value": target.value,
                    "normalized": target.normalized_value,
                }
                for target in sorted(wan_targets, key=lambda item: item.id)
            ],
        },
        "stages": stages,
        "intensity": intensity,
        "exclusions": exclusions,
        "dispatch": {
            "mode": dispatch.get("mode"),
            "preferred_agent_id": dispatch.get("preferred_agent_id"),
            "eligible_agent_ids": list(eligible_agent_ids),
            "grace_seconds": grace_seconds,
            "wait_minutes": wait_minutes,
        },
        "schedule": {
            "trigger_type": trigger_type,
            "timezone": timezone_name,
            "config": schedule,
            "scheduled_for": scheduled_for.isoformat() if scheduled_for else None,
        },
        "created_at": created_at.isoformat(),
        "dry_run": bool(dry_run),
    }
    assert_no_secrets(snapshot)
    return snapshot


def assert_no_secrets(payload: Any) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() in SECRET_KEYS:
                raise SnapshotError("Execution snapshot must not contain secrets")
            assert_no_secrets(value)
    elif isinstance(payload, list):
        for item in payload:
            assert_no_secrets(item)


def worker_targets_from_snapshot(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    exclusions = exclusion_networks_from_rows(snapshot.get("exclusions") or [])
    targets: list[dict[str, str]] = []
    if snapshot.get("scope") == "lan":
        cidrs = [row["cidr"] for row in (snapshot.get("targets") or {}).get("networks") or []]
        remaining = apply_exclusions_to_cidrs(cidrs, exclusions)
        if cidrs and not remaining:
            raise SnapshotError("Exclusions remove all LAN targets")
        targets.extend({"type": "cidr", "value": cidr} for cidr in remaining)
        return targets
    for row in (snapshot.get("targets") or {}).get("wan_targets") or []:
        kind = row["type"]
        value = row["normalized"]
        if kind in {WAN_TARGET_IP, WAN_TARGET_CIDR}:
            remaining = apply_exclusions_to_cidrs([value], exclusions)
            if not remaining:
                continue
            for item in remaining:
                targets.append({"type": "cidr" if "/" in item else "ip", "value": item})
        else:
            targets.append({"type": WAN_TARGET_FQDN, "value": value})
    original = (snapshot.get("targets") or {}).get("wan_targets") or []
    if not targets:
        if original:
            raise SnapshotError("Exclusions remove all WAN targets")
        return []
    return targets


def job_payload_from_snapshot(job: ScanJob) -> dict[str, Any]:
    snapshot = job.execution_snapshot or {}
    stages = snapshot.get("stages") or {}
    intensity = snapshot.get("intensity") or {}
    targets = worker_targets_from_snapshot(snapshot)
    cidrs = [row["value"] for row in targets if row["type"] in {WAN_TARGET_IP, WAN_TARGET_CIDR}]
    return {
        "job_id": job.id,
        "scan_id": job.scan_id,
        "tenant_id": job.tenant_id,
        "scope": snapshot.get("scope") or "",
        "snapshot_version": snapshot.get("snapshot_version") or job.snapshot_version,
        "definition_revision": job.definition_revision,
        "targets": targets,
        "stages": stages,
        "intensity": intensity.get("resolved") or {},
        "intensity_preset": intensity.get("preset"),
        "exclusions": snapshot.get("exclusions") or [],
        "cidrs": cidrs,
        "profile": "discovery_nuclei" if stages.get("vulnerability") else "discovery",
        "nuclei_severities": stages.get("nuclei_severities") or "",
        "nuclei_tags": stages.get("nuclei_tags") or "",
        "dry_run": bool(snapshot.get("dry_run")),
    }


def worker_identity(job: ScanJob) -> str:
    if job.claimed_agent_id:
        return f"agent:{job.claimed_agent_id}"
    if job.claimed_by == CENTRAL_WORKER:
        return CENTRAL_WORKER
    return job.claimed_by or ""


def is_secret_key(key: str) -> bool:
    lowered = str(key).lower()
    if lowered in SECRET_KEYS:
        return True
    return any(needle in lowered for needle in _SECRET_KEY_NEEDLES)


def scalar_provenance_value(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (dict, list)):
        return None
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, (int, float)):
        text = str(value).strip()
    else:
        return None
    return text or None


def _sanitize_merged_value(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if is_secret_key(str(key)):
                continue
            nested = _sanitize_merged_value(item)
            if nested in (None, "", [], {}):
                continue
            cleaned[str(key)] = nested
        return cleaned
    if isinstance(value, list):
        return [item for item in (_sanitize_merged_value(row) for row in value) if item not in (None, "", [], {})]
    return value


def merge_provenance(existing: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        if is_secret_key(str(key)):
            continue
        if key in PROVENANCE_SCALAR_KEYS:
            scalar = scalar_provenance_value(value)
            if scalar is None:
                continue
            merged[key] = scalar
            continue
        cleaned = _sanitize_merged_value(value)
        if cleaned in (None, "", [], {}):
            continue
        merged[key] = cleaned
    return merged
