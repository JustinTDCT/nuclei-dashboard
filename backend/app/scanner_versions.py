"""Scanner runtime / tool / template inventory, comparison, and run provenance.

Agent.runtime_inventory is current operational state.
ScanJob.runtime_provenance is historical evidence for that run.
Derived comparison is never stored on the Agent row.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import Agent, ScanJob

INVENTORY_FIELDS = (
    "runtime_version",
    "nuclei_version",
    "nuclei_templates_version",
    "naabu_version",
    "httpx_version",
)
STATUS_MATCH = "match"
STATUS_MISMATCH = "mismatch"
STATUS_NOT_REPORTED = "not_reported"
STATUS_NOT_CONFIGURED = "not_configured"
APPROVED_SETTING_KEYS = {
    "runtime_version": "approved_scanner_runtime_version",
    "nuclei_version": "approved_nuclei_version",
    "nuclei_templates_version": "approved_nuclei_templates_version",
    "naabu_version": "approved_naabu_version",
    "httpx_version": "approved_httpx_version",
}
STATUS_LABELS = {
    STATUS_MATCH: "Matches approved",
    STATUS_MISMATCH: "Mismatch",
    STATUS_NOT_REPORTED: "Not reported",
    STATUS_NOT_CONFIGURED: "No approved version configured",
}
MAX_VERSION_CHARS = 200
HISTORICAL_ALIASES = {"nuclei_templates_version": ("nuclei_templates", "nuclei_template_version")}
_PINNED_PATH = Path(__file__).resolve().with_name("pinned_scanner_versions.json")
_VERSION_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


class InventoryError(ValueError):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class VersionProvenanceError(Exception):
    def __init__(self, detail: str, status_code: int = 409):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def load_pinned_scanner_versions() -> dict[str, str]:
    data = json.loads(_PINNED_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("pinned scanner versions must be an object")
    pins: dict[str, str] = {}
    for key in INVENTORY_FIELDS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            pins[key] = value.strip()
    if len(pins) != len(INVENTORY_FIELDS):
        missing = [key for key in INVENTORY_FIELDS if not pins.get(key)]
        raise ValueError("missing pinned scanner versions: " + ", ".join(missing))
    return pins


def approved_settings_defaults() -> dict[str, str]:
    pins = load_pinned_scanner_versions()
    return {setting: pins.get(field, "") for field, setting in APPROVED_SETTING_KEYS.items()}


def canonicalize_version(value: str | None) -> str | None:
    if value is None:
        return None
    text = _WHITESPACE_RE.sub(" ", str(value).strip())
    if not text:
        return None
    token = _VERSION_TOKEN_RE.search(text)
    if token:
        text = token.group(0)
    if text.lower().startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    return text.lower()


def versions_equal(left: str | None, right: str | None) -> bool:
    a = canonicalize_version(left)
    b = canonicalize_version(right)
    if a is None or b is None:
        return False
    return a == b


def approved_versions_from_settings(cfg: dict[str, Any] | None) -> dict[str, str]:
    data = cfg or {}
    out: dict[str, str] = {}
    for field, setting in APPROVED_SETTING_KEYS.items():
        value = data.get(setting)
        text = str(value).strip() if value is not None else ""
        out[field] = text
    return out


def compare_field(approved: str | None, installed: str | None) -> str:
    if not (approved or "").strip():
        return STATUS_NOT_CONFIGURED
    if not (installed or "").strip():
        return STATUS_NOT_REPORTED
    if versions_equal(approved, installed):
        return STATUS_MATCH
    return STATUS_MISMATCH


def compare_inventory(
    approved: dict[str, str] | None,
    inventory: dict[str, Any] | None,
) -> dict[str, Any]:
    approved_map = approved or {}
    installed_map = inventory if isinstance(inventory, dict) else {}
    fields: dict[str, Any] = {}
    statuses: list[str] = []
    for field in INVENTORY_FIELDS:
        approved_value = (approved_map.get(field) or "").strip() or None
        installed_value = installed_map.get(field) if isinstance(installed_map.get(field), str) else None
        if isinstance(installed_value, str):
            installed_value = installed_value.strip() or None
        status = compare_field(approved_value, installed_value)
        fields[field] = {
            "approved": approved_value,
            "installed": installed_value,
            "status": status,
        }
        statuses.append(status)
    configured = [item for item in statuses if item != STATUS_NOT_CONFIGURED]
    if not configured:
        overall = STATUS_NOT_CONFIGURED
    elif STATUS_MISMATCH in configured:
        overall = STATUS_MISMATCH
    elif STATUS_NOT_REPORTED in configured:
        overall = STATUS_NOT_REPORTED
    else:
        overall = STATUS_MATCH
    return {"overall": overall, "fields": fields}


def inventory_from_agent(agent: Agent) -> dict[str, str] | None:
    payload = agent.runtime_inventory
    if not isinstance(payload, dict) or not payload:
        return None
    return {key: str(payload[key]) for key in INVENTORY_FIELDS if payload.get(key)}


def agent_version_view(agent: Agent, approved: dict[str, str] | None) -> dict[str, Any]:
    inventory = inventory_from_agent(agent)
    comparison = compare_inventory(approved, inventory)
    return {
        "runtime_inventory": inventory,
        "runtime_inventory_reported_at": agent.runtime_inventory_reported_at,
        "version_status": comparison["overall"],
        "version_comparison": comparison,
    }


def validate_runtime_inventory(payload: Any) -> dict[str, str]:
    from app.scan_snapshot import is_secret_key, scalar_provenance_value

    if payload is None:
        raise InventoryError("runtime_inventory is required when provided")
    if not isinstance(payload, dict):
        raise InventoryError("runtime_inventory must be an object")
    if any(isinstance(value, (dict, list)) for value in payload.values()):
        raise InventoryError("runtime_inventory must not contain nested data")
    for key in payload:
        if is_secret_key(str(key)):
            raise InventoryError("runtime_inventory must not contain secrets")
        if str(key) not in INVENTORY_FIELDS:
            raise InventoryError(f"unknown runtime_inventory field: {key}")
    cleaned: dict[str, str] = {}
    for field in INVENTORY_FIELDS:
        if field not in payload:
            continue
        scalar = scalar_provenance_value(payload.get(field))
        if scalar is None:
            raise InventoryError("runtime_inventory values must be scalar strings")
        if len(scalar) > MAX_VERSION_CHARS:
            raise InventoryError("runtime_inventory version exceeds the maximum allowed size")
        cleaned[field] = scalar
    return cleaned


def inventories_equal(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    for field in INVENTORY_FIELDS:
        if canonicalize_version((left or {}).get(field) if isinstance(left, dict) else None) != canonicalize_version(
            (right or {}).get(field) if isinstance(right, dict) else None
        ):
            return False
    return True


def apply_agent_inventory(
    db: Session,
    agent: Agent,
    inventory: dict[str, str],
    *,
    reported_at: datetime,
) -> bool:
    previous = inventory_from_agent(agent)
    changed = previous is None or not inventories_equal(previous, inventory)
    agent.runtime_inventory = inventory
    agent.runtime_inventory_reported_at = reported_at
    db.add(agent)
    return changed


def provenance_version(payload: dict[str, Any] | None, field: str) -> str | None:
    from app.scan_snapshot import scalar_provenance_value

    if not isinstance(payload, dict):
        return None
    value = scalar_provenance_value(payload.get(field))
    if value:
        return value
    for alias in HISTORICAL_ALIASES.get(field, ()):
        value = scalar_provenance_value(payload.get(alias))
        if value:
            return value
    return None


def required_run_version_keys(job: ScanJob) -> list[str]:
    from app.raw_artifacts import (
        RAW_EVIDENCE_SKIPPED_NO_TARGETS,
        expected_artifact_keys,
        snapshot_is_dry_run,
    )

    if snapshot_is_dry_run(job):
        return []
    payload = job.runtime_provenance if isinstance(job.runtime_provenance, dict) else {}
    evidence = payload.get("raw_evidence") if isinstance(payload.get("raw_evidence"), dict) else {}
    if evidence.get("status") == RAW_EVIDENCE_SKIPPED_NO_TARGETS:
        artifact_keys = [str(key) for key in (evidence.get("artifact_keys") or [])]
    else:
        artifact_keys = expected_artifact_keys(job)
    keys = ["runtime_version"]
    for artifact_key in artifact_keys:
        if artifact_key.endswith(".naabu") and "naabu_version" not in keys:
            keys.append("naabu_version")
        elif artifact_key.endswith(".httpx") and "httpx_version" not in keys:
            keys.append("httpx_version")
        elif artifact_key.endswith(".nuclei"):
            if "nuclei_version" not in keys:
                keys.append("nuclei_version")
            if "nuclei_templates_version" not in keys:
                keys.append("nuclei_templates_version")
    return keys


def apply_version_provenance_requirement(job: ScanJob, *, ok: bool) -> None:
    if not ok:
        return
    required = required_run_version_keys(job)
    if not required:
        return
    payload = job.runtime_provenance if isinstance(job.runtime_provenance, dict) else {}
    missing = [key for key in required if not provenance_version(payload, key)]
    if missing:
        raise VersionProvenanceError(
            "Required scanner version provenance was not persisted: " + ", ".join(missing)
        )


def remap_incoming_provenance(body: dict[str, Any] | None) -> dict[str, Any]:
    incoming = dict(body or {})
    if "nuclei_templates" in incoming and "nuclei_templates_version" not in incoming:
        incoming["nuclei_templates_version"] = incoming.get("nuclei_templates")
    return incoming


def merge_run_provenance(existing: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, Any]:
    from app.scan_snapshot import merge_provenance

    return merge_provenance(existing, remap_incoming_provenance(incoming))
