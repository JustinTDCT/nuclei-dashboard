"""Scan stage configuration and custom port validation."""

from __future__ import annotations

from typing import Any

from app.models import (
    PORT_MODE_COMMON,
    PORT_MODE_CUSTOM,
    PORT_MODE_DEEP,
    PORT_MODE_NONE,
    PORT_MODES,
)

COMMON_TOP_PORTS = 100
DEEP_TOP_PORTS = 1000

LEGACY_DISCOVERY = "discovery"
LEGACY_DISCOVERY_NUCLEI = "discovery_nuclei"


class StageConfigError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def parse_custom_ports(raw: str | list[int | str] | None) -> list[str]:
    if raw is None or raw == "" or raw == []:
        return []
    if isinstance(raw, list):
        tokens = [str(item).strip() for item in raw if str(item).strip()]
    else:
        tokens = [part.strip() for part in str(raw).replace(" ", "").split(",") if part.strip()]
    ports: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        spec = _validate_port_token(token)
        if spec not in seen:
            seen.add(spec)
            ports.append(spec)
    return ports


def _validate_port_token(token: str) -> str:
    if "-" in token:
        left, sep, right = token.partition("-")
        if not sep or "-" in right:
            raise StageConfigError(f"Malformed port range: {token}")
        start = _parse_port_number(left)
        end = _parse_port_number(right)
        if start > end:
            raise StageConfigError(f"Reversed port range: {token}")
        if start == end:
            return str(start)
        return f"{start}-{end}"
    return str(_parse_port_number(token))


def _parse_port_number(value: str) -> int:
    if not value.isdigit():
        raise StageConfigError(f"Invalid port: {value}")
    port = int(value)
    if port <= 0 or port > 65535:
        raise StageConfigError(f"Port out of range: {port}")
    return port


def stages_from_legacy_profile(profile: str, nuclei_severities: str, nuclei_tags: str) -> dict[str, Any]:
    vulnerability = profile == LEGACY_DISCOVERY_NUCLEI
    return normalize_stage_config(
        {
            "discovery": True,
            "port_mode": PORT_MODE_COMMON,
            "custom_ports": [],
            "fingerprint": True,
            "vulnerability": vulnerability,
            "nuclei_severities": nuclei_severities or "critical,high,medium",
            "nuclei_tags": nuclei_tags or "",
        }
    )


def normalize_stage_config(raw: dict[str, Any] | None, *, legacy_profile: str | None = None) -> dict[str, Any]:
    data = dict(raw or {})
    if not data and legacy_profile:
        return stages_from_legacy_profile(legacy_profile, "critical,high,medium", "")
    discovery = bool(data.get("discovery", True))
    port_mode = str(data.get("port_mode") or PORT_MODE_COMMON)
    if port_mode not in PORT_MODES:
        raise StageConfigError("Port mode must be none, common, deep, or custom")
    custom_ports = parse_custom_ports(data.get("custom_ports"))
    fingerprint = bool(data.get("fingerprint", True))
    vulnerability = bool(data.get("vulnerability", False))
    severities = str(data.get("nuclei_severities") or "critical,high,medium").strip()
    tags = str(data.get("nuclei_tags") or "").strip()
    if not discovery and port_mode != PORT_MODE_NONE:
        raise StageConfigError("Port discovery requires the discovery stage")
    if port_mode == PORT_MODE_CUSTOM and not custom_ports:
        raise StageConfigError("Custom port mode requires at least one valid port or range")
    if port_mode != PORT_MODE_CUSTOM and custom_ports:
        raise StageConfigError("Custom ports are only allowed when port mode is custom")
    if not discovery and not fingerprint and not vulnerability and port_mode == PORT_MODE_NONE:
        raise StageConfigError("At least one scan stage must be enabled")
    if vulnerability and not severities:
        raise StageConfigError("Vulnerability scanning requires Nuclei severities")
    return {
        "discovery": discovery,
        "port_mode": port_mode,
        "custom_ports": custom_ports,
        "fingerprint": fingerprint,
        "vulnerability": vulnerability,
        "nuclei_severities": severities,
        "nuclei_tags": tags,
    }


def legacy_profile_from_stages(stages: dict[str, Any]) -> str:
    if stages.get("vulnerability"):
        return LEGACY_DISCOVERY_NUCLEI
    return LEGACY_DISCOVERY
