"""Scan exclusions: normalize, resolve effective set, subtract from targets."""

from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    EXCLUSION_CIDR,
    EXCLUSION_IP,
    EXCLUSION_RANGE,
    EXCLUSION_SCOPE_GLOBAL,
    EXCLUSION_SCOPE_NETWORK,
    EXCLUSION_SCOPE_SCAN,
    EXCLUSION_SCOPE_SITE,
    EXCLUSION_SCOPE_TENANT,
    EXCLUSION_SCOPES,
    EXCLUSION_TYPES,
    ScanExclusion,
)

_MAX_RANGE_SPAN = 1 << 24


class ExclusionError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def normalize_exclusion(exclusion_type: str, value: str) -> tuple[str, str]:
    if exclusion_type not in EXCLUSION_TYPES:
        raise ExclusionError("Exclusion type must be ip, cidr, or range")
    raw = (value or "").strip()
    if not raw:
        raise ExclusionError("Exclusion value is required")
    if exclusion_type == EXCLUSION_IP:
        return EXCLUSION_IP, str(ipaddress.ip_address(raw))
    if exclusion_type == EXCLUSION_CIDR:
        return EXCLUSION_CIDR, str(ipaddress.ip_network(raw, strict=False))
    return EXCLUSION_RANGE, _normalize_range(raw)


def _normalize_range(value: str) -> str:
    if "-" not in value:
        raise ExclusionError("IP range must be start-end")
    start_raw, sep, end_raw = value.partition("-")
    if not sep or "-" in end_raw:
        raise ExclusionError("Malformed IP range")
    start = ipaddress.ip_address(start_raw.strip())
    end = ipaddress.ip_address(end_raw.strip())
    if start.version != end.version:
        raise ExclusionError("IP range versions must match")
    if int(start) > int(end):
        raise ExclusionError("Reversed IP range")
    if int(end) - int(start) > _MAX_RANGE_SPAN:
        raise ExclusionError("IP range is too large to store safely")
    return f"{start}-{end}"


def exclusion_networks(normalized_type: str, normalized_value: str) -> list[ipaddress._BaseNetwork]:
    if normalized_type == EXCLUSION_IP:
        addr = ipaddress.ip_address(normalized_value)
        return [ipaddress.ip_network(addr)]
    if normalized_type == EXCLUSION_CIDR:
        return [ipaddress.ip_network(normalized_value, strict=False)]
    start_raw, _, end_raw = normalized_value.partition("-")
    start = ipaddress.ip_address(start_raw)
    end = ipaddress.ip_address(end_raw)
    return list(ipaddress.summarize_address_range(start, end))


def subtract_networks(
    targets: list[ipaddress._BaseNetwork],
    exclusions: list[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    remaining = list(targets)
    for exclusion in exclusions:
        next_remaining: list[ipaddress._BaseNetwork] = []
        for network in remaining:
            if network.version != exclusion.version or not network.overlaps(exclusion):
                next_remaining.append(network)
                continue
            next_remaining.extend(_subtract_one(network, exclusion))
        remaining = next_remaining
    return list(ipaddress.collapse_addresses(remaining))


def _subtract_one(network: ipaddress._BaseNetwork, exclusion: ipaddress._BaseNetwork) -> list[ipaddress._BaseNetwork]:
    if exclusion.supernet_of(network) or exclusion == network:
        return []
    if not network.supernet_of(exclusion):
        clipped = _clip_overlap(network, exclusion)
        return clipped
    return list(network.address_exclude(exclusion))


def _clip_overlap(
    network: ipaddress._BaseNetwork, exclusion: ipaddress._BaseNetwork
) -> list[ipaddress._BaseNetwork]:
    start = max(int(network.network_address), int(exclusion.network_address))
    end = min(int(network.broadcast_address), int(exclusion.broadcast_address))
    if start > end:
        return [network]
    overlap_nets = list(
        ipaddress.summarize_address_range(
            ipaddress.ip_address(start),
            ipaddress.ip_address(end),
        )
    )
    remaining = [network]
    for piece in overlap_nets:
        nxt: list[ipaddress._BaseNetwork] = []
        for current in remaining:
            if current.version != piece.version or not current.overlaps(piece):
                nxt.append(current)
                continue
            if piece.supernet_of(current) or piece == current:
                continue
            if current.supernet_of(piece):
                nxt.extend(current.address_exclude(piece))
            else:
                nxt.extend(_clip_overlap(current, piece))
        remaining = nxt
    return remaining


def ip_intersects_exclusions(ip: str, exclusions: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in exclusions)


def effective_exclusions(
    db: Session,
    *,
    tenant_id: int,
    site_id: int | None,
    network_ids: list[int],
    scan_id: int | None,
) -> list[ScanExclusion]:
    rows = (
        db.query(ScanExclusion)
        .filter(ScanExclusion.archived_at.is_(None))
        .filter(
            (ScanExclusion.scope == EXCLUSION_SCOPE_GLOBAL)
            | (
                (ScanExclusion.scope == EXCLUSION_SCOPE_TENANT)
                & (ScanExclusion.tenant_id == tenant_id)
            )
            | (
                (ScanExclusion.scope == EXCLUSION_SCOPE_SITE)
                & (ScanExclusion.tenant_id == tenant_id)
                & (ScanExclusion.site_id == site_id)
            )
            | (
                (ScanExclusion.scope == EXCLUSION_SCOPE_NETWORK)
                & (ScanExclusion.tenant_id == tenant_id)
                & (ScanExclusion.network_id.in_(network_ids or [-1]))
            )
            | (
                (ScanExclusion.scope == EXCLUSION_SCOPE_SCAN)
                & (ScanExclusion.tenant_id == tenant_id)
                & (ScanExclusion.scan_id == scan_id)
            )
        )
        .order_by(ScanExclusion.id)
        .all()
    )
    for row in rows:
        if row.tenant_id is not None and row.tenant_id != tenant_id:
            raise ExclusionError("Cross-tenant exclusion reference is not allowed")
    return rows


def serialize_exclusions(rows: list[ScanExclusion]) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "scope": row.scope,
            "type": row.exclusion_type,
            "value": row.value,
            "normalized": row.normalized_value,
        }
        for row in rows
    ]


def exclusion_networks_from_rows(rows: list[ScanExclusion] | list[dict[str, Any]]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for row in rows:
        if isinstance(row, dict):
            networks.extend(exclusion_networks(row["type"], row["normalized"]))
        else:
            networks.extend(exclusion_networks(row.exclusion_type, row.normalized_value))
    return networks


def apply_exclusions_to_cidrs(
    cidrs: list[str], exclusions: list[ipaddress._BaseNetwork]
) -> list[str]:
    targets = [ipaddress.ip_network(item, strict=False) for item in cidrs]
    remaining = subtract_networks(targets, exclusions)
    return [str(item) for item in remaining]


def assert_scope_keys(
    scope: str,
    *,
    tenant_id: int | None,
    site_id: int | None,
    network_id: int | None,
    scan_id: int | None,
) -> None:
    if scope not in EXCLUSION_SCOPES:
        raise ExclusionError("Invalid exclusion scope")
    if scope == EXCLUSION_SCOPE_GLOBAL:
        if any(v is not None for v in (tenant_id, site_id, network_id, scan_id)):
            raise ExclusionError("Global exclusions cannot reference tenant objects")
        return
    if tenant_id is None:
        raise ExclusionError("Tenant-scoped exclusions require a tenant")
    if scope == EXCLUSION_SCOPE_TENANT and any(v is not None for v in (site_id, network_id, scan_id)):
        raise ExclusionError("Tenant exclusions cannot reference site, network, or scan")
    if scope == EXCLUSION_SCOPE_SITE and (site_id is None or network_id is not None or scan_id is not None):
        raise ExclusionError("Site exclusions require a site and no network/scan")
    if scope == EXCLUSION_SCOPE_NETWORK and (site_id is None or network_id is None or scan_id is not None):
        raise ExclusionError("Network exclusions require site and network")
    if scope == EXCLUSION_SCOPE_SCAN and scan_id is None:
        raise ExclusionError("Scan exclusions require a scan")
