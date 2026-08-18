"""Asset current-state projection and historical observation writing.

Phase 1B does not correlate Assets. Incoming scanner reports still use the
legacy Device resolver. Each Device maps to at most one Asset via
Device.asset_id. Matching by IP/hostname/MAC across Assets is Phase 1C.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address, ip_network
import json

from sqlalchemy.orm import Session

from app.classify import is_placeholder_name, normalize_hostname
from app.locality import compatibility_site_for_tenant
from app.models import (
    CRITICALITIES,
    DISPOSITIONS,
    IDENTIFIER_HOSTNAME,
    IDENTIFIER_MAC,
    IDENTIFIER_TYPES,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_STATES,
    SOURCE_LEGACY_MIGRATION,
    SOURCE_MANUAL,
    SOURCE_SCANNER,
    UNASSIGNED_SITE_NAME,
    Asset,
    AssetAddress,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
    Network,
    ScanJob,
    Site,
    Tag,
)
from app.schemas import DeviceReport


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_tag_name(value: str) -> str:
    return " ".join((value or "").strip().split()).lower()


def is_placeholder_hostname(value: str, ip: str = "") -> bool:
    return is_placeholder_name(value, ip)


def observation_fingerprint(hostname: str, ip: str, scope: str, ports) -> str:
    host = normalize_hostname(hostname)
    if is_placeholder_hostname(host, ip):
        host = ""
    payload = json.dumps(
        {
            "hostname": host,
            "ip": (ip or "").strip(),
            "ports": [
                {"port": port, "protocol": protocol}
                for port, protocol, _, _ in sorted(_iter_ports(ports), key=lambda row: (row[0], row[1]))
            ],
            "scope": (scope or "").strip().lower(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def normalize_identifier(identifier_type: str, value: str) -> str:
    raw = (value or "").strip()
    if identifier_type == IDENTIFIER_MAC:
        return "".join(ch for ch in raw.lower() if ch.isalnum())
    if identifier_type in {IDENTIFIER_HOSTNAME, "fqdn", "dns_name", "tls_name"}:
        return raw.rstrip(".").lower()
    return raw.lower()


def address_family(ip: str) -> str:
    try:
        parsed = ip_address((ip or "").strip())
    except ValueError:
        return "ipv4"
    return "ipv6" if parsed.version == 6 else "ipv4"


def display_name_for(hostname: str, ip: str, fallback: str = "") -> str:
    name = (hostname or "").strip()
    if name:
        return name
    if (ip or "").strip():
        return ip.strip()
    return fallback


def resolve_network_for_ip(db: Session, site_id: int | None, ip: str) -> Network | None:
    if not site_id or not (ip or "").strip():
        return None
    try:
        parsed = ip_address(ip.strip())
    except ValueError:
        return None
    matches: list[Network] = []
    networks = (
        db.query(Network)
        .filter(Network.site_id == site_id, Network.archived_at.is_(None))
        .all()
    )
    for network in networks:
        try:
            if parsed in ip_network(network.cidr, strict=False):
                matches.append(network)
        except ValueError:
            continue
    if len(matches) == 1:
        return matches[0]
    return None


def fallback_lan_site(db: Session, tenant_id: int) -> Site:
    imported = compatibility_site_for_tenant(db, tenant_id)
    if imported is not None:
        return imported
    existing = (
        db.query(Site)
        .filter(Site.tenant_id == tenant_id, Site.name == UNASSIGNED_SITE_NAME)
        .first()
    )
    if existing is not None:
        return existing
    site = Site(tenant_id=tenant_id, name=UNASSIGNED_SITE_NAME)
    db.add(site)
    db.flush()
    return site


def observation_context(db: Session, job_id: int, ip: str, report_scope: str) -> dict:
    job = db.get(ScanJob, job_id)
    scan = job.scan if job else None
    agent = scan.agent if scan else None
    scope = (scan.scope if scan else report_scope) or report_scope
    site_id = None
    agent_id = None
    if scope == "lan" and agent is not None:
        site_id = agent.site_id
        agent_id = agent.id
    network = resolve_network_for_ip(db, site_id, ip) if site_id else None
    return {
        "site_id": site_id,
        "network_id": network.id if network else None,
        "agent_id": agent_id,
        "scope": scope,
        "scan_job_id": job_id,
        "source": SOURCE_SCANNER,
    }


def ensure_asset_for_device(db: Session, device: Device, context: dict) -> Asset:
    if device.asset_id:
        asset = db.get(Asset, device.asset_id)
        if asset is not None:
            return asset
    site_id = context.get("site_id")
    if (device.scope or context.get("scope")) == "lan" and site_id is None:
        site_id = fallback_lan_site(db, device.tenant_id).id
    if (device.scope or context.get("scope")) == "wan":
        site_id = None
    now = utcnow()
    asset = Asset(
        tenant_id=device.tenant_id,
        site_id=site_id,
        display_name=display_name_for(device.hostname, device.ip),
        classification=device.classification or "Unknown",
        description=device.description or "",
        lifecycle_state=LIFECYCLE_ACTIVE,
        disposition="unreviewed",
        criticality="normal",
        is_expected=False,
        first_seen=device.first_seen or now,
        last_seen=device.last_seen or now,
        updated_at=now,
    )
    db.add(asset)
    db.flush()
    device.asset_id = asset.id
    db.flush()
    return asset


def upsert_identifier(
    db: Session,
    asset: Asset,
    identifier_type: str,
    value: str,
    *,
    source: str,
    seen_at: datetime | None,
) -> AssetIdentifier | None:
    raw = (value or "").strip()
    if not raw or identifier_type not in IDENTIFIER_TYPES:
        return None
    if identifier_type == IDENTIFIER_HOSTNAME and is_placeholder_hostname(raw):
        return None
    normalized = normalize_identifier(identifier_type, raw)
    if not normalized:
        return None
    row = (
        db.query(AssetIdentifier)
        .filter(
            AssetIdentifier.asset_id == asset.id,
            AssetIdentifier.identifier_type == identifier_type,
            AssetIdentifier.normalized_value == normalized,
        )
        .first()
    )
    if row is None:
        row = AssetIdentifier(
            asset_id=asset.id,
            tenant_id=asset.tenant_id,
            identifier_type=identifier_type,
            value=raw,
            normalized_value=normalized,
            source=source,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        db.add(row)
        db.flush()
        return row
    row.value = raw
    row.last_seen = seen_at
    if not row.first_seen:
        row.first_seen = seen_at
    return row


def upsert_address(
    db: Session,
    asset: Asset,
    ip: str,
    *,
    site_id: int | None,
    network_id: int | None,
    source: str,
    seen_at: datetime,
) -> AssetAddress | None:
    raw = (ip or "").strip()
    if not raw:
        return None
    try:
        ip_address(raw)
    except ValueError:
        return None
    row = (
        db.query(AssetAddress)
        .filter(AssetAddress.asset_id == asset.id, AssetAddress.ip == raw)
        .first()
    )
    if row is None:
        row = AssetAddress(
            asset_id=asset.id,
            tenant_id=asset.tenant_id,
            site_id=site_id,
            network_id=network_id,
            ip=raw,
            address_family=address_family(raw),
            source=source,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        db.add(row)
        db.flush()
        return row
    row.last_seen = seen_at
    if not row.first_seen:
        row.first_seen = seen_at
    if site_id is not None:
        row.site_id = site_id
    if network_id is not None:
        row.network_id = network_id
    return row


def _iter_ports(ports: list | None) -> list[tuple[int, str, str, str]]:
    rows: list[tuple[int, str, str, str]] = []
    for item in ports or []:
        port = None
        protocol = "tcp"
        product = ""
        version = ""
        if isinstance(item, dict):
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            protocol = str(item.get("protocol") or "tcp").lower() or "tcp"
            product = str(item.get("product") or item.get("service") or "")
            version = str(item.get("version") or "")
        else:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
        if port is None:
            continue
        rows.append((port, protocol, product, version))
    return rows


def upsert_services(
    db: Session,
    asset: Asset,
    ip: str,
    ports: list | None,
    *,
    address_id: int | None,
    title: str,
    tech: str,
    source: str,
    seen_at: datetime,
) -> None:
    for port, protocol, product, version in _iter_ports(ports):
        row = (
            db.query(AssetService)
            .filter(
                AssetService.asset_id == asset.id,
                AssetService.ip == (ip or ""),
                AssetService.port == port,
                AssetService.protocol == protocol,
            )
            .first()
        )
        if row is None:
            db.add(
                AssetService(
                    asset_id=asset.id,
                    tenant_id=asset.tenant_id,
                    address_id=address_id,
                    ip=ip or "",
                    port=port,
                    protocol=protocol,
                    product=product,
                    version=version,
                    tls_metadata={},
                    web_title=title or "",
                    tech=tech or "",
                    source=source,
                    first_seen=seen_at,
                    last_seen=seen_at,
                )
            )
            continue
        row.last_seen = seen_at
        if not row.first_seen:
            row.first_seen = seen_at
        if address_id is not None:
            row.address_id = address_id
        if product:
            row.product = product
        if version:
            row.version = version
        if title:
            row.web_title = title
        if tech:
            row.tech = tech


def find_observation(
    db: Session,
    asset: Asset,
    *,
    scan_job_id: int | None,
    observation_key: str,
) -> AssetObservation | None:
    existing_q = db.query(AssetObservation).filter(
        AssetObservation.asset_id == asset.id,
        AssetObservation.observation_key == observation_key,
    )
    if scan_job_id is not None:
        existing_q = existing_q.filter(AssetObservation.scan_job_id == scan_job_id)
    else:
        existing_q = existing_q.filter(AssetObservation.scan_job_id.is_(None))
    return existing_q.first()


def append_observation(
    db: Session,
    asset: Asset,
    *,
    context: dict,
    hostname: str,
    ip: str,
    snapshot: dict,
    observed_at: datetime,
    observation_key: str,
) -> AssetObservation:
    existing = find_observation(
        db,
        asset,
        scan_job_id=context.get("scan_job_id"),
        observation_key=observation_key,
    )
    if existing is not None:
        return existing
    scan_job_id = context.get("scan_job_id")
    row = AssetObservation(
        asset_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=context.get("site_id"),
        network_id=context.get("network_id"),
        agent_id=context.get("agent_id"),
        scan_job_id=scan_job_id,
        scope=context.get("scope") or "",
        source=context.get("source") or SOURCE_SCANNER,
        observed_at=observed_at,
        hostname=hostname or "",
        ip=ip or "",
        snapshot=snapshot,
        observation_key=observation_key,
        provenance=context.get("source") or SOURCE_SCANNER,
    )
    db.add(row)
    db.flush()
    return row


def apply_device_report(db: Session, device: Device, report: DeviceReport, job_id: int) -> Asset:
    """Write Asset facts after the legacy Device resolver has finished.

    Does not search other Assets and does not merge by IP/hostname/MAC.
    """
    report_ip = (report.ip or "").strip()
    report_hostname = (report.hostname or "").strip()
    report_scope = (report.scope or "").strip()
    context = observation_context(db, job_id, report_ip, report_scope or device.scope)
    asset = ensure_asset_for_device(db, device, context)
    snapshot = {
        "hostname": report_hostname,
        "ip": report_ip,
        "ports": list(report.ports or []),
        "title": report.title or "",
        "tech": report.tech or "",
        "auto_label": report.auto_label or "",
        "classification": report.classification or "",
        "scope": report_scope or context.get("scope") or "",
    }
    observation_key = observation_fingerprint(
        report_hostname,
        report_ip,
        snapshot["scope"],
        snapshot["ports"],
    )
    if find_observation(db, asset, scan_job_id=job_id, observation_key=observation_key) is not None:
        return asset
    now = utcnow()
    if not asset.is_expected:
        if asset.first_seen is None:
            asset.first_seen = now
        asset.last_seen = now
        if asset.lifecycle_state is None:
            asset.lifecycle_state = LIFECYCLE_ACTIVE
    name = display_name_for(device.hostname, device.ip, asset.display_name)
    if name:
        asset.display_name = name
    if device.classification and (not asset.classification or asset.classification == "Unknown"):
        asset.classification = device.classification
    if device.description and not asset.description:
        asset.description = device.description
    if context.get("site_id") and asset.site_id is None and (device.scope or context.get("scope")) == "lan":
        asset.site_id = context["site_id"]
    asset.updated_at = now

    if report_hostname and not is_placeholder_hostname(report_hostname, report_ip):
        upsert_identifier(db, asset, IDENTIFIER_HOSTNAME, report_hostname, source=SOURCE_SCANNER, seen_at=now)
    address = upsert_address(
        db,
        asset,
        report_ip,
        site_id=context.get("site_id"),
        network_id=context.get("network_id"),
        source=SOURCE_SCANNER,
        seen_at=now,
    )
    upsert_services(
        db,
        asset,
        report_ip,
        list(report.ports or []),
        address_id=address.id if address else None,
        title=report.title or "",
        tech=report.tech or "",
        source=SOURCE_SCANNER,
        seen_at=now,
    )
    append_observation(
        db,
        asset,
        context=context,
        hostname=report_hostname,
        ip=report_ip,
        snapshot=snapshot,
        observed_at=now,
        observation_key=observation_key,
    )
    db.flush()
    return asset


def get_or_create_tag(db: Session, tenant_id: int, name: str) -> Tag:
    cleaned = " ".join((name or "").strip().split())
    if not cleaned:
        raise ValueError("Tag name is required")
    normalized = normalize_tag_name(cleaned)
    tag = (
        db.query(Tag)
        .filter(Tag.tenant_id == tenant_id, Tag.normalized_name == normalized)
        .first()
    )
    if tag is not None:
        return tag
    tag = Tag(tenant_id=tenant_id, name=cleaned, normalized_name=normalized)
    db.add(tag)
    db.flush()
    return tag


def assign_tag(entity, tag: Tag) -> bool:
    if tag.tenant_id != entity.tenant_id:
        raise ValueError("Cannot assign a tag from another tenant")
    if tag in entity.tags:
        return False
    entity.tags.append(tag)
    return True


def remove_tag(entity, tag: Tag) -> bool:
    if tag not in entity.tags:
        return False
    entity.tags.remove(tag)
    return True


def validate_lifecycle(value: str) -> str:
    if value not in LIFECYCLE_STATES:
        raise ValueError("Invalid lifecycle_state")
    return value


def validate_disposition(value: str) -> str:
    if value not in DISPOSITIONS:
        raise ValueError("Invalid disposition")
    return value


def validate_criticality(value: str) -> str:
    if value not in CRITICALITIES:
        raise ValueError("Invalid criticality")
    return value


def sync_linked_devices(asset: Asset, *, classification: str | None = None, description: str | None = None) -> None:
    for device in asset.devices:
        if classification is not None:
            device.classification = classification
        if description is not None:
            device.description = description


__all__ = [
    "SOURCE_LEGACY_MIGRATION",
    "SOURCE_MANUAL",
    "SOURCE_SCANNER",
    "apply_device_report",
    "assign_tag",
    "display_name_for",
    "ensure_asset_for_device",
    "find_observation",
    "get_or_create_tag",
    "normalize_identifier",
    "normalize_tag_name",
    "observation_context",
    "observation_fingerprint",
    "remove_tag",
    "resolve_network_for_ip",
    "sync_linked_devices",
    "upsert_address",
    "upsert_identifier",
    "upsert_services",
    "utcnow",
    "validate_criticality",
    "validate_disposition",
    "validate_lifecycle",
]
