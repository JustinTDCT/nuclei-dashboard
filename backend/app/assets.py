"""Asset current-state projection and historical observation writing.

Phase 1C: Asset correlation is authoritative. Device rows are a
compatibility projection written after the correlation decision.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address, ip_network
import json

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from app.classify import is_placeholder_name, normalize_hostname
from app.locality import compatibility_site_for_tenant
from app.models import (
    CRITICALITIES,
    DECISION_LINKED_EXISTING,
    DISPOSITIONS,
    DISPOSITION_UNREVIEWED,
    IDENTIFIER_DEVICE_ID,
    IDENTIFIER_DNS_NAME,
    IDENTIFIER_FQDN,
    IDENTIFIER_HOSTNAME,
    IDENTIFIER_MAC,
    IDENTIFIER_SERIAL,
    IDENTIFIER_TLS_NAME,
    IDENTIFIER_TYPES,
    IDENTIFIER_VALIDITY_ACTIVE,
    IDENTIFIER_VALIDITY_INCORRECT,
    LIFECYCLE_ACTIVE,
    LIFECYCLE_INACTIVE,
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


def observation_fingerprint(
    hostname: str,
    ip: str,
    scope: str,
    ports,
    *,
    mac: str = "",
    serial: str = "",
    device_identifier: str = "",
    fqdn: str = "",
    tls_name: str = "",
    dns_name: str = "",
    title: str = "",
    tech: str = "",
    classification: str = "",
    auto_label: str = "",
) -> str:
    host = normalize_hostname(hostname)
    if is_placeholder_hostname(host, ip):
        host = ""
    payload_obj = {
        "hostname": host,
        "ip": (ip or "").strip(),
        "ports": [
            {"port": port, "protocol": protocol}
            for port, protocol, _, _ in sorted(_iter_ports(ports), key=lambda row: (row[0], row[1]))
        ],
        "scope": (scope or "").strip().lower(),
        "mac": normalize_identifier(IDENTIFIER_MAC, mac) if mac else "",
        "serial": normalize_identifier(IDENTIFIER_SERIAL, serial) if serial else "",
        "device_identifier": normalize_identifier(IDENTIFIER_DEVICE_ID, device_identifier)
        if device_identifier
        else "",
        "fqdn": normalize_identifier(IDENTIFIER_FQDN, fqdn) if fqdn else "",
        "tls_name": normalize_identifier(IDENTIFIER_TLS_NAME, tls_name) if tls_name else "",
        "dns_name": normalize_identifier(IDENTIFIER_DNS_NAME, dns_name) if dns_name else "",
        "title": (title or "").strip(),
        "tech": (tech or "").strip(),
        "classification": (classification or "").strip(),
        "auto_label": (auto_label or "").strip(),
    }
    payload = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def report_snapshot(report: DeviceReport, scope: str) -> dict:
    return {
        "hostname": (report.hostname or "").strip(),
        "ip": (report.ip or "").strip(),
        "ports": list(report.ports or []),
        "title": report.title or "",
        "tech": report.tech or "",
        "auto_label": report.auto_label or "",
        "classification": report.classification or "",
        "scope": scope,
        "mac": report.mac or "",
        "serial": report.serial or "",
        "device_identifier": report.device_identifier or "",
        "fqdn": report.fqdn or "",
        "tls_name": report.tls_name or "",
        "dns_name": report.dns_name or "",
    }


def observation_key_from_snapshot(snapshot: dict) -> str:
    snap = snapshot or {}
    return observation_fingerprint(
        snap.get("hostname") or "",
        snap.get("ip") or "",
        snap.get("scope") or "",
        snap.get("ports") or [],
        mac=snap.get("mac") or "",
        serial=snap.get("serial") or "",
        device_identifier=snap.get("device_identifier") or "",
        fqdn=snap.get("fqdn") or "",
        tls_name=snap.get("tls_name") or "",
        dns_name=snap.get("dns_name") or "",
        title=snap.get("title") or "",
        tech=snap.get("tech") or "",
        classification=snap.get("classification") or "",
        auto_label=snap.get("auto_label") or "",
    )


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
            validity=IDENTIFIER_VALIDITY_ACTIVE,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        db.add(row)
        db.flush()
        return row
    if row.validity == IDENTIFIER_VALIDITY_INCORRECT:
        return None
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
        if row is None or sa_inspect(row).deleted:
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
    db.flush()


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


def apply_scanner_facts_from_snapshot(
    db: Session,
    asset: Asset,
    snapshot: dict,
    *,
    hostname: str = "",
    ip: str = "",
    site_id: int | None = None,
    network_id: int | None = None,
    seen_at: datetime,
) -> None:
    """Replay one observation snapshot onto scanner-derived current projections."""
    snap = snapshot or {}
    report_ip = (ip or snap.get("ip") or "").strip()
    report_hostname = (hostname or snap.get("hostname") or "").strip()
    if report_hostname and not is_placeholder_hostname(report_hostname, report_ip):
        upsert_identifier(db, asset, IDENTIFIER_HOSTNAME, report_hostname, source=SOURCE_SCANNER, seen_at=seen_at)
        if "." in report_hostname:
            upsert_identifier(db, asset, IDENTIFIER_FQDN, report_hostname, source=SOURCE_SCANNER, seen_at=seen_at)
    for identifier_type, key in (
        (IDENTIFIER_MAC, "mac"),
        (IDENTIFIER_SERIAL, "serial"),
        (IDENTIFIER_DEVICE_ID, "device_identifier"),
        (IDENTIFIER_FQDN, "fqdn"),
        (IDENTIFIER_TLS_NAME, "tls_name"),
        (IDENTIFIER_DNS_NAME, "dns_name"),
    ):
        value = str(snap.get(key) or "").strip()
        if value:
            upsert_identifier(db, asset, identifier_type, value, source=SOURCE_SCANNER, seen_at=seen_at)
    address = upsert_address(
        db,
        asset,
        report_ip,
        site_id=site_id,
        network_id=network_id,
        source=SOURCE_SCANNER,
        seen_at=seen_at,
    )
    upsert_services(
        db,
        asset,
        report_ip,
        snap.get("ports") or [],
        address_id=address.id if address else None,
        title=str(snap.get("title") or ""),
        tech=str(snap.get("tech") or ""),
        source=SOURCE_SCANNER,
        seen_at=seen_at,
    )


def recalculate_asset_seen(asset: Asset, observations: list[AssetObservation] | None = None) -> None:
    """Current first/last-seen and lifecycle must reflect remaining observations."""
    rows = observations if observations is not None else list(asset.observations)
    times = [row.observed_at for row in rows if row.observed_at is not None]
    if not times:
        asset.first_seen = None
        asset.last_seen = None
        asset.lifecycle_state = None
        return
    asset.first_seen = min(times)
    asset.last_seen = max(times)
    if asset.lifecycle_state != LIFECYCLE_INACTIVE:
        asset.lifecycle_state = LIFECYCLE_ACTIVE


def rebuild_scanner_projections(db: Session, asset: Asset) -> None:
    """Rebuild scanner-derived identifiers/addresses/services from observations.

    Manual identifiers and identifiers marked incorrect are preserved.
    """
    scanner_ids = (
        db.query(AssetIdentifier)
        .filter(
            AssetIdentifier.asset_id == asset.id,
            AssetIdentifier.source == SOURCE_SCANNER,
            AssetIdentifier.validity == IDENTIFIER_VALIDITY_ACTIVE,
        )
        .all()
    )
    for row in scanner_ids:
        db.delete(row)
    scanner_addresses = (
        db.query(AssetAddress)
        .filter(AssetAddress.asset_id == asset.id, AssetAddress.source == SOURCE_SCANNER)
        .all()
    )
    for row in scanner_addresses:
        db.delete(row)
    scanner_services = (
        db.query(AssetService)
        .filter(AssetService.asset_id == asset.id, AssetService.source == SOURCE_SCANNER)
        .all()
    )
    for row in scanner_services:
        db.delete(row)
    db.flush()
    for row in [*scanner_ids, *scanner_addresses, *scanner_services]:
        if row in db:
            db.expunge(row)
    db.expire(asset, ["identifiers", "addresses", "services", "observations"])

    observations = (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset.id)
        .order_by(AssetObservation.observed_at.asc(), AssetObservation.id.asc())
        .all()
    )
    for observation in observations:
        apply_scanner_facts_from_snapshot(
            db,
            asset,
            observation.snapshot or {},
            hostname=observation.hostname,
            ip=observation.ip,
            site_id=observation.site_id,
            network_id=observation.network_id,
            seen_at=observation.observed_at or utcnow(),
        )
    recalculate_asset_seen(asset, observations)
    name = display_name_for(
        next((row.hostname for row in reversed(observations) if row.hostname), ""),
        next((row.ip for row in reversed(observations) if row.ip), ""),
        asset.display_name,
    )
    if name:
        asset.display_name = name
    asset.updated_at = utcnow()


def _write_observation_facts(
    db: Session,
    asset: Asset,
    report: DeviceReport,
    context: dict,
    *,
    observed_at: datetime,
    observation_key: str,
    snapshot: dict,
) -> None:
    report_ip = (report.ip or "").strip()
    report_hostname = (report.hostname or "").strip()
    apply_scanner_facts_from_snapshot(
        db,
        asset,
        snapshot,
        hostname=report_hostname,
        ip=report_ip,
        site_id=context.get("site_id"),
        network_id=context.get("network_id"),
        seen_at=observed_at,
    )
    append_observation(
        db,
        asset,
        context=context,
        hostname=report_hostname,
        ip=report_ip,
        snapshot=snapshot,
        observed_at=observed_at,
        observation_key=observation_key,
    )


def _apply_observation_lifecycle(
    db: Session,
    asset: Asset,
    *,
    observed_at: datetime,
    observation_key: str,
    classification: str,
    site_id: int | None,
    scope: str,
) -> None:
    from app.events import emit_new_asset, emit_previously_inactive_returned

    first_observation = asset.first_seen is None
    was_inactive = asset.lifecycle_state == LIFECYCLE_INACTIVE
    if first_observation:
        asset.first_seen = observed_at
    asset.last_seen = observed_at
    asset.lifecycle_state = LIFECYCLE_ACTIVE
    if site_id and asset.site_id is None and scope == "lan":
        asset.site_id = site_id
    if classification and (not asset.classification or asset.classification == "Unknown"):
        asset.classification = classification
    asset.updated_at = observed_at
    if first_observation:
        emit_new_asset(db, asset)
    if was_inactive:
        emit_previously_inactive_returned(db, asset, observation_key=observation_key)


def create_discovered_asset(
    db: Session,
    *,
    tenant_id: int,
    site_id: int | None,
    report: DeviceReport,
    scope: str,
    observed_at: datetime,
) -> Asset:
    from app.events import emit_new_asset

    if scope == "lan" and site_id is None:
        site_id = fallback_lan_site(db, tenant_id).id
    if scope == "wan":
        site_id = None
    asset = Asset(
        tenant_id=tenant_id,
        site_id=site_id,
        display_name=display_name_for(report.hostname, report.ip),
        classification=report.classification or "Unknown",
        description="",
        lifecycle_state=LIFECYCLE_ACTIVE,
        disposition=DISPOSITION_UNREVIEWED,
        criticality="normal",
        is_expected=False,
        first_seen=observed_at,
        last_seen=observed_at,
        updated_at=observed_at,
    )
    db.add(asset)
    db.flush()
    emit_new_asset(db, asset)
    return asset


def ingest_device_report(
    db: Session,
    tenant_id: int,
    report: DeviceReport,
    job_id: int,
) -> tuple[Asset, bool]:
    """Correlate then persist observation facts. Returns (asset, retry)."""
    from app.correlation import (
        canonical_asset_id,
        correlate,
        find_correlation_decision,
        persist_correlation_decision,
        post_correlation_asset_policy_hook,
        signals_from_report,
    )

    report_ip = (report.ip or "").strip()
    report_scope = (report.scope or "").strip()
    context = observation_context(db, job_id, report_ip, report_scope)
    scope = context.get("scope") or report_scope
    snapshot = report_snapshot(report, scope)
    observation_key = observation_key_from_snapshot(snapshot)
    existing_decision = find_correlation_decision(db, scan_job_id=job_id, observation_key=observation_key)
    if existing_decision is not None:
        asset_id = existing_decision.selected_asset_id
        if asset_id is None:
            raise RuntimeError("Stored correlation decision is missing selected_asset_id")
        asset = db.get(Asset, canonical_asset_id(db, asset_id))
        if asset is None:
            raise RuntimeError("Stored correlation decision references a missing Asset")
        return asset, True

    signals = signals_from_report(tenant_id, report, context)
    result = correlate(db, signals)
    now = utcnow()
    if result.decision == DECISION_LINKED_EXISTING and result.selected_asset_id:
        asset = db.get(Asset, canonical_asset_id(db, result.selected_asset_id))
        if asset is None:
            asset = create_discovered_asset(
                db, tenant_id=tenant_id, site_id=context.get("site_id"), report=report, scope=scope, observed_at=now
            )
            result.selected_asset_id = asset.id
            result.decision = "created_new"
        else:
            _apply_observation_lifecycle(
                db,
                asset,
                observed_at=now,
                observation_key=observation_key,
                classification=report.classification or "",
                site_id=context.get("site_id"),
                scope=scope,
            )
    else:
        asset = create_discovered_asset(
            db, tenant_id=tenant_id, site_id=context.get("site_id"), report=report, scope=scope, observed_at=now
        )
        result.selected_asset_id = asset.id
    name = display_name_for(report.hostname, report.ip, asset.display_name)
    if name:
        asset.display_name = name
    _write_observation_facts(
        db,
        asset,
        report,
        context,
        observed_at=now,
        observation_key=observation_key,
        snapshot=snapshot,
    )
    persist_correlation_decision(
        db,
        tenant_id=tenant_id,
        site_id=context.get("site_id"),
        scan_job_id=job_id,
        observation_key=observation_key,
        source_device_id=None,
        result=result,
    )
    post_correlation_asset_policy_hook(db, asset, result, context)
    db.flush()
    return asset, False


def apply_device_report(db: Session, device: Device, report: DeviceReport, job_id: int) -> Asset:
    """Compatibility wrapper. Correlation is authoritative."""
    asset, _retry = ingest_device_report(db, device.tenant_id, report, job_id)
    device.asset_id = asset.id
    if asset.site_id and device.scope == "lan":
        device.site_id = asset.site_id
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
    "apply_scanner_facts_from_snapshot",
    "ingest_device_report",
    "assign_tag",
    "display_name_for",
    "ensure_asset_for_device",
    "find_observation",
    "get_or_create_tag",
    "normalize_identifier",
    "normalize_tag_name",
    "observation_context",
    "observation_fingerprint",
    "observation_key_from_snapshot",
    "rebuild_scanner_projections",
    "recalculate_asset_seen",
    "remove_tag",
    "report_snapshot",
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
