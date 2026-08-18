"""Audited manual Asset identity operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session, selectinload

from app.assets import (
    SOURCE_MANUAL,
    normalize_identifier,
    rebuild_scanner_projections,
    recalculate_asset_seen,
    utcnow,
)
from app.audit import record_audit
from app.correlation import canonical_asset_id
from app.finding_lifecycle import merge_asset_findings
from app.locality import get_site
from app.models import (
    IDENTIFIER_TYPES,
    IDENTIFIER_VALIDITY_ACTIVE,
    IDENTIFIER_VALIDITY_INCORRECT,
    LIFECYCLE_ACTIVE,
    Alert,
    Asset,
    AssetAddress,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
    Finding,
    User,
)


class IdentityError(ValueError):
    def __init__(self, detail: str, status_code: int = 400):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


def _require_same_tenant(source: Asset, target: Asset) -> None:
    if source.tenant_id != target.tenant_id:
        raise IdentityError("Cross-tenant identity operations are not allowed", 400)


def get_live_asset(db: Session, asset_id: int, *, tenant_id: int | None = None) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise IdentityError("Asset not found", 404)
    if tenant_id is not None and asset.tenant_id != tenant_id:
        raise IdentityError("Asset not found", 404)
    return asset


def follow_canonical(db: Session, asset: Asset) -> Asset:
    canonical_id = canonical_asset_id(db, asset.id)
    if canonical_id == asset.id:
        return asset
    found = db.get(Asset, canonical_id)
    if found is None:
        return asset
    return found


def _consolidate_devices(db: Session, keeper: Device, donor: Device) -> Device:
    """Merge two compatibility Device rows after an explicit Asset merge."""
    if donor.id == keeper.id:
        return keeper
    if donor.ip and (not keeper.ip or (donor.last_seen or donor.first_seen) >= (keeper.last_seen or keeper.first_seen)):
        keeper.ip = donor.ip
    if donor.ports:
        keeper.ports = sorted({*(keeper.ports or []), *(donor.ports or [])})
    if donor.title and not keeper.title:
        keeper.title = donor.title
    if donor.tech and not keeper.tech:
        keeper.tech = donor.tech
    if donor.auto_label and not keeper.auto_label:
        keeper.auto_label = donor.auto_label
    if donor.description and not keeper.description:
        keeper.description = donor.description
    if keeper.classification in ("", "Unknown") and donor.classification not in ("", "Unknown", "Other"):
        keeper.classification = donor.classification
    if donor.first_seen and (not keeper.first_seen or donor.first_seen < keeper.first_seen):
        keeper.first_seen = donor.first_seen
    if donor.last_seen and (not keeper.last_seen or donor.last_seen > keeper.last_seen):
        keeper.last_seen = donor.last_seen
    if keeper.site_id is None and donor.site_id is not None:
        keeper.site_id = donor.site_id
    db.query(Finding).filter(Finding.device_id == donor.id).update(
        {Finding.device_id: keeper.id}, synchronize_session=False
    )
    db.query(Alert).filter(Alert.device_id == donor.id).update(
        {Alert.device_id: keeper.id}, synchronize_session=False
    )
    db.delete(donor)
    db.flush()
    return keeper


def _attach_device_to_canonical(db: Session, device: Device, target: Asset) -> Device:
    if target.site_id and device.scope == "lan" and device.site_id is None:
        device.site_id = target.site_id
    query = db.query(Device).filter(
        Device.id != device.id,
        Device.tenant_id == target.tenant_id,
        Device.hostname == device.hostname,
        Device.scope == device.scope,
        Device.asset_id == target.id,
    )
    if device.site_id is None:
        query = query.filter(Device.site_id.is_(None))
    else:
        query = query.filter(Device.site_id == device.site_id)
    existing = query.first()
    if existing is None:
        device.asset_id = target.id
        db.flush()
        return device
    return _consolidate_devices(db, existing, device)


def merge_assets(
    db: Session,
    *,
    target: Asset,
    source_ids: list[int],
    actor: User,
    reason: str = "",
) -> Asset:
    if target.merged_into_asset_id:
        raise IdentityError("Cannot merge into an Asset that is already merged")
    sources: list[Asset] = []
    for source_id in source_ids:
        source = get_live_asset(db, source_id)
        if source.id == target.id:
            raise IdentityError("Cannot merge an Asset into itself")
        _require_same_tenant(source, target)
        if source.merged_into_asset_id:
            raise IdentityError(f"Asset #{source.id} is already merged")
        sources.append(source)
    if not sources:
        raise IdentityError("At least one source Asset is required")

    before = {
        "target_id": target.id,
        "source_ids": [source.id for source in sources],
        "target_identifiers": len(target.identifiers),
        "target_addresses": len(target.addresses),
        "target_observations": len(target.observations),
    }
    now = utcnow()
    for source in sources:
        for identifier in list(source.identifiers):
            existing = (
                db.query(AssetIdentifier)
                .filter(
                    AssetIdentifier.asset_id == target.id,
                    AssetIdentifier.identifier_type == identifier.identifier_type,
                    AssetIdentifier.normalized_value == identifier.normalized_value,
                )
                .first()
            )
            if existing is None:
                identifier.asset_id = target.id
                identifier.tenant_id = target.tenant_id
            elif identifier.validity == IDENTIFIER_VALIDITY_INCORRECT:
                continue
        db.flush()
        for address in list(source.addresses):
            existing = (
                db.query(AssetAddress)
                .filter(AssetAddress.asset_id == target.id, AssetAddress.ip == address.ip)
                .first()
            )
            if existing is None:
                address.asset_id = target.id
                address.tenant_id = target.tenant_id
            else:
                if address.last_seen and (not existing.last_seen or address.last_seen > existing.last_seen):
                    existing.last_seen = address.last_seen
                if address.first_seen and (not existing.first_seen or address.first_seen < existing.first_seen):
                    existing.first_seen = address.first_seen
        db.flush()
        for service in list(source.services):
            existing = (
                db.query(AssetService)
                .filter(
                    AssetService.asset_id == target.id,
                    AssetService.ip == service.ip,
                    AssetService.port == service.port,
                    AssetService.protocol == service.protocol,
                )
                .first()
            )
            if existing is None:
                service.asset_id = target.id
                service.tenant_id = target.tenant_id
            else:
                if service.last_seen and (not existing.last_seen or service.last_seen > existing.last_seen):
                    existing.last_seen = service.last_seen
                if service.first_seen and (not existing.first_seen or service.first_seen < existing.first_seen):
                    existing.first_seen = service.first_seen
        db.flush()
        for observation in list(source.observations):
            collision = (
                db.query(AssetObservation)
                .filter(
                    AssetObservation.asset_id == target.id,
                    AssetObservation.observation_key == observation.observation_key,
                    AssetObservation.scan_job_id == observation.scan_job_id
                    if observation.scan_job_id is not None
                    else AssetObservation.scan_job_id.is_(None),
                )
                .first()
            )
            if collision is None:
                observation.asset_id = target.id
                observation.tenant_id = target.tenant_id
        for device in list(source.devices):
            _attach_device_to_canonical(db, device, target)
        merge_asset_findings(db, target=target, sources=[source])
        source.merged_into_asset_id = target.id
        source.merged_at = now
        source.updated_at = now
    if target.site_id is None:
        for source in sources:
            if source.site_id is not None:
                target.site_id = source.site_id
                break
    if target.classification in ("", "Unknown"):
        for source in sources:
            if source.classification not in ("", "Unknown"):
                target.classification = source.classification
                break
    target.updated_at = now
    db.flush()
    db.expire(target, ["observations", "identifiers", "addresses", "services", "devices"])
    for merged in sources:
        db.expire(merged, ["observations", "identifiers", "addresses", "services", "devices"])
    target = (
        db.query(Asset)
        .options(
            selectinload(Asset.observations),
            selectinload(Asset.identifiers),
            selectinload(Asset.addresses),
            selectinload(Asset.services),
        )
        .filter(Asset.id == target.id)
        .one()
    )
    for merged in sources:
        emptied = (
            db.query(Asset)
            .options(selectinload(Asset.observations))
            .filter(Asset.id == merged.id)
            .one()
        )
        remaining = (
            db.query(AssetObservation)
            .filter(AssetObservation.asset_id == emptied.id)
            .all()
        )
        recalculate_asset_seen(emptied, remaining)
    rebuild_scanner_projections(db, target)
    record_audit(
        db,
        actor=actor,
        action="asset.merge",
        object_type="asset",
        object_id=target.id,
        tenant_id=target.tenant_id,
        site_id=target.site_id,
        details={
            "reason": reason,
            "before": before,
            "after": {
                "target_id": target.id,
                "source_ids": [source.id for source in sources],
                "merged_into": {source.id: target.id for source in sources},
            },
        },
    )
    return target


def reassociate_observations(
    db: Session,
    *,
    source: Asset,
    target: Asset,
    observation_ids: list[int],
    actor: User,
    reason: str = "",
    action: str = "asset.observation_reassociate",
) -> tuple[Asset, Asset]:
    _require_same_tenant(source, target)
    if source.merged_into_asset_id or target.merged_into_asset_id:
        raise IdentityError("Cannot reassign observations on a merged Asset")
    if not observation_ids:
        raise IdentityError("Select at least one observation")
    rows = (
        db.query(AssetObservation)
        .filter(AssetObservation.id.in_(observation_ids), AssetObservation.asset_id == source.id)
        .all()
    )
    if len(rows) != len(set(observation_ids)):
        raise IdentityError("One or more observations were not found on the source Asset")
    for observation in rows:
        collision = (
            db.query(AssetObservation)
            .filter(
                AssetObservation.asset_id == target.id,
                AssetObservation.observation_key == observation.observation_key,
                AssetObservation.scan_job_id == observation.scan_job_id
                if observation.scan_job_id is not None
                else AssetObservation.scan_job_id.is_(None),
            )
            .first()
        )
        if collision is not None:
            raise IdentityError(
                f"Observation {observation.id} would collide with existing history on Asset #{target.id}"
            )
        observation.asset_id = target.id
        observation.tenant_id = target.tenant_id
    db.flush()
    db.refresh(source)
    db.refresh(target)
    source = (
        db.query(Asset)
        .options(
            selectinload(Asset.observations),
            selectinload(Asset.identifiers),
            selectinload(Asset.addresses),
            selectinload(Asset.services),
        )
        .filter(Asset.id == source.id)
        .one()
    )
    target = (
        db.query(Asset)
        .options(
            selectinload(Asset.observations),
            selectinload(Asset.identifiers),
            selectinload(Asset.addresses),
            selectinload(Asset.services),
        )
        .filter(Asset.id == target.id)
        .one()
    )
    rebuild_scanner_projections(db, source)
    rebuild_scanner_projections(db, target)
    record_audit(
        db,
        actor=actor,
        action=action,
        object_type="asset",
        object_id=target.id,
        tenant_id=target.tenant_id,
        site_id=target.site_id,
        details={
            "reason": reason,
            "source_asset_id": source.id,
            "target_asset_id": target.id,
            "observation_ids": observation_ids,
        },
    )
    return source, target


def split_observations_to_new_asset(
    db: Session,
    *,
    source: Asset,
    observation_ids: list[int],
    actor: User,
    reason: str = "",
) -> Asset:
    if source.merged_into_asset_id:
        raise IdentityError("Cannot split a merged Asset")
    # Phase 2A: AssetFindings stay on the source Asset. Observation selection
    # cannot deterministically prove which logical finding belongs to the new
    # Asset, so findings are not moved or duplicated.
    now = utcnow()
    target = Asset(
        tenant_id=source.tenant_id,
        site_id=source.site_id,
        display_name=source.display_name,
        classification=source.classification if source.classification != "Unknown" else "Unknown",
        description="",
        lifecycle_state=LIFECYCLE_ACTIVE,
        disposition="unreviewed",
        criticality=source.criticality,
        is_expected=False,
        first_seen=None,
        last_seen=None,
        updated_at=now,
    )
    db.add(target)
    db.flush()
    reassociate_observations(
        db,
        source=source,
        target=target,
        observation_ids=observation_ids,
        actor=actor,
        reason=reason,
        action="asset.split",
    )
    return target


def correct_identifier(
    db: Session,
    *,
    asset: Asset,
    identifier: AssetIdentifier,
    actor: User,
    reason: str,
    replacement_value: str = "",
    replacement_type: str | None = None,
) -> AssetIdentifier:
    if identifier.asset_id != asset.id or identifier.tenant_id != asset.tenant_id:
        raise IdentityError("Identifier does not belong to this Asset")
    if identifier.validity == IDENTIFIER_VALIDITY_INCORRECT:
        raise IdentityError("Identifier is already marked incorrect")
    now = utcnow()
    identifier.validity = IDENTIFIER_VALIDITY_INCORRECT
    identifier.corrected_at = now
    identifier.corrected_by_id = actor.id
    identifier.correction_reason = reason or ""
    replacement = None
    value = (replacement_value or "").strip()
    if value:
        itype = replacement_type or identifier.identifier_type
        if itype not in IDENTIFIER_TYPES:
            raise IdentityError("Invalid replacement identifier type")
        normalized = normalize_identifier(itype, value)
        replacement = AssetIdentifier(
            asset_id=asset.id,
            tenant_id=asset.tenant_id,
            identifier_type=itype,
            value=value,
            normalized_value=normalized,
            source=SOURCE_MANUAL,
            validity=IDENTIFIER_VALIDITY_ACTIVE,
            first_seen=None,
            last_seen=None,
        )
        db.add(replacement)
        db.flush()
        identifier.replacement_identifier_id = replacement.id
    asset.updated_at = now
    record_audit(
        db,
        actor=actor,
        action="asset.identifier_correct",
        object_type="asset",
        object_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        details={
            "identifier_id": identifier.id,
            "identifier_type": identifier.identifier_type,
            "value": identifier.value,
            "reason": reason,
            "replacement_identifier_id": replacement.id if replacement else None,
            "replacement_value": value or None,
        },
    )
    return identifier


def _reconcile_lan_devices_for_site(db: Session, asset: Asset, target_site_id: int) -> None:
    """Collapse LAN Device rows that would collide after a Site move."""
    lan_devices = [row for row in list(asset.devices) if row.scope == "lan"]
    groups: dict[tuple[int, str, str], list[Device]] = {}
    for device in lan_devices:
        key = (device.tenant_id, device.hostname, device.scope)
        groups.setdefault(key, []).append(device)
    for devices in groups.values():
        keeper = next((row for row in devices if row.site_id == target_site_id), None)
        if keeper is None:
            keeper = min(devices, key=lambda row: row.id)
        for donor in devices:
            if donor.id == keeper.id:
                continue
            _consolidate_devices(db, keeper, donor)
        keeper.site_id = target_site_id
    db.expire(asset, ["devices"])


def move_asset_site(
    db: Session,
    *,
    asset: Asset,
    site_id: int,
    actor: User,
    reason: str = "",
) -> Asset:
    if asset.merged_into_asset_id:
        raise IdentityError("Cannot move a merged Asset")
    site = get_site(db, site_id, tenant_id=asset.tenant_id)
    if site.tenant_id != asset.tenant_id:
        raise IdentityError("Site does not belong to this tenant")
    before = asset.site_id
    db.expire(asset, ["site", "devices"])
    _reconcile_lan_devices_for_site(db, asset, site.id)
    asset.site_id = site.id
    asset.site = site
    asset.updated_at = utcnow()
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="asset.move_site",
        object_type="asset",
        object_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=site.id,
        details={"reason": reason, "before_site_id": before, "after_site_id": site.id},
    )
    from app.policy import apply_asset_handling

    apply_asset_handling(
        db,
        asset,
        observation_override={"site_id": site.id, "network_id": None},
    )
    return asset


def identity_http_error(exc: IdentityError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)
