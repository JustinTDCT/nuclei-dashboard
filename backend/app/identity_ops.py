"""Audited manual Asset identity operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session, selectinload

from app.assets import (
    SOURCE_MANUAL,
    SOURCE_SCANNER,
    display_name_for,
    normalize_identifier,
    utcnow,
)
from app.audit import record_audit
from app.correlation import canonical_asset_id
from app.locality import get_site
from app.models import (
    IDENTIFIER_TYPES,
    IDENTIFIER_VALIDITY_ACTIVE,
    IDENTIFIER_VALIDITY_INCORRECT,
    LIFECYCLE_ACTIVE,
    Asset,
    AssetAddress,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
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


def _recalculate_seen(asset: Asset) -> None:
    times = [row.observed_at for row in asset.observations if row.observed_at is not None]
    if not times:
        if asset.is_expected:
            asset.first_seen = None
            asset.last_seen = None
            asset.lifecycle_state = None
        return
    asset.first_seen = min(times)
    asset.last_seen = max(times)
    if asset.lifecycle_state is None:
        asset.lifecycle_state = LIFECYCLE_ACTIVE


def _rebuild_scanner_projections(db: Session, asset: Asset) -> None:
    scanner_ids = [
        row
        for row in list(asset.identifiers)
        if row.source == SOURCE_SCANNER and row.validity == IDENTIFIER_VALIDITY_ACTIVE
    ]
    for row in scanner_ids:
        db.delete(row)
    for row in list(asset.addresses):
        if row.source == SOURCE_SCANNER:
            db.delete(row)
    for row in list(asset.services):
        if row.source == SOURCE_SCANNER:
            db.delete(row)
    db.flush()

    from app.assets import upsert_address, upsert_identifier, upsert_services

    for observation in sorted(asset.observations, key=lambda row: row.observed_at):
        if observation.hostname:
            upsert_identifier(
                db,
                asset,
                "hostname",
                observation.hostname,
                source=SOURCE_SCANNER,
                seen_at=observation.observed_at,
            )
        address = upsert_address(
            db,
            asset,
            observation.ip,
            site_id=observation.site_id,
            network_id=observation.network_id,
            source=SOURCE_SCANNER,
            seen_at=observation.observed_at,
        )
        snapshot = observation.snapshot or {}
        upsert_services(
            db,
            asset,
            observation.ip,
            snapshot.get("ports") or [],
            address_id=address.id if address else None,
            title=str(snapshot.get("title") or ""),
            tech=str(snapshot.get("tech") or ""),
            source=SOURCE_SCANNER,
            seen_at=observation.observed_at,
        )
    _recalculate_seen(asset)
    name = display_name_for(
        next((row.hostname for row in reversed(asset.observations) if row.hostname), ""),
        next((row.ip for row in reversed(asset.observations) if row.ip), ""),
        asset.display_name,
    )
    if name:
        asset.display_name = name
    asset.updated_at = utcnow()


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
            device.asset_id = target.id
            if target.site_id and device.scope == "lan" and device.site_id is None:
                device.site_id = target.site_id
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
    target = (
        db.query(Asset)
        .options(selectinload(Asset.observations), selectinload(Asset.identifiers), selectinload(Asset.addresses))
        .filter(Asset.id == target.id)
        .one()
    )
    _recalculate_seen(target)
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
        .options(selectinload(Asset.observations), selectinload(Asset.identifiers), selectinload(Asset.addresses))
        .filter(Asset.id == source.id)
        .one()
    )
    target = (
        db.query(Asset)
        .options(selectinload(Asset.observations), selectinload(Asset.identifiers), selectinload(Asset.addresses))
        .filter(Asset.id == target.id)
        .one()
    )
    _rebuild_scanner_projections(db, source)
    _rebuild_scanner_projections(db, target)
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
    asset.site_id = site.id
    asset.updated_at = utcnow()
    for device in asset.devices:
        if device.scope == "lan":
            device.site_id = site.id
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
    return asset


def identity_http_error(exc: IdentityError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)
