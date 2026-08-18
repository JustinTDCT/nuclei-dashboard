from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, selectinload

from app.assets import (
    SOURCE_MANUAL,
    assign_tag,
    get_or_create_tag,
    normalize_identifier,
    remove_tag,
    sync_linked_devices,
    upsert_address,
    upsert_identifier,
    utcnow,
    validate_criticality,
    validate_disposition,
    validate_lifecycle,
)
from app.audit import record_audit
from app.auth import require_any, require_user
from app.database import get_db
from app.identity_ops import (
    IdentityError,
    correct_identifier,
    identity_http_error,
    merge_assets,
    move_asset_site,
    reassociate_observations,
    split_observations_to_new_asset,
)
from app.locality import get_site, get_tenant
from app.models import (
    IDENTIFIER_HOSTNAME,
    IDENTIFIER_MAC,
    TECHNICAL_OPEN,
    Asset,
    AssetFinding,
    AssetAddress,
    AssetCorrelationDecision,
    AssetIdentifier,
    AssetObservation,
    AssetService,
    Device,
    DomainEvent,
    Finding,
    Tag,
    User,
)
from app.routers.devices import _finding_out
from app.schemas import (
    DEVICE_CLASSES,
    AssetAddressOut,
    AssetCreate,
    AssetDetail,
    AssetIdentifierCorrectIn,
    AssetIdentifierOut,
    AssetListItem,
    AssetMergeIn,
    AssetMoveSiteIn,
    AssetObservationOut,
    AssetReassociateIn,
    AssetServiceOut,
    AssetSplitIn,
    AssetUpdate,
    CorrelationDecisionOut,
    DomainEventOut,
    HistoryPage,
    TagAssignIn,
    TagIn,
    TagOut,
)

router = APIRouter(tags=["assets"])


def _get_asset(db: Session, asset_id: int, tenant_id: int | None = None) -> Asset:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if tenant_id is not None and asset.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _current_hostname(asset: Asset) -> str | None:
    hostnames = [
        row
        for row in asset.identifiers
        if row.identifier_type == IDENTIFIER_HOSTNAME and getattr(row, "validity", "active") == "active"
    ]
    hostnames.sort(key=lambda row: row.last_seen or row.created_at, reverse=True)
    if hostnames:
        return hostnames[0].value
    return asset.display_name or None


def _current_addresses(asset: Asset) -> list[str]:
    rows = sorted(asset.addresses, key=lambda row: row.last_seen or row.created_at, reverse=True)
    return [row.ip for row in rows[:4] if row.ip]


def _findings_count_map(db: Session, asset_ids: list[int]) -> dict[int, int]:
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetFinding.asset_id, func.count(AssetFinding.id))
        .filter(
            AssetFinding.asset_id.in_(asset_ids),
            AssetFinding.technical_state == TECHNICAL_OPEN,
        )
        .group_by(AssetFinding.asset_id)
        .all()
    )
    return {asset_id: int(count) for asset_id, count in rows}


def _serialize_list_item(asset: Asset, findings_count: int = 0) -> AssetListItem:
    return AssetListItem(
        id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        site_name=asset.site.name if asset.site else None,
        merged_into_asset_id=asset.merged_into_asset_id,
        display_name=asset.display_name,
        hostname=_current_hostname(asset),
        current_addresses=_current_addresses(asset),
        classification=asset.classification,
        description=asset.description or "",
        lifecycle_state=asset.lifecycle_state,
        disposition=asset.disposition,
        criticality=asset.criticality,
        is_expected=asset.is_expected,
        is_not_yet_observed=bool(asset.is_expected and asset.first_seen is None),
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        tags=[TagOut.model_validate(tag) for tag in asset.tags],
        findings_count=findings_count,
        created_at=asset.created_at,
    )


@router.get("/tenants/{tenant_id}/tags", response_model=list[TagOut])
def list_tags(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    get_tenant(db, tenant_id)
    return db.query(Tag).filter(Tag.tenant_id == tenant_id).order_by(Tag.name).all()


@router.post("/tenants/{tenant_id}/tags", response_model=TagOut)
def create_tag(
    tenant_id: int,
    body: TagIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    try:
        tag = get_or_create_tag(db, tenant_id, body.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        db,
        actor=user,
        action="tag.create",
        object_type="tag",
        object_id=tag.id,
        tenant_id=tenant_id,
        details={"name": tag.name},
    )
    db.commit()
    db.refresh(tag)
    return tag


@router.get("/tenants/{tenant_id}/assets", response_model=list[AssetListItem])
def list_assets(
    tenant_id: int,
    site_id: int | None = None,
    q: str | None = None,
    disposition: str | None = None,
    lifecycle_state: str | None = None,
    criticality: str | None = None,
    expected: bool | None = None,
    include_merged: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    query = (
        db.query(Asset)
        .options(
            selectinload(Asset.site),
            selectinload(Asset.tags),
            selectinload(Asset.addresses),
            selectinload(Asset.identifiers),
        )
        .filter(Asset.tenant_id == tenant_id)
    )
    if not include_merged:
        query = query.filter(Asset.merged_into_asset_id.is_(None))
    if site_id is not None:
        get_site(db, site_id, tenant_id=tenant_id)
        query = query.filter(Asset.site_id == site_id)
    if disposition:
        query = query.filter(Asset.disposition == disposition)
    if lifecycle_state:
        query = query.filter(Asset.lifecycle_state == lifecycle_state)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if expected is True:
        query = query.filter(Asset.is_expected.is_(True), Asset.first_seen.is_(None))
    if expected is False:
        query = query.filter(or_(Asset.is_expected.is_(False), Asset.first_seen.isnot(None)))
    if q:
        like = f"%{q}%"
        query = query.outerjoin(AssetIdentifier, AssetIdentifier.asset_id == Asset.id).outerjoin(
            AssetAddress, AssetAddress.asset_id == Asset.id
        )
        query = query.filter(
            or_(
                Asset.display_name.ilike(like),
                Asset.classification.ilike(like),
                Asset.description.ilike(like),
                AssetIdentifier.value.ilike(like),
                AssetAddress.ip.ilike(like),
            )
        ).distinct()
    assets = query.order_by(Asset.last_seen.desc().nullslast(), Asset.display_name, Asset.id).limit(1000).all()
    counts = _findings_count_map(db, [asset.id for asset in assets])
    return [_serialize_list_item(asset, counts.get(asset.id, 0)) for asset in assets]


@router.get("/tenants/{tenant_id}/assets/export")
def export_assets(tenant_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    get_tenant(db, tenant_id)
    assets = (
        db.query(Asset)
        .options(selectinload(Asset.site), selectinload(Asset.tags), selectinload(Asset.addresses))
        .filter(Asset.tenant_id == tenant_id)
        .order_by(Asset.display_name, Asset.id)
        .all()
    )
    lines = [
        "id,display_name,site,addresses,classification,lifecycle_state,disposition,criticality,expected,first_seen,last_seen,tags"
    ]
    for asset in assets:
        lines.append(
            ",".join(
                [
                    str(asset.id),
                    _csv(asset.display_name),
                    _csv(asset.site.name if asset.site else ""),
                    _csv(";".join(_current_addresses(asset))),
                    _csv(asset.classification),
                    asset.lifecycle_state or "",
                    asset.disposition,
                    asset.criticality,
                    "yes" if asset.is_expected and asset.first_seen is None else "no",
                    asset.first_seen.isoformat() if asset.first_seen else "",
                    asset.last_seen.isoformat() if asset.last_seen else "",
                    _csv(";".join(tag.name for tag in asset.tags)),
                ]
            )
        )
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/csv")


@router.post("/tenants/{tenant_id}/assets", response_model=AssetDetail)
def create_expected_asset(
    tenant_id: int,
    body: AssetCreate,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    get_tenant(db, tenant_id)
    site = get_site(db, body.site_id, tenant_id=tenant_id)
    if site.tenant_id != tenant_id:
        raise HTTPException(status_code=400, detail="Site does not belong to this tenant")
    if body.classification not in DEVICE_CLASSES:
        raise HTTPException(status_code=400, detail="Invalid classification")
    try:
        disposition = validate_disposition(body.disposition)
        criticality = validate_criticality(body.criticality)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = utcnow()
    asset = Asset(
        tenant_id=tenant_id,
        site_id=site.id,
        display_name=body.display_name.strip(),
        classification=body.classification,
        description=body.description or "",
        lifecycle_state=None,
        disposition=disposition,
        criticality=criticality,
        is_expected=True,
        first_seen=None,
        last_seen=None,
        updated_at=now,
    )
    db.add(asset)
    db.flush()
    if body.hostname.strip():
        upsert_identifier(
            db, asset, IDENTIFIER_HOSTNAME, body.hostname, source=SOURCE_MANUAL, seen_at=None
        )
        row = (
            db.query(AssetIdentifier)
            .filter(
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.identifier_type == IDENTIFIER_HOSTNAME,
                AssetIdentifier.normalized_value == normalize_identifier(IDENTIFIER_HOSTNAME, body.hostname),
            )
            .first()
        )
        if row is not None:
            row.first_seen = None
            row.last_seen = None
    if body.mac.strip():
        upsert_identifier(db, asset, IDENTIFIER_MAC, body.mac, source=SOURCE_MANUAL, seen_at=None)
        row = (
            db.query(AssetIdentifier)
            .filter(
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.identifier_type == IDENTIFIER_MAC,
            )
            .first()
        )
        if row is not None:
            row.first_seen = None
            row.last_seen = None
    if body.ip.strip():
        upsert_address(
            db,
            asset,
            body.ip,
            site_id=site.id,
            network_id=None,
            source=SOURCE_MANUAL,
            seen_at=now,
        )
        addr = (
            db.query(AssetAddress)
            .filter(AssetAddress.asset_id == asset.id, AssetAddress.ip == body.ip.strip())
            .first()
        )
        if addr is not None:
            addr.first_seen = None
            addr.last_seen = None
    for name in body.tags:
        try:
            assign_tag(asset, get_or_create_tag(db, tenant_id, name))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        db,
        actor=user,
        action="asset.manual_create",
        object_type="asset",
        object_id=asset.id,
        tenant_id=tenant_id,
        site_id=site.id,
        details={"display_name": asset.display_name, "hostname": body.hostname, "ip": body.ip},
    )
    from app.policy import apply_asset_handling

    apply_asset_handling(db, asset)
    db.commit()
    return get_asset(asset.id, user, db)


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int, _: User = Depends(require_any), db: Session = Depends(get_db)):
    asset = (
        db.query(Asset)
        .options(
            selectinload(Asset.site),
            selectinload(Asset.tags),
            selectinload(Asset.addresses),
            selectinload(Asset.identifiers),
            selectinload(Asset.services),
            selectinload(Asset.devices),
        )
        .filter(Asset.id == asset_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    device_ids = [device.id for device in asset.devices]
    findings: list[Finding] = []
    if device_ids:
        findings = (
            db.query(Finding)
            .filter(Finding.device_id.in_(device_ids))
            .order_by(Finding.found_at.desc())
            .limit(200)
            .all()
        )
    item = AssetDetail(**_serialize_list_item(asset, len(findings)).model_dump())
    item.identifiers = [AssetIdentifierOut.model_validate(row) for row in asset.identifiers]
    item.addresses = [AssetAddressOut.model_validate(row) for row in asset.addresses]
    item.services = [AssetServiceOut.model_validate(row) for row in asset.services]
    item.device_ids = device_ids
    item.findings = [_finding_out(finding) for finding in findings]
    latest = (
        db.query(AssetCorrelationDecision)
        .filter(AssetCorrelationDecision.selected_asset_id == asset.id)
        .order_by(AssetCorrelationDecision.created_at.desc())
        .first()
    )
    item.latest_correlation = CorrelationDecisionOut.model_validate(latest) if latest else None
    if latest and latest.decision == "ambiguous":
        item.possible_matches = latest.candidates or []
    item.recent_events = [
        DomainEventOut.model_validate(row)
        for row in (
            db.query(DomainEvent)
            .filter(DomainEvent.asset_id == asset.id)
            .order_by(DomainEvent.occurred_at.desc())
            .limit(20)
            .all()
        )
    ]
    return item


@router.patch("/assets/{asset_id}", response_model=AssetDetail)
def update_asset(
    asset_id: int,
    body: AssetUpdate,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    before = {
        "display_name": asset.display_name,
        "classification": asset.classification,
        "description": asset.description,
        "lifecycle_state": asset.lifecycle_state,
        "disposition": asset.disposition,
        "criticality": asset.criticality,
    }
    metadata_changed = False
    if body.display_name is not None:
        name = body.display_name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Display name is required")
        asset.display_name = name
        metadata_changed = True
    if body.classification is not None:
        if body.classification not in DEVICE_CLASSES:
            raise HTTPException(status_code=400, detail="Invalid classification")
        asset.classification = body.classification
        sync_linked_devices(asset, classification=body.classification)
        metadata_changed = True
    if body.description is not None:
        asset.description = body.description
        sync_linked_devices(asset, description=body.description)
        metadata_changed = True
    if body.lifecycle_state is not None:
        try:
            asset.lifecycle_state = validate_lifecycle(body.lifecycle_state)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        metadata_changed = True
    if body.disposition is not None:
        try:
            new_disposition = validate_disposition(body.disposition)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if new_disposition != asset.disposition:
            previous = asset.disposition
            asset.disposition = new_disposition
            record_audit(
                db,
                actor=user,
                action="asset.disposition_change",
                object_type="asset",
                object_id=asset.id,
                tenant_id=asset.tenant_id,
                site_id=asset.site_id,
                details={"before": previous, "after": new_disposition},
            )
    if body.criticality is not None:
        try:
            new_criticality = validate_criticality(body.criticality)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if new_criticality != asset.criticality:
            previous = asset.criticality
            asset.criticality = new_criticality
            from app.intel.priority import recalculate_priorities_for_assets

            recalculate_priorities_for_assets(db, [asset.id])
            record_audit(
                db,
                actor=user,
                action="asset.criticality_change",
                object_type="asset",
                object_id=asset.id,
                tenant_id=asset.tenant_id,
                site_id=asset.site_id,
                details={"before": previous, "after": new_criticality},
            )
    asset.updated_at = utcnow()
    if metadata_changed:
        record_audit(
            db,
            actor=user,
            action="asset.metadata_update",
            object_type="asset",
            object_id=asset.id,
            tenant_id=asset.tenant_id,
            site_id=asset.site_id,
            details={"before": before, "after": {
                "display_name": asset.display_name,
                "classification": asset.classification,
                "description": asset.description,
                "lifecycle_state": asset.lifecycle_state,
                "disposition": asset.disposition,
                "criticality": asset.criticality,
            }},
        )
    db.commit()
    return get_asset(asset.id, user, db)


@router.post("/assets/{asset_id}/tags", response_model=AssetDetail)
def add_asset_tag(
    asset_id: int,
    body: TagAssignIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    tag = _resolve_tag(db, asset.tenant_id, body)
    try:
        assign_tag(asset, tag)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if tag.normalized_name == "cui":
        from app.intel.priority import recalculate_priorities_for_assets

        recalculate_priorities_for_assets(db, [asset.id])
    record_audit(
        db,
        actor=user,
        action="asset.tag_change",
        object_type="asset",
        object_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        details={"op": "add", "tag_id": tag.id, "name": tag.name},
    )
    from app.policy import apply_asset_handling

    apply_asset_handling(db, asset)
    db.commit()
    return get_asset(asset.id, user, db)


@router.delete("/assets/{asset_id}/tags/{tag_id}", response_model=AssetDetail)
def delete_asset_tag(
    asset_id: int,
    tag_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    tag = db.query(Tag).filter(Tag.id == tag_id, Tag.tenant_id == asset.tenant_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    remove_tag(asset, tag)
    if tag.normalized_name == "cui":
        from app.intel.priority import recalculate_priorities_for_assets

        recalculate_priorities_for_assets(db, [asset.id])
    record_audit(
        db,
        actor=user,
        action="asset.tag_change",
        object_type="asset",
        object_id=asset.id,
        tenant_id=asset.tenant_id,
        site_id=asset.site_id,
        details={"op": "remove", "tag_id": tag.id, "name": tag.name},
    )
    from app.policy import apply_asset_handling

    apply_asset_handling(db, asset)
    db.commit()
    return get_asset(asset.id, user, db)


@router.get("/assets/{asset_id}/identifiers", response_model=HistoryPage)
def list_identifiers(
    asset_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id),
        AssetIdentifier.last_seen.desc().nullslast(),
        AssetIdentifierOut,
        limit,
        offset,
    )


@router.get("/assets/{asset_id}/addresses", response_model=HistoryPage)
def list_addresses(
    asset_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(AssetAddress).filter(AssetAddress.asset_id == asset.id),
        AssetAddress.last_seen.desc().nullslast(),
        AssetAddressOut,
        limit,
        offset,
    )


@router.get("/assets/{asset_id}/services", response_model=HistoryPage)
def list_services(
    asset_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(AssetService).filter(AssetService.asset_id == asset.id),
        AssetService.last_seen.desc().nullslast(),
        AssetServiceOut,
        limit,
        offset,
    )


@router.get("/assets/{asset_id}/correlation", response_model=HistoryPage)
def list_correlation(
    asset_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(AssetCorrelationDecision).filter(AssetCorrelationDecision.selected_asset_id == asset.id),
        AssetCorrelationDecision.created_at.desc(),
        CorrelationDecisionOut,
        limit,
        offset,
    )


@router.get("/assets/{asset_id}/events", response_model=HistoryPage)
def list_events(
    asset_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(DomainEvent).filter(DomainEvent.asset_id == asset.id),
        DomainEvent.occurred_at.desc(),
        DomainEventOut,
        limit,
        offset,
    )


@router.post("/assets/{asset_id}/merge", response_model=AssetDetail)
def merge_asset(
    asset_id: int,
    body: AssetMergeIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    target = _get_asset(db, asset_id)
    try:
        merge_assets(
            db,
            target=target,
            source_ids=body.source_asset_ids,
            actor=user,
            reason=body.reason,
        )
    except IdentityError as exc:
        raise identity_http_error(exc) from exc
    db.commit()
    return get_asset(target.id, user, db)


@router.post("/assets/{asset_id}/split", response_model=AssetDetail)
def split_asset(
    asset_id: int,
    body: AssetSplitIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    source = _get_asset(db, asset_id)
    try:
        target = split_observations_to_new_asset(
            db,
            source=source,
            observation_ids=body.observation_ids,
            actor=user,
            reason=body.reason,
        )
    except IdentityError as exc:
        raise identity_http_error(exc) from exc
    db.commit()
    return get_asset(target.id, user, db)


@router.post("/assets/{asset_id}/observations/{observation_id}/reassociate", response_model=AssetDetail)
def reassociate_observation(
    asset_id: int,
    observation_id: int,
    body: AssetReassociateIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    source = _get_asset(db, asset_id)
    target = _get_asset(db, body.target_asset_id)
    try:
        reassociate_observations(
            db,
            source=source,
            target=target,
            observation_ids=[observation_id],
            actor=user,
            reason=body.reason,
        )
    except IdentityError as exc:
        raise identity_http_error(exc) from exc
    db.commit()
    return get_asset(target.id, user, db)


@router.post("/assets/{asset_id}/identifiers/{identifier_id}/correct", response_model=AssetDetail)
def correct_asset_identifier(
    asset_id: int,
    identifier_id: int,
    body: AssetIdentifierCorrectIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    identifier = db.get(AssetIdentifier, identifier_id)
    if identifier is None or identifier.asset_id != asset.id:
        raise HTTPException(status_code=404, detail="Identifier not found")
    try:
        correct_identifier(
            db,
            asset=asset,
            identifier=identifier,
            actor=user,
            reason=body.reason,
            replacement_value=body.replacement_value,
            replacement_type=body.replacement_type,
        )
    except IdentityError as exc:
        raise identity_http_error(exc) from exc
    db.commit()
    return get_asset(asset.id, user, db)


@router.post("/assets/{asset_id}/move-site", response_model=AssetDetail)
def move_site(
    asset_id: int,
    body: AssetMoveSiteIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    try:
        move_asset_site(db, asset=asset, site_id=body.site_id, actor=user, reason=body.reason)
    except IdentityError as exc:
        raise identity_http_error(exc) from exc
    db.commit()
    return get_asset(asset.id, user, db)


@router.get("/assets/{asset_id}/observations", response_model=HistoryPage)
def list_observations(
    asset_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    return _page(
        db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id),
        AssetObservation.observed_at.desc(),
        AssetObservationOut,
        limit,
        offset,
    )


def _page(query, order, schema, limit: int, offset: int) -> HistoryPage:
    total = query.count()
    rows = query.order_by(order).offset(offset).limit(limit).all()
    return HistoryPage(items=[schema.model_validate(row) for row in rows], total=total, limit=limit, offset=offset)


def _resolve_tag(db: Session, tenant_id: int, body: TagAssignIn) -> Tag:
    if body.tag_id is not None:
        tag = db.query(Tag).filter(Tag.id == body.tag_id).first()
        if not tag or tag.tenant_id != tenant_id:
            raise HTTPException(status_code=400, detail="Tag does not belong to this tenant")
        return tag
    if body.name:
        try:
            return get_or_create_tag(db, tenant_id, body.name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="tag_id or name is required")


def _csv(value: str) -> str:
    text = (value or "").replace('"', '""')
    return f'"{text}"'
