from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import can_access_tenant, is_internal_operator, require_object_tenant, require_visible_tenant
from app.auth import require_any, require_user
from app.database import get_db
from app.locality import get_tenant
from app.models import (
    POLICY_CATEGORIES,
    POLICY_SCOPES,
    Asset,
    AssetFinding,
    PolicyRule,
    User,
)
from app.policy import (
    PolicyError,
    PolicyResolver,
    archive_policy,
    context_for_findings,
    contexts_for_assets,
    create_policy,
    evaluate_draft,
    get_policy,
    list_policies,
    serialize_evaluation,
    set_policy_enabled,
    update_policy,
)
from app.schemas import PolicyArchiveIn, PolicyEvaluationOut, PolicyIn, PolicyOut, PolicyPreviewIn, PolicyUpdateIn

router = APIRouter(tags=["policies"])


def _http(exc: PolicyError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def serialize_policy(row: PolicyRule) -> PolicyOut:
    return PolicyOut(
        id=row.id,
        name=row.name,
        description=row.description or "",
        category=row.category,
        scope_type=row.scope_type,
        tenant_id=row.tenant_id,
        site_id=row.site_id,
        network_id=row.network_id,
        tenant_name=row.tenant.name if row.tenant else ("GLOBAL" if row.scope_type == "global" else None),
        site_name=row.site.name if row.site else None,
        network_name=row.network.name if row.network else None,
        priority=row.priority,
        enabled=row.enabled,
        conditions=list(row.conditions or []),
        actions=dict(row.actions or {}),
        revision=row.revision,
        created_by_user_id=row.created_by_user_id,
        updated_by_user_id=row.updated_by_user_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
        archived_at=row.archived_at,
        archived_by_user_id=row.archived_by_user_id,
        archive_reason=row.archive_reason,
    )


def _payload(body: PolicyIn | PolicyPreviewIn) -> dict:
    return {
        "name": body.name,
        "description": body.description,
        "category": body.category,
        "scope_type": body.scope_type,
        "tenant_id": body.tenant_id,
        "site_id": body.site_id,
        "network_id": body.network_id,
        "priority": body.priority,
        "conditions": [item.model_dump() for item in body.conditions],
        "actions": body.actions,
    }


@router.get("/policies", response_model=list[PolicyOut])
def api_list_policies(
    category: str | None = None,
    scope_type: str | None = None,
    tenant_id: int | None = None,
    site_id: int | None = None,
    network_id: int | None = None,
    enabled: bool | None = None,
    include_archived: bool = False,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    if category and category not in POLICY_CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid category")
    if scope_type and scope_type not in POLICY_SCOPES:
        raise HTTPException(status_code=400, detail="Invalid scope_type")
    if tenant_id is not None:
        require_visible_tenant(db, user, tenant_id)
    rows = list_policies(
        db,
        category=category,
        scope_type=scope_type,
        tenant_id=tenant_id,
        site_id=site_id,
        network_id=network_id,
        enabled=enabled,
        include_archived=include_archived,
    )
    if not is_internal_operator(user):
        rows = [row for row in rows if row.tenant_id is not None and can_access_tenant(db, user, row.tenant_id)]
    return [serialize_policy(row) for row in rows]


@router.get("/policies/{policy_id}", response_model=PolicyOut)
def api_get_policy(policy_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    try:
        row = get_policy(db, policy_id)
        if not is_internal_operator(user):
            require_object_tenant(db, user, row, tenant_id=row.tenant_id, detail="Policy not found")
        return serialize_policy(row)
    except PolicyError as exc:
        raise _http(exc) from exc


@router.post("/policies", response_model=PolicyOut)
def api_create_policy(body: PolicyIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        row = create_policy(db, actor=user, payload=_payload(body))
        db.commit()
        db.refresh(row)
        return serialize_policy(get_policy(db, row.id))
    except PolicyError as exc:
        db.rollback()
        raise _http(exc) from exc


@router.patch("/policies/{policy_id}", response_model=PolicyOut)
def api_update_policy(
    policy_id: int,
    body: PolicyUpdateIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    try:
        row = get_policy(db, policy_id)
        changes = body.model_dump(exclude_unset=True)
        if "conditions" in changes and changes["conditions"] is not None:
            changes["conditions"] = [item if isinstance(item, dict) else item for item in changes["conditions"]]
        update_policy(db, actor=user, row=row, changes=changes)
        db.commit()
        return serialize_policy(get_policy(db, policy_id))
    except PolicyError as exc:
        db.rollback()
        raise _http(exc) from exc


@router.post("/policies/{policy_id}/enable", response_model=PolicyOut)
def api_enable_policy(policy_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        row = set_policy_enabled(db, actor=user, row=get_policy(db, policy_id), enabled=True)
        db.commit()
        return serialize_policy(get_policy(db, row.id))
    except PolicyError as exc:
        db.rollback()
        raise _http(exc) from exc


@router.post("/policies/{policy_id}/disable", response_model=PolicyOut)
def api_disable_policy(policy_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        row = set_policy_enabled(db, actor=user, row=get_policy(db, policy_id), enabled=False)
        db.commit()
        return serialize_policy(get_policy(db, row.id))
    except PolicyError as exc:
        db.rollback()
        raise _http(exc) from exc


@router.post("/policies/{policy_id}/archive", response_model=PolicyOut)
def api_archive_policy(
    policy_id: int,
    body: PolicyArchiveIn | None = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    try:
        row = archive_policy(db, actor=user, row=get_policy(db, policy_id), reason=(body.reason if body else ""))
        db.commit()
        return serialize_policy(get_policy(db, row.id, include_archived=True))
    except PolicyError as exc:
        db.rollback()
        raise _http(exc) from exc


@router.get("/tenants/{tenant_id}/assets/{asset_id}/policy-evaluation", response_model=dict)
def api_asset_policy_evaluation(
    tenant_id: int,
    asset_id: int,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    require_visible_tenant(db, user, tenant_id)
    asset = db.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    resolver = PolicyResolver(db)
    context = contexts_for_assets(db, [asset])[asset.id]
    handling = serialize_evaluation(resolver.evaluate(context, "asset_handling"))
    inactivity = serialize_evaluation(resolver.evaluate(context, "asset_inactivity"))
    return {
        "asset_id": asset.id,
        "tenant_id": asset.tenant_id,
        "site_id": context.site_id,
        "network_id": context.network_id,
        "current": {
            "classification": asset.classification,
            "disposition": asset.disposition,
        },
        "effective": {
            "classification": handling["effective"]["classification"],
            "disposition": handling["effective"]["disposition"],
            "inactive_after_days": inactivity["effective"]["inactive_after_days"],
        },
        "actions": {**handling["actions"], **inactivity["actions"]},
        "matched_rules": handling["matched_rules"] + inactivity["matched_rules"],
        "handling": handling,
        "inactivity": inactivity,
    }


@router.get("/tenants/{tenant_id}/asset-findings/{asset_finding_id}/policy-evaluation", response_model=dict)
def api_finding_policy_evaluation(
    tenant_id: int,
    asset_finding_id: int,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    require_visible_tenant(db, user, tenant_id)
    finding = db.get(AssetFinding, asset_finding_id)
    if finding is None or finding.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset finding not found")
    resolver = PolicyResolver(db)
    contexts = context_for_findings(db, [finding])
    context = contexts[finding.id]
    result = serialize_evaluation(resolver.evaluate(context, "finding_lifecycle"))
    result["current"] = {"consecutive_clean_scans": finding.consecutive_clean_scans}
    return result


@router.post("/policies/preview", response_model=dict)
def api_preview_policy(body: PolicyPreviewIn, user: User = Depends(require_any), db: Session = Depends(get_db)):
    try:
        if body.asset_finding_id is not None:
            finding = db.get(AssetFinding, body.asset_finding_id)
            require_object_tenant(
                db,
                user,
                finding,
                tenant_id=finding.tenant_id if finding else None,
                detail="Asset finding not found",
            )
            context = context_for_findings(db, [finding])[finding.id]
        elif body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            require_object_tenant(
                db, user, asset, tenant_id=asset.tenant_id if asset else None, detail="Asset not found"
            )
            context = contexts_for_assets(db, [asset])[asset.id]
        else:
            raise HTTPException(status_code=400, detail="asset_id or asset_finding_id is required")
        result = evaluate_draft(db, draft=_payload(body), context=context)
        return serialize_evaluation(result)
    except PolicyError as exc:
        raise _http(exc) from exc
