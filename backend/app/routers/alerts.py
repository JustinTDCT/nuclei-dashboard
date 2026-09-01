from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from app.access import apply_tenant_scope, require_object_tenant, require_tenant_access
from app.alert_engine import delivery_summary_map, evaluate_event_alert_policy
from app.audit import record_audit
from app.auth import require_any, require_user
from app.database import get_db
from app.models import EVENT_TYPE_LABELS, Alert, DomainEvent, User
from app.pagination import LIST_PAGE_DEFAULT, LIST_PAGE_MAX, as_page, paginate_query
from app.schemas import AlertDetailOut, AlertDeliveryOut, AlertOut, HistoryPage

router = APIRouter(prefix="/alerts", tags=["alerts"])
events_router = APIRouter(prefix="/events", tags=["events"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_alert(row: Alert, summary: dict | None = None) -> AlertOut:
    return AlertOut(
        id=row.id,
        tenant_id=row.tenant_id,
        type=row.type,
        title=row.title,
        body=row.body,
        is_acknowledged=row.is_acknowledged,
        device_id=row.device_id,
        agent_id=row.agent_id,
        created_at=row.created_at,
        severity=row.severity,
        site_id=row.site_id,
        network_id=row.network_id,
        asset_id=row.asset_id,
        asset_finding_id=row.asset_finding_id,
        domain_event_id=row.domain_event_id,
        dashboard_visible=True if row.dashboard_visible is None else bool(row.dashboard_visible),
        occurrence_count=row.occurrence_count or 1,
        first_event_at=row.first_event_at,
        last_event_at=row.last_event_at,
        tenant_name=row.tenant.name if row.tenant else None,
        site_name=row.site.name if row.site else None,
        event_type_label=EVENT_TYPE_LABELS.get(row.type, row.type),
        delivery_summary=summary,
    )


def _visible_query(db: Session):
    return db.query(Alert).options(selectinload(Alert.tenant), selectinload(Alert.site)).filter(
        Alert.dashboard_visible.is_(True)
    )


@router.get("", response_model=HistoryPage)
def list_alerts(
    tenant_id: int | None = None,
    open_only: bool = False,
    severity: str | None = None,
    event_type: str | None = None,
    type: str | None = None,
    limit: int = Query(default=LIST_PAGE_DEFAULT, ge=1, le=LIST_PAGE_MAX),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    query = apply_tenant_scope(_visible_query(db), user, Alert.tenant_id)
    if tenant_id:
        require_tenant_access(db, user, tenant_id)
        query = query.filter(Alert.tenant_id == tenant_id)
    if open_only:
        query = query.filter(Alert.is_acknowledged.is_(False))
    if severity:
        query = query.filter(Alert.severity == severity)
    kind = event_type or type
    if kind:
        query = query.filter(Alert.type == kind)
    total, rows = paginate_query(
        query,
        order_by=(Alert.created_at.desc(), Alert.id.desc()),
        limit=limit,
        offset=offset,
    )
    summaries = delivery_summary_map(db, [row.id for row in rows])
    return as_page(
        [_serialize_alert(row, summaries.get(row.id)) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert(alert_id: int, user: User = Depends(require_any), db: Session = Depends(get_db)):
    row = (
        db.query(Alert)
        .options(
            selectinload(Alert.tenant),
            selectinload(Alert.site),
            selectinload(Alert.deliveries),
            selectinload(Alert.source_event),
        )
        .filter(Alert.id == alert_id)
        .first()
    )
    require_object_tenant(db, user, row, tenant_id=row.tenant_id if row else None, detail="Alert not found")
    summaries = delivery_summary_map(db, [row.id])
    base = _serialize_alert(row, summaries.get(row.id))
    event = row.source_event
    source_event = None
    if event is not None:
        source_event = {
            "id": event.id,
            "event_type": event.event_type,
            "event_type_label": EVENT_TYPE_LABELS.get(event.event_type, event.event_type),
            "occurred_at": event.occurred_at,
            "tenant_id": event.tenant_id,
            "site_id": event.site_id,
            "network_id": event.network_id,
            "source": event.source,
        }
    return AlertDetailOut(
        **base.model_dump(),
        policy_explanation=row.policy_explanation,
        source_event=source_event,
        deliveries=[
            AlertDeliveryOut(
                id=item.id,
                channel=item.channel,
                destination=item.destination,
                status=item.status,
                attempt_count=item.attempt_count,
                last_attempt_at=item.last_attempt_at,
                delivered_at=item.delivered_at,
                last_error=item.last_error,
                response_status=item.response_status,
            )
            for item in row.deliveries
        ],
        acknowledged_at=row.acknowledged_at,
        acknowledged_by_id=row.acknowledged_by_id,
    )


@router.post("/{alert_id}/ack", response_model=AlertOut)
def ack_alert(alert_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    alert = db.query(Alert).options(selectinload(Alert.tenant), selectinload(Alert.site)).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.is_acknowledged:
        return _serialize_alert(alert)
    alert.is_acknowledged = True
    alert.acknowledged_at = _now()
    alert.acknowledged_by_id = user.id
    record_audit(
        db,
        actor=user,
        action="alert.acknowledged",
        object_type="alert",
        object_id=alert.id,
        tenant_id=alert.tenant_id,
        site_id=alert.site_id,
        details={"alert_id": alert.id, "type": alert.type, "severity": alert.severity},
    )
    db.commit()
    db.refresh(alert)
    return _serialize_alert(alert)


@router.post("/ack-all")
def ack_all(
    tenant_id: int | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    type: str | None = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.is_acknowledged.is_(False), Alert.dashboard_visible.is_(True))
    if tenant_id:
        query = query.filter(Alert.tenant_id == tenant_id)
    if severity:
        query = query.filter(Alert.severity == severity)
    kind = event_type or type
    if kind:
        query = query.filter(Alert.type == kind)
    now = _now()
    updated = query.update(
        {
            Alert.is_acknowledged: True,
            Alert.acknowledged_at: now,
            Alert.acknowledged_by_id: user.id,
        },
        synchronize_session=False,
    )
    if updated:
        record_audit(
            db,
            actor=user,
            action="alert.acknowledged_all",
            object_type="alert",
            tenant_id=tenant_id,
            details={
                "updated": updated,
                "tenant_id": tenant_id,
                "severity": severity,
                "event_type": kind,
            },
        )
    db.commit()
    return {"updated": updated}


@events_router.get("/{event_id}/alert-policy-evaluation")
def event_alert_policy_evaluation(
    event_id: int,
    user: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    event = db.get(DomainEvent, event_id)
    require_object_tenant(
        db, user, event, tenant_id=event.tenant_id if event else None, detail="Event not found"
    )
    evaluation = evaluate_event_alert_policy(db, event)
    return {
        "event": {
            "id": event.id,
            "event_type": event.event_type,
            "event_type_label": EVENT_TYPE_LABELS.get(event.event_type, event.event_type),
            "occurred_at": event.occurred_at,
            "tenant_id": event.tenant_id,
            "site_id": event.site_id,
            "network_id": event.network_id,
            "asset_id": event.asset_id,
            "source": event.source,
        },
        **evaluation,
        "dedupe_key": None,
        "suppression": evaluation.get("effective", {}).get("suppress_for_minutes", 0),
    }
