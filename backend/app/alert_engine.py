"""Phase 3B alert routing and outbound delivery.

Domain transactions emit DomainEvent + queue rows only. This module
claims pending work, evaluates alert policy, projects Alerts, and
performs SMTP/webhook I/O in a separate step.
"""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from app.assets import utcnow
from app.emailer import MailDeliveryError, MailResult, admin_emails, deliver_mail, staff_emails
from app.models import (
    ALERT_DELIVERY_BATCH_SIZE,
    ALERT_EMAIL_ADMINS,
    ALERT_EMAIL_OFF,
    ALERT_EMAIL_STAFF,
    ALERT_QUEUE_FAILED,
    ALERT_QUEUE_PENDING,
    ALERT_QUEUE_PROCESSED,
    ALERT_QUEUE_PROCESSING,
    ALERT_ROUTE_BATCH_SIZE,
    ALERT_SEVERITY_HIGH,
    DELIVERY_CHANNEL_EMAIL,
    DELIVERY_CHANNEL_WEBHOOK,
    DELIVERY_FAILED,
    DELIVERY_PENDING,
    DELIVERY_PROCESSING,
    DELIVERY_SENT,
    EVENT_TYPE_LABELS,
    MAX_DELIVERY_ATTEMPTS,
    POLICY_CATEGORY_ALERTING,
    ROUTING_ALERT_COALESCED,
    ROUTING_ALERT_CREATED,
    ROUTING_NO_NOTIFICATION,
    Alert,
    AlertDelivery,
    AlertEventRoute,
    Asset,
    AssetFinding,
    DomainEvent,
    EventAlertQueue,
    FindingTreatment,
)
from app.policy import PolicyEvaluationContext, PolicyResolver, serialize_evaluation, system_default_alert_actions

log = logging.getLogger(__name__)

WEBHOOK_CONNECT_TIMEOUT = 5
WEBHOOK_READ_TIMEOUT = 10
WEBHOOK_MAX_BYTES = 64 * 1024
BACKOFF_SECONDS = (0, 60, 300, 900, 3600)


class WebhookDeliveryError(Exception):
    def __init__(self, detail: str, *, status_code: int | None = None, permanent: bool = False):
        self.detail = detail
        self.status_code = status_code
        self.permanent = permanent
        super().__init__(detail)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise WebhookDeliveryError(f"Redirect {code} is not followed", status_code=code, permanent=True)


def system_default_actions(event_type: str) -> dict[str, Any]:
    return system_default_alert_actions(event_type)


def webhook_url_from_action(value: Any) -> str | None:
    if not isinstance(value, dict) or not value.get("enabled"):
        return None
    url = str(value.get("url") or "").strip()
    return url or None


def logical_subject(event: DomainEvent) -> tuple[str, str]:
    if event.asset_finding_id:
        return "asset_finding", str(event.asset_finding_id)
    if event.asset_id:
        return "asset", str(event.asset_id)
    if event.agent_id:
        return "agent", str(event.agent_id)
    if event.scan_job_id:
        return "scan_job", str(event.scan_job_id)
    if event.treatment_id:
        return "treatment", str(event.treatment_id)
    if event.policy_rule_id:
        return "policy", str(event.policy_rule_id)
    details = event.details or {}
    if details.get("wan_target_id"):
        return "wan_target", str(details["wan_target_id"])
    return "event", str(event.id)


def route_identity(actions: dict[str, Any]) -> str:
    webhook = webhook_url_from_action(actions.get("webhook")) or "off"
    return f"{actions.get('email', ALERT_EMAIL_OFF)}:{bool(actions.get('dashboard'))}:{webhook}"


def dedupe_key_for(event: DomainEvent, actions: dict[str, Any]) -> str:
    kind, subject_id = logical_subject(event)
    tenant = event.tenant_id if event.tenant_id is not None else "global"
    return f"{tenant}:{event.event_type}:{kind}:{subject_id}:{route_identity(actions)}"


def notification_enabled(actions: dict[str, Any]) -> bool:
    dashboard = bool(actions.get("dashboard"))
    email = actions.get("email") not in {None, ALERT_EMAIL_OFF}
    webhook = webhook_url_from_action(actions.get("webhook")) is not None
    return dashboard or email or webhook


def _safe_error(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    for needle in ("password", "secret", "token", "authorization", "apikey"):
        if needle in text.lower():
            return "delivery failed"
    return text[:400]


def contexts_for_events(db: Session, events: list[DomainEvent]) -> dict[int, PolicyEvaluationContext]:
    asset_ids = list({row.asset_id for row in events if row.asset_id})
    finding_ids = list({row.asset_finding_id for row in events if row.asset_finding_id})
    treatment_ids = list({row.treatment_id for row in events if row.treatment_id})
    assets = {
        row.id: row
        for row in db.query(Asset).options(selectinload(Asset.tags)).filter(Asset.id.in_(asset_ids)).all()
    } if asset_ids else {}
    findings = {
        row.id: row
        for row in db.query(AssetFinding)
        .options(selectinload(AssetFinding.vulnerability))
        .filter(AssetFinding.id.in_(finding_ids))
        .all()
    } if finding_ids else {}
    extra_asset_ids = [row.asset_id for row in findings.values() if row.asset_id not in assets]
    if extra_asset_ids:
        for row in db.query(Asset).options(selectinload(Asset.tags)).filter(Asset.id.in_(extra_asset_ids)).all():
            assets[row.id] = row
    treatments = {
        row.id: row
        for row in db.query(FindingTreatment).filter(FindingTreatment.id.in_(treatment_ids)).all()
    } if treatment_ids else {}
    from app.policy import contexts_for_assets, context_for_findings

    asset_contexts = contexts_for_assets(db, list(assets.values())) if assets else {}
    finding_contexts = context_for_findings(db, list(findings.values()), assets=list(assets.values())) if findings else {}
    contexts: dict[int, PolicyEvaluationContext] = {}
    for event in events:
        asset = assets.get(event.asset_id) if event.asset_id else None
        if asset is not None and event.tenant_id is not None and asset.tenant_id != event.tenant_id:
            raise ValueError("Cross-tenant event/asset relationship is not allowed")
        finding = findings.get(event.asset_finding_id) if event.asset_finding_id else None
        if finding is not None and event.tenant_id is not None and finding.tenant_id != event.tenant_id:
            raise ValueError("Cross-tenant event/finding relationship is not allowed")
        treatment = treatments.get(event.treatment_id) if event.treatment_id else None
        if treatment is not None and event.tenant_id is not None and treatment.tenant_id != event.tenant_id:
            raise ValueError("Cross-tenant event/treatment relationship is not allowed")
        base = None
        if finding is not None:
            base = finding_contexts.get(finding.id)
        elif asset is not None:
            base = asset_contexts.get(asset.id)
        site_id = event.site_id
        network_id = event.network_id if event.site_id is not None else None
        classification = asset.classification if asset is not None else "Unknown"
        disposition = asset.disposition if asset is not None else "unreviewed"
        criticality = asset.criticality if asset is not None else "normal"
        is_expected = bool(asset.is_expected) if asset is not None else False
        tags = frozenset(tag.normalized_name for tag in (asset.tags if asset is not None else []))
        severity = base.severity if base is not None else None
        priority = finding.priority if finding is not None else (base.priority if base is not None else None)
        has_cve = False
        if finding is not None and finding.vulnerability is not None:
            has_cve = bool(finding.vulnerability.cve_id)
        elif base is not None:
            has_cve = bool(base.has_cve)
        treatment_state = finding.treatment_state if finding is not None else None
        if treatment is not None:
            treatment_state = treatment.status
        contexts[event.id] = PolicyEvaluationContext(
            tenant_id=event.tenant_id,
            site_id=site_id,
            network_id=network_id,
            asset_id=event.asset_id,
            asset_finding_id=event.asset_finding_id,
            hostname=base.hostname if base is not None else (asset.display_name if asset is not None else ""),
            tags=tags if tags else (base.tags if base is not None else frozenset()),
            tag_names=base.tag_names if base is not None else (),
            criticality=criticality,
            is_expected=is_expected,
            observed_ports=base.observed_ports if base is not None else frozenset(),
            severity=severity,
            priority=priority,
            has_cve=has_cve,
            current_classification=classification,
            current_disposition=disposition,
            event_type=event.event_type,
            source=event.source,
            treatment_state=treatment_state,
            domain_event_id=event.id,
        )
    return contexts


def evaluate_event_alert_policy(
    db: Session,
    event: DomainEvent,
    *,
    resolver: PolicyResolver | None = None,
    context: PolicyEvaluationContext | None = None,
) -> dict[str, Any]:
    engine = resolver or PolicyResolver(db)
    if context is None:
        context = contexts_for_events(db, [event])[event.id]
    result = engine.evaluate(context, POLICY_CATEGORY_ALERTING)
    return serialize_evaluation(result)


def _title_for(event: DomainEvent) -> str:
    label = EVENT_TYPE_LABELS.get(event.event_type, event.event_type)
    details = event.details or {}
    name = details.get("display_name") or details.get("agent_name") or details.get("name")
    if name:
        return f"{label}: {name}"
    return label


def _body_for(event: DomainEvent) -> str:
    details = event.details or {}
    lines = [EVENT_TYPE_LABELS.get(event.event_type, event.event_type)]
    if details.get("reason"):
        lines.append(str(details["reason"]))
    if details.get("previous_disposition") and details.get("new_disposition"):
        lines.append(f"Disposition {details['previous_disposition']} → {details['new_disposition']}")
    if event.asset_id:
        lines.append(f"Asset #{event.asset_id}")
    if event.agent_id:
        lines.append(f"Agent #{event.agent_id}")
    if details.get("source_ip"):
        lines.append(f"Source IP: {details['source_ip']}")
    return "\n".join(lines)


def _claim_queue(db: Session, *, limit: int) -> list[EventAlertQueue]:
    now = utcnow()
    candidate_ids = (
        select(EventAlertQueue.id)
        .where(
            EventAlertQueue.status == ALERT_QUEUE_PENDING,
            EventAlertQueue.next_attempt_at <= now,
        )
        .order_by(EventAlertQueue.id.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = db.execute(
        update(EventAlertQueue)
        .where(EventAlertQueue.id.in_(candidate_ids))
        .values(status=ALERT_QUEUE_PROCESSING, updated_at=now, attempts=EventAlertQueue.attempts + 1)
        .returning(EventAlertQueue.id)
    ).scalars().all()
    if not rows:
        return []
    db.flush()
    return (
        db.query(EventAlertQueue)
        .options(selectinload(EventAlertQueue.domain_event))
        .filter(EventAlertQueue.id.in_(list(rows)))
        .order_by(EventAlertQueue.id.asc())
        .all()
    )


def _open_alert_for_dedupe(db: Session, *, tenant_id: int | None, key: str, window_minutes: int) -> Alert | None:
    query = db.query(Alert).filter(
        Alert.dedupe_key == key,
        Alert.is_acknowledged.is_(False),
    )
    if tenant_id is None:
        query = query.filter(Alert.tenant_id.is_(None))
    else:
        query = query.filter(Alert.tenant_id == tenant_id)
    if window_minutes <= 0:
        return None
    cutoff = utcnow() - timedelta(minutes=window_minutes)
    query = query.filter(Alert.last_event_at.isnot(None), Alert.last_event_at >= cutoff)
    return query.order_by(Alert.id.asc()).first()


def _enqueue_deliveries(db: Session, alert: Alert, event: DomainEvent, actions: dict[str, Any]) -> None:
    now = utcnow()
    email_mode = actions.get("email")
    if email_mode in {ALERT_EMAIL_STAFF, ALERT_EMAIL_ADMINS}:
        recipients = admin_emails(db) if email_mode == ALERT_EMAIL_ADMINS else staff_emails(db)
        destination = ",".join(recipients)
        existing = (
            db.query(AlertDelivery)
            .filter(AlertDelivery.alert_id == alert.id, AlertDelivery.channel == DELIVERY_CHANNEL_EMAIL)
            .first()
        )
        if existing is None:
            db.add(
                AlertDelivery(
                    alert_id=alert.id,
                    channel=DELIVERY_CHANNEL_EMAIL,
                    destination=destination,
                    status=DELIVERY_PENDING,
                    next_attempt_at=now,
                    payload_snapshot={
                        "alert_id": alert.id,
                        "domain_event_id": event.id,
                        "event_type": event.event_type,
                        "title": alert.title,
                        "mode": email_mode,
                    },
                    updated_at=now,
                )
            )
    webhook_url = webhook_url_from_action(actions.get("webhook"))
    if webhook_url:
        existing = (
            db.query(AlertDelivery)
            .filter(AlertDelivery.alert_id == alert.id, AlertDelivery.channel == DELIVERY_CHANNEL_WEBHOOK)
            .first()
        )
        if existing is None:
            db.add(
                AlertDelivery(
                    alert_id=alert.id,
                    channel=DELIVERY_CHANNEL_WEBHOOK,
                    destination=webhook_url,
                    status=DELIVERY_PENDING,
                    next_attempt_at=now,
                    payload_snapshot=safe_webhook_payload(event, alert),
                    updated_at=now,
                )
            )


def safe_webhook_payload(event: DomainEvent, alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.id,
        "domain_event_id": event.id,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "tenant_id": event.tenant_id,
        "site_id": event.site_id,
        "network_id": event.network_id,
        "asset_id": event.asset_id,
        "asset_finding_id": event.asset_finding_id,
        "scan_job_id": event.scan_job_id,
        "agent_id": event.agent_id,
        "severity": alert.severity,
        "title": alert.title,
        "occurrence_count": alert.occurrence_count,
    }


def _record_route(
    db: Session,
    *,
    event: DomainEvent,
    alert: Alert | None,
    result: str,
    actions: dict[str, Any],
    explanation: dict[str, Any],
) -> None:
    existing = db.query(AlertEventRoute).filter(AlertEventRoute.domain_event_id == event.id).first()
    if existing is not None:
        return
    db.add(
        AlertEventRoute(
            domain_event_id=event.id,
            alert_id=alert.id if alert is not None else None,
            routing_result=result,
            effective_actions=actions,
            policy_explanation=explanation,
            evaluated_at=utcnow(),
        )
    )


def route_pending_events(db: Session, *, limit: int = ALERT_ROUTE_BATCH_SIZE) -> int:
    claimed = _claim_queue(db, limit=limit)
    if not claimed:
        return 0
    events = [row.domain_event for row in claimed if row.domain_event is not None]
    already = {
        row.domain_event_id
        for row in db.query(AlertEventRoute.domain_event_id)
        .filter(AlertEventRoute.domain_event_id.in_([event.id for event in events]))
        .all()
    }
    resolver = PolicyResolver(db)
    contexts = contexts_for_events(db, [event for event in events if event.id not in already]) if events else {}
    processed = 0
    for item in claimed:
        event = item.domain_event
        now = utcnow()
        try:
            if event is None:
                item.status = ALERT_QUEUE_FAILED
                item.last_error = "missing domain event"
                item.updated_at = now
                continue
            if event.id in already:
                item.status = ALERT_QUEUE_PROCESSED
                item.processed_at = now
                item.updated_at = now
                processed += 1
                continue
            context = contexts[event.id]
            evaluation = resolver.evaluate(context, POLICY_CATEGORY_ALERTING)
            explanation = serialize_evaluation(evaluation)
            actions = dict(evaluation.effective)
            if not notification_enabled(actions):
                _record_route(
                    db,
                    event=event,
                    alert=None,
                    result=ROUTING_NO_NOTIFICATION,
                    actions=actions,
                    explanation=explanation,
                )
                item.status = ALERT_QUEUE_PROCESSED
                item.processed_at = now
                item.updated_at = now
                processed += 1
                continue
            key = dedupe_key_for(event, actions)
            suppress = int(actions.get("suppress_for_minutes") or 0)
            existing = _open_alert_for_dedupe(db, tenant_id=event.tenant_id, key=key, window_minutes=suppress)
            if existing is not None:
                existing.occurrence_count = int(existing.occurrence_count or 1) + 1
                existing.last_event_at = event.occurred_at
                existing.last_domain_event_id = event.id
                _record_route(
                    db,
                    event=event,
                    alert=existing,
                    result=ROUTING_ALERT_COALESCED,
                    actions=actions,
                    explanation=explanation,
                )
                item.status = ALERT_QUEUE_PROCESSED
                item.processed_at = now
                item.updated_at = now
                processed += 1
                continue
            alert = Alert(
                tenant_id=event.tenant_id,
                type=event.event_type[:40],
                title=_title_for(event),
                body=_body_for(event),
                agent_id=event.agent_id,
                domain_event_id=event.id,
                last_domain_event_id=event.id,
                severity=str(actions.get("severity") or ALERT_SEVERITY_HIGH),
                site_id=event.site_id,
                network_id=event.network_id,
                asset_id=event.asset_id,
                asset_finding_id=event.asset_finding_id,
                scan_job_id=event.scan_job_id,
                policy_explanation=explanation,
                dashboard_visible=bool(actions.get("dashboard")),
                dedupe_key=key,
                occurrence_count=1,
                first_event_at=event.occurred_at,
                last_event_at=event.occurred_at,
            )
            db.add(alert)
            db.flush()
            _enqueue_deliveries(db, alert, event, actions)
            _record_route(
                db,
                event=event,
                alert=alert,
                result=ROUTING_ALERT_CREATED,
                actions=actions,
                explanation=explanation,
            )
            item.status = ALERT_QUEUE_PROCESSED
            item.processed_at = now
            item.updated_at = now
            processed += 1
        except Exception as exc:  # noqa: BLE001 — route failure must not roll back domain facts
            log.exception("Alert routing failed for queue %s", item.id)
            item.status = ALERT_QUEUE_PENDING if item.attempts < MAX_DELIVERY_ATTEMPTS else ALERT_QUEUE_FAILED
            item.last_error = _safe_error(exc)
            item.next_attempt_at = now + timedelta(seconds=BACKOFF_SECONDS[min(item.attempts, len(BACKOFF_SECONDS) - 1)])
            item.updated_at = now
    db.flush()
    return processed


def post_webhook(url: str, payload: dict[str, Any]) -> int:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebhookDeliveryError("Webhook URL must use http or https", permanent=True)
    if parsed.username or parsed.password:
        raise WebhookDeliveryError("Webhook URL must not contain credentials", permanent=True)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "nuclei-dashboard-alert/3b"},
    )
    opener = urllib.request.build_opener(
        _NoRedirect,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=WEBHOOK_CONNECT_TIMEOUT + WEBHOOK_READ_TIMEOUT) as response:
            status = int(getattr(response, "status", 200) or 200)
            leftover = response.read(WEBHOOK_MAX_BYTES + 1)
            if len(leftover) > WEBHOOK_MAX_BYTES:
                raise WebhookDeliveryError("Webhook response exceeded size limit", status_code=status, permanent=True)
            if 200 <= status < 300:
                return status
            permanent = 400 <= status < 500 and status != 429
            raise WebhookDeliveryError(f"Webhook HTTP {status}", status_code=status, permanent=permanent)
    except WebhookDeliveryError:
        raise
    except urllib.error.HTTPError as exc:
        permanent = 400 <= int(exc.code) < 500 and int(exc.code) != 429
        raise WebhookDeliveryError(f"Webhook HTTP {exc.code}", status_code=int(exc.code), permanent=permanent) from exc
    except TimeoutError as exc:
        raise WebhookDeliveryError("Webhook timed out") from exc
    except OSError as exc:
        raise WebhookDeliveryError(_safe_error(exc)) from exc


def _claim_deliveries(db: Session, *, limit: int) -> list[AlertDelivery]:
    now = utcnow()
    candidate_ids = (
        select(AlertDelivery.id)
        .where(
            AlertDelivery.status == DELIVERY_PENDING,
            AlertDelivery.next_attempt_at <= now,
        )
        .order_by(AlertDelivery.id.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = db.execute(
        update(AlertDelivery)
        .where(AlertDelivery.id.in_(candidate_ids))
        .values(
            status=DELIVERY_PROCESSING,
            updated_at=now,
            last_attempt_at=now,
            attempt_count=AlertDelivery.attempt_count + 1,
        )
        .returning(AlertDelivery.id)
    ).scalars().all()
    if not rows:
        return []
    db.flush()
    return (
        db.query(AlertDelivery)
        .options(selectinload(AlertDelivery.alert))
        .filter(AlertDelivery.id.in_(list(rows)))
        .order_by(AlertDelivery.id.asc())
        .all()
    )


def _finish_delivery(row: AlertDelivery, *, success: bool, error: str | None, status_code: int | None, permanent: bool) -> None:
    now = utcnow()
    row.response_status = status_code
    row.last_error = error
    row.updated_at = now
    row.last_attempt_at = now
    if success:
        row.status = DELIVERY_SENT
        row.delivered_at = now
        return
    if permanent or row.attempt_count >= MAX_DELIVERY_ATTEMPTS:
        row.status = DELIVERY_FAILED
        return
    delay = BACKOFF_SECONDS[min(row.attempt_count, len(BACKOFF_SECONDS) - 1)]
    row.status = DELIVERY_PENDING
    row.next_attempt_at = now + timedelta(seconds=delay)


def process_pending_deliveries(
    db: Session,
    *,
    limit: int = ALERT_DELIVERY_BATCH_SIZE,
    webhook_post=post_webhook,
    mail_send=deliver_mail,
) -> int:
    claimed = _claim_deliveries(db, limit=limit)
    if not claimed:
        return 0
    db.commit()
    handled = 0
    for row in claimed:
        fresh = Session(bind=db.bind)
        try:
            delivery = fresh.get(AlertDelivery, row.id)
            if delivery is None:
                continue
            try:
                if delivery.channel == DELIVERY_CHANNEL_EMAIL:
                    recipients = [item.strip() for item in (delivery.destination or "").split(",") if item.strip()]
                    result: MailResult = mail_send(
                        fresh,
                        recipients,
                        delivery.alert.title if delivery.alert else "Nuclei Dashboard alert",
                        delivery.alert.body if delivery.alert else "",
                    )
                    if result.ok:
                        _finish_delivery(delivery, success=True, error=None, status_code=None, permanent=False)
                    else:
                        _finish_delivery(
                            delivery,
                            success=False,
                            error=result.error or "email failed",
                            status_code=None,
                            permanent=result.permanent,
                        )
                else:
                    payload = dict(delivery.payload_snapshot or {})
                    status = webhook_post(delivery.destination, payload)
                    _finish_delivery(delivery, success=True, error=None, status_code=status, permanent=False)
            except WebhookDeliveryError as exc:
                _finish_delivery(
                    delivery,
                    success=False,
                    error=_safe_error(exc),
                    status_code=exc.status_code,
                    permanent=exc.permanent,
                )
            except MailDeliveryError as exc:
                _finish_delivery(
                    delivery,
                    success=False,
                    error=_safe_error(exc),
                    status_code=None,
                    permanent=getattr(exc, "permanent", False),
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("Alert delivery %s failed", row.id)
                _finish_delivery(delivery, success=False, error=_safe_error(exc), status_code=None, permanent=False)
            fresh.commit()
            handled += 1
        finally:
            fresh.close()
    return handled


def route_pending_events_job() -> int:
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        processed = route_pending_events(db)
        db.commit()
        return processed
    except Exception:
        db.rollback()
        log.exception("Alert routing job failed")
        return 0
    finally:
        db.close()


def process_pending_deliveries_job() -> int:
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        handled = process_pending_deliveries(db)
        return handled
    except Exception:
        db.rollback()
        log.exception("Alert delivery job failed")
        return 0
    finally:
        db.close()


def delivery_summary_map(db: Session, alert_ids: list[int]) -> dict[int, dict[str, Any]]:
    if not alert_ids:
        return {}
    rows = (
        db.query(
            AlertDelivery.alert_id,
            AlertDelivery.channel,
            AlertDelivery.status,
            func.count(AlertDelivery.id),
        )
        .filter(AlertDelivery.alert_id.in_(alert_ids))
        .group_by(AlertDelivery.alert_id, AlertDelivery.channel, AlertDelivery.status)
        .all()
    )
    summaries: dict[int, dict[str, Any]] = {alert_id: {"email": None, "webhook": None, "failed": 0} for alert_id in alert_ids}
    for alert_id, channel, status, count in rows:
        item = summaries.setdefault(alert_id, {"email": None, "webhook": None, "failed": 0})
        item[channel] = status
        if status == DELIVERY_FAILED:
            item["failed"] += int(count)
    return summaries


__all__ = [
    "WebhookDeliveryError",
    "contexts_for_events",
    "dedupe_key_for",
    "delivery_summary_map",
    "evaluate_event_alert_policy",
    "logical_subject",
    "notification_enabled",
    "post_webhook",
    "process_pending_deliveries",
    "process_pending_deliveries_job",
    "route_pending_events",
    "route_pending_events_job",
    "safe_webhook_payload",
    "system_default_actions",
]
