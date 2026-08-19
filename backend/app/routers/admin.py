from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.access import (
    apply_tenant_scope,
    is_internal_operator,
    tenant_scope_clause,
    visible_tenant_query,
)
from app.audit import record_audit
from app.auth import require_admin, require_any
from app.database import get_db
from app.finding_lifecycle import open_finding_severity_counts
from app.intel.priority import open_finding_priority_counts
from app.intel.sync import intelligence_status, refresh_intelligence
from app.models import AGENT_HEALTH_SECONDS, Agent, Alert, AlertDelivery, AssetFinding, Device, ScanJob, Tenant, User
from app.scan_intensity import DEFAULT_CAPS
from app.schemas import DisplaySettingsOut, SettingsIn, SettingsOut
from app.scanner_versions import APPROVED_SETTING_KEYS
from app.settings_store import get_settings, save_settings
from app.timezones import list_iana_timezones, validate_iana_timezone

router = APIRouter(tags=["admin"])


@router.get("/admin/settings", response_model=SettingsOut)
def read_settings(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return SettingsOut(**get_settings(db))


@router.put("/admin/settings", response_model=SettingsOut)
def write_settings(body: SettingsIn, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    timezone = validate_iana_timezone(body.default_timezone)
    current = get_settings(db)
    payload = body.model_dump()
    payload["default_timezone"] = timezone
    saved = save_settings(db, payload)
    cap_keys = ("preferred_agent_grace_seconds", "agent_job_wait_minutes", *DEFAULT_CAPS)
    cap_changes = {
        key: {"before": current.get(key), "after": saved.get(key)}
        for key in cap_keys
        if current.get(key) != saved.get(key)
    }
    if current.get("default_timezone") != timezone:
        record_audit(
            db,
            actor=user,
            action="settings.timezone_change",
            object_type="settings",
            object_id=None,
            details={"before": current.get("default_timezone"), "after": timezone},
        )
    if cap_changes:
        record_audit(
            db,
            actor=user,
            action="settings.scan_limits_change",
            object_type="settings",
            object_id=None,
            details=cap_changes,
        )
    if current.get("raw_scan_artifact_retention_days") != saved.get("raw_scan_artifact_retention_days"):
        record_audit(
            db,
            actor=user,
            action="settings.raw_artifact_retention_change",
            object_type="settings",
            object_id=None,
            details={
                "before": current.get("raw_scan_artifact_retention_days"),
                "after": saved.get("raw_scan_artifact_retention_days"),
            },
        )
    version_changes = {
        key: {"before": current.get(key), "after": saved.get(key)}
        for key in APPROVED_SETTING_KEYS.values()
        if current.get(key) != saved.get(key)
    }
    if version_changes:
        record_audit(
            db,
            actor=user,
            action="settings.scanner_versions_change",
            object_type="settings",
            object_id=None,
            details=version_changes,
        )
    db.commit()
    return SettingsOut(**saved)


@router.get("/display-settings", response_model=DisplaySettingsOut)
def display_settings(_: User = Depends(require_any), db: Session = Depends(get_db)):
    return DisplaySettingsOut(default_timezone=get_settings(db).get("default_timezone") or "UTC")


@router.get("/admin/vulnerability-intelligence/status")
def vulnerability_intelligence_status(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return intelligence_status(db)


@router.post("/admin/vulnerability-intelligence/refresh")
def vulnerability_intelligence_refresh(
    source: str | None = None,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    sources = [source] if source else None
    return refresh_intelligence(db, sources=sources, force=True)


@router.get("/timezones")
def timezones(_: User = Depends(require_any)):
    return {"timezones": list_iana_timezones()}


@router.get("/dashboard")
def dashboard(user: User = Depends(require_any), db: Session = Depends(get_db)):
    alert_filter = tenant_scope_clause(user, Alert.tenant_id)
    device_filter = tenant_scope_clause(user, Device.tenant_id)
    finding_filter = tenant_scope_clause(user, AssetFinding.tenant_id)
    heartbeat_cut = datetime.now(timezone.utc) - timedelta(seconds=AGENT_HEALTH_SECONDS)
    pending = (
        apply_tenant_scope(db.query(func.count(Agent.id)), user, Agent.tenant_id)
        .filter(Agent.status == "pending_approval")
        .scalar()
        or 0
    )
    total_agents = apply_tenant_scope(db.query(func.count(Agent.id)), user, Agent.tenant_id).scalar() or 0
    online = (
        apply_tenant_scope(db.query(func.count(Agent.id)), user, Agent.tenant_id)
        .filter(Agent.status == "approved", Agent.last_heartbeat >= heartbeat_cut)
        .scalar()
        or 0
    )
    delivery_query = (
        db.query(func.count(AlertDelivery.id))
        .join(Alert, Alert.id == AlertDelivery.alert_id)
        .filter(AlertDelivery.status == "failed")
        .filter(alert_filter)
    )
    return {
        "tenants": visible_tenant_query(db, user).count(),
        "users": (db.query(func.count(User.id)).scalar() or 0) if is_internal_operator(user) else 0,
        "open_alerts": db.query(func.count(Alert.id)).filter(
            Alert.is_acknowledged.is_(False), Alert.dashboard_visible.is_(True), alert_filter
        ).scalar() or 0,
        "open_alerts_critical": db.query(func.count(Alert.id)).filter(
            Alert.is_acknowledged.is_(False),
            Alert.dashboard_visible.is_(True),
            Alert.severity == "critical",
            alert_filter,
        ).scalar() or 0,
        "open_alerts_high": db.query(func.count(Alert.id)).filter(
            Alert.is_acknowledged.is_(False),
            Alert.dashboard_visible.is_(True),
            Alert.severity == "high",
            alert_filter,
        ).scalar() or 0,
        "delivery_failures": delivery_query.scalar() or 0,
        "new_devices": db.query(func.count(Device.id)).filter(Device.status == "new", device_filter).scalar() or 0,
        "agents": {
            "total": total_agents,
            "pending": pending,
            "online": online,
        },
        "findings": open_finding_severity_counts(db, tenant_filter=finding_filter),
        "priorities": open_finding_priority_counts(db, tenant_filter=finding_filter),
        "recent_alerts": [
            {
                "id": a.id,
                "tenant_id": a.tenant_id,
                "type": a.type,
                "title": a.title,
                "created_at": a.created_at,
                "is_acknowledged": a.is_acknowledged,
                "severity": a.severity,
                "occurrence_count": a.occurrence_count or 1,
            }
            for a in apply_tenant_scope(db.query(Alert), user, Alert.tenant_id)
            .filter(Alert.dashboard_visible.is_(True))
            .order_by(Alert.created_at.desc())
            .limit(8)
            .all()
        ],
        "recent_jobs": [
            {
                "id": j.id,
                "tenant_id": j.tenant_id,
                "scan_id": j.scan_id,
                "status": j.status,
                "hosts_found": j.hosts_found,
                "findings_count": j.findings_count,
                "created_at": j.created_at,
            }
            for j in apply_tenant_scope(db.query(ScanJob), user, ScanJob.tenant_id)
            .order_by(ScanJob.created_at.desc())
            .limit(8)
            .all()
        ],
    }
