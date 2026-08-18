from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.auth import require_admin, require_any
from app.database import get_db
from app.models import Agent, Alert, Device, Finding, ScanJob, Tenant, User
from app.schemas import DisplaySettingsOut, SettingsIn, SettingsOut
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
    if current.get("default_timezone") != timezone:
        record_audit(
            db,
            actor=user,
            action="settings.timezone_change",
            object_type="settings",
            object_id=None,
            details={"before": current.get("default_timezone"), "after": timezone},
            commit=True,
        )
    return SettingsOut(**saved)


@router.get("/display-settings", response_model=DisplaySettingsOut)
def display_settings(_: User = Depends(require_any), db: Session = Depends(get_db)):
    return DisplaySettingsOut(default_timezone=get_settings(db).get("default_timezone") or "UTC")


@router.get("/timezones")
def timezones(_: User = Depends(require_any)):
    return {"timezones": list_iana_timezones()}


@router.get("/dashboard")
def dashboard(_: User = Depends(require_any), db: Session = Depends(get_db)):
    online_cut = datetime.now(timezone.utc) - timedelta(seconds=90)
    agents = db.query(Agent).all()
    return {
        "tenants": db.query(func.count(Tenant.id)).scalar() or 0,
        "users": db.query(func.count(User.id)).scalar() or 0,
        "open_alerts": db.query(func.count(Alert.id)).filter(Alert.is_acknowledged.is_(False)).scalar() or 0,
        "new_devices": db.query(func.count(Device.id)).filter(Device.status == "new").scalar() or 0,
        "agents": {
            "total": len(agents),
            "pending": sum(1 for a in agents if a.status == "pending_approval"),
            "online": sum(
                1
                for a in agents
                if a.last_heartbeat
                and (a.last_heartbeat if a.last_heartbeat.tzinfo else a.last_heartbeat.replace(tzinfo=timezone.utc))
                >= online_cut
            ),
        },
        "findings": dict(
            db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
        ),
        "recent_alerts": [
            {
                "id": a.id,
                "tenant_id": a.tenant_id,
                "type": a.type,
                "title": a.title,
                "created_at": a.created_at,
                "is_acknowledged": a.is_acknowledged,
            }
            for a in db.query(Alert).order_by(Alert.created_at.desc()).limit(8).all()
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
            for j in db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(8).all()
        ],
    }
