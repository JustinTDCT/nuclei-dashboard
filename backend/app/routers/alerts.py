from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_any, require_user
from app.database import get_db
from app.models import Alert, User
from app.schemas import AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    tenant_id: int | None = None,
    open_only: bool = False,
    _: User = Depends(require_any),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if tenant_id:
        query = query.filter(Alert.tenant_id == tenant_id)
    if open_only:
        query = query.filter(Alert.is_acknowledged.is_(False))
    return query.order_by(Alert.created_at.desc()).limit(500).all()


@router.post("/{alert_id}/ack", response_model=AlertOut)
def ack_alert(alert_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by_id = user.id
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/ack-all")
def ack_all(
    tenant_id: int | None = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.is_acknowledged.is_(False))
    if tenant_id:
        query = query.filter(Alert.tenant_id == tenant_id)
    now = datetime.now(timezone.utc)
    updated = query.update(
        {
            Alert.is_acknowledged: True,
            Alert.acknowledged_at: now,
            Alert.acknowledged_by_id: user.id,
        },
        synchronize_session=False,
    )
    db.commit()
    return {"updated": updated}
