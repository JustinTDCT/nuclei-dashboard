from sqlalchemy.orm import Session

from app.events import emit_agent_identity_mismatch
from app.models import Alert


def create_alert(
    db: Session,
    *,
    alert_type: str,
    title: str,
    body: str,
    tenant_id: int | None = None,
    device_id: int | None = None,
    agent_id: int | None = None,
    email_to: list[str] | None = None,
) -> Alert:
    """Legacy dashboard-row helper. Does not send email or enqueue deliveries."""
    del email_to
    alert = Alert(
        tenant_id=tenant_id,
        type=alert_type,
        title=title,
        body=body,
        device_id=device_id,
        agent_id=agent_id,
        dashboard_visible=True,
        occurrence_count=1,
    )
    db.add(alert)
    db.flush()
    return alert


def impersonation_alert(db: Session, agent, detail: str, *, source_ip: str | None = None):
    return emit_agent_identity_mismatch(db, agent, reason=detail, source_ip=source_ip)
