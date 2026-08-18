from sqlalchemy.orm import Session

from app.emailer import admin_emails, send_mail, staff_emails
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
    alert = Alert(
        tenant_id=tenant_id,
        type=alert_type,
        title=title,
        body=body,
        device_id=device_id,
        agent_id=agent_id,
    )
    db.add(alert)
    db.flush()
    recipients = email_to if email_to is not None else staff_emails(db)
    send_mail(db, recipients, title, body)
    return alert


def impersonation_alert(db: Session, agent, detail: str) -> Alert:
    title = f"Agent impersonation attempt: {agent.name}"
    body = (
        f"An enrollment or auth attempt for agent {agent.uuid} ({agent.name}) "
        f"did not match the bound key.\n\n{detail}"
    )
    return create_alert(
        db,
        alert_type="impersonation",
        title=title,
        body=body,
        tenant_id=agent.tenant_id,
        agent_id=agent.id,
        email_to=admin_emails(db),
    )
