import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.models import User
from app.settings_store import get_settings

log = logging.getLogger(__name__)


class MailDeliveryError(Exception):
    def __init__(self, detail: str, *, permanent: bool = False):
        self.detail = detail
        self.permanent = permanent
        super().__init__(detail)


@dataclass
class MailResult:
    ok: bool
    error: str | None = None
    permanent: bool = False


def deliver_mail(db: Session, to_addrs: list[str], subject: str, body: str) -> MailResult:
    recipients = [addr for addr in to_addrs if addr]
    if not recipients:
        return MailResult(ok=False, error="No email recipients", permanent=True)
    cfg = get_settings(db)
    host = cfg.get("smtp_host") or ""
    if not host:
        return MailResult(ok=False, error="SMTP not configured", permanent=True)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_user") or "noreply@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    try:
        port = int(cfg.get("smtp_port") or 587)
        if cfg.get("smtp_tls", True):
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.starttls()
                if cfg.get("smtp_user"):
                    smtp.login(cfg.get("smtp_user"), cfg.get("smtp_password") or "")
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                if cfg.get("smtp_user"):
                    smtp.login(cfg.get("smtp_user"), cfg.get("smtp_password") or "")
                smtp.send_message(msg)
        return MailResult(ok=True)
    except Exception as exc:
        log.exception("Failed to send email: %s", subject)
        raise MailDeliveryError(str(exc)[:400]) from exc


def send_mail(db: Session, to_addrs: list[str], subject: str, body: str) -> MailResult:
    """Compatibility wrapper. Returns an explicit result instead of swallowing SMTP state."""
    try:
        return deliver_mail(db, to_addrs, subject, body)
    except MailDeliveryError as exc:
        log.exception("Failed to send email: %s", subject)
        return MailResult(ok=False, error=str(exc), permanent=exc.permanent)


def admin_emails(db: Session) -> list[str]:
    return [u.email for u in db.query(User).filter(User.role == "admin", User.is_active.is_(True)).all() if u.email]


def staff_emails(db: Session) -> list[str]:
    return [
        u.email
        for u in db.query(User).filter(User.role.in_(["admin", "user"]), User.is_active.is_(True)).all()
        if u.email
    ]
