import logging
import smtplib
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.models import User
from app.settings_store import get_settings

log = logging.getLogger(__name__)


def send_mail(db: Session, to_addrs: list[str], subject: str, body: str) -> None:
    if not to_addrs:
        return
    cfg = get_settings(db)
    host = cfg.get("smtp_host") or ""
    if not host:
        log.info("SMTP not configured; skip email: %s", subject)
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_user") or "noreply@localhost"
    msg["To"] = ", ".join(to_addrs)
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
    except Exception:
        log.exception("Failed to send email: %s", subject)


def admin_emails(db: Session) -> list[str]:
    return [u.email for u in db.query(User).filter(User.role == "admin", User.is_active.is_(True)).all() if u.email]


def staff_emails(db: Session) -> list[str]:
    return [
        u.email
        for u in db.query(User).filter(User.role.in_(["admin", "user"]), User.is_active.is_(True)).all()
        if u.email
    ]
