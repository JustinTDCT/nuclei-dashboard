from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Setting
from app.schemas import SettingsOut
from app.timezones import FALLBACK_TIMEZONE, coerce_timezone

DEFAULTS = SettingsOut().model_dump()


def get_settings(db: Session) -> dict:
    row = db.query(Setting).filter(Setting.key == "system").first()
    data = dict(DEFAULTS)
    if row and row.value:
        data.update(row.value)
    if not (data.get("central_host") or "").strip():
        parsed = urlparse(settings.public_url)
        data["central_host"] = parsed.hostname or ""
        if parsed.port:
            data["central_port"] = parsed.port
        elif parsed.scheme == "https":
            data["central_port"] = 443
        elif parsed.scheme == "http":
            data["central_port"] = 80
        data["central_tls"] = parsed.scheme != "http"
    data["default_timezone"] = coerce_timezone(data.get("default_timezone") or FALLBACK_TIMEZONE)
    return data


def central_url(db: Session) -> str:
    cfg = get_settings(db)
    host = (cfg.get("central_host") or "").strip()
    if not host:
        return settings.public_url
    port = int(cfg.get("central_port") or 8118)
    scheme = "https" if cfg.get("central_tls", True) else "http"
    return f"{scheme}://{host}:{port}"


def save_settings(db: Session, values: dict) -> dict:
    data = get_settings(db)
    data.update(values)
    row = db.query(Setting).filter(Setting.key == "system").first()
    if row is None:
        row = Setting(key="system", value=data)
        db.add(row)
    else:
        row.value = data
    db.commit()
    return data
