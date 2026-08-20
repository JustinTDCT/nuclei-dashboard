from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Setting
from app.schemas import SettingsOut
from app.settings_crypto import SettingsCryptoError, decrypt_secret, encrypt_secret, encryption_key_configured, is_encrypted_secret
from app.timezones import FALLBACK_TIMEZONE, coerce_timezone

DEFAULTS = SettingsOut().model_dump()
SMTP_PASSWORD_MASK = "********"
_SETTINGS_RESPONSE_ONLY = frozenset({"smtp_password_configured"})
for _key in _SETTINGS_RESPONSE_ONLY:
    DEFAULTS.pop(_key, None)


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
    stored_password = data.get("smtp_password") or ""
    if stored_password:
        data["smtp_password"] = decrypt_secret(stored_password)
    return data


def central_url(db: Session) -> str:
    cfg = get_settings(db)
    host = (cfg.get("central_host") or "").strip()
    if not host:
        return settings.public_url
    port = int(cfg.get("central_port") or 8118)
    scheme = "https" if cfg.get("central_tls", True) else "http"
    return f"{scheme}://{host}:{port}"


def public_settings(data: dict) -> dict:
    out = dict(data)
    configured = bool((out.get("smtp_password") or "").strip())
    out["smtp_password"] = SMTP_PASSWORD_MASK if configured else ""
    out["smtp_password_configured"] = configured
    return out


def save_settings(db: Session, values: dict) -> dict:
    data = get_settings(db)
    incoming = {key: value for key, value in values.items() if key not in _SETTINGS_RESPONSE_ONLY}
    incoming_password = incoming.get("smtp_password")
    row = db.query(Setting).filter(Setting.key == "system").first()
    raw_password = ""
    if row and isinstance(row.value, dict):
        raw_password = row.value.get("smtp_password") or ""
    if incoming_password in (None, "", SMTP_PASSWORD_MASK):
        keep = raw_password
        if keep and not is_encrypted_secret(keep) and encryption_key_configured():
            keep = encrypt_secret(decrypt_secret(keep))
        incoming["smtp_password"] = keep
    else:
        if not encryption_key_configured():
            raise SettingsCryptoError("SETTINGS_ENCRYPTION_KEY is required to store an SMTP password")
        incoming["smtp_password"] = encrypt_secret(incoming_password)
    data.update(incoming)
    for key in _SETTINGS_RESPONSE_ONLY:
        data.pop(key, None)
    row = db.query(Setting).filter(Setting.key == "system").first()
    if row is None:
        row = Setting(key="system", value=data)
        db.add(row)
    else:
        row.value = data
    db.commit()
    return data
