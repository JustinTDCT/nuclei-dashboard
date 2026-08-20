from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Setting
from app.schemas import SettingsOut
from app.settings_crypto import (
    FERNET_KEY_HELP,
    SettingsCryptoError,
    decrypt_secret,
    encrypt_secret,
    encryption_key_configured,
    is_encrypted_secret,
    is_valid_fernet_key,
)
from app.startup_security import InsecureConfigurationError
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


def raw_smtp_password(db: Session) -> str:
    row = db.query(Setting).filter(Setting.key == "system").first()
    if row is None or not isinstance(row.value, dict):
        return ""
    return str(row.value.get("smtp_password") or "")


def validate_and_migrate_smtp_password(db: Session) -> None:
    """Refuse to run with an unprotected or undecryptable SMTP password.

    No SMTP password → encryption key may be absent.
    SMTP password present → a distinct generated Fernet key is mandatory.
    Legacy plaintext is encrypted in place when a valid key exists.
    """
    stored = raw_smtp_password(db)
    key = (settings.settings_encryption_key or "").strip()
    if not stored:
        if key and not is_valid_fernet_key(key):
            raise InsecureConfigurationError(FERNET_KEY_HELP)
        return
    if not key:
        raise InsecureConfigurationError(
            "SETTINGS_ENCRYPTION_KEY is required because an SMTP password is stored"
        )
    if not is_valid_fernet_key(key):
        raise InsecureConfigurationError(FERNET_KEY_HELP)
    if is_encrypted_secret(stored):
        try:
            decrypt_secret(stored, key=key)
        except SettingsCryptoError as exc:
            raise InsecureConfigurationError(
                "Encrypted SMTP password could not be decrypted with SETTINGS_ENCRYPTION_KEY"
            ) from exc
        return
    row = db.query(Setting).filter(Setting.key == "system").first()
    assert row is not None and isinstance(row.value, dict)
    updated = dict(row.value)
    updated["smtp_password"] = encrypt_secret(stored, key=key)
    row.value = updated
    db.commit()


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
        if keep and not is_encrypted_secret(keep):
            if not encryption_key_configured():
                raise SettingsCryptoError("SETTINGS_ENCRYPTION_KEY is required to store an SMTP password")
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
