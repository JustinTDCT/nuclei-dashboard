"""Application-level encryption for SMTP credentials at rest.

Uses a dedicated SETTINGS_ENCRYPTION_KEY that must be a generated Fernet
key. The SMTP password must remain reversible because the mailer needs
the original credential.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

SECRET_PREFIX = "enc:v1:"
FERNET_KEY_HELP = (
    "SETTINGS_ENCRYPTION_KEY must be a Fernet key from "
    "`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`"
)


class SettingsCryptoError(RuntimeError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def is_valid_fernet_key(raw: str | None) -> bool:
    text = (raw or "").strip()
    if not text:
        return False
    try:
        Fernet(text.encode("utf-8"))
    except (ValueError, TypeError):
        return False
    return True


def _fernet_from_key(raw: str) -> Fernet:
    text = (raw or "").strip()
    if not text:
        raise SettingsCryptoError("SETTINGS_ENCRYPTION_KEY is required to protect the SMTP password")
    if not is_valid_fernet_key(text):
        raise SettingsCryptoError(FERNET_KEY_HELP)
    return Fernet(text.encode("utf-8"))


def encryption_key_configured() -> bool:
    return is_valid_fernet_key(settings.settings_encryption_key)


def encrypt_secret(plaintext: str, *, key: str | None = None) -> str:
    value = plaintext or ""
    if not value:
        return ""
    if value.startswith(SECRET_PREFIX):
        return value
    material = key if key is not None else settings.settings_encryption_key
    token = _fernet_from_key(material).encrypt(value.encode("utf-8")).decode("ascii")
    return f"{SECRET_PREFIX}{token}"


def decrypt_secret(value: str, *, key: str | None = None) -> str:
    text = value or ""
    if not text:
        return ""
    if not text.startswith(SECRET_PREFIX):
        return text
    material = key if key is not None else settings.settings_encryption_key
    if not (material or "").strip():
        raise SettingsCryptoError("SETTINGS_ENCRYPTION_KEY is required to decrypt the SMTP password")
    try:
        return _fernet_from_key(material).decrypt(text[len(SECRET_PREFIX) :].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise SettingsCryptoError("SMTP password could not be decrypted with SETTINGS_ENCRYPTION_KEY") from exc


def is_encrypted_secret(value: str | None) -> bool:
    return bool(value) and str(value).startswith(SECRET_PREFIX)
