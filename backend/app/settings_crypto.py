"""Application-level encryption for SMTP credentials at rest.

Uses a dedicated SETTINGS_ENCRYPTION_KEY. The SMTP password must remain
reversible because the mailer needs the original credential.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

SECRET_PREFIX = "enc:v1:"


class SettingsCryptoError(RuntimeError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _fernet_from_key(raw: str) -> Fernet:
    text = (raw or "").strip()
    if not text:
        raise SettingsCryptoError("SETTINGS_ENCRYPTION_KEY is required to protect the SMTP password")
    try:
        return Fernet(text.encode("utf-8"))
    except (ValueError, TypeError):
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encryption_key_configured() -> bool:
    return bool((settings.settings_encryption_key or "").strip())


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
