"""Refuse to start with known-placeholder or reused control-plane secrets."""

from __future__ import annotations

from urllib.parse import unquote, urlparse

from app.config import Settings

INSECURE_SECRET_VALUES = frozenset(
    {
        "",
        "changeme",
        "change-this-scanner-token",
        "change-this-to-a-long-random-string",
        "dev-secret-change-me",
        "secret",
        "password",
        "admin",
    }
)
MIN_SECRET_KEY_LENGTH = 32
MIN_SCANNER_TOKEN_LENGTH = 24
MIN_ADMIN_PASSWORD_LENGTH = 12


class InsecureConfigurationError(RuntimeError):
    """Raised when startup secrets are empty, known placeholders, or reused."""


def _normalized_secret(value: str | None) -> str:
    return (value or "").strip()


def _is_insecure_secret(value: str | None) -> bool:
    return _normalized_secret(value).lower() in INSECURE_SECRET_VALUES


def _database_password(database_url: str) -> str:
    parsed = urlparse(database_url or "")
    return unquote(parsed.password or "")


def validate_runtime_secrets(cfg: Settings, *, require_admin_password: bool = True) -> None:
    problems: list[str] = []
    secret_key = _normalized_secret(cfg.secret_key)
    scanner_token = _normalized_secret(cfg.scanner_token)
    admin_password = _normalized_secret(cfg.admin_password)
    database_password = _database_password(cfg.database_url)

    if _is_insecure_secret(secret_key) or len(secret_key) < MIN_SECRET_KEY_LENGTH:
        problems.append("SECRET_KEY is empty, a known placeholder, or shorter than 32 characters")
    if _is_insecure_secret(scanner_token) or len(scanner_token) < MIN_SCANNER_TOKEN_LENGTH:
        problems.append("SCANNER_TOKEN is empty, a known placeholder, or shorter than 24 characters")
    if require_admin_password and (
        _is_insecure_secret(admin_password) or len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH
    ):
        problems.append("ADMIN_PASSWORD is empty, a known placeholder, or shorter than 12 characters")
    if _is_insecure_secret(database_password):
        problems.append("DATABASE_URL / POSTGRES_PASSWORD is empty or a known placeholder")
    provided = {
        "SECRET_KEY": secret_key,
        "SCANNER_TOKEN": scanner_token,
    }
    if require_admin_password and admin_password:
        provided["ADMIN_PASSWORD"] = admin_password
    if database_password:
        provided["POSTGRES_PASSWORD"] = database_password
    seen: dict[str, str] = {}
    for label, value in provided.items():
        owner = seen.get(value)
        if owner and owner != label:
            problems.append(f"{owner} and {label} must be distinct")
        else:
            seen[value] = label
    if problems:
        raise InsecureConfigurationError(
            "Refusing to start with insecure default credentials: " + "; ".join(problems)
        )
