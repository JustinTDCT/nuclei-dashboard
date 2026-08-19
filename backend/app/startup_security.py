"""Refuse to start with known-placeholder or empty control-plane secrets."""

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
    """Raised when startup secrets are empty or known placeholders."""


def _normalized_secret(value: str | None) -> str:
    return (value or "").strip()


def _is_insecure_secret(value: str | None) -> bool:
    return _normalized_secret(value).lower() in INSECURE_SECRET_VALUES


def _database_password(database_url: str) -> str:
    parsed = urlparse(database_url or "")
    return unquote(parsed.password or "")


def validate_runtime_secrets(cfg: Settings) -> None:
    problems: list[str] = []
    secret_key = _normalized_secret(cfg.secret_key)
    scanner_token = _normalized_secret(cfg.scanner_token)
    admin_password = _normalized_secret(cfg.admin_password)
    database_password = _database_password(cfg.database_url)

    if _is_insecure_secret(secret_key) or len(secret_key) < MIN_SECRET_KEY_LENGTH:
        problems.append("SECRET_KEY is empty, a known placeholder, or shorter than 32 characters")
    if _is_insecure_secret(scanner_token) or len(scanner_token) < MIN_SCANNER_TOKEN_LENGTH:
        problems.append("SCANNER_TOKEN is empty, a known placeholder, or shorter than 24 characters")
    if _is_insecure_secret(admin_password) or len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
        problems.append("ADMIN_PASSWORD is empty, a known placeholder, or shorter than 12 characters")
    if _is_insecure_secret(database_password):
        problems.append("DATABASE_URL / POSTGRES_PASSWORD is empty or a known placeholder")
    if problems:
        raise InsecureConfigurationError(
            "Refusing to start with insecure default credentials: " + "; ".join(problems)
        )
