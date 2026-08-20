"""Durable login and Agent-challenge rate limits / lockouts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthThrottle

SCOPE_LOGIN_USER = "login_user"
SCOPE_LOGIN_IP = "login_ip"
SCOPE_CHALLENGE_AGENT = "agent_challenge"
SCOPE_CHALLENGE_IP = "agent_challenge_ip"

LOGIN_DENIED_DETAIL = "Invalid credentials"
LOGIN_RATE_DETAIL = "Too many login attempts. Try again later."
CHALLENGE_RATE_DETAIL = "Too many authentication challenges. Try again later."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _locked_row(db: Session, scope: str, subject: str) -> AuthThrottle:
    db.execute(
        insert(AuthThrottle)
        .values(scope=scope, subject=subject, attempt_count=0)
        .on_conflict_do_nothing(constraint="uq_auth_throttles_scope_subject")
    )
    return (
        db.query(AuthThrottle)
        .filter(AuthThrottle.scope == scope, AuthThrottle.subject == subject)
        .with_for_update()
        .one()
    )


def _reset_window(row: AuthThrottle, now: datetime, window: timedelta) -> None:
    started = row.window_started_at
    if started is not None and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if started is None or now - started > window:
        row.attempt_count = 0
        row.window_started_at = now
        row.locked_until = None


def _raise_if_locked(row: AuthThrottle, now: datetime, detail: str) -> None:
    locked = row.locked_until
    if locked is None:
        return
    if locked.tzinfo is None:
        locked = locked.replace(tzinfo=timezone.utc)
    if locked > now:
        raise HTTPException(status_code=429, detail=detail)


def _record_attempt(
    db: Session,
    *,
    scope: str,
    subject: str,
    limit: int,
    window_seconds: int,
    lockout_seconds: int | None,
    detail: str,
    increment: bool,
) -> AuthThrottle:
    now = _now()
    row = _locked_row(db, scope, subject)
    try:
        _raise_if_locked(row, now, detail)
    except HTTPException:
        db.commit()
        raise
    _reset_window(row, now, timedelta(seconds=max(1, window_seconds)))
    if increment:
        row.attempt_count = int(row.attempt_count or 0) + 1
    row.last_attempt_at = now
    blocked = increment and row.attempt_count > limit
    if blocked and lockout_seconds:
        row.locked_until = now + timedelta(seconds=max(1, lockout_seconds))
    db.commit()
    db.refresh(row)
    if blocked:
        raise HTTPException(status_code=429, detail=detail)
    return row


def assert_login_allowed(db: Session, *, username: str, source_ip: str) -> None:
    ip = (source_ip or "unknown").strip() or "unknown"
    name = (username or "").strip().lower() or "unknown"
    _record_attempt(
        db,
        scope=SCOPE_LOGIN_IP,
        subject=ip,
        limit=max(1, settings.login_ip_limit),
        window_seconds=settings.login_ip_window_seconds,
        lockout_seconds=settings.login_lockout_seconds,
        detail=LOGIN_RATE_DETAIL,
        increment=True,
    )
    row = _locked_row(db, SCOPE_LOGIN_USER, name)
    try:
        _raise_if_locked(row, _now(), LOGIN_RATE_DETAIL)
    finally:
        db.commit()


def record_login_failure(db: Session, *, username: str) -> None:
    name = (username or "").strip().lower() or "unknown"
    _record_attempt(
        db,
        scope=SCOPE_LOGIN_USER,
        subject=name,
        limit=max(1, settings.login_failure_limit),
        window_seconds=settings.login_failure_window_seconds,
        lockout_seconds=settings.login_lockout_seconds,
        detail=LOGIN_RATE_DETAIL,
        increment=True,
    )


def record_login_success(db: Session, *, username: str) -> None:
    name = (username or "").strip().lower() or "unknown"
    row = _locked_row(db, SCOPE_LOGIN_USER, name)
    row.attempt_count = 0
    row.locked_until = None
    row.window_started_at = _now()
    row.last_attempt_at = _now()
    db.commit()


def assert_challenge_allowed(db: Session, *, agent_uuid: str, source_ip: str) -> None:
    ip = (source_ip or "unknown").strip() or "unknown"
    uuid = (agent_uuid or "").strip() or "unknown"
    _record_attempt(
        db,
        scope=SCOPE_CHALLENGE_IP,
        subject=ip,
        limit=max(1, settings.agent_challenge_ip_limit),
        window_seconds=settings.agent_challenge_window_seconds,
        lockout_seconds=settings.login_lockout_seconds,
        detail=CHALLENGE_RATE_DETAIL,
        increment=True,
    )
    _record_attempt(
        db,
        scope=SCOPE_CHALLENGE_AGENT,
        subject=uuid,
        limit=max(1, settings.agent_challenge_limit),
        window_seconds=settings.agent_challenge_window_seconds,
        lockout_seconds=settings.login_lockout_seconds,
        detail=CHALLENGE_RATE_DETAIL,
        increment=True,
    )
