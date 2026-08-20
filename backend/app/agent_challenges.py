"""Durable, multi-record, single-use Agent authentication challenges."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.auth_throttle import assert_challenge_allowed
from app.config import settings
from app.crypto_util import new_nonce
from app.models import Agent, AgentChallenge


def _now() -> datetime:
    return datetime.now(timezone.utc)


def prune_expired_challenges(db: Session, *, now: datetime | None = None, batch_size: int = 200) -> int:
    current = now or _now()
    rows = (
        db.query(AgentChallenge)
        .filter(AgentChallenge.expires_at <= current, AgentChallenge.consumed_at.is_(None))
        .order_by(AgentChallenge.expires_at.asc(), AgentChallenge.id.asc())
        .limit(batch_size)
        .all()
    )
    for row in rows:
        db.delete(row)
    return len(rows)


def create_challenge(db: Session, agent: Agent, *, source_ip: str) -> AgentChallenge:
    assert_challenge_allowed(db, agent_uuid=agent.uuid, source_ip=source_ip)
    prune_expired_challenges(db)
    now = _now()
    row = AgentChallenge(
        agent_id=agent.id,
        nonce=new_nonce(),
        expires_at=now + timedelta(seconds=max(30, settings.agent_challenge_ttl_seconds)),
        created_at=now,
        source_ip=(source_ip or "")[:80] or None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def consume_challenge(db: Session, agent: Agent, nonce: str) -> AgentChallenge:
    now = _now()
    row = (
        db.query(AgentChallenge)
        .filter(
            AgentChallenge.agent_id == agent.id,
            AgentChallenge.nonce == nonce,
            AgentChallenge.consumed_at.is_(None),
        )
        .with_for_update()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired nonce")
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= now:
        db.delete(row)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired nonce")
    row.consumed_at = now
    db.commit()
    db.refresh(row)
    return row
