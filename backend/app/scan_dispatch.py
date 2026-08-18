"""LAN agent pool, health, dispatch policy, atomic claim, waiting/missed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.locality import authorized_agent_ids
from app.models import (
    AGENT_HEALTH_SECONDS,
    DEFAULT_AGENT_JOB_WAIT_MINUTES,
    DEFAULT_PREFERRED_AGENT_GRACE_SECONDS,
    DISPATCH_ANY_AVAILABLE,
    DISPATCH_PREFERRED_FAILOVER,
    JOB_FAILED,
    JOB_MISSED,
    JOB_QUEUED,
    JOB_RUNNING,
    JOB_WAITING_FOR_AGENT,
    Agent,
    Network,
    ScanJob,
)
from app.settings_store import get_settings

CENTRAL_WORKER = "central"


class DispatchError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def is_agent_healthy(agent: Agent, *, now: datetime | None = None, window_seconds: int = AGENT_HEALTH_SECONDS) -> bool:
    if agent.status != "approved":
        return False
    heartbeat = _aware(agent.last_heartbeat)
    if heartbeat is None:
        return False
    current = now or utcnow()
    return heartbeat >= current - timedelta(seconds=window_seconds)


def is_agent_online(agent: Agent, *, now: datetime | None = None) -> bool:
    return is_agent_healthy(agent, now=now)


def common_eligible_agents(db: Session, networks: list[Network]) -> list[Agent]:
    if not networks:
        raise DispatchError("LAN scans require at least one network")
    site_ids = {network.site_id for network in networks}
    tenant_ids = {network.tenant_id for network in networks}
    if len(site_ids) != 1 or len(tenant_ids) != 1:
        raise DispatchError("LAN scan definitions cannot span sites")
    pools = [authorized_agent_ids(db, network.id) for network in networks]
    common_ids = set(pools[0]).intersection(*pools[1:]) if len(pools) > 1 else set(pools[0])
    if not common_ids:
        raise DispatchError("Agent is not authorized for every selected network")
    agents = (
        db.query(Agent)
        .filter(
            Agent.id.in_(common_ids),
            Agent.tenant_id == networks[0].tenant_id,
            Agent.site_id == networks[0].site_id,
            Agent.status != "revoked",
        )
        .order_by(Agent.id)
        .all()
    )
    if not agents:
        raise DispatchError("Agent is not authorized for every selected network")
    return agents


def resolve_dispatch_policy(networks: list[Network], eligible_ids: set[int]) -> dict[str, Any]:
    modes = {network.dispatch_mode for network in networks}
    preferred = [network for network in networks if network.dispatch_mode == DISPATCH_PREFERRED_FAILOVER]
    if not preferred:
        return {"mode": DISPATCH_ANY_AVAILABLE, "preferred_agent_id": None}
    preferred_ids = {network.preferred_agent_id for network in preferred}
    if None in preferred_ids:
        raise DispatchError("Preferred + Failover networks must name a preferred agent")
    if len(preferred_ids) != 1:
        raise DispatchError("Selected networks disagree on the preferred agent")
    preferred_id = next(iter(preferred_ids))
    if preferred_id not in eligible_ids:
        raise DispatchError("Preferred agent is not in the common eligible pool")
    if DISPATCH_ANY_AVAILABLE in modes and preferred:
        # Mixed: preferred networks force Preferred + Failover for the whole definition.
        pass
    return {"mode": DISPATCH_PREFERRED_FAILOVER, "preferred_agent_id": preferred_id}


def dispatch_settings(db: Session) -> tuple[int, int]:
    settings = get_settings(db)
    try:
        grace = int(settings.get("preferred_agent_grace_seconds") or DEFAULT_PREFERRED_AGENT_GRACE_SECONDS)
        wait_minutes = int(settings.get("agent_job_wait_minutes") or DEFAULT_AGENT_JOB_WAIT_MINUTES)
    except (TypeError, ValueError) as exc:
        raise DispatchError("Invalid agent wait / grace settings") from exc
    if grace < 0 or wait_minutes <= 0:
        raise DispatchError("Agent wait / grace settings must be positive")
    return grace, wait_minutes


def healthy_eligible(agents: Iterable[Agent], *, now: datetime | None = None) -> list[Agent]:
    current = now or utcnow()
    return [agent for agent in agents if is_agent_healthy(agent, now=current)]


def initial_job_status(healthy: list[Agent], wait_minutes: int, now: datetime) -> dict[str, Any]:
    if healthy:
        return {
            "status": JOB_QUEUED,
            "waiting_since": None,
            "wait_expires_at": None,
        }
    return {
        "status": JOB_WAITING_FOR_AGENT,
        "waiting_since": now,
        "wait_expires_at": now + timedelta(minutes=wait_minutes),
    }


def agent_may_claim_now(
    agent: Agent,
    snapshot: dict[str, Any],
    agents_by_id: dict[int, Agent],
    *,
    now: datetime | None = None,
) -> bool:
    current = now or utcnow()
    dispatch = snapshot.get("dispatch") or {}
    eligible = set(dispatch.get("eligible_agent_ids") or [])
    if agent.id not in eligible:
        return False
    if not is_agent_healthy(agent, now=current):
        return False
    mode = dispatch.get("mode")
    preferred_id = dispatch.get("preferred_agent_id")
    if mode != DISPATCH_PREFERRED_FAILOVER or preferred_id is None:
        return True
    if agent.id == preferred_id:
        return True
    preferred = agents_by_id.get(preferred_id)
    if preferred is None or not is_agent_healthy(preferred, now=current):
        return True
    grace = int(dispatch.get("grace_seconds") or DEFAULT_PREFERRED_AGENT_GRACE_SECONDS)
    created = snapshot.get("created_at")
    try:
        available_from = datetime.fromisoformat(created) if created else current
    except ValueError:
        available_from = current
    available_from = _aware(available_from) or current
    return current >= available_from + timedelta(seconds=grace)


def atomic_claim_job(db: Session, job_id: int, agent: Agent, *, now: datetime | None = None) -> ScanJob | None:
    current = now or utcnow()
    result = db.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status.in_((JOB_QUEUED, JOB_WAITING_FOR_AGENT)),
            ScanJob.claimed_agent_id.is_(None),
            ScanJob.claimed_by.is_(None),
        )
        .values(
            status=JOB_RUNNING,
            claimed_agent_id=agent.id,
            claimed_by=agent.uuid,
            started_at=current,
        )
        .returning(ScanJob.id)
    )
    claimed_id = result.scalar_one_or_none()
    if claimed_id is None:
        return None
    db.flush()
    return db.get(ScanJob, job_id)


def fail_unclaimed_job(db: Session, job: ScanJob, detail: str) -> ScanJob:
    job.status = JOB_FAILED
    job.error = detail
    job.finished_at = utcnow()
    job.claimed_agent_id = None
    job.claimed_by = None
    db.flush()
    return job


def mark_job_missed(db: Session, job: ScanJob, detail: str) -> ScanJob:
    job.status = JOB_MISSED
    job.error = detail
    job.finished_at = utcnow()
    db.flush()
    return job
