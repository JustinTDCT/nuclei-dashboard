from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.alerts import impersonation_alert
from app.auth import create_agent_token, decode_token
from app.crypto_util import new_nonce, verify_ed25519
from app.database import get_db
from app.inventory import store_findings, upsert_devices
from app.jobs import fail_job, job_payload
from app.locality import LanScanInvalidError, assert_scan_executable, is_authorized
from app.models import JOB_QUEUED, JOB_WAITING_FOR_AGENT, Agent, Device, Network, Scan, ScanJob
from app.scan_dispatch import agent_may_claim_now, atomic_claim_job, is_agent_healthy
from app.scan_security import ExecutionBlocked, revalidate_lan_claim
from app.scan_snapshot import merge_provenance
from app.schemas import AgentTokenIn, DeviceReport, EnrollIn, FindingReport

router = APIRouter(prefix="/agent", tags=["agent"])
bearer = HTTPBearer(auto_error=False)
_challenges: dict[str, tuple[str, float]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _get_agent(db: Session, agent_uuid: str) -> Agent:
    agent = db.query(Agent).filter(Agent.uuid == agent_uuid).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Unknown agent")
    if agent.status == "revoked":
        raise HTTPException(status_code=403, detail="Agent revoked")
    return agent


@router.post("/enroll")
def enroll(body: EnrollIn, request: Request, db: Session = Depends(get_db)):
    agent = _get_agent(db, body.uuid)
    if agent.status == "approved":
        if agent.public_key and agent.public_key != body.public_key:
            impersonation_alert(db, agent, "Enroll attempt used a different public key after approval.")
            db.commit()
            raise HTTPException(status_code=403, detail="Agent key mismatch")
        agent.hostname = body.hostname or agent.hostname
        agent.container_id = body.container_id or agent.container_id
        agent.last_ip = _client_ip(request)
        db.commit()
        return {"status": agent.status, "approved": True}

    if not agent.enrollment_secret or body.enrollment_secret != agent.enrollment_secret:
        raise HTTPException(status_code=403, detail="Invalid enrollment secret")

    if agent.public_key and agent.public_key != body.public_key:
        impersonation_alert(db, agent, "A second enroll presented a different public key before approval.")
        db.commit()
        raise HTTPException(status_code=403, detail="Agent key mismatch")

    agent.public_key = body.public_key
    agent.hostname = body.hostname
    agent.container_id = body.container_id
    agent.last_ip = _client_ip(request)
    agent.status = "pending_approval"
    db.commit()
    return {"status": agent.status, "approved": False}


@router.get("/challenge")
def challenge(uuid: str, db: Session = Depends(get_db)):
    agent = _get_agent(db, uuid)
    if not agent.public_key:
        raise HTTPException(status_code=400, detail="Agent has not enrolled")
    nonce = new_nonce()
    _challenges[uuid] = (nonce, _now().timestamp() + 120)
    return {"nonce": nonce}


@router.post("/token")
def token(body: AgentTokenIn, db: Session = Depends(get_db)):
    agent = _get_agent(db, body.uuid)
    if not agent.public_key:
        raise HTTPException(status_code=400, detail="Agent has not enrolled")
    stored = _challenges.pop(body.uuid, None)
    if not stored or stored[0] != body.nonce or stored[1] < _now().timestamp():
        raise HTTPException(status_code=401, detail="Invalid or expired nonce")
    if not verify_ed25519(agent.public_key, body.nonce, body.signature):
        impersonation_alert(db, agent, "Token request signature did not match the bound public key.")
        db.commit()
        raise HTTPException(status_code=403, detail="Invalid signature")
    if agent.status != "approved":
        return {"status": agent.status, "approved": False, "access_token": None}
    return {
        "status": agent.status,
        "approved": True,
        "access_token": create_agent_token(agent.uuid, agent.id, agent.tenant_id),
    }


def current_agent(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> Agent:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(creds.credentials)
    if payload.get("typ") != "agent":
        raise HTTPException(status_code=401, detail="Invalid token")
    agent = db.query(Agent).filter(Agent.uuid == payload["sub"]).first()
    if not agent or agent.status != "approved":
        raise HTTPException(status_code=403, detail="Agent not approved")
    return agent


@router.post("/heartbeat")
def heartbeat(request: Request, agent: Agent = Depends(current_agent), db: Session = Depends(get_db)):
    agent.last_heartbeat = _now()
    agent.last_ip = _client_ip(request)
    db.commit()
    return {"ok": True, "status": agent.status}


@router.get("/jobs")
def poll_jobs(agent: Agent = Depends(current_agent), db: Session = Depends(get_db)):
    jobs = (
        db.query(ScanJob)
        .join(Scan, Scan.id == ScanJob.scan_id)
        .filter(
            ScanJob.status.in_((JOB_QUEUED, JOB_WAITING_FOR_AGENT)),
            Scan.scope == "lan",
        )
        .order_by(ScanJob.created_at.asc())
        .limit(25)
        .all()
    )
    payloads = []
    for job in jobs:
        if not _agent_in_job_pool(job, agent):
            continue
        if job.execution_snapshot:
            if not _any_snapshot_agent_authorized(db, job):
                fail_job(db, job, "Agent is not authorized for network after queueing")
                continue
            try:
                revalidate_lan_claim(db, job, agent)
            except ExecutionBlocked:
                continue
            agents = _agents_for_snapshot(db, job)
            if not agent_may_claim_now(agent, job.execution_snapshot, agents):
                continue
            payloads.append(job_payload(db, job))
            if len(payloads) >= 5:
                break
            continue
        if job.scan.agent_id != agent.id:
            continue
        try:
            assert_scan_executable(db, job.scan)
            payloads.append(job_payload(db, job))
        except LanScanInvalidError as exc:
            fail_job(db, job, exc.detail)
        if len(payloads) >= 5:
            break
    return payloads


@router.post("/jobs/{job_id}/start")
def start_job(job_id: int, agent: Agent = Depends(current_agent), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job or not job.scan or job.scan.scope != "lan":
        raise HTTPException(status_code=404, detail="Job not available")
    if job.status not in {JOB_QUEUED, JOB_WAITING_FOR_AGENT}:
        raise HTTPException(status_code=404, detail="Job not available")
    if not _agent_in_job_pool(job, agent):
        raise HTTPException(status_code=404, detail="Job not available")
    try:
        if job.execution_snapshot:
            revalidate_lan_claim(db, job, agent)
            agents = _agents_for_snapshot(db, job)
            if not is_agent_healthy(agent):
                raise HTTPException(status_code=409, detail="Agent is not healthy")
            if not agent_may_claim_now(agent, job.execution_snapshot, agents):
                raise HTTPException(status_code=409, detail="Preferred agent still has claim priority")
        else:
            if job.scan.agent_id != agent.id:
                raise HTTPException(status_code=404, detail="Job not available")
            assert_scan_executable(db, job.scan)
        payload = job_payload(db, job)
    except ExecutionBlocked as exc:
        fail_job(db, job, exc.detail)
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    except LanScanInvalidError as exc:
        fail_job(db, job, exc.detail)
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    claimed = atomic_claim_job(db, job.id, agent)
    if claimed is None:
        raise HTTPException(status_code=409, detail="Job already claimed")
    try:
        if claimed.execution_snapshot:
            revalidate_lan_claim(db, claimed, agent)
        else:
            assert_scan_executable(db, claimed.scan)
    except (ExecutionBlocked, LanScanInvalidError) as exc:
        fail_job(db, claimed, getattr(exc, "detail", str(exc)))
        raise HTTPException(status_code=409, detail=getattr(exc, "detail", str(exc))) from exc
    claimed.runtime_provenance = merge_provenance(
        claimed.runtime_provenance,
        {"worker": "agent", "claimed_agent_id": agent.id, "agent_uuid": agent.uuid},
    )
    db.commit()
    return job_payload(db, claimed)


@router.post("/jobs/{job_id}/devices")
def post_devices(
    job_id: int,
    body: list[DeviceReport],
    agent: Agent = Depends(current_agent),
    db: Session = Depends(get_db),
):
    job = _owned_job(db, job_id, agent.uuid)
    created, _ = upsert_devices(db, job.tenant_id, job.id, body)
    job.hosts_found = db.query(Device).filter(Device.last_scan_job_id == job.id).count()
    db.commit()
    return {"ok": True, "new_devices": created, "hosts_found": job.hosts_found}


@router.post("/jobs/{job_id}/findings")
def post_findings(
    job_id: int,
    body: list[FindingReport],
    agent: Agent = Depends(current_agent),
    db: Session = Depends(get_db),
):
    job = _owned_job(db, job_id, agent.uuid)
    added = store_findings(db, job.tenant_id, job.id, job.scan.scope, body)
    job.findings_count = (job.findings_count or 0) + added
    db.commit()
    return {"ok": True, "added": added}


@router.post("/jobs/{job_id}/complete")
def complete_job(
    job_id: int,
    ok: bool = True,
    error: str | None = None,
    agent: Agent = Depends(current_agent),
    db: Session = Depends(get_db),
):
    job = _owned_job(db, job_id, agent.uuid)
    job.status = "done" if ok else "failed"
    job.error = error
    job.finished_at = _now()
    db.commit()
    return {"ok": True, "status": job.status}


def _owned_job(db: Session, job_id: int, claimed_by: str) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job or job.claimed_by != claimed_by:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.post("/jobs/{job_id}/provenance")
def post_provenance(
    job_id: int,
    body: dict,
    agent: Agent = Depends(current_agent),
    db: Session = Depends(get_db),
):
    job = _owned_job(db, job_id, agent.uuid)
    job.runtime_provenance = merge_provenance(job.runtime_provenance, body)
    db.commit()
    return {"ok": True}


def _agent_in_job_pool(job: ScanJob, agent: Agent) -> bool:
    snapshot = job.execution_snapshot or {}
    eligible = (snapshot.get("dispatch") or {}).get("eligible_agent_ids")
    if eligible is not None:
        return agent.id in set(eligible)
    return job.scan is not None and job.scan.agent_id == agent.id


def _agents_for_snapshot(db: Session, job: ScanJob) -> dict[int, Agent]:
    ids = ((job.execution_snapshot or {}).get("dispatch") or {}).get("eligible_agent_ids") or []
    if not ids:
        return {}
    rows = db.query(Agent).filter(Agent.id.in_(ids)).all()
    return {row.id: row for row in rows}


def _any_snapshot_agent_authorized(db: Session, job: ScanJob) -> bool:
    snapshot = job.execution_snapshot or {}
    network_ids = [row["id"] for row in (snapshot.get("targets") or {}).get("networks") or []]
    if not network_ids:
        return False
    networks = db.query(Network).filter(Network.id.in_(network_ids)).all()
    if len(networks) != len(network_ids):
        return False
    if any(network.archived_at is not None or network.tenant_id != job.tenant_id for network in networks):
        return False
    for agent_id in (snapshot.get("dispatch") or {}).get("eligible_agent_ids") or []:
        if all(is_authorized(db, network.id, agent_id) for network in networks):
            return True
    return False
