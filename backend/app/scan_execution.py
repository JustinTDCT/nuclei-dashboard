"""Authoritative Phase 1D Run execution context.

Poll, start, inventory, findings, and history must use the immutable
Run snapshot and claim — never the editable Scan Definition.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

from sqlalchemy.orm import Session

from app.models import JOB_RUNNING, Agent, ScanJob
from app.scan_exclusions import effective_exclusions, exclusion_networks_from_rows, serialize_exclusions
from app.scan_security import ExecutionBlocked, pin_fqdn_targets
from app.scan_snapshot import job_payload_from_snapshot, worker_targets_from_snapshot


def run_scope(job: ScanJob) -> str:
    snapshot = job.execution_snapshot or {}
    scope = snapshot.get("scope")
    if scope in {"lan", "wan"}:
        return scope
    raise ExecutionBlocked("Run has no immutable scope snapshot")


def snapshot_scope_clause(scope: str):
    return ScanJob.execution_snapshot["scope"].astext == scope


def execution_context(db: Session, job: ScanJob) -> dict[str, Any]:
    if not job.execution_snapshot:
        raise ExecutionBlocked("Run has no immutable execution snapshot")
    scope = run_scope(job)
    snapshot = job.execution_snapshot
    site = snapshot.get("site") or {}
    site_id = site.get("id") if scope == "lan" else None
    networks = (snapshot.get("targets") or {}).get("networks") or []
    agent_id = job.claimed_agent_id
    if agent_id is None and job.claimed_by and job.claimed_by != "central":
        agent = db.query(Agent).filter(Agent.uuid == job.claimed_by).first()
        agent_id = agent.id if agent else None
    return {
        "scope": scope,
        "site_id": site_id,
        "network_ids": [row["id"] for row in networks if row.get("id") is not None],
        "claimed_agent_id": agent_id,
        "snapshot": snapshot,
    }


def resolve_snapshot_network(db: Session, job: ScanJob, ip: str) -> int | None:
    context = execution_context(db, job)
    if context["scope"] != "lan" or not context["network_ids"] or not (ip or "").strip():
        return None
    try:
        parsed = ip_address(ip.strip())
    except ValueError:
        return None
    matches = []
    for row in (context["snapshot"].get("targets") or {}).get("networks") or []:
        network_id = row.get("id")
        cidr = row.get("cidr")
        if network_id is None or not cidr:
            continue
        try:
            if parsed in ip_network(cidr, strict=False):
                matches.append(network_id)
        except ValueError:
            continue
    if len(matches) == 1:
        return matches[0]
    return None


def current_worker_exclusions(db: Session, job: ScanJob) -> list[dict[str, Any]]:
    context = execution_context(db, job)
    return serialize_exclusions(
        effective_exclusions(
            db,
            tenant_id=job.tenant_id,
            site_id=context["site_id"],
            network_ids=context["network_ids"],
            scan_id=job.scan_id,
        )
    )


def worker_execution_payload(db: Session, job: ScanJob) -> dict[str, Any]:
    if not job.execution_snapshot:
        raise ExecutionBlocked("Run has no immutable execution snapshot")
    snapshot = dict(job.execution_snapshot)
    current = current_worker_exclusions(db, job)
    combined = list(snapshot.get("exclusions") or [])
    seen = {row.get("id") for row in combined}
    for row in current:
        if row.get("id") not in seen:
            combined.append(row)
    snapshot["exclusions"] = combined
    targets = worker_targets_from_snapshot(snapshot)
    nets = exclusion_networks_from_rows(combined)
    try:
        pinned = pin_fqdn_targets(targets, nets)
    except ExecutionBlocked:
        raise
    payload = job_payload_from_snapshot(job)
    payload["scope"] = run_scope(job)
    payload["targets"] = pinned
    payload["exclusions"] = combined
    payload["cidrs"] = [row["value"] for row in pinned if row["type"] in {"ip", "cidr"}]
    return payload


def require_active_phase1d_run(job: ScanJob | None, *, claimed_by: str | None = None) -> ScanJob:
    if job is None:
        raise ExecutionBlocked("Job not found")
    if claimed_by is not None and job.claimed_by != claimed_by:
        raise ExecutionBlocked("Job not found")
    if job.status != JOB_RUNNING:
        raise ExecutionBlocked("Job is not an active Phase 1D run")
    if not job.execution_snapshot:
        raise ExecutionBlocked("Job is not an active Phase 1D run")
    return job
