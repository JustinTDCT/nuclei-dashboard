"""Live authorization revalidation after a Run is queued."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from sqlalchemy.orm import Session

from app.locality import is_authorized
from app.models import WAN_TARGET_FQDN, Agent, AuthorizedWanTarget, Network, ScanJob, Site
from app.scan_exclusions import (
    effective_exclusions,
    exclusion_networks_from_rows,
    serialize_exclusions,
)
from app.scan_intensity import IntensityError, assert_resolved_within_caps, caps_from_settings
from app.scan_snapshot import SnapshotError, worker_targets_from_snapshot
from app.settings_store import get_settings


class ExecutionBlocked(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def revalidate_lan_claim(db: Session, job: ScanJob, agent: Agent) -> None:
    snapshot = job.execution_snapshot or {}
    site_info = snapshot.get("site") or {}
    site_id = site_info.get("id")
    site = db.get(Site, site_id) if site_id else None
    if site is None or site.archived_at is not None or site.tenant_id != job.tenant_id:
        raise ExecutionBlocked("Site is archived or no longer authorized")
    if agent.tenant_id != job.tenant_id or agent.site_id != site.id:
        raise ExecutionBlocked("Agent is not authorized for this site")
    if agent.status != "approved":
        raise ExecutionBlocked("Agent is not approved")
    networks = []
    for row in (snapshot.get("targets") or {}).get("networks") or []:
        network = db.get(Network, row["id"])
        if (
            network is None
            or network.archived_at is not None
            or network.tenant_id != job.tenant_id
            or network.site_id != site.id
        ):
            raise ExecutionBlocked("One or more networks are archived or unauthorized")
        if not is_authorized(db, network.id, agent.id):
            raise ExecutionBlocked(f"Agent is not authorized for network {network.name}")
        networks.append(network)
    if not networks:
        raise ExecutionBlocked("LAN run has no authorized networks")
    _revalidate_caps_and_exclusions(db, job, snapshot, site_id, [n.id for n in networks])


def revalidate_wan_start(db: Session, job: ScanJob) -> None:
    snapshot = job.execution_snapshot or {}
    for row in (snapshot.get("targets") or {}).get("wan_targets") or []:
        target = db.get(AuthorizedWanTarget, row["id"])
        if target is None or target.tenant_id != job.tenant_id or target.archived_at is not None:
            raise ExecutionBlocked("One or more authorized WAN targets were revoked")
        if target.target_type != row.get("type") or target.normalized_value != row.get("normalized"):
            raise ExecutionBlocked("Authorized WAN target value no longer matches the snapshot")
    _revalidate_caps_and_exclusions(db, job, snapshot, None, [])


def _revalidate_caps_and_exclusions(
    db: Session,
    job: ScanJob,
    snapshot: dict[str, Any],
    site_id: int | None,
    network_ids: list[int],
) -> None:
    settings = get_settings(db)
    resolved = (snapshot.get("intensity") or {}).get("resolved") or {}
    try:
        assert_resolved_within_caps(resolved, caps_from_settings(settings))
    except IntensityError as exc:
        raise ExecutionBlocked(exc.detail) from exc
    current = serialize_exclusions(
        effective_exclusions(
            db,
            tenant_id=job.tenant_id,
            site_id=site_id,
            network_ids=network_ids,
            scan_id=job.scan_id,
        )
    )
    snap_ids = {row["id"] for row in (snapshot.get("exclusions") or [])}
    added = [row for row in current if row["id"] not in snap_ids]
    if added:
        combined = list(snapshot.get("exclusions") or []) + added
        try:
            probe = dict(snapshot)
            probe["exclusions"] = combined
            worker_targets_from_snapshot(probe)
        except SnapshotError as exc:
            raise ExecutionBlocked(exc.detail) from exc
        extra_nets = exclusion_networks_from_rows(added)
        original_nets = exclusion_networks_from_rows(snapshot.get("exclusions") or [])
        if extra_nets:
            try:
                worker_targets_from_snapshot(snapshot)
            except SnapshotError:
                raise ExecutionBlocked("Newly added exclusions make this run unsafe")
            # Fail closed if new exclusions intersect snapshotted target space.
            from ipaddress import ip_network

            targets = []
            if snapshot.get("scope") == "lan":
                targets = [ip_network(row["cidr"], strict=False) for row in (snapshot.get("targets") or {}).get("networks") or []]
            else:
                for row in (snapshot.get("targets") or {}).get("wan_targets") or []:
                    if row.get("type") in {"ip", "cidr"}:
                        targets.append(ip_network(row["normalized"], strict=False))
                    elif row.get("type") == WAN_TARGET_FQDN:
                        _assert_fqdn_safe_against(row.get("normalized") or row.get("value") or "", extra_nets)
            if any(t.overlaps(exc) for t in targets for exc in extra_nets):
                raise ExecutionBlocked("Newly added exclusions make this run unsafe")
            _ = original_nets


def resolve_fqdn_addresses(fqdn: str) -> list[ipaddress._BaseAddress]:
    name = (fqdn or "").strip().rstrip(".").lower()
    if not name:
        raise ExecutionBlocked("Queued FQDN target is empty")
    try:
        infos = socket.getaddrinfo(name, None)
    except OSError as exc:
        raise ExecutionBlocked(f"Cannot resolve FQDN {name} against current exclusions") from exc
    addresses = []
    for info in infos:
        host = info[4][0]
        try:
            addresses.append(ipaddress.ip_address(host.split("%", 1)[0]))
        except ValueError:
            continue
    if not addresses:
        raise ExecutionBlocked(f"Cannot resolve FQDN {name} against current exclusions")
    return addresses


def _assert_fqdn_safe_against(fqdn: str, extra_nets: list) -> None:
    if not extra_nets:
        return
    for address in resolve_fqdn_addresses(fqdn):
        if any(address in network for network in extra_nets):
            raise ExecutionBlocked("Newly added exclusions make this run unsafe")
