"""Scan Definition validation, revisioning, and Run creation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.locality import (
    LanScanInvalidError,
    companion_subnet,
    get_agent,
    get_network,
    get_site,
    is_authorized,
    require_active_network,
    require_active_site,
)
from app.models import (
    JOB_QUEUED,
    JOB_WAITING_FOR_AGENT,
    SCHEDULE_MANUAL,
    SNAPSHOT_VERSION,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    AuthorizedWanTarget,
    Network,
    Scan,
    ScanJob,
    ScanNetworkTarget,
    ScanWanTarget,
    Site,
    Subnet,
)
from app.scan_dispatch import (
    DispatchError,
    common_eligible_agents,
    dispatch_settings,
    healthy_eligible,
    initial_job_status,
    resolve_dispatch_policy,
)
from app.scan_exclusions import (
    ExclusionError,
    effective_exclusions,
    serialize_exclusions,
)
from app.scan_intensity import IntensityError, caps_from_settings, resolve_intensity
from app.scan_schedule import (
    ScheduleError,
    effective_scan_timezone,
    next_occurrence,
    normalize_schedule_config,
)
from app.scan_snapshot import SnapshotError, build_execution_snapshot, worker_targets_from_snapshot
from app.scan_stages import StageConfigError, normalize_stage_config, stages_from_legacy_profile
from app.settings_store import get_settings
from app.wan_targets import WanTargetInvalidError, require_active_wan_target


class ScanDefinitionError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


DEFINITION_ERRORS = (
    ScanDefinitionError,
    DispatchError,
    IntensityError,
    StageConfigError,
    ScheduleError,
    ExclusionError,
    SnapshotError,
    WanTargetInvalidError,
    LanScanInvalidError,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def http_error(exc: Exception) -> HTTPException:
    detail = getattr(exc, "detail", str(exc))
    return HTTPException(status_code=400, detail=detail)


def definition_targets(db: Session, scan: Scan) -> tuple[Site | None, list[Network], list[AuthorizedWanTarget]]:
    if scan.scope == "lan":
        links = list(scan.network_targets)
        if not links:
            return _legacy_lan_targets(db, scan)
        networks = []
        for link in links:
            network = db.get(Network, link.network_id)
            if not network or network.tenant_id != scan.tenant_id:
                raise ScanDefinitionError("LAN scan references an invalid network")
            networks.append(network)
        site_ids = {network.site_id for network in networks}
        if scan.site_id:
            site_ids.add(scan.site_id)
        if len(site_ids) != 1:
            raise ScanDefinitionError("LAN scan definitions cannot span sites")
        site = db.get(Site, next(iter(site_ids)))
        if not site or site.tenant_id != scan.tenant_id:
            raise ScanDefinitionError("LAN scan site is missing or belongs to another tenant")
        return site, networks, []
    links = list(scan.wan_target_links)
    if not links:
        return None, [], _legacy_wan_targets(db, scan)
    targets = []
    for link in links:
        target = db.get(AuthorizedWanTarget, link.authorized_wan_target_id)
        if not target or target.tenant_id != scan.tenant_id:
            raise ScanDefinitionError("WAN scan references an unauthorized target")
        targets.append(target)
    return None, [], targets


def _legacy_lan_targets(db: Session, scan: Scan) -> tuple[Site | None, list[Network], list[AuthorizedWanTarget]]:
    from app.models import Agent, NetworkAgent

    subnet_ids = list(scan.subnet_ids or [])
    site = db.get(Site, scan.site_id) if scan.site_id else None
    if site is None and scan.agent_id:
        agent = db.get(Agent, scan.agent_id)
        if agent and agent.tenant_id == scan.tenant_id:
            site = db.get(Site, agent.site_id)
    if subnet_ids:
        networks = _networks_from_legacy_subnets(db, scan.tenant_id, subnet_ids)
        return site, networks, []
    if site is None or not scan.agent_id:
        return site, [], []
    networks = (
        db.query(Network)
        .join(NetworkAgent, NetworkAgent.network_id == Network.id)
        .filter(
            Network.site_id == site.id,
            Network.archived_at.is_(None),
            NetworkAgent.agent_id == scan.agent_id,
        )
        .all()
    )
    return site, networks, []


def _legacy_wan_targets(db: Session, scan: Scan) -> list[AuthorizedWanTarget]:
    subnet_ids = list(scan.subnet_ids or [])
    if not subnet_ids:
        return []
    subnets = (
        db.query(Subnet)
        .filter(Subnet.tenant_id == scan.tenant_id, Subnet.scope == "wan", Subnet.id.in_(subnet_ids))
        .all()
    )
    values = {str(__import__("ipaddress").ip_network(row.cidr, strict=False)) for row in subnets}
    if not values:
        return []
    return (
        db.query(AuthorizedWanTarget)
        .filter(
            AuthorizedWanTarget.tenant_id == scan.tenant_id,
            AuthorizedWanTarget.normalized_value.in_(values),
            AuthorizedWanTarget.archived_at.is_(None),
        )
        .all()
    )


def _networks_from_legacy_subnets(db: Session, tenant_id: int, subnet_ids: list[int]) -> list[Network]:
    unique = list(dict.fromkeys(subnet_ids))
    subnets = (
        db.query(Subnet)
        .filter(Subnet.tenant_id == tenant_id, Subnet.scope == "lan", Subnet.id.in_(unique))
        .all()
    )
    if len(subnets) != len(unique):
        raise ScanDefinitionError("One or more LAN networks are invalid for this scope")
    networks = []
    for subnet in subnets:
        if not subnet.network_id:
            raise ScanDefinitionError("LAN subnet is not mapped to a site network")
        network = db.get(Network, subnet.network_id)
        if not network or network.tenant_id != tenant_id:
            raise ScanDefinitionError("One or more LAN networks are invalid for this scope")
        networks.append(network)
    return networks


def validate_definition(
    db: Session,
    scan: Scan,
    *,
    for_run: bool = False,
) -> dict[str, Any]:
    if scan.archived_at is not None and for_run:
        raise ScanDefinitionError("Archived scan definitions cannot run")
    if scan.needs_review and for_run:
        raise ScanDefinitionError("Scan definition needs review before it can run")
    settings = get_settings(db)
    site, networks, wan_targets = definition_targets(db, scan)
    stages = _stages_for(scan)
    intensity = resolve_intensity(scan.intensity_config or None, caps_from_settings(settings))
    schedule = normalize_schedule_config(scan.schedule_config or None, interval_minutes=scan.interval_minutes)
    if scan.scope == "lan":
        if site is None:
            raise ScanDefinitionError("LAN scans require a site")
        if site.tenant_id != scan.tenant_id:
            raise ScanDefinitionError("LAN scan site belongs to another tenant")
        if for_run:
            require_active_site(site)
        if not networks:
            raise ScanDefinitionError("LAN scans require at least one network")
        for network in networks:
            if network.site_id != site.id or network.tenant_id != scan.tenant_id:
                raise ScanDefinitionError("Selected networks must belong to the scan site")
            if for_run:
                require_active_network(network)
        agents = common_eligible_agents(db, networks)
        eligible_ids = [agent.id for agent in agents]
        dispatch = resolve_dispatch_policy(networks, set(eligible_ids))
        timezone_name = effective_scan_timezone(site.timezone, settings.get("default_timezone"), "lan")
    else:
        for target in wan_targets:
            if target.tenant_id != scan.tenant_id:
                raise ScanDefinitionError("WAN target belongs to another tenant")
            if for_run and target.archived_at is not None:
                raise ScanDefinitionError("WAN scan references an archived authorized target")
        agents = []
        eligible_ids = []
        dispatch = {"mode": "central", "preferred_agent_id": None}
        timezone_name = effective_scan_timezone(None, settings.get("default_timezone"), "wan")
        site = None
        networks = []
    grace, wait_minutes = dispatch_settings(db)
    exclusions = serialize_exclusions(
        effective_exclusions(
            db,
            tenant_id=scan.tenant_id,
            site_id=site.id if site else None,
            network_ids=[network.id for network in networks],
            scan_id=scan.id,
        )
    )
    return {
        "site": site,
        "networks": networks,
        "wan_targets": wan_targets,
        "stages": stages,
        "intensity": intensity,
        "schedule": schedule,
        "dispatch": dispatch,
        "eligible_agents": agents,
        "eligible_agent_ids": eligible_ids,
        "exclusions": exclusions,
        "timezone_name": timezone_name,
        "grace_seconds": grace,
        "wait_minutes": wait_minutes,
        "settings": settings,
    }


def _stages_for(scan: Scan) -> dict[str, Any]:
    if scan.stage_config:
        return normalize_stage_config(scan.stage_config)
    return stages_from_legacy_profile(scan.profile, scan.nuclei_severities, scan.nuclei_tags)


def apply_scan_payload(db: Session, scan: Scan, body: Any, *, creating: bool) -> None:
    from app.schemas import ScanIn

    payload: ScanIn = body
    if payload.scope not in {"lan", "wan"}:
        raise ScanDefinitionError("Scope must be lan or wan")
    scan.name = payload.name
    scan.scope = payload.scope
    scan.is_enabled = payload.is_enabled
    existing_legacy = (scan.schedule_config or {}).get("type") == "legacy_interval"
    if payload.schedule_config is not None:
        scan.schedule_config = normalize_schedule_config(
            payload.schedule_config,
            interval_minutes=payload.interval_minutes,
            allow_legacy=existing_legacy and payload.schedule_config.get("type") == "legacy_interval",
        )
    elif payload.interval_minutes:
        scan.schedule_config = normalize_schedule_config(
            None, interval_minutes=payload.interval_minutes, allow_legacy=True
        )
    elif creating:
        scan.schedule_config = {"type": SCHEDULE_MANUAL}
    if payload.stage_config is not None:
        scan.stage_config = normalize_stage_config(payload.stage_config)
        scan.profile = "discovery_nuclei" if scan.stage_config.get("vulnerability") else "discovery"
        scan.nuclei_severities = scan.stage_config.get("nuclei_severities") or scan.nuclei_severities
        scan.nuclei_tags = scan.stage_config.get("nuclei_tags") or ""
    else:
        scan.profile = payload.profile
        scan.nuclei_severities = payload.nuclei_severities
        scan.nuclei_tags = payload.nuclei_tags
        scan.stage_config = stages_from_legacy_profile(payload.profile, payload.nuclei_severities, payload.nuclei_tags)
    settings = get_settings(db)
    if payload.intensity_config is not None:
        resolved = resolve_intensity(payload.intensity_config, caps_from_settings(settings))
        scan.intensity_config = {"preset": resolved["preset"], **(payload.intensity_config or {})}
    elif creating:
        scan.intensity_config = {"preset": "normal"}
        resolve_intensity(scan.intensity_config, caps_from_settings(settings))
    else:
        resolve_intensity(scan.intensity_config or {"preset": "normal"}, caps_from_settings(settings))

    scan.interval_minutes = None
    if (scan.schedule_config or {}).get("type") == "legacy_interval":
        scan.interval_minutes = int(scan.schedule_config["interval_minutes"])

    if payload.scope == "lan":
        _apply_lan_targets(db, scan, payload)
    else:
        _apply_wan_targets(db, scan, payload)

    validated = validate_definition(db, scan, for_run=False)
    scan.next_run_at = None
    if scan.is_enabled and scan.archived_at is None and validated["schedule"]["type"] != SCHEDULE_MANUAL:
        scan.next_run_at = next_occurrence(
            validated["schedule"],
            tz_name=validated["timezone_name"],
            after=utcnow(),
        )


def _apply_lan_targets(db: Session, scan: Scan, payload: Any) -> None:
    network_ids = list(payload.network_ids or [])
    if not network_ids and payload.subnet_ids:
        networks = _networks_from_legacy_subnets(db, scan.tenant_id, payload.subnet_ids)
        network_ids = [network.id for network in networks]
    if payload.site_id:
        site = get_site(db, payload.site_id, tenant_id=scan.tenant_id)
    elif payload.agent_id:
        agent = get_agent(db, payload.agent_id, tenant_id=scan.tenant_id)
        site = get_site(db, agent.site_id, tenant_id=scan.tenant_id)
        scan.agent_id = agent.id
    else:
        raise ScanDefinitionError("LAN scans require a site")
    require_active_site(site)
    if not network_ids and payload.agent_id:
        agent = get_agent(db, payload.agent_id, tenant_id=scan.tenant_id)
        from app.models import NetworkAgent

        network_ids = [
            row.id
            for row in db.query(Network)
            .join(NetworkAgent, NetworkAgent.network_id == Network.id)
            .filter(
                Network.site_id == site.id,
                Network.archived_at.is_(None),
                NetworkAgent.agent_id == agent.id,
            )
            .all()
        ]
    if not network_ids:
        raise ScanDefinitionError("LAN scans require at least one network")
    networks = []
    for network_id in network_ids:
        network = get_network(db, network_id, tenant_id=scan.tenant_id)
        require_active_network(network)
        if network.site_id != site.id:
            raise ScanDefinitionError("Selected networks must belong to the same site")
        networks.append(network)
    common_eligible_agents(db, networks)
    resolve_dispatch_policy(networks, {agent.id for agent in common_eligible_agents(db, networks)})
    scan.site_id = site.id
    scan.network_targets.clear()
    db.flush()
    for network in networks:
        db.add(ScanNetworkTarget(scan=scan, network_id=network.id))
    scan.wan_target_links.clear()
    scan.subnet_ids = [companion_subnet(db, network).id for network in networks if companion_subnet(db, network)]


def _apply_wan_targets(db: Session, scan: Scan, payload: Any) -> None:
    scan.site_id = None
    scan.agent_id = payload.agent_id
    target_ids = list(payload.wan_target_ids or [])
    if not target_ids and payload.subnet_ids:
        target_ids = _wan_ids_from_subnets(db, scan.tenant_id, payload.subnet_ids)
    if not target_ids:
        from app.wan_targets import active_wan_targets_for_tenant

        target_ids = [row.id for row in active_wan_targets_for_tenant(db, scan.tenant_id)]
    if not target_ids:
        scan.network_targets.clear()
        scan.wan_target_links.clear()
        scan.subnet_ids = []
        return
    targets = [require_active_wan_target(db, target_id, tenant_id=scan.tenant_id) for target_id in target_ids]
    scan.network_targets.clear()
    scan.wan_target_links.clear()
    db.flush()
    for target in targets:
        db.add(ScanWanTarget(scan=scan, authorized_wan_target_id=target.id))
    scan.subnet_ids = _companion_subnet_ids_for_wan(db, scan.tenant_id, targets)


def _wan_ids_from_subnets(db: Session, tenant_id: int, subnet_ids: list[int]) -> list[int]:
    import ipaddress

    subnets = (
        db.query(Subnet)
        .filter(Subnet.tenant_id == tenant_id, Subnet.scope == "wan", Subnet.id.in_(subnet_ids))
        .all()
    )
    if len(subnets) != len(set(subnet_ids)):
        raise ScanDefinitionError("One or more authorized WAN targets are invalid for this tenant")
    normalized = [str(ipaddress.ip_network(row.cidr, strict=False)) for row in subnets]
    targets = (
        db.query(AuthorizedWanTarget)
        .filter(
            AuthorizedWanTarget.tenant_id == tenant_id,
            AuthorizedWanTarget.normalized_value.in_(normalized),
            AuthorizedWanTarget.archived_at.is_(None),
        )
        .all()
    )
    by_value = {row.normalized_value: row.id for row in targets}
    missing = [value for value in normalized if value not in by_value]
    if missing:
        raise ScanDefinitionError("One or more authorized WAN targets are invalid for this tenant")
    return [by_value[value] for value in normalized]


def _companion_subnet_ids_for_wan(
    db: Session, tenant_id: int, targets: list[AuthorizedWanTarget]
) -> list[int]:
    cidrs = [row.normalized_value for row in targets if row.target_type in {"ip", "cidr"}]
    if not cidrs:
        return []
    rows = (
        db.query(Subnet)
        .filter(Subnet.tenant_id == tenant_id, Subnet.scope == "wan", Subnet.cidr.in_(cidrs))
        .all()
    )
    return [row.id for row in rows]


def increment_revision(scan: Scan) -> None:
    scan.definition_revision = int(scan.definition_revision or 1) + 1
    scan.updated_at = utcnow()


def create_run(
    db: Session,
    scan: Scan,
    *,
    trigger_type: str = TRIGGER_MANUAL,
    scheduled_for: datetime | None = None,
) -> ScanJob:
    if scan.archived_at is not None:
        raise ScanDefinitionError("Archived scan definitions cannot run")
    validated = validate_definition(db, scan, for_run=True)
    now = utcnow()
    snapshot = build_execution_snapshot(
        scan=scan,
        site=validated["site"],
        networks=validated["networks"],
        wan_targets=validated["wan_targets"],
        stages=validated["stages"],
        intensity=validated["intensity"],
        exclusions=validated["exclusions"],
        dispatch=validated["dispatch"],
        eligible_agent_ids=validated["eligible_agent_ids"],
        schedule=validated["schedule"],
        timezone_name=validated["timezone_name"],
        trigger_type=trigger_type,
        scheduled_for=scheduled_for,
        grace_seconds=validated["grace_seconds"],
        wait_minutes=validated["wait_minutes"],
        created_at=now,
    )
    try:
        worker_targets_from_snapshot(snapshot)
    except SnapshotError as exc:
        raise ScanDefinitionError(exc.detail) from exc
    if scan.scope == "lan":
        healthy = healthy_eligible(validated["eligible_agents"], now=now)
        status_fields = initial_job_status(healthy, validated["wait_minutes"], now)
    else:
        status_fields = {"status": JOB_QUEUED, "waiting_since": None, "wait_expires_at": None}
    job = ScanJob(
        scan_id=scan.id,
        tenant_id=scan.tenant_id,
        status=status_fields["status"],
        execution_snapshot=snapshot,
        snapshot_version=SNAPSHOT_VERSION,
        definition_revision=scan.definition_revision,
        trigger_type=trigger_type,
        scheduled_for=scheduled_for,
        waiting_since=status_fields["waiting_since"],
        wait_expires_at=status_fields["wait_expires_at"],
        runtime_provenance={"snapshot_version": SNAPSHOT_VERSION, "worker": None},
    )
    db.add(job)
    db.flush()
    return job
