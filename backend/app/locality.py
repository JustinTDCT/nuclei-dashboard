from ipaddress import ip_network

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    COMPATIBILITY_SITE_NAME,
    DISPATCH_ANY_AVAILABLE,
    DISPATCH_PREFERRED_FAILOVER,
    Agent,
    Network,
    NetworkAgent,
    Site,
    Subnet,
    Tenant,
)

DISPATCH_MODES = frozenset({DISPATCH_ANY_AVAILABLE, DISPATCH_PREFERRED_FAILOVER})


class LanScanInvalidError(ValueError):
    """Stored LAN scan definition is no longer fully executable."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def valid_cidr(cidr: str) -> str:
    try:
        return str(ip_network(cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid CIDR") from exc


def get_tenant(db: Session, tenant_id: int) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def get_site(db: Session, site_id: int, *, tenant_id: int | None = None) -> Site:
    site = db.query(Site).filter(Site.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if tenant_id is not None and site.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Site not found")
    return site


def get_network(db: Session, network_id: int, *, tenant_id: int | None = None) -> Network:
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")
    if tenant_id is not None and network.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Network not found")
    return network


def get_agent(db: Session, agent_id: int, *, tenant_id: int | None = None) -> Agent:
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if tenant_id is not None and agent.tenant_id != tenant_id:
        raise HTTPException(status_code=400, detail="Agent not found for tenant")
    return agent


def require_active_site(site: Site) -> Site:
    if site.archived_at is not None:
        raise HTTPException(status_code=400, detail="Site is archived")
    return site


def require_active_network(network: Network) -> Network:
    if network.archived_at is not None:
        raise HTTPException(status_code=400, detail="Network is archived")
    return network


def site_name_taken(db: Session, tenant_id: int, name: str, *, exclude_id: int | None = None) -> bool:
    q = db.query(Site).filter(Site.tenant_id == tenant_id, Site.name == name)
    if exclude_id is not None:
        q = q.filter(Site.id != exclude_id)
    return q.first() is not None


def network_name_taken(db: Session, site_id: int, name: str, *, exclude_id: int | None = None) -> bool:
    q = db.query(Network).filter(Network.site_id == site_id, Network.name == name)
    if exclude_id is not None:
        q = q.filter(Network.id != exclude_id)
    return q.first() is not None


def companion_subnet(db: Session, network: Network) -> Subnet | None:
    return db.query(Subnet).filter(Subnet.network_id == network.id, Subnet.scope == "lan").first()


def sync_lan_subnet(db: Session, network: Network) -> Subnet:
    subnet = companion_subnet(db, network)
    if subnet is None:
        subnet = Subnet(
            tenant_id=network.tenant_id,
            name=network.name,
            cidr=network.cidr,
            scope="lan",
            site_id=network.site_id,
            network_id=network.id,
        )
        db.add(subnet)
        db.flush()
        return subnet
    subnet.name = network.name
    subnet.cidr = network.cidr
    subnet.site_id = network.site_id
    subnet.tenant_id = network.tenant_id
    return subnet


def authorized_agent_ids(db: Session, network_id: int) -> set[int]:
    rows = db.query(NetworkAgent.agent_id).filter(NetworkAgent.network_id == network_id).all()
    return {row[0] for row in rows}


def is_authorized(db: Session, network_id: int, agent_id: int) -> bool:
    return (
        db.query(NetworkAgent)
        .filter(NetworkAgent.network_id == network_id, NetworkAgent.agent_id == agent_id)
        .first()
        is not None
    )


def assert_agent_on_site(agent: Agent, site: Site) -> None:
    if agent.site_id != site.id or agent.tenant_id != site.tenant_id:
        raise HTTPException(status_code=400, detail="Agent must belong to the same site")


def assert_network_on_site(network: Network, site: Site) -> None:
    if network.site_id != site.id or network.tenant_id != site.tenant_id:
        raise HTTPException(status_code=400, detail="Network must belong to the same site")


def authorize_agent(db: Session, network: Network, agent: Agent) -> NetworkAgent:
    if agent.tenant_id != network.tenant_id:
        raise HTTPException(status_code=400, detail="Cannot authorize an agent from another tenant")
    if agent.site_id != network.site_id:
        raise HTTPException(status_code=400, detail="Cannot authorize an agent from another site")
    existing = (
        db.query(NetworkAgent)
        .filter(NetworkAgent.network_id == network.id, NetworkAgent.agent_id == agent.id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Agent is already authorized for this network")
    link = NetworkAgent(network_id=network.id, agent_id=agent.id)
    db.add(link)
    db.flush()
    return link


def deauthorize_agent(db: Session, network: Network, agent_id: int) -> None:
    link = (
        db.query(NetworkAgent)
        .filter(NetworkAgent.network_id == network.id, NetworkAgent.agent_id == agent_id)
        .first()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Authorization not found")
    db.delete(link)
    if network.preferred_agent_id == agent_id:
        network.preferred_agent_id = None
        if network.dispatch_mode == DISPATCH_PREFERRED_FAILOVER:
            network.dispatch_mode = DISPATCH_ANY_AVAILABLE


def set_dispatch(db: Session, network: Network, mode: str, preferred_agent_id: int | None) -> None:
    if mode not in DISPATCH_MODES:
        raise HTTPException(status_code=400, detail="Invalid dispatch mode")
    if mode == DISPATCH_ANY_AVAILABLE:
        network.dispatch_mode = DISPATCH_ANY_AVAILABLE
        network.preferred_agent_id = None
        return
    if preferred_agent_id is None:
        raise HTTPException(status_code=400, detail="Preferred + Failover requires a preferred agent")
    agent = get_agent(db, preferred_agent_id, tenant_id=network.tenant_id)
    if agent.site_id != network.site_id:
        raise HTTPException(status_code=400, detail="Preferred agent must belong to the same site")
    if not is_authorized(db, network.id, agent.id):
        raise HTTPException(status_code=400, detail="Preferred agent must be authorized for this network")
    network.dispatch_mode = DISPATCH_PREFERRED_FAILOVER
    network.preferred_agent_id = agent.id


def resolve_lan_networks(db: Session, tenant_id: int, subnet_ids: list[int]) -> list[Network]:
    if not subnet_ids:
        return []
    unique_ids = list(dict.fromkeys(subnet_ids))
    subnets = (
        db.query(Subnet)
        .filter(Subnet.tenant_id == tenant_id, Subnet.scope == "lan", Subnet.id.in_(unique_ids))
        .all()
    )
    if len(subnets) != len(unique_ids):
        raise HTTPException(status_code=400, detail="One or more LAN networks are invalid for this scope")
    networks: list[Network] = []
    for subnet in subnets:
        if not subnet.network_id:
            raise HTTPException(status_code=400, detail="LAN subnet is not mapped to a site network")
        network = db.query(Network).filter(Network.id == subnet.network_id).first()
        if not network or network.tenant_id != tenant_id:
            raise HTTPException(status_code=400, detail="One or more LAN networks are invalid for this scope")
        networks.append(network)
    return networks


def validate_lan_scan(db: Session, tenant_id: int, agent_id: int | None, subnet_ids: list[int]) -> Agent:
    if not agent_id:
        raise LanScanInvalidError("LAN scans require an agent")
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.tenant_id == tenant_id).first()
    if not agent:
        raise LanScanInvalidError("Agent not found for tenant")
    site = db.query(Site).filter(Site.id == agent.site_id, Site.tenant_id == tenant_id).first()
    if not site:
        raise LanScanInvalidError("Agent site is missing or belongs to another tenant")
    if site.archived_at is not None:
        raise LanScanInvalidError("Site is archived")
    if subnet_ids:
        try:
            networks = resolve_lan_networks(db, tenant_id, subnet_ids)
        except HTTPException as exc:
            raise LanScanInvalidError(str(exc.detail)) from exc
        sites = {n.site_id for n in networks}
        if sites != {agent.site_id}:
            raise LanScanInvalidError("Selected networks must belong to the agent's site")
        for network in networks:
            if network.archived_at is not None:
                raise LanScanInvalidError("Cannot use an archived network in a scan")
            if not is_authorized(db, network.id, agent.id):
                raise LanScanInvalidError(f"Agent is not authorized for network {network.name}")
    else:
        authorized = (
            db.query(Network)
            .join(NetworkAgent, NetworkAgent.network_id == Network.id)
            .filter(
                Network.site_id == agent.site_id,
                Network.archived_at.is_(None),
                NetworkAgent.agent_id == agent.id,
            )
            .first()
        )
        if authorized is None:
            raise LanScanInvalidError("Agent is not authorized for any networks at this site")
    return agent


def require_lan_scan(db: Session, tenant_id: int, agent_id: int | None, subnet_ids: list[int]) -> Agent:
    try:
        return validate_lan_scan(db, tenant_id, agent_id, subnet_ids)
    except LanScanInvalidError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc


def assert_scan_executable(db: Session, scan) -> None:
    if scan.scope != "lan":
        return
    validate_lan_scan(db, scan.tenant_id, scan.agent_id, scan.subnet_ids or [])


def lan_cidrs_for_scan(db: Session, tenant_id: int, agent: Agent, subnet_ids: list[int]) -> list[str]:
    validate_lan_scan(db, tenant_id, agent.id, subnet_ids)
    if subnet_ids:
        networks = resolve_lan_networks(db, tenant_id, subnet_ids)
        return [network.cidr for network in sorted(networks, key=lambda item: (item.name, item.id))]
    networks = (
        db.query(Network)
        .join(NetworkAgent, NetworkAgent.network_id == Network.id)
        .filter(
            Network.tenant_id == tenant_id,
            Network.site_id == agent.site_id,
            Network.archived_at.is_(None),
            NetworkAgent.agent_id == agent.id,
        )
        .order_by(Network.name, Network.id)
        .all()
    )
    return [network.cidr for network in networks]


def drop_cross_site_authorizations(db: Session, agent: Agent) -> None:
    stale = (
        db.query(NetworkAgent)
        .join(Network, Network.id == NetworkAgent.network_id)
        .filter(NetworkAgent.agent_id == agent.id, Network.site_id != agent.site_id)
        .all()
    )
    stale_network_ids = {link.network_id for link in stale}
    for link in stale:
        db.delete(link)
    if not stale_network_ids:
        return
    preferred = (
        db.query(Network)
        .filter(Network.id.in_(stale_network_ids), Network.preferred_agent_id == agent.id)
        .all()
    )
    for network in preferred:
        network.preferred_agent_id = None
        if network.dispatch_mode == DISPATCH_PREFERRED_FAILOVER:
            network.dispatch_mode = DISPATCH_ANY_AVAILABLE


def compatibility_site_for_tenant(db: Session, tenant_id: int) -> Site | None:
    return (
        db.query(Site)
        .filter(Site.tenant_id == tenant_id, Site.name == COMPATIBILITY_SITE_NAME)
        .first()
    )
