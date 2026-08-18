from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

DISPATCH_ANY_AVAILABLE = "any_available"
DISPATCH_PREFERRED_FAILOVER = "preferred_failover"
COMPATIBILITY_SITE_NAME = "Imported Site"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin, user, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    subnets: Mapped[list["Subnet"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    sites: Mapped[list["Site"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    agents: Mapped[list["Agent"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    devices: Mapped[list["Device"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_sites_tenant_id_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    timezone: Mapped[str | None] = mapped_column(String(80), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="sites")
    networks: Mapped[list["Network"]] = relationship(back_populates="site", cascade="all, delete-orphan")
    agents: Mapped[list["Agent"]] = relationship(back_populates="site")


class Network(Base):
    __tablename__ = "networks"
    __table_args__ = (
        UniqueConstraint("site_id", "name", name="uq_networks_site_id_name"),
        CheckConstraint(
            "dispatch_mode IN ('any_available', 'preferred_failover')",
            name="ck_networks_dispatch_mode",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    cidr: Mapped[str] = mapped_column(String(80))
    dispatch_mode: Mapped[str] = mapped_column(String(32), default=DISPATCH_ANY_AVAILABLE)
    preferred_agent_id: Mapped[int | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship()
    site: Mapped["Site"] = relationship(back_populates="networks")
    preferred_agent: Mapped["Agent | None"] = relationship(foreign_keys=[preferred_agent_id])
    agent_links: Mapped[list["NetworkAgent"]] = relationship(
        back_populates="network", cascade="all, delete-orphan"
    )


class NetworkAgent(Base):
    __tablename__ = "network_agents"
    __table_args__ = (UniqueConstraint("network_id", "agent_id", name="uq_network_agents_network_id_agent_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    network: Mapped["Network"] = relationship(back_populates="agent_links")
    agent: Mapped["Agent"] = relationship(back_populates="network_links")


class Subnet(Base):
    __tablename__ = "subnets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    cidr: Mapped[str] = mapped_column(String(80))
    scope: Mapped[str] = mapped_column(String(10))  # wan, lan
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    network_id: Mapped[int | None] = mapped_column(
        ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="subnets")
    site: Mapped["Site | None"] = relationship()
    network: Mapped["Network | None"] = relationship()


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    enrollment_secret: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="pending_enrollment")
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="agents")
    site: Mapped["Site"] = relationship(back_populates="agents")
    scans: Mapped[list["Scan"]] = relationship(back_populates="agent")
    network_links: Mapped[list["NetworkAgent"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    scope: Mapped[str] = mapped_column(String(10))  # wan, lan
    profile: Mapped[str] = mapped_column(String(30), default="discovery")  # discovery, discovery_nuclei
    nuclei_severities: Mapped[str] = mapped_column(String(80), default="critical,high,medium")
    nuclei_tags: Mapped[str] = mapped_column(String(255), default="")
    subnet_ids: Mapped[list] = mapped_column(JSONB, default=list)
    interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="scans")
    agent: Mapped["Agent | None"] = relationship(back_populates="scans")
    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, done, failed
    claimed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="jobs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="job")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "hostname", "scope", name="uq_device_tenant_hostname_scope"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(80), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    scope: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(10), default="new")  # new, known, stale
    classification: Mapped[str] = mapped_column(String(80), default="Unknown")
    description: Mapped[str] = mapped_column(Text, default="")
    auto_label: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    tech: Mapped[str] = mapped_column(Text, default="")
    ports: Mapped[list] = mapped_column(JSONB, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="devices")
    findings: Mapped[list["Finding"]] = relationship(back_populates="device")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    template_id: Mapped[str] = mapped_column(String(200), index=True)
    name: Mapped[str] = mapped_column(String(500), default="")
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    host: Mapped[str] = mapped_column(String(500), default="")
    matched_at: Mapped[str] = mapped_column(String(500), default="")
    tags: Mapped[str] = mapped_column(String(500), default="")
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    raw_json: Mapped[dict] = mapped_column(JSONB, default=dict)

    tenant: Mapped["Tenant"] = relationship(back_populates="findings")
    job: Mapped["ScanJob | None"] = relationship(back_populates="findings")
    device: Mapped["Device | None"] = relationship(back_populates="findings")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    tenant: Mapped["Tenant | None"] = relationship(back_populates="alerts")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(80), nullable=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str] = mapped_column(String(40), index=True)
    object_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
