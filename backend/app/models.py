from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

DISPATCH_ANY_AVAILABLE = "any_available"
DISPATCH_PREFERRED_FAILOVER = "preferred_failover"
COMPATIBILITY_SITE_NAME = "Imported Site"
UNASSIGNED_SITE_NAME = "Unassigned Assets"

LIFECYCLE_ACTIVE = "active"
LIFECYCLE_INACTIVE = "inactive"
LIFECYCLE_STATES = frozenset({LIFECYCLE_ACTIVE, LIFECYCLE_INACTIVE})

DISPOSITION_UNREVIEWED = "unreviewed"
DISPOSITION_APPROVED = "approved"
DISPOSITION_UNAUTHORIZED = "unauthorized"
DISPOSITION_IGNORED = "ignored"
DISPOSITIONS = frozenset(
    {DISPOSITION_UNREVIEWED, DISPOSITION_APPROVED, DISPOSITION_UNAUTHORIZED, DISPOSITION_IGNORED}
)

CRITICALITY_LOW = "low"
CRITICALITY_NORMAL = "normal"
CRITICALITY_HIGH = "high"
CRITICALITY_CRITICAL = "critical"
CRITICALITIES = frozenset({CRITICALITY_LOW, CRITICALITY_NORMAL, CRITICALITY_HIGH, CRITICALITY_CRITICAL})

IDENTIFIER_MAC = "mac"
IDENTIFIER_HOSTNAME = "hostname"
IDENTIFIER_FQDN = "fqdn"
IDENTIFIER_DNS_NAME = "dns_name"
IDENTIFIER_TLS_NAME = "tls_name"
IDENTIFIER_SERIAL = "serial"
IDENTIFIER_DEVICE_ID = "device_id"
IDENTIFIER_OTHER = "other"
IDENTIFIER_TYPES = frozenset(
    {
        IDENTIFIER_MAC,
        IDENTIFIER_HOSTNAME,
        IDENTIFIER_FQDN,
        IDENTIFIER_DNS_NAME,
        IDENTIFIER_TLS_NAME,
        IDENTIFIER_SERIAL,
        IDENTIFIER_DEVICE_ID,
        IDENTIFIER_OTHER,
    }
)

SOURCE_SCANNER = "scanner"
SOURCE_LEGACY_MIGRATION = "legacy_migration"
SOURCE_MANUAL = "manual"
ASSET_SOURCES = frozenset({SOURCE_SCANNER, SOURCE_LEGACY_MIGRATION, SOURCE_MANUAL})

IDENTIFIER_VALIDITY_ACTIVE = "active"
IDENTIFIER_VALIDITY_INCORRECT = "incorrect"
IDENTIFIER_VALIDITIES = frozenset({IDENTIFIER_VALIDITY_ACTIVE, IDENTIFIER_VALIDITY_INCORRECT})

DECISION_LINKED_EXISTING = "linked_existing"
DECISION_CREATED_NEW = "created_new"
DECISION_AMBIGUOUS = "ambiguous"
CORRELATION_DECISIONS = frozenset(
    {DECISION_LINKED_EXISTING, DECISION_CREATED_NEW, DECISION_AMBIGUOUS}
)

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CORRELATION_CONFIDENCES = frozenset({CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW})

EVENT_NEW_ASSET = "new_asset"
EVENT_ASSET_BECAME_INACTIVE = "asset_became_inactive"
EVENT_PREVIOUSLY_INACTIVE_RETURNED = "previously_inactive_asset_returned"
PHASE1C_EVENT_TYPES = frozenset(
    {EVENT_NEW_ASSET, EVENT_ASSET_BECAME_INACTIVE, EVENT_PREVIOUSLY_INACTIVE_RETURNED}
)

CORRELATION_ALGORITHM_VERSION = "1c.3"

tag_assets = Table(
    "asset_tags",
    Base.metadata,
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, index=True),
)

tag_sites = Table(
    "site_tags",
    Base.metadata,
    Column("site_id", ForeignKey("sites.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, index=True),
)

tag_networks = Table(
    "network_tags",
    Base.metadata,
    Column("network_id", ForeignKey("networks.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, index=True),
)


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
    assets: Mapped[list["Asset"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    tags: Mapped[list["Tag"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
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
    assets: Mapped[list["Asset"]] = relationship(back_populates="site")
    tags: Mapped[list["Tag"]] = relationship(secondary=tag_sites, back_populates="sites")


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
    tags: Mapped[list["Tag"]] = relationship(secondary=tag_networks, back_populates="networks")


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
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "hostname",
            "scope",
            "site_id",
            "asset_id",
            name="uq_device_tenant_hostname_scope",
        ),
        Index("ix_devices_tenant_id_site_id_scope", "tenant_id", "site_id", "scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
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
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="devices")
    site: Mapped["Site | None"] = relationship()
    asset: Mapped["Asset | None"] = relationship(back_populates="devices")
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


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("tenant_id", "normalized_name", name="uq_tags_tenant_id_normalized_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    normalized_name: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="tags")
    assets: Mapped[list["Asset"]] = relationship(secondary=tag_assets, back_populates="tags")
    sites: Mapped[list["Site"]] = relationship(secondary=tag_sites, back_populates="tags")
    networks: Mapped[list["Network"]] = relationship(secondary=tag_networks, back_populates="tags")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "lifecycle_state IS NULL OR lifecycle_state IN ('active', 'inactive')",
            name="ck_assets_lifecycle_state",
        ),
        CheckConstraint(
            "disposition IN ('unreviewed', 'approved', 'unauthorized', 'ignored')",
            name="ck_assets_disposition",
        ),
        CheckConstraint(
            "criticality IN ('low', 'normal', 'high', 'critical')",
            name="ck_assets_criticality",
        ),
        Index("ix_assets_tenant_id_last_seen", "tenant_id", "last_seen"),
        Index("ix_assets_tenant_id_site_id", "tenant_id", "site_id"),
        Index("ix_assets_merged_into_asset_id", "merged_into_asset_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    merged_into_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    merged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    classification: Mapped[str] = mapped_column(String(80), default="Unknown")
    description: Mapped[str] = mapped_column(Text, default="")
    lifecycle_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    disposition: Mapped[str] = mapped_column(String(20), default=DISPOSITION_UNREVIEWED)
    criticality: Mapped[str] = mapped_column(String(20), default=CRITICALITY_NORMAL)
    is_expected: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="assets")
    site: Mapped["Site | None"] = relationship(back_populates="assets")
    merged_into: Mapped["Asset | None"] = relationship(
        remote_side="Asset.id", foreign_keys=[merged_into_asset_id]
    )
    devices: Mapped[list["Device"]] = relationship(back_populates="asset")
    identifiers: Mapped[list["AssetIdentifier"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    addresses: Mapped[list["AssetAddress"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    services: Mapped[list["AssetService"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    observations: Mapped[list["AssetObservation"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    correlation_decisions: Mapped[list["AssetCorrelationDecision"]] = relationship(
        back_populates="selected_asset"
    )
    domain_events: Mapped[list["DomainEvent"]] = relationship(back_populates="asset")
    tags: Mapped[list["Tag"]] = relationship(secondary=tag_assets, back_populates="assets")


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "identifier_type",
            "normalized_value",
            name="uq_asset_identifiers_asset_type_value",
        ),
        CheckConstraint(
            "identifier_type IN ('mac', 'hostname', 'fqdn', 'dns_name', 'tls_name', 'serial', 'device_id', 'other')",
            name="ck_asset_identifiers_type",
        ),
        CheckConstraint(
            "validity IN ('active', 'incorrect')",
            name="ck_asset_identifiers_validity",
        ),
        Index("ix_asset_identifiers_tenant_type_value", "tenant_id", "identifier_type", "normalized_value"),
        Index(
            "ix_asset_identifiers_active_lookup",
            "tenant_id",
            "identifier_type",
            "normalized_value",
            postgresql_where=text("validity = 'active'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    identifier_type: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(String(255))
    normalized_value: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    validity: Mapped[str] = mapped_column(String(20), default=IDENTIFIER_VALIDITY_ACTIVE)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    corrected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    corrected_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    correction_reason: Mapped[str] = mapped_column(Text, default="")
    replacement_identifier_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_identifiers.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="identifiers")


class AssetAddress(Base):
    __tablename__ = "asset_addresses"
    __table_args__ = (
        UniqueConstraint("asset_id", "ip", name="uq_asset_addresses_asset_id_ip"),
        CheckConstraint("address_family IN ('ipv4', 'ipv6')", name="ck_asset_addresses_family"),
        Index("ix_asset_addresses_tenant_id_ip", "tenant_id", "ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    network_id: Mapped[int | None] = mapped_column(
        ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(80))
    address_family: Mapped[str] = mapped_column(String(8), default="ipv4")
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="addresses")


class AssetService(Base):
    __tablename__ = "asset_services"
    __table_args__ = (
        UniqueConstraint("asset_id", "ip", "port", "protocol", name="uq_asset_services_asset_ip_port_proto"),
        Index("ix_asset_services_tenant_ip_port", "tenant_id", "ip", "port"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    address_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_addresses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(80), default="")
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(80), default="")
    tls_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    web_title: Mapped[str] = mapped_column(String(500), default="")
    tech: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="services")


class AssetObservation(Base):
    __tablename__ = "asset_observations"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id",
            "asset_id",
            "observation_key",
            name="uq_asset_observations_job_asset_key",
        ),
        Index("ix_asset_observations_asset_id_observed_at", "asset_id", "observed_at"),
        Index("ix_asset_observations_tenant_id_observed_at", "tenant_id", "observed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    network_id: Mapped[int | None] = mapped_column(
        ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scope: Mapped[str] = mapped_column(String(10), default="")
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(80), default="")
    snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)
    observation_key: Mapped[str] = mapped_column(String(64))
    provenance: Mapped[str] = mapped_column(String(80), default=SOURCE_SCANNER)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="observations")


class AssetCorrelationDecision(Base):
    __tablename__ = "asset_correlation_decisions"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id",
            "observation_key",
            name="uq_asset_correlation_decisions_job_key",
        ),
        CheckConstraint(
            "decision IN ('linked_existing', 'created_new', 'ambiguous')",
            name="ck_asset_correlation_decisions_decision",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_asset_correlation_decisions_confidence",
        ),
        Index("ix_asset_correlation_decisions_tenant_id_created_at", "tenant_id", "created_at"),
        Index("ix_asset_correlation_decisions_selected_asset_id", "selected_asset_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    observation_key: Mapped[str] = mapped_column(String(64))
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    selected_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    decision: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer, default=0)
    algorithm_version: Mapped[str] = mapped_column(String(32), default=CORRELATION_ALGORITHM_VERSION)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    candidates: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    selected_asset: Mapped["Asset | None"] = relationship(back_populates="correlation_decisions")


class DomainEvent(Base):
    __tablename__ = "domain_events"
    __table_args__ = (
        UniqueConstraint("idempotence_key", name="uq_domain_events_idempotence_key"),
        Index("ix_domain_events_tenant_id_event_type_occurred_at", "tenant_id", "event_type", "occurred_at"),
        Index("ix_domain_events_asset_id_occurred_at", "asset_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    idempotence_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset | None"] = relationship(back_populates="domain_events")
