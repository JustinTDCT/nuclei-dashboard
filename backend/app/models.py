from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
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

SNAPSHOT_VERSION = "1d.1"
SNAPSHOT_LEGACY_PRE_1D = "legacy_pre_1d"
LEGACY_PRE_1D_REQUEUE_ERROR = (
    "Pre-1D job has no immutable execution snapshot and must be requeued after Phase 1D upgrade"
)

EVENT_SCAN_MISSED_UNAVAILABLE_AGENT = "scan_missed_unavailable_agent"
PHASE1D_EVENT_TYPES = frozenset({EVENT_SCAN_MISSED_UNAVAILABLE_AGENT})

DETECTOR_NUCLEI = "nuclei"
DETECTOR_TYPES = frozenset({DETECTOR_NUCLEI})

TECHNICAL_OPEN = "open"
TECHNICAL_RESOLVED = "resolved"
TECHNICAL_STATES = frozenset({TECHNICAL_OPEN, TECHNICAL_RESOLVED})

TREATMENT_UNADDRESSED = "unaddressed"
TREATMENT_MITIGATED = "mitigated"
TREATMENT_ACCEPTED_RISK = "accepted_risk"
TREATMENT_FALSE_POSITIVE = "false_positive"
TREATMENT_STATES = frozenset(
    {TREATMENT_UNADDRESSED, TREATMENT_MITIGATED, TREATMENT_ACCEPTED_RISK, TREATMENT_FALSE_POSITIVE}
)

HISTORY_OPENED = "opened"
HISTORY_RESOLVED = "resolved"
HISTORY_REOPENED = "reopened"
HISTORY_TRANSITIONS = frozenset({HISTORY_OPENED, HISTORY_RESOLVED, HISTORY_REOPENED})

EVALUATION_DETECTED = "detected"
EVALUATION_CLEAN = "clean"
EVALUATION_OUTCOMES = frozenset({EVALUATION_DETECTED, EVALUATION_CLEAN})

EVENT_NEW_FINDING = "new_finding"
EVENT_VULNERABILITY_RESOLVED = "vulnerability_resolved"
EVENT_VULNERABILITY_REOPENED = "vulnerability_reopened"
PHASE2A_EVENT_TYPES = frozenset(
    {EVENT_NEW_FINDING, EVENT_VULNERABILITY_RESOLVED, EVENT_VULNERABILITY_REOPENED}
)

EVENT_ASSET_DISPOSITION_CHANGED = "asset_disposition_changed"
EVENT_TREATMENT_CREATED = "treatment_created"
EVENT_TREATMENT_EXPIRED = "treatment_expired"
EVENT_SCAN_FAILED = "scan_failed"
EVENT_AGENT_IDENTITY_MISMATCH = "agent_identity_mismatch"
EVENT_WAN_TARGET_CHANGED = "wan_target_changed"
EVENT_POLICY_CHANGED = "policy_changed"
PHASE3B_EVENT_TYPES = frozenset(
    {
        EVENT_ASSET_DISPOSITION_CHANGED,
        EVENT_TREATMENT_CREATED,
        EVENT_TREATMENT_EXPIRED,
        EVENT_SCAN_FAILED,
        EVENT_AGENT_IDENTITY_MISMATCH,
        EVENT_WAN_TARGET_CHANGED,
        EVENT_POLICY_CHANGED,
    }
)
DOMAIN_EVENT_TYPES = (
    PHASE1C_EVENT_TYPES | PHASE1D_EVENT_TYPES | PHASE2A_EVENT_TYPES | PHASE3B_EVENT_TYPES
)
EVENT_TYPE_LABELS = {
    EVENT_NEW_ASSET: "New Asset",
    EVENT_ASSET_BECAME_INACTIVE: "Asset Became Inactive",
    EVENT_PREVIOUSLY_INACTIVE_RETURNED: "Inactive Asset Returned",
    EVENT_ASSET_DISPOSITION_CHANGED: "Asset Disposition Changed",
    EVENT_NEW_FINDING: "New Vulnerability / Finding",
    EVENT_VULNERABILITY_RESOLVED: "Vulnerability Resolved",
    EVENT_VULNERABILITY_REOPENED: "Vulnerability Reopened",
    EVENT_TREATMENT_CREATED: "Finding Treatment Created",
    EVENT_TREATMENT_EXPIRED: "Finding Treatment Expired",
    EVENT_SCAN_FAILED: "Scan Failed",
    EVENT_SCAN_MISSED_UNAVAILABLE_AGENT: "Scan Missed — No Available Agent",
    EVENT_AGENT_IDENTITY_MISMATCH: "Agent Identity Mismatch",
    EVENT_WAN_TARGET_CHANGED: "WAN Target Changed",
    EVENT_POLICY_CHANGED: "Policy Changed",
}

ALERT_SEVERITY_INFO = "info"
ALERT_SEVERITY_LOW = "low"
ALERT_SEVERITY_MEDIUM = "medium"
ALERT_SEVERITY_HIGH = "high"
ALERT_SEVERITY_CRITICAL = "critical"
ALERT_SEVERITIES = frozenset(
    {
        ALERT_SEVERITY_INFO,
        ALERT_SEVERITY_LOW,
        ALERT_SEVERITY_MEDIUM,
        ALERT_SEVERITY_HIGH,
        ALERT_SEVERITY_CRITICAL,
    }
)
ALERT_EMAIL_OFF = "off"
ALERT_EMAIL_STAFF = "staff"
ALERT_EMAIL_ADMINS = "admins"
ALERT_EMAIL_MODES = frozenset({ALERT_EMAIL_OFF, ALERT_EMAIL_STAFF, ALERT_EMAIL_ADMINS})
ALERT_QUEUE_PENDING = "pending"
ALERT_QUEUE_PROCESSING = "processing"
ALERT_QUEUE_PROCESSED = "processed"
ALERT_QUEUE_FAILED = "failed"
ALERT_QUEUE_STATUSES = frozenset(
    {ALERT_QUEUE_PENDING, ALERT_QUEUE_PROCESSING, ALERT_QUEUE_PROCESSED, ALERT_QUEUE_FAILED}
)
DELIVERY_CHANNEL_EMAIL = "email"
DELIVERY_CHANNEL_WEBHOOK = "webhook"
DELIVERY_CHANNELS = frozenset({DELIVERY_CHANNEL_EMAIL, DELIVERY_CHANNEL_WEBHOOK})
DELIVERY_PENDING = "pending"
DELIVERY_PROCESSING = "processing"
DELIVERY_SENT = "sent"
DELIVERY_FAILED = "failed"
DELIVERY_STATUSES = frozenset(
    {DELIVERY_PENDING, DELIVERY_PROCESSING, DELIVERY_SENT, DELIVERY_FAILED}
)
ROUTING_ALERT_CREATED = "alert_created"
ROUTING_ALERT_COALESCED = "alert_coalesced"
ROUTING_NO_NOTIFICATION = "no_notification"
ROUTING_RESULTS = frozenset({ROUTING_ALERT_CREATED, ROUTING_ALERT_COALESCED, ROUTING_NO_NOTIFICATION})
MAX_SUPPRESS_FOR_MINUTES = 43200
MAX_DELIVERY_ATTEMPTS = 5
DELIVERY_LEASE_SECONDS = 120
ALERT_ROUTE_BATCH_SIZE = 50
ALERT_DELIVERY_BATCH_SIZE = 25

DEFAULT_FINDING_RESOLUTION_CLEAN_SCANS = 2

PRIORITY_P1 = "p1"
PRIORITY_P2 = "p2"
PRIORITY_P3 = "p3"
PRIORITY_P4 = "p4"
PRIORITIES = frozenset({PRIORITY_P1, PRIORITY_P2, PRIORITY_P3, PRIORITY_P4})
PRIORITY_MODEL_VERSION = "2b.1"

TREATMENT_RECORD_MITIGATED = "mitigated"
TREATMENT_RECORD_ACCEPTED_RISK = "accepted_risk"
TREATMENT_RECORD_FALSE_POSITIVE = "false_positive"
TREATMENT_RECORD_TYPES = frozenset(
    {TREATMENT_RECORD_MITIGATED, TREATMENT_RECORD_ACCEPTED_RISK, TREATMENT_RECORD_FALSE_POSITIVE}
)

TREATMENT_STATUS_PENDING_REVIEW = "pending_review"
TREATMENT_STATUS_ACTIVE = "active"
TREATMENT_STATUS_EXPIRED = "expired"
TREATMENT_STATUS_REVOKED = "revoked"
TREATMENT_STATUS_SUPERSEDED = "superseded"
TREATMENT_STATUSES = frozenset(
    {
        TREATMENT_STATUS_PENDING_REVIEW,
        TREATMENT_STATUS_ACTIVE,
        TREATMENT_STATUS_EXPIRED,
        TREATMENT_STATUS_REVOKED,
        TREATMENT_STATUS_SUPERSEDED,
    }
)

TREATMENT_SOURCE_MANUAL = "manual"
TREATMENT_SOURCE_LEGACY_PROJECTION = "legacy_projection"
TREATMENT_SOURCES = frozenset({TREATMENT_SOURCE_MANUAL, TREATMENT_SOURCE_LEGACY_PROJECTION})

COMPENSATING_STATUS_ACTIVE = "active"
COMPENSATING_STATUS_RETIRED = "retired"
COMPENSATING_STATUSES = frozenset({COMPENSATING_STATUS_ACTIVE, COMPENSATING_STATUS_RETIRED})

CONTROL_REF_RELATED = "related"
CONTROL_REF_EVIDENCE = "evidence"
CONTROL_REF_SUPPORTS = "supports"
CONTROL_REFERENCE_TYPES = frozenset({CONTROL_REF_RELATED, CONTROL_REF_EVIDENCE, CONTROL_REF_SUPPORTS})

CONTROL_SUBJECT_ASSET = "asset"
CONTROL_SUBJECT_ASSET_FINDING = "asset_finding"
CONTROL_SUBJECT_FINDING = "finding"
CONTROL_SUBJECT_TREATMENT = "treatment"
CONTROL_SUBJECT_SCAN_JOB = "scan_job"
CONTROL_SUBJECT_TYPES = frozenset(
    {
        CONTROL_SUBJECT_ASSET,
        CONTROL_SUBJECT_ASSET_FINDING,
        CONTROL_SUBJECT_FINDING,
        CONTROL_SUBJECT_TREATMENT,
        CONTROL_SUBJECT_SCAN_JOB,
    }
)

POLICY_CATEGORY_ASSET_HANDLING = "asset_handling"
POLICY_CATEGORY_ASSET_INACTIVITY = "asset_inactivity"
POLICY_CATEGORY_FINDING_LIFECYCLE = "finding_lifecycle"
POLICY_CATEGORY_ALERTING = "alerting"
POLICY_CATEGORIES = frozenset(
    {
        POLICY_CATEGORY_ASSET_HANDLING,
        POLICY_CATEGORY_ASSET_INACTIVITY,
        POLICY_CATEGORY_FINDING_LIFECYCLE,
        POLICY_CATEGORY_ALERTING,
    }
)

POLICY_SCOPE_GLOBAL = "global"
POLICY_SCOPE_TENANT = "tenant"
POLICY_SCOPE_SITE = "site"
POLICY_SCOPE_NETWORK = "network"
POLICY_SCOPES = frozenset(
    {POLICY_SCOPE_GLOBAL, POLICY_SCOPE_TENANT, POLICY_SCOPE_SITE, POLICY_SCOPE_NETWORK}
)

TREATMENT_DISPLAY_UNADDRESSED = "unaddressed"
TREATMENT_DISPLAY_PENDING_REVIEW = "pending_review"
TREATMENT_DISPLAY_ACTIVE = "active"
TREATMENT_DISPLAY_REVIEW_DUE = "review_due"
TREATMENT_DISPLAY_REVIEW_OVERDUE = "review_overdue"
TREATMENT_DISPLAY_EXPIRED = "expired"
TREATMENT_DISPLAY_REVOKED = "revoked"
TREATMENT_DISPLAY_SUPERSEDED = "superseded"

LEGACY_TREATMENT_RATIONALE = (
    "Imported from pre-Phase-2C treatment projection; original rationale and reviewer were not recorded."
)

INTEL_SOURCE_NVD = "nvd"
INTEL_SOURCE_EPSS = "epss"
INTEL_SOURCE_CISA_KEV = "cisa_kev"
INTEL_SOURCES = frozenset({INTEL_SOURCE_NVD, INTEL_SOURCE_EPSS, INTEL_SOURCE_CISA_KEV})

CWE_PLACEHOLDERS = frozenset({"NVD-CWE-NOINFO", "NVD-CWE-OTHER"})
CUI_TAG_NORMALIZED = "cui"

COVERAGE_KIND_URL = "url"
COVERAGE_KIND_IP = "ip"
COVERAGE_KIND_IP_PORT = "ip_port"
COVERAGE_KIND_FQDN = "fqdn"
COVERAGE_KIND_CIDR = "cidr"
COVERAGE_KIND_OTHER = "other"
COVERAGE_KINDS = frozenset(
    {
        COVERAGE_KIND_URL,
        COVERAGE_KIND_IP,
        COVERAGE_KIND_IP_PORT,
        COVERAGE_KIND_FQDN,
        COVERAGE_KIND_CIDR,
        COVERAGE_KIND_OTHER,
    }
)
HOST_COVERAGE_KINDS = frozenset(
    {COVERAGE_KIND_URL, COVERAGE_KIND_IP, COVERAGE_KIND_IP_PORT, COVERAGE_KIND_FQDN}
)

WAN_TARGET_IP = "ip"
WAN_TARGET_CIDR = "cidr"
WAN_TARGET_FQDN = "fqdn"
WAN_TARGET_TYPES = frozenset({WAN_TARGET_IP, WAN_TARGET_CIDR, WAN_TARGET_FQDN})

PORT_MODE_NONE = "none"
PORT_MODE_COMMON = "common"
PORT_MODE_DEEP = "deep"
PORT_MODE_CUSTOM = "custom"
PORT_MODES = frozenset({PORT_MODE_NONE, PORT_MODE_COMMON, PORT_MODE_DEEP, PORT_MODE_CUSTOM})

INTENSITY_LOW = "low"
INTENSITY_NORMAL = "normal"
INTENSITY_HIGH = "high"
INTENSITY_CUSTOM = "custom"
INTENSITY_PRESETS = frozenset({INTENSITY_LOW, INTENSITY_NORMAL, INTENSITY_HIGH, INTENSITY_CUSTOM})

SCHEDULE_MANUAL = "manual"
SCHEDULE_DAILY = "daily"
SCHEDULE_WEEKLY = "weekly"
SCHEDULE_MONTHLY = "monthly"
SCHEDULE_CRON = "cron"
SCHEDULE_LEGACY_INTERVAL = "legacy_interval"
SCHEDULE_TYPES = frozenset(
    {
        SCHEDULE_MANUAL,
        SCHEDULE_DAILY,
        SCHEDULE_WEEKLY,
        SCHEDULE_MONTHLY,
        SCHEDULE_CRON,
        SCHEDULE_LEGACY_INTERVAL,
    }
)

TRIGGER_MANUAL = "manual"
TRIGGER_SCHEDULED = "scheduled"
TRIGGER_TYPES = frozenset({TRIGGER_MANUAL, TRIGGER_SCHEDULED})

JOB_QUEUED = "queued"
JOB_WAITING_FOR_AGENT = "waiting_for_agent"
JOB_RUNNING = "running"
JOB_DONE = "done"
JOB_FAILED = "failed"
JOB_MISSED = "missed"
JOB_STATUSES = frozenset(
    {JOB_QUEUED, JOB_WAITING_FOR_AGENT, JOB_RUNNING, JOB_DONE, JOB_FAILED, JOB_MISSED}
)

EXCLUSION_SCOPE_GLOBAL = "global"
EXCLUSION_SCOPE_TENANT = "tenant"
EXCLUSION_SCOPE_SITE = "site"
EXCLUSION_SCOPE_NETWORK = "network"
EXCLUSION_SCOPE_SCAN = "scan"
EXCLUSION_SCOPES = frozenset(
    {
        EXCLUSION_SCOPE_GLOBAL,
        EXCLUSION_SCOPE_TENANT,
        EXCLUSION_SCOPE_SITE,
        EXCLUSION_SCOPE_NETWORK,
        EXCLUSION_SCOPE_SCAN,
    }
)

EXCLUSION_IP = "ip"
EXCLUSION_CIDR = "cidr"
EXCLUSION_RANGE = "range"
EXCLUSION_TYPES = frozenset({EXCLUSION_IP, EXCLUSION_CIDR, EXCLUSION_RANGE})

AGENT_HEALTH_SECONDS = 90
DEFAULT_PREFERRED_AGENT_GRACE_SECONDS = 60
DEFAULT_AGENT_JOB_WAIT_MINUTES = 30

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
    viewer_all_tenants: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    viewer_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    viewer_tenant_grants: Mapped[list["ViewerTenantGrant"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="ViewerTenantGrant.user_id",
    )


class ViewerTenantGrant(Base):
    __tablename__ = "viewer_tenant_grants"
    __table_args__ = (
        Index("ix_viewer_tenant_grants_tenant_id", "tenant_id"),
        Index("ix_viewer_tenant_grants_user_id", "user_id"),
    )

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    granted_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User"] = relationship(
        back_populates="viewer_tenant_grants",
        foreign_keys=[user_id],
    )
    tenant: Mapped["Tenant"] = relationship()


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
    asset_findings: Mapped[list["AssetFinding"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    authorized_wan_targets: Mapped[list["AuthorizedWanTarget"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


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
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    scope: Mapped[str] = mapped_column(String(10))  # wan, lan
    profile: Mapped[str] = mapped_column(String(30), default="discovery")  # discovery, discovery_nuclei
    nuclei_severities: Mapped[str] = mapped_column(String(80), default="critical,high,medium")
    nuclei_tags: Mapped[str] = mapped_column(String(255), default="")
    subnet_ids: Mapped[list] = mapped_column(JSONB, default=list)
    interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    definition_revision: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    stage_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    intensity_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    schedule_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="scans")
    agent: Mapped["Agent | None"] = relationship(back_populates="scans")
    site: Mapped["Site | None"] = relationship()
    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    network_targets: Mapped[list["ScanNetworkTarget"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    wan_target_links: Mapped[list["ScanWanTarget"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint("scan_id", "scheduled_for", name="uq_scan_jobs_scan_id_scheduled_for"),
        Index("ix_scan_jobs_status_created_at", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    claimed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    snapshot_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    definition_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trigger_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_agent_id: Mapped[int | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    waiting_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wait_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    runtime_provenance: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="jobs")
    claimed_agent: Mapped["Agent | None"] = relationship()
    findings: Mapped[list["Finding"]] = relationship(back_populates="job")
    detector_coverage: Mapped[list["ScanRunDetectorCoverage"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class AuthorizedWanTarget(Base):
    __tablename__ = "authorized_wan_targets"
    __table_args__ = (
        CheckConstraint(
            "target_type IN ('ip', 'cidr', 'fqdn')",
            name="ck_authorized_wan_targets_type",
        ),
        Index("ix_authorized_wan_targets_tenant_id_normalized", "tenant_id", "normalized_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    target_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255))
    normalized_value: Mapped[str] = mapped_column(String(255))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="authorized_wan_targets")
    scan_links: Mapped[list["ScanWanTarget"]] = relationship(back_populates="wan_target")


class ScanNetworkTarget(Base):
    __tablename__ = "scan_network_targets"
    __table_args__ = (
        UniqueConstraint("scan_id", "network_id", name="uq_scan_network_targets_scan_id_network_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["Scan"] = relationship(back_populates="network_targets")
    network: Mapped["Network"] = relationship()


class ScanWanTarget(Base):
    __tablename__ = "scan_wan_targets"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "authorized_wan_target_id",
            name="uq_scan_wan_targets_scan_id_target_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    authorized_wan_target_id: Mapped[int] = mapped_column(
        ForeignKey("authorized_wan_targets.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["Scan"] = relationship(back_populates="wan_target_links")
    wan_target: Mapped["AuthorizedWanTarget"] = relationship(back_populates="scan_links")


class ScanExclusion(Base):
    __tablename__ = "scan_exclusions"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('global', 'tenant', 'site', 'network', 'scan')",
            name="ck_scan_exclusions_scope",
        ),
        CheckConstraint(
            "exclusion_type IN ('ip', 'cidr', 'range')",
            name="ck_scan_exclusions_type",
        ),
        CheckConstraint(
            "("
            "scope = 'global' AND tenant_id IS NULL AND site_id IS NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'tenant' AND tenant_id IS NOT NULL AND site_id IS NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'site' AND tenant_id IS NOT NULL AND site_id IS NOT NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'network' AND tenant_id IS NOT NULL AND site_id IS NOT NULL "
            "AND network_id IS NOT NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'scan' AND tenant_id IS NOT NULL AND scan_id IS NOT NULL"
            ")",
            name="ck_scan_exclusions_scope_keys",
        ),
        Index("ix_scan_exclusions_tenant_id_scope", "tenant_id", "scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(20))
    exclusion_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255))
    normalized_value: Mapped[str] = mapped_column(String(255))
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    network_id: Mapped[int | None] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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
    __table_args__ = (
        UniqueConstraint("evidence_key", name="uq_findings_evidence_key"),
        Index("ix_findings_asset_id_found_at", "asset_id", "found_at"),
        Index("ix_findings_asset_finding_id_found_at", "asset_finding_id", "found_at"),
        Index("ix_findings_scan_job_id_asset_finding_id", "scan_job_id", "asset_finding_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    detector_type: Mapped[str] = mapped_column(String(40), default="", server_default="")
    detector_key: Mapped[str] = mapped_column(String(200), default="", server_default="")
    evidence_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
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
    asset: Mapped["Asset | None"] = relationship()
    asset_finding: Mapped["AssetFinding | None"] = relationship(back_populates="evidence")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_id_dedupe_key_ack", "tenant_id", "dedupe_key", "is_acknowledged"),
        Index("ix_alerts_dashboard_open_severity", "dashboard_visible", "is_acknowledged", "severity"),
        Index("ix_alerts_tenant_id_severity_created_at", "tenant_id", "severity", "created_at"),
        Index("ix_alerts_domain_event_id", "domain_event_id"),
        Index("ix_alerts_asset_id", "asset_id"),
        Index("ix_alerts_asset_finding_id", "asset_finding_id"),
    )

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
    domain_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("domain_events.id", ondelete="SET NULL"), nullable=True
    )
    last_domain_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("domain_events.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    asset_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="SET NULL"), nullable=True
    )
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    policy_explanation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dashboard_visible: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    dedupe_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    first_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped["Tenant | None"] = relationship(back_populates="alerts")
    site: Mapped["Site | None"] = relationship()
    network: Mapped["Network | None"] = relationship()
    source_event: Mapped["DomainEvent | None"] = relationship(foreign_keys=[domain_event_id])
    last_event: Mapped["DomainEvent | None"] = relationship(foreign_keys=[last_domain_event_id])
    deliveries: Mapped[list["AlertDelivery"]] = relationship(back_populates="alert")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_id_created_at_id", "tenant_id", "created_at", "id"),
    )

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
    asset_findings: Mapped[list["AssetFinding"]] = relationship(back_populates="asset")
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
        Index("ix_domain_events_tenant_id_occurred_at_id", "tenant_id", "occurred_at", "id"),
        Index("ix_domain_events_site_id_event_type_occurred_at", "site_id", "event_type", "occurred_at"),
        Index("ix_domain_events_network_id_event_type_occurred_at", "network_id", "event_type", "occurred_at"),
        Index("ix_domain_events_asset_id_occurred_at", "asset_id", "occurred_at"),
        Index("ix_domain_events_asset_finding_id_occurred_at", "asset_finding_id", "occurred_at"),
        Index("ix_domain_events_scan_job_id", "scan_job_id"),
        Index("ix_domain_events_agent_id", "agent_id"),
        Index("ix_domain_events_treatment_id", "treatment_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    asset_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="SET NULL"), nullable=True
    )
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    treatment_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding_treatments.id", ondelete="SET NULL"), nullable=True
    )
    policy_rule_id: Mapped[int | None] = mapped_column(ForeignKey("policy_rules.id", ondelete="SET NULL"), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(40), default=SOURCE_SCANNER)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    idempotence_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset | None"] = relationship(back_populates="domain_events")
    site: Mapped["Site | None"] = relationship()
    network: Mapped["Network | None"] = relationship()
    alert_queue: Mapped["EventAlertQueue | None"] = relationship(back_populates="domain_event", uselist=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("canonical_key", name="uq_vulnerabilities_canonical_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(255), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    mappings: Mapped[list["VulnerabilityDetectorMapping"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    asset_findings: Mapped[list["AssetFinding"]] = relationship(back_populates="vulnerability")
    intelligence: Mapped["VulnerabilityIntelligence | None"] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", uselist=False
    )
    cwes: Mapped[list["VulnerabilityCwe"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    references: Mapped[list["VulnerabilityReference"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class VulnerabilityDetectorMapping(Base):
    __tablename__ = "vulnerability_detector_mappings"
    __table_args__ = (
        UniqueConstraint("detector_type", "detector_key", name="uq_vulnerability_detector_mappings_type_key"),
        Index("ix_vulnerability_detector_mappings_vulnerability_id", "vulnerability_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    detector_type: Mapped[str] = mapped_column(String(40))
    detector_key: Mapped[str] = mapped_column(String(200))
    last_severity: Mapped[str] = mapped_column(String(20), default="", server_default="")
    last_tags: Mapped[str] = mapped_column(String(500), default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="mappings")


class AssetFinding(Base):
    __tablename__ = "asset_findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "vulnerability_id", name="uq_asset_findings_asset_id_vulnerability_id"),
        CheckConstraint(
            "technical_state IN ('open', 'resolved')",
            name="ck_asset_findings_technical_state",
        ),
        CheckConstraint(
            "treatment_state IN ('unaddressed', 'mitigated', 'accepted_risk', 'false_positive')",
            name="ck_asset_findings_treatment_state",
        ),
        CheckConstraint(
            "priority IS NULL OR priority IN ('p1', 'p2', 'p3', 'p4')",
            name="ck_asset_findings_priority",
        ),
        Index("ix_asset_findings_tenant_id_technical_state", "tenant_id", "technical_state"),
        Index("ix_asset_findings_tenant_id_technical_state_priority", "tenant_id", "technical_state", "priority"),
        Index("ix_asset_findings_asset_id_technical_state", "asset_id", "technical_state"),
        Index("ix_asset_findings_vulnerability_id", "vulnerability_id"),
        Index("ix_asset_findings_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    technical_state: Mapped[str] = mapped_column(String(20), default=TECHNICAL_OPEN, server_default="open")
    treatment_state: Mapped[str] = mapped_column(String(32), default=TREATMENT_UNADDRESSED, server_default="unaddressed")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_clean_scans: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    reopened_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True)
    priority_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority_model_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    priority_explanation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    priority_calculated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="asset_findings")
    asset: Mapped["Asset"] = relationship(back_populates="asset_findings")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="asset_findings")
    evidence: Mapped[list["Finding"]] = relationship(back_populates="asset_finding")
    history: Mapped[list["AssetFindingHistory"]] = relationship(
        back_populates="asset_finding", cascade="all, delete-orphan"
    )
    evaluations: Mapped[list["AssetFindingRunEvaluation"]] = relationship(
        back_populates="asset_finding", cascade="all, delete-orphan"
    )
    treatments: Mapped[list["FindingTreatment"]] = relationship(
        back_populates="asset_finding", cascade="all, delete-orphan"
    )


class AssetFindingHistory(Base):
    __tablename__ = "asset_finding_history"
    __table_args__ = (
        UniqueConstraint("idempotence_key", name="uq_asset_finding_history_idempotence_key"),
        CheckConstraint(
            "transition_type IN ('opened', 'resolved', 'reopened')",
            name="ck_asset_finding_history_transition_type",
        ),
        Index("ix_asset_finding_history_asset_finding_id_occurred_at", "asset_finding_id", "occurred_at"),
        Index("ix_asset_finding_history_tenant_id_occurred_at", "tenant_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_finding_id: Mapped[int] = mapped_column(ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    transition_type: Mapped[str] = mapped_column(String(20))
    previous_technical_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    new_technical_state: Mapped[str] = mapped_column(String(20))
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    idempotence_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset_finding: Mapped["AssetFinding"] = relationship(back_populates="history")


class ScanRunDetectorCoverage(Base):
    __tablename__ = "scan_run_detector_coverage"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id",
            "detector_type",
            "target",
            name="uq_scan_run_detector_coverage_job_detector_target",
        ),
        CheckConstraint(
            "target_kind IN ('url', 'ip', 'ip_port', 'fqdn', 'cidr', 'other')",
            name="ck_scan_run_detector_coverage_target_kind",
        ),
        Index("ix_scan_run_detector_coverage_tenant_id", "tenant_id"),
        Index("ix_scan_run_detector_coverage_scan_job_id_detector_type", "scan_job_id", "detector_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    detector_type: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(500))
    normalized_host: Mapped[str] = mapped_column(String(255), default="", server_default="")
    target_kind: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job: Mapped["ScanJob"] = relationship(back_populates="detector_coverage")


class AssetFindingRunEvaluation(Base):
    __tablename__ = "asset_finding_run_evaluations"
    __table_args__ = (
        UniqueConstraint(
            "asset_finding_id",
            "scan_job_id",
            name="uq_asset_finding_run_evaluations_finding_job",
        ),
        CheckConstraint(
            "outcome IN ('detected', 'clean')",
            name="ck_asset_finding_run_evaluations_outcome",
        ),
        Index("ix_asset_finding_run_evaluations_scan_job_id", "scan_job_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_finding_id: Mapped[int] = mapped_column(ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    outcome: Mapped[str] = mapped_column(String(20))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset_finding: Mapped["AssetFinding"] = relationship(back_populates="evaluations")


class VulnerabilityIntelligence(Base):
    __tablename__ = "vulnerability_intelligence"
    __table_args__ = (
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_vulnerability_intelligence_epss_score",
        ),
        CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)",
            name="ck_vulnerability_intelligence_epss_percentile",
        ),
        CheckConstraint(
            "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)",
            name="ck_vulnerability_intelligence_cvss_base_score",
        ),
    )

    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    nvd_status: Mapped[str | None] = mapped_column(String(80), nullable=True)
    nvd_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    nvd_last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_base_score: Mapped[float | None] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_base_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric(12, 11), nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(12, 11), nullable=True)
    epss_score_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    epss_model_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_known_ransomware_campaign_use: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    kev_vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    nvd_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    epss_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="intelligence")


class VulnerabilityCwe(Base):
    __tablename__ = "vulnerability_cwes"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "cwe_id", "source", name="uq_vulnerability_cwes_vuln_cwe_source"),
        Index("ix_vulnerability_cwes_vulnerability_id", "vulnerability_id"),
        Index("ix_vulnerability_cwes_cwe_id", "cwe_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    cwe_id: Mapped[str] = mapped_column(String(40))
    source: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="cwes")


class VulnerabilityReference(Base):
    __tablename__ = "vulnerability_references"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "url", "source", name="uq_vulnerability_references_vuln_url_source"),
        Index("ix_vulnerability_references_vulnerability_id", "vulnerability_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2000))
    source: Mapped[str] = mapped_column(String(120), default="")
    tags: Mapped[list] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="references")


class VulnerabilityIntelligenceSync(Base):
    __tablename__ = "vulnerability_intelligence_sync"
    __table_args__ = (
        CheckConstraint(
            "source IN ('nvd', 'epss', 'cisa_kev')",
            name="ck_vulnerability_intelligence_sync_source",
        ),
    )

    source: Mapped[str] = mapped_column(String(40), primary_key=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_seen: Mapped[int | None] = mapped_column(Integer, nullable=True)
    records_updated: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, server_default=text("'{}'::jsonb"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingTreatment(Base):
    __tablename__ = "finding_treatments"
    __table_args__ = (
        CheckConstraint(
            "treatment_type IN ('mitigated', 'accepted_risk', 'false_positive')",
            name="ck_finding_treatments_treatment_type",
        ),
        CheckConstraint(
            "status IN ('pending_review', 'active', 'expired', 'revoked', 'superseded')",
            name="ck_finding_treatments_status",
        ),
        CheckConstraint(
            "source IN ('manual', 'legacy_projection')",
            name="ck_finding_treatments_source",
        ),
        Index("ix_finding_treatments_tenant_id", "tenant_id"),
        Index("ix_finding_treatments_asset_finding_id", "asset_finding_id"),
        Index("ix_finding_treatments_status", "status"),
        Index("ix_finding_treatments_expires_at", "expires_at"),
        Index("ix_finding_treatments_review_due_at", "review_due_at"),
        Index("ix_finding_treatments_status_expires_at", "status", "expires_at"),
        Index(
            "uq_finding_treatments_one_active",
            "asset_finding_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    asset_finding_id: Mapped[int] = mapped_column(ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True)
    treatment_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(Text)
    evidence_notes: Mapped[str] = mapped_column(Text, default="", server_default="")
    source: Mapped[str] = mapped_column(String(32), default=TREATMENT_SOURCE_MANUAL, server_default="manual")
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revoked_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset_finding: Mapped["AssetFinding"] = relationship(back_populates="treatments")
    compensating_controls: Mapped[list["CompensatingControl"]] = relationship(
        back_populates="treatment", cascade="all, delete-orphan"
    )


class CompensatingControl(Base):
    __tablename__ = "compensating_controls"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'retired')",
            name="ck_compensating_controls_status",
        ),
        Index("ix_compensating_controls_tenant_id", "tenant_id"),
        Index("ix_compensating_controls_treatment_id", "treatment_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    treatment_id: Mapped[int] = mapped_column(ForeignKey("finding_treatments.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    evidence_notes: Mapped[str] = mapped_column(Text, default="", server_default="")
    status: Mapped[str] = mapped_column(String(20), default=COMPENSATING_STATUS_ACTIVE, server_default="active")
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    retirement_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    treatment: Mapped["FindingTreatment"] = relationship(back_populates="compensating_controls")


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    __table_args__ = (UniqueConstraint("slug", "version", name="uq_compliance_frameworks_slug_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(80))
    publisher: Mapped[str] = mapped_column(String(255), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    source_url: Mapped[str] = mapped_column(String(2000), default="", server_default="")
    source_release_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    source_metadata: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    controls: Mapped[list["ComplianceControl"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_key", name="uq_compliance_controls_framework_id_control_key"),
        Index("ix_compliance_controls_framework_id", "framework_id"),
        Index("ix_compliance_controls_control_key", "control_key"),
        Index("ix_compliance_controls_family", "family"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), index=True)
    control_key: Mapped[str] = mapped_column(String(80))
    family: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(500), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    source_metadata: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    sort_order: Mapped[int | None] = mapped_column(Integer, nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    framework: Mapped["ComplianceFramework"] = relationship(back_populates="controls")


class ComplianceControlReference(Base):
    __tablename__ = "compliance_control_references"
    __table_args__ = (
        CheckConstraint(
            "("
            "(CASE WHEN asset_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN asset_finding_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN finding_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN treatment_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN scan_job_id IS NOT NULL THEN 1 ELSE 0 END)"
            ") = 1",
            name="ck_compliance_control_references_exactly_one_subject",
        ),
        CheckConstraint(
            "reference_type IN ('related', 'evidence', 'supports')",
            name="ck_compliance_control_references_reference_type",
        ),
        Index("ix_compliance_control_references_tenant_id", "tenant_id"),
        Index("ix_compliance_control_references_control_id", "control_id"),
        Index("ix_compliance_control_references_asset_id", "asset_id"),
        Index("ix_compliance_control_references_asset_finding_id", "asset_finding_id"),
        Index("ix_compliance_control_references_finding_id", "finding_id"),
        Index("ix_compliance_control_references_treatment_id", "treatment_id"),
        Index("ix_compliance_control_references_scan_job_id", "scan_job_id"),
        Index(
            "uq_compliance_control_references_active_asset_id",
            "control_id",
            "asset_id",
            unique=True,
            postgresql_where=text("asset_id IS NOT NULL AND removed_at IS NULL"),
        ),
        Index(
            "uq_compliance_control_references_active_asset_finding_id",
            "control_id",
            "asset_finding_id",
            unique=True,
            postgresql_where=text("asset_finding_id IS NOT NULL AND removed_at IS NULL"),
        ),
        Index(
            "uq_compliance_control_references_active_finding_id",
            "control_id",
            "finding_id",
            unique=True,
            postgresql_where=text("finding_id IS NOT NULL AND removed_at IS NULL"),
        ),
        Index(
            "uq_compliance_control_references_active_treatment_id",
            "control_id",
            "treatment_id",
            unique=True,
            postgresql_where=text("treatment_id IS NOT NULL AND removed_at IS NULL"),
        ),
        Index(
            "uq_compliance_control_references_active_scan_job_id",
            "control_id",
            "scan_job_id",
            unique=True,
            postgresql_where=text("scan_job_id IS NOT NULL AND removed_at IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("compliance_controls.id", ondelete="RESTRICT"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    asset_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="CASCADE"), nullable=True
    )
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    treatment_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding_treatments.id", ondelete="CASCADE"), nullable=True
    )
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True)
    reference_type: Mapped[str] = mapped_column(String(20), default=CONTROL_REF_RELATED, server_default="related")
    notes: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    removal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    control: Mapped["ComplianceControl"] = relationship()


class PolicyRule(Base):
    __tablename__ = "policy_rules"
    __table_args__ = (
        CheckConstraint(
            "category IN ('asset_handling', 'asset_inactivity', 'finding_lifecycle', 'alerting')",
            name="ck_policy_rules_category",
        ),
        CheckConstraint(
            "scope_type IN ('global', 'tenant', 'site', 'network')",
            name="ck_policy_rules_scope_type",
        ),
        CheckConstraint(
            "("
            "(scope_type = 'global' AND tenant_id IS NULL AND site_id IS NULL AND network_id IS NULL) OR "
            "(scope_type = 'tenant' AND tenant_id IS NOT NULL AND site_id IS NULL AND network_id IS NULL) OR "
            "(scope_type = 'site' AND tenant_id IS NOT NULL AND site_id IS NOT NULL AND network_id IS NULL) OR "
            "(scope_type = 'network' AND tenant_id IS NOT NULL AND site_id IS NOT NULL AND network_id IS NOT NULL)"
            ")",
            name="ck_policy_rules_scope_shape",
        ),
        CheckConstraint("revision >= 1", name="ck_policy_rules_revision"),
        Index("ix_policy_rules_category_enabled_archived", "category", "enabled", "archived_at"),
        Index("ix_policy_rules_scope_lookup", "scope_type", "tenant_id", "site_id", "network_id"),
        Index("ix_policy_rules_category_scope_tenant", "category", "scope_type", "tenant_id"),
        Index(
            "ix_policy_rules_enabled_archived_category_priority",
            "enabled",
            "archived_at",
            "category",
            "priority",
        ),
        Index("ix_policy_rules_tenant_id", "tenant_id"),
        Index("ix_policy_rules_site_id", "site_id"),
        Index("ix_policy_rules_network_id", "network_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    category: Mapped[str] = mapped_column(String(40))
    scope_type: Mapped[str] = mapped_column(String(20))
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), nullable=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    conditions: Mapped[list] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    actions: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    archive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped["Tenant | None"] = relationship()
    site: Mapped["Site | None"] = relationship()
    network: Mapped["Network | None"] = relationship()


class EventAlertQueue(Base):
    __tablename__ = "event_alert_queue"
    __table_args__ = (
        UniqueConstraint("domain_event_id", name="uq_event_alert_queue_domain_event_id"),
        Index("ix_event_alert_queue_pending", "status", "next_attempt_at"),
        CheckConstraint(
            "status IN ('pending', 'processing', 'processed', 'failed')",
            name="ck_event_alert_queue_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_event_id: Mapped[int] = mapped_column(ForeignKey("domain_events.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(20), default=ALERT_QUEUE_PENDING, server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    domain_event: Mapped["DomainEvent"] = relationship(back_populates="alert_queue")


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    __table_args__ = (
        UniqueConstraint("alert_id", "channel", name="uq_alert_deliveries_alert_id_channel"),
        Index("ix_alert_deliveries_pending", "status", "next_attempt_at"),
        Index("ix_alert_deliveries_alert_id", "alert_id"),
        CheckConstraint(
            "channel IN ('email', 'webhook')",
            name="ck_alert_deliveries_channel",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'sent', 'failed')",
            name="ck_alert_deliveries_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    channel: Mapped[str] = mapped_column(String(20))
    destination: Mapped[str] = mapped_column(String(500), default="", server_default="")
    status: Mapped[str] = mapped_column(String(20), default=DELIVERY_PENDING, server_default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert: Mapped["Alert"] = relationship(back_populates="deliveries")


class AlertEventRoute(Base):
    __tablename__ = "alert_event_routes"
    __table_args__ = (
        UniqueConstraint("domain_event_id", name="uq_alert_event_routes_domain_event_id"),
        Index("ix_alert_event_routes_alert_id", "alert_id"),
        CheckConstraint(
            "routing_result IN ('alert_created', 'alert_coalesced', 'no_notification')",
            name="ck_alert_event_routes_result",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_event_id: Mapped[int] = mapped_column(ForeignKey("domain_events.id", ondelete="CASCADE"))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    routing_result: Mapped[str] = mapped_column(String(40))
    effective_actions: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    policy_explanation: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    domain_event: Mapped["DomainEvent"] = relationship()
    alert: Mapped["Alert | None"] = relationship()
