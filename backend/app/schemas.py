from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator

DEVICE_CLASSES = (
    "Unknown",
    "Desktop",
    "Laptop",
    "Server",
    "Server Management",
    "Virtual Server",
    "Virtual Host",
    "Switch",
    "Router / Firewall",
    "Print Server (non server)",
    "Access Point",
    "IoT Device",
    "UPS",
    "Other",
)


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = Field(pattern="^(admin|user|viewer)$")


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=8)
    role: str | None = Field(default=None, pattern="^(admin|user|viewer)$")
    is_active: bool | None = None


class TenantIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    notes: str = ""


class TenantOut(BaseModel):
    id: int
    name: str
    notes: str
    created_at: datetime

    model_config = {"from_attributes": True}


class SubnetIn(BaseModel):
    name: str
    cidr: str
    scope: str = Field(pattern="^(wan|lan)$")
    site_id: int | None = None


class SubnetOut(BaseModel):
    id: int
    tenant_id: int
    name: str
    cidr: str
    scope: str
    site_id: int | None = None
    network_id: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SiteIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    timezone: str | None = None


class SiteOut(BaseModel):
    id: int
    tenant_id: int
    name: str
    timezone: str | None
    archived_at: datetime | None
    is_archived: bool = False
    created_at: datetime
    effective_timezone: str = "UTC"
    network_count: int = 0
    agent_count: int = 0
    tags: list["TagOut"] = []

    model_config = {"from_attributes": True}


class NetworkIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    cidr: str
    dispatch_mode: str = Field(default="any_available", pattern="^(any_available|preferred_failover)$")
    preferred_agent_id: int | None = None


class NetworkOut(BaseModel):
    id: int
    tenant_id: int
    site_id: int
    name: str
    cidr: str
    dispatch_mode: str
    preferred_agent_id: int | None
    archived_at: datetime | None
    is_archived: bool = False
    created_at: datetime
    subnet_id: int | None = None
    authorized_agent_ids: list[int] = []
    tags: list["TagOut"] = []

    model_config = {"from_attributes": True}


class NetworkAuthorizationIn(BaseModel):
    agent_ids: list[int]


class AgentCreate(BaseModel):
    name: str
    site_id: int


class AgentUpdate(BaseModel):
    name: str | None = None
    site_id: int | None = None


class AgentOut(BaseModel):
    id: int
    tenant_id: int
    site_id: int
    site_name: str | None = None
    name: str
    uuid: str
    status: str
    hostname: str | None
    container_id: str | None
    last_ip: str | None
    last_heartbeat: datetime | None
    created_at: datetime
    approved_at: datetime | None
    enrollment_secret: str | None = None
    online: bool = False

    model_config = {"from_attributes": True}


class ScanIn(BaseModel):
    name: str
    scope: str = Field(pattern="^(wan|lan)$")
    agent_id: int | None = None
    site_id: int | None = None
    profile: str = Field(default="discovery", pattern="^(discovery|discovery_nuclei)$")
    nuclei_severities: str = "critical,high,medium"
    nuclei_tags: str = ""
    subnet_ids: list[int] = []
    network_ids: list[int] = []
    wan_target_ids: list[int] = []
    interval_minutes: int | None = None
    is_enabled: bool = True
    stage_config: dict[str, Any] | None = None
    intensity_config: dict[str, Any] | None = None
    schedule_config: dict[str, Any] | None = None


class ScanOut(BaseModel):
    id: int
    tenant_id: int
    agent_id: int | None
    site_id: int | None = None
    name: str
    scope: str
    profile: str
    nuclei_severities: str
    nuclei_tags: str
    subnet_ids: list[Any]
    network_ids: list[int] = []
    wan_target_ids: list[int] = []
    interval_minutes: int | None
    is_enabled: bool
    last_scheduled_at: datetime | None
    next_run_at: datetime | None = None
    definition_revision: int = 1
    stage_config: dict[str, Any] = {}
    intensity_config: dict[str, Any] = {}
    schedule_config: dict[str, Any] = {}
    archived_at: datetime | None = None
    needs_review: bool = False
    dispatch_summary: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanJobOut(BaseModel):
    id: int
    scan_id: int
    tenant_id: int
    status: str
    claimed_by: str | None
    claimed_agent_id: int | None = None
    error: str | None
    hosts_found: int
    findings_count: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    scan_name: str | None = None
    scope: str | None = None
    trigger_type: str | None = None
    scheduled_for: datetime | None = None
    definition_revision: int | None = None
    snapshot_version: str | None = None
    waiting_since: datetime | None = None
    wait_expires_at: datetime | None = None
    execution_snapshot: dict[str, Any] | None = None
    runtime_provenance: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class AuthorizedWanTargetIn(BaseModel):
    name: str = ""
    target_type: str = Field(pattern="^(ip|cidr|fqdn)$")
    value: str = Field(min_length=1, max_length=255)


class AuthorizedWanTargetOut(BaseModel):
    id: int
    tenant_id: int
    name: str
    target_type: str
    value: str
    normalized_value: str
    archived_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanExclusionIn(BaseModel):
    scope: str = Field(pattern="^(global|tenant|site|network|scan)$")
    exclusion_type: str = Field(pattern="^(ip|cidr|range)$")
    value: str = Field(min_length=1, max_length=255)
    tenant_id: int | None = None
    site_id: int | None = None
    network_id: int | None = None
    scan_id: int | None = None


class ScanExclusionOut(BaseModel):
    id: int
    scope: str
    exclusion_type: str
    value: str
    normalized_value: str
    tenant_id: int | None
    site_id: int | None
    network_id: int | None
    scan_id: int | None
    archived_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: int
    tenant_id: int
    site_id: int | None = None
    ip: str
    hostname: str = ""
    scope: str
    status: str
    classification: str
    description: str = ""
    auto_label: str
    title: str
    tech: str
    ports: list[Any]
    first_seen: datetime
    last_seen: datetime
    asset_id: int | None = None
    findings_count: int = 0

    model_config = {"from_attributes": True}


class DeviceUpdate(BaseModel):
    classification: str | None = None
    description: str | None = None
    status: str | None = Field(default=None, pattern="^(new|known|stale)$")


class FindingOut(BaseModel):
    id: int
    tenant_id: int
    scan_job_id: int | None
    device_id: int | None
    asset_id: int | None = None
    asset_finding_id: int | None = None
    detector_type: str = ""
    detector_key: str = ""
    hostname: str = ""
    ip: str = ""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    tags: str
    found_at: datetime
    raw_json: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class DeviceDetail(DeviceOut):
    findings: list[FindingOut] = []


class AlertOut(BaseModel):
    id: int
    tenant_id: int | None
    type: str
    title: str
    body: str
    is_acknowledged: bool
    device_id: int | None
    agent_id: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class SettingsOut(BaseModel):
    central_host: str = ""
    central_port: int = 8118
    central_tls: bool = True
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True
    stale_days: int = 14
    asset_inactive_days: int = 30
    default_nuclei_severities: str = "critical,high,medium"
    default_timezone: str = "UTC"
    preferred_agent_grace_seconds: int = 60
    agent_job_wait_minutes: int = 30
    scan_cap_naabu_rate: int = 5000
    scan_cap_naabu_concurrency: int = 100
    scan_cap_naabu_timeout_ms: int = 10000
    scan_cap_naabu_retries: int = 5
    scan_cap_httpx_rate: int = 500
    scan_cap_httpx_threads: int = 150
    scan_cap_httpx_timeout: int = 30
    scan_cap_httpx_retries: int = 5
    scan_cap_nuclei_rate: int = 500
    scan_cap_nuclei_concurrency: int = 100
    scan_cap_nuclei_timeout: int = 30
    scan_cap_nuclei_retries: int = 5
    finding_resolution_clean_scans: int = 2

    @field_validator("finding_resolution_clean_scans")
    @classmethod
    def _positive_clean_scans(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("finding_resolution_clean_scans must be a positive integer")
        return value


class DisplaySettingsOut(BaseModel):
    default_timezone: str = "UTC"


class SettingsIn(SettingsOut):
    pass


class AssetFindingOut(BaseModel):
    id: int
    tenant_id: int
    asset_id: int
    asset_hostname: str = ""
    asset_display_name: str = ""
    vulnerability_id: int
    canonical_key: str
    cve_id: str | None = None
    title: str
    identity_label: str
    severity: str
    technical_state: str
    treatment_state: str
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    consecutive_clean_scans: int
    reopened_count: int
    evidence_count: int = 0
    created_at: datetime
    updated_at: datetime


class AssetFindingHistoryOut(BaseModel):
    id: int
    asset_finding_id: int
    tenant_id: int
    transition_type: str
    previous_technical_state: str | None = None
    new_technical_state: str
    scan_job_id: int | None = None
    occurred_at: datetime
    details: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class AssetFindingDetail(AssetFindingOut):
    description: str = ""
    detector_type: str = ""
    detector_key: str = ""
    history: list[AssetFindingHistoryOut] = []
    evidence: list[FindingOut] = []


class EnrollIn(BaseModel):
    uuid: str
    enrollment_secret: str
    public_key: str
    hostname: str = ""
    container_id: str = ""


class AgentTokenIn(BaseModel):
    uuid: str
    nonce: str
    signature: str


class DeviceReport(BaseModel):
    ip: str
    scope: str
    hostname: str = ""
    classification: str = ""
    ports: list[Any] = []
    title: str = ""
    tech: str = ""
    auto_label: str = ""
    mac: str = ""
    serial: str = ""
    device_identifier: str = ""
    fqdn: str = ""
    tls_name: str = ""
    dns_name: str = ""


class FindingReport(BaseModel):
    template_id: str = ""
    name: str = ""
    severity: str = "info"
    host: str = ""
    matched_at: str = ""
    tags: str = ""
    timestamp: str | None = None
    raw: dict[str, Any] = {}


class DetectorCoverageIn(BaseModel):
    detector_type: str = "nuclei"
    targets: list[str] = []

    @field_validator("detector_type")
    @classmethod
    def _detector_type(cls, value: str) -> str:
        token = (value or "").strip().lower()
        if not token:
            raise ValueError("detector_type is required")
        return token


class TagOut(BaseModel):
    id: int
    tenant_id: int
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TagIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class TagAssignIn(BaseModel):
    tag_id: int | None = None
    name: str | None = Field(default=None, max_length=80)


class AssetListItem(BaseModel):
    id: int
    tenant_id: int
    site_id: int | None
    site_name: str | None = None
    merged_into_asset_id: int | None = None
    display_name: str
    hostname: str | None = None
    current_addresses: list[str] = []
    classification: str
    description: str = ""
    lifecycle_state: str | None = None
    disposition: str
    criticality: str
    is_expected: bool
    is_not_yet_observed: bool = False
    first_seen: datetime | None
    last_seen: datetime | None
    tags: list[TagOut] = []
    findings_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetIdentifierOut(BaseModel):
    id: int
    asset_id: int
    identifier_type: str
    value: str
    normalized_value: str
    source: str
    validity: str = "active"
    first_seen: datetime | None
    last_seen: datetime | None
    corrected_at: datetime | None = None
    correction_reason: str = ""
    replacement_identifier_id: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetAddressOut(BaseModel):
    id: int
    asset_id: int
    site_id: int | None
    network_id: int | None
    ip: str
    address_family: str
    source: str
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetServiceOut(BaseModel):
    id: int
    asset_id: int
    address_id: int | None
    ip: str
    port: int
    protocol: str
    product: str
    version: str
    tls_metadata: dict[str, Any] = {}
    web_title: str
    tech: str
    source: str
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetObservationOut(BaseModel):
    id: int
    asset_id: int
    tenant_id: int
    site_id: int | None
    network_id: int | None
    agent_id: int | None
    scan_job_id: int | None
    scope: str
    source: str
    observed_at: datetime
    hostname: str
    ip: str
    snapshot: dict[str, Any] = {}
    observation_key: str = ""
    provenance: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CorrelationEvidenceItem(BaseModel):
    label: str
    contribution: int
    polarity: str = "plus"


class CorrelationCandidateOut(BaseModel):
    asset_id: int
    display_name: str
    score: int
    confidence: str
    blocked: bool = False
    block_reason: str = ""
    evidence: list[CorrelationEvidenceItem] = []


class CorrelationDecisionOut(BaseModel):
    id: int
    tenant_id: int
    site_id: int | None
    scan_job_id: int | None
    observation_key: str
    selected_asset_id: int | None
    decision: str
    confidence: str
    score: int
    algorithm_version: str
    evidence: list[Any] = []
    candidates: list[Any] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class DomainEventOut(BaseModel):
    id: int
    event_type: str
    tenant_id: int
    site_id: int | None
    asset_id: int | None
    occurred_at: datetime
    source: str
    details: dict[str, Any] = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetDetail(AssetListItem):
    identifiers: list[AssetIdentifierOut] = []
    addresses: list[AssetAddressOut] = []
    services: list[AssetServiceOut] = []
    device_ids: list[int] = []
    findings: list[FindingOut] = []
    latest_correlation: CorrelationDecisionOut | None = None
    recent_events: list[DomainEventOut] = []
    possible_matches: list[Any] = []


class AssetMergeIn(BaseModel):
    source_asset_ids: list[int]
    reason: str = ""


class AssetSplitIn(BaseModel):
    observation_ids: list[int]
    reason: str = ""


class AssetReassociateIn(BaseModel):
    target_asset_id: int
    reason: str = ""


class AssetIdentifierCorrectIn(BaseModel):
    reason: str = ""
    replacement_value: str = ""
    replacement_type: str | None = None


class AssetMoveSiteIn(BaseModel):
    site_id: int
    reason: str = ""


class AssetCreate(BaseModel):
    site_id: int
    display_name: str = Field(min_length=1, max_length=255)
    hostname: str = ""
    mac: str = ""
    ip: str = ""
    classification: str = "Unknown"
    description: str = ""
    criticality: str = "normal"
    disposition: str = "unreviewed"
    tags: list[str] = []


class AssetUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    classification: str | None = None
    description: str | None = None
    lifecycle_state: str | None = None
    disposition: str | None = None
    criticality: str | None = None


class HistoryPage(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


SiteOut.model_rebuild()
NetworkOut.model_rebuild()
AssetListItem.model_rebuild()
AssetDetail.model_rebuild()
