from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field

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


class SubnetOut(BaseModel):
    id: int
    tenant_id: int
    name: str
    cidr: str
    scope: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentCreate(BaseModel):
    name: str


class AgentOut(BaseModel):
    id: int
    tenant_id: int
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
    profile: str = Field(default="discovery", pattern="^(discovery|discovery_nuclei)$")
    nuclei_severities: str = "critical,high,medium"
    nuclei_tags: str = ""
    subnet_ids: list[int] = []
    interval_minutes: int | None = None
    is_enabled: bool = True


class ScanOut(BaseModel):
    id: int
    tenant_id: int
    agent_id: int | None
    name: str
    scope: str
    profile: str
    nuclei_severities: str
    nuclei_tags: str
    subnet_ids: list[Any]
    interval_minutes: int | None
    is_enabled: bool
    last_scheduled_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanJobOut(BaseModel):
    id: int
    scan_id: int
    tenant_id: int
    status: str
    claimed_by: str | None
    error: str | None
    hosts_found: int
    findings_count: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    scan_name: str | None = None
    scope: str | None = None

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: int
    tenant_id: int
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
    default_nuclei_severities: str = "critical,high,medium"


class SettingsIn(SettingsOut):
    pass


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


class FindingReport(BaseModel):
    template_id: str = ""
    name: str = ""
    severity: str = "info"
    host: str = ""
    matched_at: str = ""
    tags: str = ""
    timestamp: str | None = None
    raw: dict[str, Any] = {}
