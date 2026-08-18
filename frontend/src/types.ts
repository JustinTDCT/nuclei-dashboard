export type Role = "admin" | "user" | "viewer";

export interface StaffUser {
  id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface Tenant {
  id: number;
  name: string;
  notes: string;
  created_at: string;
}

export interface Subnet {
  id: number;
  tenant_id: number;
  name: string;
  cidr: string;
  scope: "wan" | "lan";
  site_id?: number | null;
  network_id?: number | null;
  created_at: string;
}

export interface Site {
  id: number;
  tenant_id: number;
  name: string;
  timezone: string | null;
  archived_at: string | null;
  is_archived: boolean;
  created_at: string;
  effective_timezone: string;
  network_count: number;
  agent_count: number;
  tags?: Tag[];
}

export interface Network {
  id: number;
  tenant_id: number;
  site_id: number;
  name: string;
  cidr: string;
  dispatch_mode: "any_available" | "preferred_failover";
  preferred_agent_id: number | null;
  archived_at: string | null;
  is_archived: boolean;
  created_at: string;
  subnet_id: number | null;
  authorized_agent_ids: number[];
  tags?: Tag[];
}

export interface Agent {
  id: number;
  tenant_id: number;
  site_id: number;
  site_name?: string | null;
  name: string;
  uuid: string;
  status: string;
  hostname: string | null;
  container_id: string | null;
  last_ip: string | null;
  last_heartbeat: string | null;
  created_at: string;
  approved_at: string | null;
  enrollment_secret: string | null;
  online: boolean;
}

export interface Scan {
  id: number;
  tenant_id: number;
  agent_id: number | null;
  name: string;
  scope: "wan" | "lan";
  profile: "discovery" | "discovery_nuclei";
  nuclei_severities: string;
  nuclei_tags: string;
  subnet_ids: number[];
  interval_minutes: number | null;
  is_enabled: boolean;
  last_scheduled_at: string | null;
  created_at: string;
}

export interface ScanJob {
  id: number;
  scan_id: number;
  tenant_id: number;
  status: string;
  claimed_by: string | null;
  error: string | null;
  hosts_found: number;
  findings_count: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scan_name?: string | null;
  scope?: string | null;
}

export interface Tag {
  id: number;
  tenant_id: number;
  name: string;
  created_at: string;
}

export interface Device {
  id: number;
  tenant_id: number;
  ip: string;
  hostname: string;
  scope: string;
  status: string;
  classification: string;
  description: string;
  auto_label: string;
  title: string;
  tech: string;
  ports: number[];
  first_seen: string;
  last_seen: string;
  asset_id?: number | null;
  findings_count?: number;
}

export interface Asset {
  id: number;
  tenant_id: number;
  site_id: number | null;
  site_name?: string | null;
  merged_into_asset_id?: number | null;
  display_name: string;
  hostname?: string | null;
  current_addresses: string[];
  classification: string;
  description: string;
  lifecycle_state: string | null;
  disposition: string;
  criticality: string;
  is_expected: boolean;
  is_not_yet_observed: boolean;
  first_seen: string | null;
  last_seen: string | null;
  tags: Tag[];
  findings_count: number;
  created_at: string;
}

export interface AssetIdentifier {
  id: number;
  asset_id: number;
  identifier_type: string;
  value: string;
  normalized_value: string;
  source: string;
  validity?: string;
  first_seen: string | null;
  last_seen: string | null;
  corrected_at?: string | null;
  correction_reason?: string;
  replacement_identifier_id?: number | null;
  created_at: string;
}

export interface AssetAddress {
  id: number;
  asset_id: number;
  site_id: number | null;
  network_id: number | null;
  ip: string;
  address_family: string;
  source: string;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
}

export interface AssetService {
  id: number;
  asset_id: number;
  address_id: number | null;
  ip: string;
  port: number;
  protocol: string;
  product: string;
  version: string;
  tls_metadata: Record<string, unknown>;
  web_title: string;
  tech: string;
  source: string;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
}

export interface AssetObservation {
  id: number;
  asset_id: number;
  tenant_id: number;
  site_id: number | null;
  network_id: number | null;
  agent_id: number | null;
  scan_job_id: number | null;
  scope: string;
  source: string;
  observed_at: string;
  hostname: string;
  ip: string;
  snapshot: Record<string, unknown>;
  provenance: string;
  created_at: string;
}

export interface CorrelationDecision {
  id: number;
  tenant_id: number;
  site_id: number | null;
  scan_job_id: number | null;
  observation_key: string;
  selected_asset_id: number | null;
  decision: string;
  confidence: string;
  score: number;
  algorithm_version: string;
  evidence: { label: string; contribution: number; polarity?: string }[];
  candidates: {
    asset_id: number;
    display_name: string;
    score: number;
    confidence: string;
    evidence?: { label: string; contribution: number }[];
  }[];
  created_at: string;
}

export interface DomainEvent {
  id: number;
  event_type: string;
  tenant_id: number;
  site_id: number | null;
  asset_id: number | null;
  occurred_at: string;
  source: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface AssetDetail extends Asset {
  identifiers: AssetIdentifier[];
  addresses: AssetAddress[];
  services: AssetService[];
  device_ids: number[];
  findings: Finding[];
  latest_correlation?: CorrelationDecision | null;
  recent_events?: DomainEvent[];
  possible_matches?: CorrelationDecision["candidates"];
}

export interface HistoryPage<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceDetail extends Device {
  findings: Finding[];
}

export interface Finding {
  id: number;
  tenant_id: number;
  scan_job_id: number | null;
  device_id: number | null;
  hostname?: string;
  ip?: string;
  template_id: string;
  name: string;
  severity: string;
  host: string;
  matched_at: string;
  tags: string;
  found_at: string;
}

export interface AlertItem {
  id: number;
  tenant_id: number | null;
  type: string;
  title: string;
  body: string;
  is_acknowledged: boolean;
  device_id: number | null;
  agent_id: number | null;
  created_at: string;
}

export interface Settings {
  central_host: string;
  central_port: number;
  central_tls: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_password: string;
  smtp_from: string;
  smtp_tls: boolean;
  stale_days: number;
  asset_inactive_days: number;
  default_nuclei_severities: string;
  default_timezone: string;
}

export interface Dashboard {
  tenants: number;
  users: number;
  open_alerts: number;
  new_devices: number;
  agents: { total: number; pending: number; online: number };
  findings: Record<string, number>;
  recent_alerts: AlertItem[];
  recent_jobs: ScanJob[];
}

export interface TenantSummary {
  devices: { new: number; known: number; stale: number };
  assets?: { total: number; unreviewed: number; expected: number };
  findings: Record<string, number>;
  agents: { total: number; pending: number; approved: number; online: number };
  open_alerts: number;
  recent_jobs: ScanJob[];
}
