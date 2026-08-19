export type Role = "admin" | "user" | "viewer";

export interface StaffUser {
  id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  viewer_all_tenants?: boolean;
  viewer_expires_at?: string | null;
  viewer_tenant_ids?: number[];
  viewer_access_status?: "not_applicable" | "disabled" | "expired" | "all_tenants" | "selected" | "none";
  has_tenant_access?: boolean;
}

export interface ReportCatalogItem {
  key: string;
  display_name: string;
  description: string;
  supported_formats: string[];
  supported_filters: { key: string; label: string; kind: string; required: boolean }[];
}

export interface ReportPreview {
  key: string;
  title: string;
  description: string;
  generated_at: string;
  timezone: string;
  scope: string;
  summary: Record<string, unknown>;
  columns: string[];
  rows: Record<string, unknown>[];
  page: number;
  page_size: number;
  total: number;
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
  runtime_inventory?: Record<string, string> | null;
  runtime_inventory_reported_at?: string | null;
  version_status?: string;
  version_comparison?: {
    overall?: string;
    fields?: Record<string, { approved?: string | null; installed?: string | null; status?: string }>;
  } | null;
  created_at: string;
  approved_at: string | null;
  enrollment_secret: string | null;
  online: boolean;
}

export interface Scan {
  id: number;
  tenant_id: number;
  agent_id: number | null;
  site_id?: number | null;
  name: string;
  scope: "wan" | "lan";
  profile: "discovery" | "discovery_nuclei";
  nuclei_severities: string;
  nuclei_tags: string;
  subnet_ids: number[];
  network_ids?: number[];
  wan_target_ids?: number[];
  interval_minutes: number | null;
  is_enabled: boolean;
  last_scheduled_at: string | null;
  next_run_at?: string | null;
  definition_revision?: number;
  stage_config?: Record<string, unknown>;
  intensity_config?: Record<string, unknown>;
  schedule_config?: Record<string, unknown>;
  archived_at?: string | null;
  needs_review?: boolean;
  dispatch_summary?: {
    mode?: string;
    preferred_agent_id?: number | null;
    eligible_agent_ids?: number[];
    failover_count?: number;
  } | null;
  created_at: string;
  updated_at?: string | null;
}

export interface ScanJob {
  id: number;
  scan_id: number;
  tenant_id: number;
  status: string;
  claimed_by: string | null;
  claimed_agent_id?: number | null;
  error: string | null;
  hosts_found: number;
  findings_count: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scan_name?: string | null;
  scope?: string | null;
  trigger_type?: string | null;
  scheduled_for?: string | null;
  definition_revision?: number | null;
  snapshot_version?: string | null;
  waiting_since?: string | null;
  wait_expires_at?: string | null;
  execution_snapshot?: Record<string, unknown> | null;
  runtime_provenance?: Record<string, unknown> | null;
}

export interface ScanArtifact {
  id: number;
  scan_job_id: number;
  tenant_id: number;
  artifact_key: string;
  tool: string;
  stage: string;
  media_type: string;
  content_encoding: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
  retention_expires_at: string;
  deleted_at: string | null;
  delete_reason: string | null;
  status: "available" | "expired" | "unavailable";
  available: boolean;
  provenance: Record<string, unknown>;
  download_filename: string;
}

export interface AuthorizedWanTarget {
  id: number;
  tenant_id: number;
  name: string;
  target_type: "ip" | "cidr" | "fqdn";
  value: string;
  normalized_value: string;
  archived_at: string | null;
  created_at: string;
}

export interface ScanExclusion {
  id: number;
  scope: "global" | "tenant" | "site" | "network" | "scan";
  exclusion_type: "ip" | "cidr" | "range";
  value: string;
  normalized_value: string;
  tenant_id: number | null;
  site_id: number | null;
  network_id: number | null;
  scan_id: number | null;
  archived_at: string | null;
  created_at: string;
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
  asset_id?: number | null;
  asset_finding_id?: number | null;
  detector_type?: string;
  detector_key?: string;
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

export interface AssetFinding {
  id: number;
  tenant_id: number;
  asset_id: number;
  asset_hostname: string;
  asset_display_name: string;
  vulnerability_id: number;
  canonical_key: string;
  cve_id: string | null;
  title: string;
  identity_label: string;
  severity: string;
  technical_state: "open" | "resolved" | string;
  treatment_state: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  consecutive_clean_scans: number;
  reopened_count: number;
  evidence_count?: number;
  priority?: "p1" | "p2" | "p3" | "p4" | null;
  priority_score?: number | null;
  priority_model_version?: string | null;
  cvss_version?: string | null;
  cvss_base_score?: number | null;
  cvss_base_severity?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  epss_score_date?: string | null;
  kev?: boolean | null;
  kev_date_added?: string | null;
  cwe_ids?: string[];
  treatment_display_status?: string;
  treatment_review_due_at?: string | null;
  treatment_expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetFindingHistory {
  id: number;
  asset_finding_id: number;
  tenant_id: number;
  transition_type: string;
  previous_technical_state: string | null;
  new_technical_state: string;
  scan_job_id: number | null;
  occurred_at: string;
  details?: Record<string, unknown>;
}

export interface PriorityFactor {
  factor: string;
  value?: unknown;
  points?: number;
  source?: string;
  note?: string;
  epss_score?: number | null;
}

export interface PriorityExplanation {
  model_version: string;
  score: number;
  priority: string;
  overrides: { type?: string; priority?: string; reason?: string }[];
  factors: PriorityFactor[];
  data_freshness?: Record<string, string | null | undefined>;
  label?: string;
}

export interface AssetFindingDetail extends AssetFinding {
  description: string;
  detector_type: string;
  detector_key: string;
  cvss_vector?: string | null;
  cvss_source?: string | null;
  epss_model_version?: string | null;
  kev_due_date?: string | null;
  kev_required_action?: string | null;
  kev_known_ransomware_campaign_use?: boolean | null;
  nvd_status?: string | null;
  nvd_fetched_at?: string | null;
  epss_fetched_at?: string | null;
  kev_fetched_at?: string | null;
  priority_explanation?: PriorityExplanation | null;
  history: AssetFindingHistory[];
  evidence: Finding[];
  current_treatment?: FindingTreatment | null;
  treatments?: FindingTreatment[];
  control_references?: ControlReference[];
  mapping_disclaimer?: string;
}

export interface CompensatingControl {
  id: number;
  tenant_id: number;
  treatment_id: number;
  name: string;
  description: string;
  evidence_notes: string;
  status: string;
  created_by_username?: string | null;
  created_at: string;
  updated_at: string;
  retired_at?: string | null;
  retired_by_username?: string | null;
  retirement_reason?: string | null;
}

export interface FindingTreatment {
  id: number;
  tenant_id: number;
  asset_finding_id: number;
  treatment_type: string;
  status: string;
  display_status: string;
  rationale: string;
  evidence_notes: string;
  source: string;
  created_by_username?: string | null;
  reviewed_by_username?: string | null;
  revoked_by_username?: string | null;
  created_at: string;
  updated_at: string;
  reviewed_at?: string | null;
  review_due_at?: string | null;
  expires_at?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  review_notes?: string | null;
  compensating_controls: CompensatingControl[];
}

export interface ComplianceFramework {
  id: number;
  slug: string;
  name: string;
  version: string;
  publisher: string;
  description: string;
  source_url: string;
  source_release_date?: string | null;
  source_metadata?: Record<string, unknown>;
  builtin: boolean;
  archived_at?: string | null;
  control_count?: number;
  mapping_disclaimer?: string;
  controls?: ComplianceControl[];
}

export interface ComplianceControl {
  id: number;
  framework_id: number;
  control_key: string;
  family?: string | null;
  title: string;
  description: string;
  archived_at?: string | null;
  framework_name?: string | null;
  framework_version?: string | null;
  framework_slug?: string | null;
}

export interface ControlReference {
  id: number;
  tenant_id: number;
  control_id: number;
  subject_type: string;
  subject_id: number;
  reference_type: string;
  notes: string;
  created_by_username?: string | null;
  created_at: string;
  removed_at?: string | null;
  removal_reason?: string | null;
  control_key: string;
  control_title: string;
  control_family?: string | null;
  framework_name: string;
  framework_version: string;
  framework_slug: string;
  mapping_disclaimer?: string;
}

export interface AlertDelivery {
  id: number;
  channel: string;
  destination: string;
  status: string;
  attempt_count: number;
  last_attempt_at: string | null;
  delivered_at: string | null;
  last_error: string | null;
  response_status: number | null;
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
  severity?: string | null;
  site_id?: number | null;
  network_id?: number | null;
  asset_id?: number | null;
  domain_event_id?: number | null;
  dashboard_visible?: boolean;
  occurrence_count?: number;
  first_event_at?: string | null;
  last_event_at?: string | null;
  tenant_name?: string | null;
  site_name?: string | null;
  event_type_label?: string | null;
  delivery_summary?: { email?: string | null; webhook?: string | null; failed?: number } | null;
  policy_explanation?: Record<string, unknown> | null;
  source_event?: {
    id: number;
    event_type: string;
    event_type_label?: string;
    occurred_at: string;
    tenant_id: number | null;
    site_id: number | null;
    network_id: number | null;
    source: string;
  } | null;
  deliveries?: AlertDelivery[];
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
  preferred_agent_grace_seconds?: number;
  agent_job_wait_minutes?: number;
  scan_cap_naabu_rate?: number;
  scan_cap_naabu_concurrency?: number;
  scan_cap_naabu_timeout_ms?: number;
  scan_cap_naabu_retries?: number;
  scan_cap_httpx_rate?: number;
  scan_cap_httpx_threads?: number;
  scan_cap_httpx_timeout?: number;
  scan_cap_httpx_retries?: number;
  scan_cap_nuclei_rate?: number;
  scan_cap_nuclei_concurrency?: number;
  scan_cap_nuclei_timeout?: number;
  scan_cap_nuclei_retries?: number;
  finding_resolution_clean_scans?: number;
  vulnerability_intelligence_enabled?: boolean;
  raw_scan_artifact_retention_days?: number;
  approved_scanner_runtime_version?: string;
  approved_nuclei_version?: string;
  approved_nuclei_templates_version?: string;
  approved_naabu_version?: string;
  approved_httpx_version?: string;
}

export interface IntelligenceSourceStatus {
  last_attempt_at: string | null;
  last_success_at: string | null;
  source_updated_at: string | null;
  records_seen: number | null;
  records_updated: number | null;
  last_error: string | null;
  metadata?: Record<string, unknown>;
  due?: boolean;
  enabled?: boolean;
}

export interface IntelligenceStatus {
  enabled: boolean;
  nvd_api_key_configured: boolean;
  sources: Record<string, IntelligenceSourceStatus>;
}

export type PolicyCategory = "asset_handling" | "asset_inactivity" | "finding_lifecycle" | "alerting";
export type PolicyScope = "global" | "tenant" | "site" | "network";

export interface PolicyCondition {
  field: string;
  op: string;
  value: string | number | boolean;
}

export interface Policy {
  id: number;
  name: string;
  description: string;
  category: PolicyCategory;
  scope_type: PolicyScope;
  tenant_id: number | null;
  site_id: number | null;
  network_id: number | null;
  tenant_name: string | null;
  site_name: string | null;
  network_name: string | null;
  priority: number;
  enabled: boolean;
  conditions: PolicyCondition[];
  actions: Record<string, unknown>;
  revision: number;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  archive_reason: string | null;
}

export interface PolicyActionExplanation {
  value: string | number;
  source: string;
  rule_id: number | null;
  rule_name: string | null;
  revision: number | null;
  scope_type: string | null;
  priority: number | null;
  matched_conditions: { field: string; op: string; value: unknown; matched: boolean; detail: string }[];
  overrode?: { rule_id: number; rule_name: string; scope_type: string; priority: number; value: unknown } | null;
}

export interface PolicyEvaluation {
  asset_id?: number;
  tenant_id?: number | null;
  site_id?: number | null;
  network_id?: number | null;
  current?: Record<string, unknown>;
  effective: Record<string, string | number>;
  actions: Record<string, PolicyActionExplanation>;
  matched_rules: { id: number; name: string; scope_type: string; priority: number }[];
}

export interface Dashboard {
  tenants: number;
  users: number;
  open_alerts: number;
  open_alerts_critical?: number;
  open_alerts_high?: number;
  delivery_failures?: number;
  new_devices: number;
  agents: { total: number; pending: number; online: number };
  findings: Record<string, number>;
  priorities?: Record<string, number>;
  recent_alerts: AlertItem[];
  recent_jobs: ScanJob[];
}

export interface TenantSummary {
  devices: { new: number; known: number; stale: number };
  assets?: { total: number; unreviewed: number; expected: number };
  findings: Record<string, number>;
  priorities?: Record<string, number>;
  agents: { total: number; pending: number; approved: number; online: number };
  open_alerts: number;
  recent_jobs: ScanJob[];
}
