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
  created_at: string;
}

export interface Agent {
  id: number;
  tenant_id: number;
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
  findings_count?: number;
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
  default_nuclei_severities: string;
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
  findings: Record<string, number>;
  agents: { total: number; pending: number; approved: number; online: number };
  open_alerts: number;
  recent_jobs: ScanJob[];
}
