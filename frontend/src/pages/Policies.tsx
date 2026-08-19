import { FormEvent, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { formatUtc, useTimezone } from "../timezone";
import type { Network, Policy, PolicyCategory, PolicyCondition, PolicyScope, Site, Tenant } from "../types";

const DEVICE_CLASSES = [
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
];
const DISPOSITIONS = ["unreviewed", "approved", "unauthorized", "ignored"];
const CRITICALITIES = ["low", "normal", "high", "critical"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PRIORITIES = ["p1", "p2", "p3", "p4"];

const CATEGORY_LABEL: Record<PolicyCategory, string> = {
  asset_handling: "Asset Handling",
  asset_inactivity: "Asset Inactivity",
  finding_lifecycle: "Finding Lifecycle",
  alerting: "Alerting",
};

const EVENT_LABELS: Record<string, string> = {
  new_asset: "New Asset",
  asset_became_inactive: "Asset Became Inactive",
  previously_inactive_asset_returned: "Inactive Asset Returned",
  asset_disposition_changed: "Asset Disposition Changed",
  new_finding: "New Vulnerability / Finding",
  vulnerability_resolved: "Vulnerability Resolved",
  vulnerability_reopened: "Vulnerability Reopened",
  treatment_created: "Finding Treatment Created",
  treatment_expired: "Finding Treatment Expired",
  scan_failed: "Scan Failed",
  scan_missed_unavailable_agent: "Scan Missed — No Available Agent",
  agent_identity_mismatch: "Agent Identity Mismatch",
  wan_target_changed: "WAN Target Changed",
  policy_changed: "Policy Changed",
};

const SCOPE_LABEL: Record<PolicyScope, string> = {
  global: "GLOBAL",
  tenant: "Tenant",
  site: "Site",
  network: "Network",
};

const FIELD_LABEL: Record<string, string> = {
  hostname: "Hostname",
  tag: "Tag",
  criticality: "Criticality",
  is_expected: "Expected asset",
  observed_port: "Observed port",
  severity: "Finding severity",
  priority: "Finding priority",
  has_cve: "Has CVE",
  event_type: "Event",
  classification: "Classification",
  disposition: "Disposition",
  treatment_state: "Treatment state",
  source: "Source",
};

const OP_LABEL: Record<string, string> = {
  equals: "is",
  glob: "matches",
  has: "is",
  lacks: "is not",
};

type ConditionDraft = { field: string; op: string; value: string };

const emptyDraft = {
  name: "",
  description: "",
  category: "asset_handling" as PolicyCategory,
  scope_type: "tenant" as PolicyScope,
  tenant_id: "",
  site_id: "",
  network_id: "",
  priority: "100",
  conditions: [] as ConditionDraft[],
  classification: "",
  disposition: "",
  inactive_after_days: "30",
  resolution_clean_scans: "2",
  alert_severity: "high",
  alert_dashboard: true,
  alert_email: "staff",
  alert_webhook_enabled: false,
  alert_webhook_url: "",
  suppress_for_minutes: "0",
};

function fieldsFor(category: PolicyCategory): { field: string; ops: string[] }[] {
  const asset = [
    { field: "hostname", ops: ["equals", "glob"] },
    { field: "tag", ops: ["has", "lacks"] },
    { field: "criticality", ops: ["equals"] },
    { field: "is_expected", ops: ["equals"] },
    { field: "observed_port", ops: ["equals"] },
  ];
  if (category === "finding_lifecycle") {
    return [
      { field: "tag", ops: ["has", "lacks"] },
      { field: "criticality", ops: ["equals"] },
      { field: "severity", ops: ["equals"] },
      { field: "priority", ops: ["equals"] },
      { field: "has_cve", ops: ["equals"] },
    ];
  }
  if (category === "alerting") {
    return [
      { field: "event_type", ops: ["equals"] },
      { field: "classification", ops: ["equals"] },
      { field: "disposition", ops: ["equals"] },
      { field: "criticality", ops: ["equals"] },
      { field: "tag", ops: ["has", "lacks"] },
      { field: "is_expected", ops: ["equals"] },
      { field: "severity", ops: ["equals"] },
      { field: "priority", ops: ["equals"] },
      { field: "has_cve", ops: ["equals"] },
      { field: "treatment_state", ops: ["equals"] },
      { field: "source", ops: ["equals"] },
    ];
  }
  return asset;
}

function conditionText(item: PolicyCondition): string {
  const field = FIELD_LABEL[item.field] || item.field;
  const op = OP_LABEL[item.op] || item.op;
  const value = item.field === "event_type" ? EVENT_LABELS[String(item.value)] || String(item.value) : String(item.value);
  return `${field} ${op} ${value}`;
}

function actionText(policy: Policy): string {
  const actions = policy.actions;
  const parts: string[] = [];
  if (actions.classification) parts.push(`Classification = ${actions.classification}`);
  if (actions.disposition) parts.push(`Disposition = ${String(actions.disposition).replace(/^./, (c) => c.toUpperCase())}`);
  if (actions.inactive_after_days) parts.push(`Mark asset inactive after ${actions.inactive_after_days} days`);
  if (actions.resolution_clean_scans) {
    parts.push(`Resolve after ${actions.resolution_clean_scans} consecutive applicable clean scans`);
  }
  if (actions.severity) parts.push(`Severity = ${String(actions.severity)}`);
  if (actions.dashboard !== undefined) parts.push(`Dashboard = ${actions.dashboard ? "Yes" : "No"}`);
  if (actions.email) parts.push(`Email = ${String(actions.email)}`);
  const webhook = actions.webhook as { enabled?: boolean; url?: string } | undefined;
  if (webhook) parts.push(webhook.enabled ? `Webhook = ${webhook.url || "enabled"}` : "Webhook = Off");
  if (actions.suppress_for_minutes !== undefined) {
    parts.push(`Suppress duplicates for ${actions.suppress_for_minutes} minutes`);
  }
  return parts.join(" · ") || "—";
}

function scopeText(policy: Policy): string {
  if (policy.scope_type === "global") return "GLOBAL";
  const names = [policy.tenant_name, policy.site_name, policy.network_name].filter(Boolean);
  return `${SCOPE_LABEL[policy.scope_type]} — ${names.join(" / ")}`;
}

export function Policies() {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const admin = user?.role === "admin";
  const { defaultTimezone } = useTimezone();
  const [rows, setRows] = useState<Policy[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [category, setCategory] = useState("");
  const [scopeType, setScopeType] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [enabled, setEnabled] = useState("");
  const [error, setError] = useState("");

  function load() {
    const qs = new URLSearchParams();
    if (category) qs.set("category", category);
    if (scopeType) qs.set("scope_type", scopeType);
    if (tenantId) qs.set("tenant_id", tenantId);
    if (enabled) qs.set("enabled", enabled);
    qs.set("include_archived", "true");
    api<Policy[]>(`/api/policies?${qs}`).then(setRows);
    api<Tenant[]>("/api/tenants").then(setTenants);
  }
  useEffect(load, [category, scopeType, tenantId, enabled]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between gap-4 items-start">
        <div>
          <h1 className="text-2xl font-semibold">Policies</h1>
          <p className="text-slate-400 text-sm max-w-3xl">
            Deterministic WHEN / WHERE / THEN rules. More specific scope wins: Network, then Site, then Tenant, then
            Global. Within the same scope, higher priority wins. A more-specific rule only overrides the actions it
            sets.
          </p>
        </div>
        {write && (
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2" onClick={() => setShowCreate(true)}>
            New policy
          </button>
        )}
      </div>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <div className="flex flex-wrap gap-3">
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {Object.entries(CATEGORY_LABEL).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={scopeType} onChange={(e) => setScopeType(e.target.value)}>
          <option value="">All scopes</option>
          {Object.entries(SCOPE_LABEL).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
          <option value="">All tenants</option>
          {tenants.map((tenant) => (
            <option key={tenant.id} value={tenant.id}>
              {tenant.name}
            </option>
          ))}
        </select>
        <select value={enabled} onChange={(e) => setEnabled(e.target.value)}>
          <option value="">Enabled and disabled</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
      </div>
      <div className="overflow-auto border border-slate-800 rounded-xl">
        <table className="w-full text-sm">
          <thead className="text-slate-400">
            <tr>
              <th className="text-left p-3">Name</th>
              <th className="text-left p-3">Category</th>
              <th className="text-left p-3">Scope</th>
              <th className="text-left p-3">Priority</th>
              <th className="text-left p-3">THEN</th>
              <th className="text-left p-3">Updated</th>
              <th className="text-left p-3">State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-slate-800 hover:bg-slate-900/70 cursor-pointer" onClick={() => setSelected(row)}>
                <td className="p-3 font-medium">{row.name}</td>
                <td className="p-3">{CATEGORY_LABEL[row.category]}</td>
                <td className="p-3">{scopeText(row)}</td>
                <td className="p-3">{row.priority}</td>
                <td className="p-3 text-slate-300">{actionText(row)}</td>
                <td className="p-3 text-slate-400">{formatUtc(row.updated_at, defaultTimezone)}</td>
                <td className="p-3">
                  {row.archived_at ? <Badge value="archived" /> : <Badge value={row.enabled ? "enabled" : "disabled"} />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && (
        <PolicyDetail
          policy={selected}
          write={write}
          admin={admin}
          timezone={defaultTimezone}
          onClose={() => setSelected(null)}
          onChanged={() => {
            load();
            api<Policy>(`/api/policies/${selected.id}`).then(setSelected);
          }}
          onError={setError}
        />
      )}
      {showCreate && (
        <PolicyBuilder
          admin={admin}
          tenants={tenants}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function PolicyDetail({
  policy,
  write,
  admin,
  timezone,
  onClose,
  onChanged,
  onError,
}: {
  policy: Policy;
  write: boolean;
  admin: boolean;
  timezone: string;
  onClose: () => void;
  onChanged: () => void;
  onError: (message: string) => void;
}) {
  const canEdit = write && (policy.scope_type !== "global" || admin) && !policy.archived_at;
  async function act(path: string) {
    try {
      await api(`/api/policies/${policy.id}${path}`, { method: "POST", body: path === "/archive" ? JSON.stringify({ reason: "" }) : undefined });
      onChanged();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed");
    }
  }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">{policy.name}</h2>
          <p className="text-slate-400 text-sm">{policy.description || "No description"}</p>
        </div>
        <button className="text-slate-400" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="grid md:grid-cols-2 gap-3 text-sm">
        <div>Category: {CATEGORY_LABEL[policy.category]}</div>
        <div>WHERE: {scopeText(policy)}</div>
        <div>Priority: {policy.priority}</div>
        <div>Revision: {policy.revision}</div>
        <div>Updated: {formatUtc(policy.updated_at, timezone)}</div>
      </div>
      <section>
        <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">WHEN</h3>
        {policy.conditions.length ? (
          <ul className="space-y-1 text-sm">
            {policy.conditions.map((item, index) => (
              <li key={`${item.field}-${index}`}>
                {index > 0 ? <span className="text-slate-500">AND </span> : null}
                {conditionText(item)}
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-sm text-slate-400">Matches all objects in this scope.</div>
        )}
      </section>
      <section>
        <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">THEN</h3>
        <div className="text-sm">{actionText(policy)}</div>
      </section>
      {canEdit && (
        <div className="flex flex-wrap gap-3">
          {policy.enabled ? (
            <button className="text-amber-300" onClick={() => act("/disable")}>
              Disable
            </button>
          ) : (
            <button className="text-cyan-400" onClick={() => act("/enable")}>
              Enable
            </button>
          )}
          <button className="text-rose-300" onClick={() => act("/archive")}>
            Archive
          </button>
        </div>
      )}
      {write && policy.scope_type === "global" && !admin && (
        <div className="text-sm text-slate-500">Only an Admin can change Global policies.</div>
      )}
    </div>
  );
}

function PolicyBuilder({
  admin,
  tenants,
  onClose,
  onCreated,
}: {
  admin: boolean;
  tenants: Tenant[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState(emptyDraft);
  const [sites, setSites] = useState<Site[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [error, setError] = useState("");
  const fieldOptions = useMemo(() => fieldsFor(form.category), [form.category]);

  useEffect(() => {
    if (!form.tenant_id) {
      setSites([]);
      setNetworks([]);
      return;
    }
    api<Site[]>(`/api/tenants/${form.tenant_id}/sites`).then(setSites);
    api<Network[]>(`/api/tenants/${form.tenant_id}/networks`).then(setNetworks);
  }, [form.tenant_id]);

  function addCondition() {
    const first = fieldOptions[0];
    setForm({ ...form, conditions: [...form.conditions, { field: first.field, op: first.ops[0], value: "" }] });
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const actions: Record<string, unknown> = {};
    if (form.category === "asset_handling") {
      if (form.classification) actions.classification = form.classification;
      if (form.disposition) actions.disposition = form.disposition;
    } else if (form.category === "asset_inactivity") {
      actions.inactive_after_days = Number(form.inactive_after_days);
    } else if (form.category === "finding_lifecycle") {
      actions.resolution_clean_scans = Number(form.resolution_clean_scans);
    } else {
      if (form.alert_severity) actions.severity = form.alert_severity;
      actions.dashboard = form.alert_dashboard;
      if (form.alert_email) actions.email = form.alert_email;
      actions.webhook = form.alert_webhook_enabled
        ? { enabled: true, url: form.alert_webhook_url }
        : { enabled: false };
      actions.suppress_for_minutes = Number(form.suppress_for_minutes) || 0;
    }
    const conditions = form.conditions
      .filter((item) => String(item.value) !== "")
      .map((item) => {
        let value: string | number | boolean = item.value;
        if (item.field === "is_expected" || item.field === "has_cve") value = item.value === "true";
        if (item.field === "observed_port") value = Number(item.value);
        return { field: item.field, op: item.op, value };
      });
    try {
      await api("/api/policies", {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          description: form.description,
          category: form.category,
          scope_type: form.scope_type,
          tenant_id: form.scope_type === "global" ? null : Number(form.tenant_id) || null,
          site_id: form.scope_type === "site" || form.scope_type === "network" ? Number(form.site_id) || null : null,
          network_id: form.scope_type === "network" ? Number(form.network_id) || null : null,
          priority: Number(form.priority) || 100,
          conditions,
          actions,
        }),
      });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="fixed inset-0 z-20 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <form
        onSubmit={onSubmit}
        className="w-full max-w-2xl max-h-[90vh] overflow-auto bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold">New policy</h2>
        <p className="text-sm text-slate-400">Describe WHEN the rule matches, WHERE it applies, and THEN what it sets.</p>
        <div>
          <label>Policy name</label>
          <input className="w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </div>
        <div>
          <label>Description</label>
          <input className="w-full" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        <div className="grid md:grid-cols-2 gap-3">
          <div>
            <label>Category</label>
            <select
              className="w-full"
              value={form.category}
              onChange={(e) =>
                setForm({
                  ...form,
                  category: e.target.value as PolicyCategory,
                  conditions: e.target.value === "alerting" ? [{ field: "event_type", op: "equals", value: "new_asset" }] : [],
                })
              }
            >
              {Object.entries(CATEGORY_LABEL).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label>Priority</label>
            <input className="w-full" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })} />
            <div className="text-xs text-slate-500 mt-1">Higher wins only against rules in the same scope.</div>
          </div>
        </div>
        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">WHERE</h3>
          <select className="w-full" value={form.scope_type} onChange={(e) => setForm({ ...form, scope_type: e.target.value as PolicyScope })}>
            {admin && <option value="global">GLOBAL</option>}
            <option value="tenant">Tenant</option>
            <option value="site">Site</option>
            <option value="network">Network</option>
          </select>
          {form.scope_type !== "global" && (
            <select className="w-full" value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.target.value, site_id: "", network_id: "" })} required>
              <option value="">Select tenant</option>
              {tenants.map((tenant) => (
                <option key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </option>
              ))}
            </select>
          )}
          {(form.scope_type === "site" || form.scope_type === "network") && (
            <select className="w-full" value={form.site_id} onChange={(e) => setForm({ ...form, site_id: e.target.value, network_id: "" })} required>
              <option value="">Select site</option>
              {sites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                </option>
              ))}
            </select>
          )}
          {form.scope_type === "network" && (
            <select className="w-full" value={form.network_id} onChange={(e) => setForm({ ...form, network_id: e.target.value })} required>
              <option value="">Select network</option>
              {networks
                .filter((network) => !form.site_id || String(network.site_id) === form.site_id)
                .map((network) => (
                  <option key={network.id} value={network.id}>
                    {network.name}
                  </option>
                ))}
            </select>
          )}
        </section>
        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">WHEN</h3>
          {form.conditions.map((item, index) => {
            const spec = fieldOptions.find((row) => row.field === item.field) || fieldOptions[0];
            return (
              <div key={index} className="grid md:grid-cols-[1fr_1fr_1fr_auto] gap-2 items-end">
                <select
                  value={item.field}
                  onChange={(e) => {
                    const next = fieldOptions.find((row) => row.field === e.target.value) || spec;
                    const copy = [...form.conditions];
                    copy[index] = { field: next.field, op: next.ops[0], value: "" };
                    setForm({ ...form, conditions: copy });
                  }}
                >
                  {fieldOptions.map((row) => (
                    <option key={row.field} value={row.field}>
                      {FIELD_LABEL[row.field]}
                    </option>
                  ))}
                </select>
                <select
                  value={item.op}
                  onChange={(e) => {
                    const copy = [...form.conditions];
                    copy[index] = { ...item, op: e.target.value };
                    setForm({ ...form, conditions: copy });
                  }}
                >
                  {spec.ops.map((op) => (
                    <option key={op} value={op}>
                      {OP_LABEL[op] || op}
                    </option>
                  ))}
                </select>
                <ConditionValue
                  field={item.field}
                  value={item.value}
                  onChange={(value) => {
                    const copy = [...form.conditions];
                    copy[index] = { ...item, value };
                    setForm({ ...form, conditions: copy });
                  }}
                />
                <button
                  type="button"
                  className="text-rose-300 text-sm"
                  onClick={() => setForm({ ...form, conditions: form.conditions.filter((_, i) => i !== index) })}
                >
                  Remove
                </button>
              </div>
            );
          })}
          <button type="button" className="text-cyan-400 text-sm" onClick={addCondition}>
            Add condition
          </button>
          {form.conditions.length > 1 && <div className="text-xs text-slate-500">All conditions must match (AND).</div>}
        </section>
        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">THEN</h3>
          {form.category === "asset_handling" && (
            <div className="grid md:grid-cols-2 gap-3">
              <div>
                <label>Classification</label>
                <select className="w-full" value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}>
                  <option value="">Leave inherited</option>
                  {DEVICE_CLASSES.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Disposition</label>
                <select className="w-full" value={form.disposition} onChange={(e) => setForm({ ...form, disposition: e.target.value })}>
                  <option value="">Leave inherited</option>
                  {DISPOSITIONS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
          {form.category === "asset_inactivity" && (
            <div>
              <label>Mark asset inactive after</label>
              <div className="flex items-center gap-2">
                <input className="w-32" value={form.inactive_after_days} onChange={(e) => setForm({ ...form, inactive_after_days: e.target.value })} />
                <span className="text-sm text-slate-400">days without observation</span>
              </div>
            </div>
          )}
          {form.category === "finding_lifecycle" && (
            <div>
              <label>Resolve after consecutive applicable clean scans</label>
              <input className="w-32" value={form.resolution_clean_scans} onChange={(e) => setForm({ ...form, resolution_clean_scans: e.target.value })} />
              <div className="text-xs text-slate-500 mt-1">
                A scan that did not actually test this finding does not count as clean.
              </div>
            </div>
          )}
          {form.category === "alerting" && (
            <div className="grid md:grid-cols-2 gap-3">
              <div>
                <label>Severity</label>
                <select className="w-full" value={form.alert_severity} onChange={(e) => setForm({ ...form, alert_severity: e.target.value })}>
                  <option value="">Leave inherited</option>
                  {["info", "low", "medium", "high", "critical"].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Dashboard</label>
                <select
                  className="w-full"
                  value={form.alert_dashboard ? "yes" : "no"}
                  onChange={(e) => setForm({ ...form, alert_dashboard: e.target.value === "yes" })}
                >
                  <option value="yes">Yes</option>
                  <option value="no">No</option>
                </select>
              </div>
              <div>
                <label>Email</label>
                <select className="w-full" value={form.alert_email} onChange={(e) => setForm({ ...form, alert_email: e.target.value })}>
                  <option value="">Leave inherited</option>
                  <option value="off">Off</option>
                  <option value="staff">Staff</option>
                  <option value="admins">Admins</option>
                </select>
              </div>
              <div>
                <label>Suppress duplicate alert for</label>
                <div className="flex items-center gap-2">
                  <input className="w-24" value={form.suppress_for_minutes} onChange={(e) => setForm({ ...form, suppress_for_minutes: e.target.value })} />
                  <span className="text-sm text-slate-400">minutes</span>
                </div>
              </div>
              <div className="md:col-span-2">
                <label>Webhook</label>
                <div className="flex items-center gap-2">
                  <select
                    value={form.alert_webhook_enabled ? "yes" : "no"}
                    onChange={(e) => setForm({ ...form, alert_webhook_enabled: e.target.value === "yes" })}
                  >
                    <option value="no">Disabled</option>
                    <option value="yes">Enabled</option>
                  </select>
                  {form.alert_webhook_enabled && (
                    <input
                      className="flex-1"
                      placeholder="https://..."
                      value={form.alert_webhook_url}
                      onChange={(e) => setForm({ ...form, alert_webhook_url: e.target.value })}
                    />
                  )}
                </div>
              </div>
            </div>
          )}
        </section>
        {error && <div className="text-rose-300 text-sm">{error}</div>}
        <div className="flex justify-end gap-3">
          <button type="button" className="text-slate-400" onClick={onClose}>
            Cancel
          </button>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2">Create</button>
        </div>
      </form>
    </div>
  );
}

function ConditionValue({ field, value, onChange }: { field: string; value: string; onChange: (value: string) => void }) {
  if (field === "event_type") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select event</option>
        {Object.entries(EVENT_LABELS).map(([key, label]) => (
          <option key={key} value={key}>
            {label}
          </option>
        ))}
      </select>
    );
  }
  if (field === "classification") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {DEVICE_CLASSES.map((item) => (
          <option key={item}>{item}</option>
        ))}
      </select>
    );
  }
  if (field === "disposition") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {DISPOSITIONS.map((item) => (
          <option key={item} value={item}>
            {item}
          </option>
        ))}
      </select>
    );
  }
  if (field === "treatment_state") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {["unaddressed", "mitigated", "accepted_risk", "false_positive", "active", "expired"].map((item) => (
          <option key={item}>{item}</option>
        ))}
      </select>
    );
  }
  if (field === "criticality") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {CRITICALITIES.map((item) => (
          <option key={item}>{item}</option>
        ))}
      </select>
    );
  }
  if (field === "severity") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {SEVERITIES.map((item) => (
          <option key={item}>{item}</option>
        ))}
      </select>
    );
  }
  if (field === "priority") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        {PRIORITIES.map((item) => (
          <option key={item}>{item}</option>
        ))}
      </select>
    );
  }
  if (field === "is_expected" || field === "has_cve") {
    return (
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    );
  }
  return <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={field === "hostname" ? "LT-*" : ""} />;
}
