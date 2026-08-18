import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { Alerts } from "./Alerts";
import { formatUtc, useTimezone } from "../timezone";
import type {
  Agent,
  AuthorizedWanTarget,
  Finding,
  Network,
  Scan,
  ScanExclusion,
  ScanJob,
  Site,
  Tenant,
  TenantSummary,
} from "../types";
import { AssetsPanel } from "./AssetsPanel";
import { SitesPanel } from "./SitesPanel";

type Tab = "overview" | "sites" | "wan" | "agents" | "scans" | "assets" | "findings" | "alerts";

export function TenantDetail() {
  const { id } = useParams();
  const tenantId = Number(id);
  const [tab, setTab] = useState<Tab>("overview");
  const [tenant, setTenant] = useState<Tenant | null>(null);

  useEffect(() => {
    api<Tenant>(`/api/tenants/${tenantId}`).then(setTenant);
  }, [tenantId]);

  if (!tenant) return <div className="text-slate-400">Loading…</div>;

  const tabs: Tab[] = ["overview", "sites", "wan", "agents", "scans", "assets", "findings", "alerts"];

  return (
    <div className="space-y-6">
      <div>
        <Link to="/tenants" className="text-sm text-cyan-400">
          ← Tenants
        </Link>
        <h1 className="text-2xl font-semibold mt-1">{tenant.name}</h1>
        <p className="text-slate-400 text-sm">{tenant.notes || "Client tenant"}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-md text-sm capitalize ${tab === t ? "bg-cyan-700 text-white" : "bg-slate-800 text-slate-300"}`}
          >
            {t === "wan" ? "WAN targets" : t}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview tenantId={tenantId} />}
      {tab === "sites" && <SitesPanel tenantId={tenantId} />}
      {tab === "wan" && <WanTargets tenantId={tenantId} />}
      {tab === "agents" && <Agents tenantId={tenantId} />}
      {tab === "scans" && <Scans tenantId={tenantId} />}
      {tab === "assets" && <AssetsPanel tenantId={tenantId} />}
      {tab === "findings" && <Findings tenantId={tenantId} />}
      {tab === "alerts" && <Alerts tenantId={tenantId} />}
    </div>
  );
}

function Overview({ tenantId }: { tenantId: number }) {
  const [data, setData] = useState<TenantSummary | null>(null);
  useEffect(() => {
    api<TenantSummary>(`/api/tenants/${tenantId}/summary`).then(setData);
    const id = setInterval(() => api<TenantSummary>(`/api/tenants/${tenantId}/summary`).then(setData), 8000);
    return () => clearInterval(id);
  }, [tenantId]);
  if (!data) return <div className="text-slate-400">Loading…</div>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Assets" value={data.assets?.total ?? 0} />
        <Stat label="Unreviewed" value={data.assets?.unreviewed ?? data.devices.new} />
        <Stat label="Expected" value={data.assets?.expected ?? 0} />
        <Stat label="Open alerts" value={data.open_alerts} />
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Agents online" value={data.agents.online} />
        <Stat label="Pending agents" value={data.agents.pending} />
        <Stat label="Critical findings" value={data.findings.critical || 0} />
        <Stat label="High findings" value={data.findings.high || 0} />
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}

function WanTargets({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const [rows, setRows] = useState<AuthorizedWanTarget[]>([]);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [targetType, setTargetType] = useState<"ip" | "cidr" | "fqdn">("cidr");
  const [error, setError] = useState("");
  const [showArchived, setShowArchived] = useState(false);

  function load() {
    api<AuthorizedWanTarget[]>(`/api/tenants/${tenantId}/wan-targets?include_archived=${showArchived}`).then(setRows);
  }
  useEffect(load, [tenantId, showArchived]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/wan-targets`, {
        method: "POST",
        body: JSON.stringify({ name, target_type: targetType, value }),
      });
      setName("");
      setValue("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">
        Authorized WAN targets only. Workers cannot receive arbitrary Internet scope. Archive instead of deleting so history stays intact.
      </p>
      {write && (
        <form onSubmit={onCreate} className="grid md:grid-cols-4 gap-3 items-end bg-slate-900 border border-slate-800 rounded-xl p-4">
          <Field label="Label" value={name} onChange={setName} />
          <div>
            <label>Type</label>
            <select className="w-full" value={targetType} onChange={(e) => setTargetType(e.target.value as "ip" | "cidr" | "fqdn")}>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="fqdn">FQDN</option>
            </select>
          </div>
          <Field label="Value" value={value} onChange={setValue} placeholder={targetType === "fqdn" ? "edge.example.com" : "203.0.113.0/24"} />
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Add authorized target</button>
        </form>
      )}
      <label className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
        <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />
        Show archived
      </label>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <Table
        headers={["Name", "Type", "Value", "Normalized", "Status", ""]}
        rows={rows.map((s) => [
          s.name,
          <Badge value={s.target_type} />,
          <span className="font-mono">{s.value}</span>,
          <span className="font-mono text-xs">{s.normalized_value}</span>,
          s.archived_at ? <Badge value="archived" /> : <Badge value="active" />,
          write && !s.archived_at ? (
            <button className="text-rose-300 text-sm" onClick={() => api(`/api/wan-targets/${s.id}/archive`, { method: "POST" }).then(load)}>
              Archive
            </button>
          ) : (
            ""
          ),
        ])}
      />
    </div>
  );
}

function Agents({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const [rows, setRows] = useState<Agent[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState("");
  const [siteId, setSiteId] = useState("");
  const [created, setCreated] = useState<Agent | null>(null);
  const { defaultTimezone } = useTimezone();

  function load() {
    api<Agent[]>(`/api/tenants/${tenantId}/agents`).then(setRows);
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then((rows) => {
      setSites(rows);
      setSiteId((current) => current || (rows[0] ? String(rows[0].id) : ""));
    });
  }
  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [tenantId]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    const agent = await api<Agent>(`/api/tenants/${tenantId}/agents`, {
      method: "POST",
      body: JSON.stringify({ name, site_id: Number(siteId) }),
    });
    setName("");
    setCreated(agent);
    load();
  }

  return (
    <div className="space-y-4">
      {write && (
        <form onSubmit={onCreate} className="flex gap-3 items-end bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex-1">
            <label>Agent name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Agent-HQ-01" />
          </div>
          <div>
            <label>Site</label>
            <select className="w-full" value={siteId} onChange={(e) => setSiteId(e.target.value)} required>
              <option value="">Select site</option>
              {sites.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.name}
                </option>
              ))}
            </select>
          </div>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2">Create agent</button>
        </form>
      )}
      {created && (
        <div className="bg-amber-950/40 border border-amber-800 rounded-xl p-4 text-sm space-y-2">
          <div className="font-medium">Agent created — download compose before the site comes online.</div>
          <div className="font-mono text-xs break-all">UUID: {created.uuid}</div>
          {created.enrollment_secret && (
            <div className="font-mono text-xs break-all">Enrollment secret: {created.enrollment_secret}</div>
          )}
          <p className="text-slate-300">
            On the LAN host run <span className="font-mono text-xs">docker compose up -d --build</span>. Docker
            pulls <span className="font-mono text-xs">scan_runtime</span> from GitHub and builds the agent.
          </p>
          <div className="flex flex-wrap gap-3">
            <button className="text-cyan-400" onClick={() => download(`/api/agents/${created.id}/compose`, `agent-${created.uuid}.yml`)}>
              Download docker-compose.yml
            </button>
            <button className="text-cyan-400" onClick={() => download(`/api/agents/${created.id}/env`, `agent-${created.uuid}.env`)}>
              Download .env
            </button>
          </div>
        </div>
      )}
      <Table
        headers={["Name", "Site", "Status", "Online", "Host", "Last seen", ""]}
        rows={rows.map((a) => [
          <div>
            <div>{a.name}</div>
            <div className="font-mono text-[11px] text-slate-500">{a.uuid}</div>
          </div>,
          a.site_name || a.site_id,
          <Badge value={a.status} />,
          <Badge value={a.online ? "online" : "offline"} />,
          a.hostname || "—",
          formatUtc(a.last_heartbeat, defaultTimezone),
          <div className="flex flex-col items-end gap-1 text-sm">
            {write && (
              <>
                <button className="text-cyan-400" onClick={() => download(`/api/agents/${a.id}/compose`, `agent-${a.uuid}.yml`)}>
                  Compose
                </button>
                <button className="text-cyan-400" onClick={() => download(`/api/agents/${a.id}/env`, `agent-${a.uuid}.env`)}>
                  Env
                </button>
              </>
            )}
            {write && a.status === "pending_approval" && (
              <button className="text-emerald-300" onClick={() => api(`/api/agents/${a.id}/approve`, { method: "POST" }).then(load)}>
                Approve
              </button>
            )}
            {write && a.status !== "revoked" && (
              <button className="text-rose-300" onClick={() => api(`/api/agents/${a.id}/revoke`, { method: "POST" }).then(load)}>
                Revoke
              </button>
            )}
          </div>,
        ])}
      />
    </div>
  );
}

function Scans({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const [scans, setScans] = useState<Scan[]>([]);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [wanTargets, setWanTargets] = useState<AuthorizedWanTarget[]>([]);
  const [exclusions, setExclusions] = useState<ScanExclusion[]>([]);
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);
  const [step, setStep] = useState(1);
  const [error, setError] = useState("");
  const { defaultTimezone } = useTimezone();
  const [form, setForm] = useState({
    name: "",
    scope: "lan" as "lan" | "wan",
    site_id: "",
    network_ids: [] as number[],
    wan_target_ids: [] as number[],
    discovery: true,
    port_mode: "common",
    custom_ports: "",
    fingerprint: true,
    vulnerability: false,
    nuclei_severities: "critical,high,medium",
    nuclei_tags: "",
    intensity: "normal",
    schedule_type: "manual",
    hour: "2",
    minute: "0",
    weekday: "0",
    day: "1",
    cron: "",
    exclusion_value: "",
    exclusion_type: "cidr",
  });

  function load() {
    api<Scan[]>(`/api/tenants/${tenantId}/scans`).then(setScans);
    api<ScanJob[]>(`/api/tenants/${tenantId}/jobs`).then(setJobs);
    api<Network[]>(`/api/tenants/${tenantId}/networks`).then(setNetworks);
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then(setSites);
    api<AuthorizedWanTarget[]>(`/api/tenants/${tenantId}/wan-targets`).then(setWanTargets);
    api<ScanExclusion[]>(`/api/tenants/${tenantId}/scan-exclusions`).then(setExclusions);
  }
  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [tenantId]);

  const siteNetworks = useMemo(
    () => networks.filter((n) => !n.is_archived && String(n.site_id) === form.site_id),
    [networks, form.site_id]
  );
  const selectedNetworks = siteNetworks.filter((n) => form.network_ids.includes(n.id));
  const preferredIds = [
    ...new Set(selectedNetworks.filter((n) => n.dispatch_mode === "preferred_failover").map((n) => n.preferred_agent_id)),
  ];
  const dispatchConflict = preferredIds.length > 1;
  const dispatchLabel =
    form.scope === "wan"
      ? "Central WAN scanner"
      : dispatchConflict
        ? "Conflicting preferred agents"
        : preferredIds.length === 1
          ? "Preferred Agent + failover"
          : "Any Available";

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/scans`, {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          scope: form.scope,
          site_id: form.scope === "lan" ? Number(form.site_id) : null,
          network_ids: form.scope === "lan" ? form.network_ids : [],
          wan_target_ids: form.scope === "wan" ? form.wan_target_ids : [],
          is_enabled: true,
          stage_config: {
            discovery: form.discovery,
            port_mode: form.port_mode,
            custom_ports: form.custom_ports,
            fingerprint: form.fingerprint,
            vulnerability: form.vulnerability,
            nuclei_severities: form.nuclei_severities,
            nuclei_tags: form.nuclei_tags,
          },
          intensity_config: { preset: form.intensity },
          schedule_config:
            form.schedule_type === "manual"
              ? { type: "manual" }
              : form.schedule_type === "cron"
                ? { type: "cron", expression: form.cron }
                : {
                    type: form.schedule_type,
                    hour: Number(form.hour),
                    minute: Number(form.minute),
                    weekday: Number(form.weekday),
                    day: Number(form.day),
                  },
        }),
      });
      setForm({ ...form, name: "" });
      setStep(1);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  async function addExclusion() {
    if (!form.exclusion_value) return;
    await api("/api/scan-exclusions", {
      method: "POST",
      body: JSON.stringify({
        scope: "tenant",
        tenant_id: tenantId,
        exclusion_type: form.exclusion_type,
        value: form.exclusion_value,
      }),
    });
    setForm({ ...form, exclusion_value: "" });
    load();
  }

  return (
    <div className="space-y-6">
      {write && (
        <form onSubmit={onCreate} className="space-y-4 bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex flex-wrap gap-2 text-xs text-slate-400">
            {["Scope", "Stages", "Intensity", "Exclusions", "Schedule", "Review"].map((label, idx) => (
              <button
                key={label}
                type="button"
                onClick={() => setStep(idx + 1)}
                className={`px-2 py-1 rounded ${step === idx + 1 ? "bg-cyan-800 text-white" : "bg-slate-800"}`}
              >
                {idx + 1}. {label}
              </button>
            ))}
          </div>
          {step === 1 && (
            <div className="grid md:grid-cols-2 gap-3">
              <Field label="Scan name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} />
              <div>
                <label>Scope</label>
                <select className="w-full" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as "lan" | "wan" })}>
                  <option value="lan">LAN</option>
                  <option value="wan">WAN</option>
                </select>
              </div>
              {form.scope === "lan" && (
                <>
                  <div>
                    <label>Site</label>
                    <select className="w-full" value={form.site_id} onChange={(e) => setForm({ ...form, site_id: e.target.value, network_ids: [] })} required>
                      <option value="">Select site</option>
                      {sites.filter((s) => !s.is_archived).map((site) => (
                        <option key={site.id} value={site.id}>
                          {site.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label>Networks at this site</label>
                    <div className="flex flex-wrap gap-3 mt-1">
                      {siteNetworks.map((n) => (
                        <label key={n.id} className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
                          <input
                            type="checkbox"
                            checked={form.network_ids.includes(n.id)}
                            onChange={(e) =>
                              setForm({
                                ...form,
                                network_ids: e.target.checked
                                  ? [...form.network_ids, n.id]
                                  : form.network_ids.filter((id) => id !== n.id),
                              })
                            }
                          />
                          {n.name} ({n.cidr})
                        </label>
                      ))}
                    </div>
                    <p className="text-xs text-slate-400 mt-2">
                      Dispatch is derived from the selected networks: {dispatchLabel}
                      {dispatchConflict ? " — selected networks disagree on the preferred agent." : ""}
                    </p>
                  </div>
                </>
              )}
              {form.scope === "wan" && (
                <div className="md:col-span-2">
                  <label>Authorized WAN targets</label>
                  <div className="flex flex-wrap gap-3 mt-1">
                    {wanTargets.filter((t) => !t.archived_at).map((t) => (
                      <label key={t.id} className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
                        <input
                          type="checkbox"
                          checked={form.wan_target_ids.includes(t.id)}
                          onChange={(e) =>
                            setForm({
                              ...form,
                              wan_target_ids: e.target.checked
                                ? [...form.wan_target_ids, t.id]
                                : form.wan_target_ids.filter((id) => id !== t.id),
                            })
                          }
                        />
                        {t.name} ({t.normalized_value})
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          {step === 2 && (
            <div className="grid md:grid-cols-2 gap-3">
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={form.discovery} onChange={(e) => setForm({ ...form, discovery: e.target.checked })} />
                Discovery
              </label>
              <div>
                <label>Port discovery</label>
                <select className="w-full" value={form.port_mode} onChange={(e) => setForm({ ...form, port_mode: e.target.value })}>
                  <option value="none">None</option>
                  <option value="common">Common</option>
                  <option value="deep">Deep</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              {form.port_mode === "custom" && (
                <Field label="Custom ports" value={form.custom_ports} onChange={(v) => setForm({ ...form, custom_ports: v })} placeholder="22,80,443,8000-8010" />
              )}
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={form.fingerprint} onChange={(e) => setForm({ ...form, fingerprint: e.target.checked })} />
                Fingerprinting
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={form.vulnerability} onChange={(e) => setForm({ ...form, vulnerability: e.target.checked })} />
                Vulnerability (Nuclei)
              </label>
              {form.vulnerability && (
                <>
                  <Field label="Nuclei severities" value={form.nuclei_severities} onChange={(v) => setForm({ ...form, nuclei_severities: v })} />
                  <Field label="Nuclei tags" value={form.nuclei_tags} onChange={(v) => setForm({ ...form, nuclei_tags: v })} />
                </>
              )}
            </div>
          )}
          {step === 3 && (
            <div>
              <label>Intensity</label>
              <select className="w-full max-w-xs" value={form.intensity} onChange={(e) => setForm({ ...form, intensity: e.target.value })}>
                <option value="low">Low</option>
                <option value="normal">Normal</option>
                <option value="high">High</option>
              </select>
            </div>
          )}
          {step === 4 && (
            <div className="space-y-3">
              <div className="flex gap-3 items-end">
                <div>
                  <label>Type</label>
                  <select value={form.exclusion_type} onChange={(e) => setForm({ ...form, exclusion_type: e.target.value })}>
                    <option value="ip">IP</option>
                    <option value="cidr">CIDR</option>
                    <option value="range">Range</option>
                  </select>
                </div>
                <Field label="Tenant exclusion" value={form.exclusion_value} onChange={(v) => setForm({ ...form, exclusion_value: v })} />
                <button type="button" className="bg-slate-800 rounded-md px-3 py-2" onClick={addExclusion}>
                  Add
                </button>
              </div>
              <div className="text-sm text-slate-400">
                Effective exclusions include Global + Tenant + Site + Network + this scan. They can only remove scope.
              </div>
              <ul className="text-sm text-slate-300">
                {exclusions.filter((row) => !row.archived_at).map((row) => (
                  <li key={row.id}>
                    {row.scope}: {row.normalized_value}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {step === 5 && (
            <div className="grid md:grid-cols-3 gap-3">
              <div>
                <label>Schedule</label>
                <select className="w-full" value={form.schedule_type} onChange={(e) => setForm({ ...form, schedule_type: e.target.value })}>
                  <option value="manual">Manual</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="cron">Advanced cron</option>
                </select>
              </div>
              {form.schedule_type !== "manual" && form.schedule_type !== "cron" && (
                <>
                  <Field label="Hour" value={form.hour} onChange={(v) => setForm({ ...form, hour: v })} />
                  <Field label="Minute" value={form.minute} onChange={(v) => setForm({ ...form, minute: v })} />
                </>
              )}
              {form.schedule_type === "weekly" && (
                <Field label="Weekday (0=Mon)" value={form.weekday} onChange={(v) => setForm({ ...form, weekday: v })} />
              )}
              {form.schedule_type === "monthly" && <Field label="Day of month" value={form.day} onChange={(v) => setForm({ ...form, day: v })} />}
              {form.schedule_type === "cron" && <Field label="Cron (m h dom mon dow)" value={form.cron} onChange={(v) => setForm({ ...form, cron: v })} />}
            </div>
          )}
          {step === 6 && (
            <div className="text-sm text-slate-300 space-y-1">
              <div>Name: {form.name}</div>
              <div>Scope: {form.scope.toUpperCase()}</div>
              <div>Dispatch: {dispatchLabel}</div>
              <div>Stages: discovery {form.discovery ? "on" : "off"}, ports {form.port_mode}, fingerprint {form.fingerprint ? "on" : "off"}, vuln {form.vulnerability ? "on" : "off"}</div>
              <div>Intensity: {form.intensity}</div>
              <div>Schedule: {form.schedule_type}</div>
              <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2 px-4 mt-2">Create scan definition</button>
            </div>
          )}
          {error && <div className="text-rose-300 text-sm">{error}</div>}
        </form>
      )}
      <div>
        <h3 className="font-medium mb-2">Scan definitions</h3>
        <Table
          headers={["Name", "Scope", "Revision", "Dispatch", "Schedule", ""]}
          rows={scans.map((s) => [
            s.name,
            <Badge value={s.scope} />,
            s.definition_revision ?? 1,
            s.dispatch_summary?.mode === "preferred_failover"
              ? `Preferred + ${s.dispatch_summary.failover_count ?? 0} failover`
              : s.scope === "wan"
                ? "Central"
                : "Any Available",
            (s.schedule_config?.type as string) || (s.interval_minutes ? `Every ${s.interval_minutes}m` : "Manual"),
            write && !s.archived_at ? (
              <div className="flex gap-3">
                <button className="text-cyan-400 text-sm" onClick={() => api(`/api/scans/${s.id}/run`, { method: "POST" }).then(load)}>
                  Run now
                </button>
                <button className="text-rose-300 text-sm" onClick={() => api(`/api/scans/${s.id}/archive`, { method: "POST" }).then(load)}>
                  Archive
                </button>
              </div>
            ) : (
              ""
            ),
          ])}
        />
      </div>
      <div>
        <h3 className="font-medium mb-2">Run history</h3>
        <Table
          headers={["Run", "Definition", "Trigger", "Status", "Worker", "Scheduled", "Created", "Started", "Finished", "Hosts", "Findings"]}
          rows={jobs.map((j) => [
            <button className="text-cyan-400" onClick={() => api<ScanJob>(`/api/jobs/${j.id}`).then(setSelectedJob)}>
              #{j.id}
            </button>,
            j.scan_name || j.scan_id,
            j.trigger_type || "—",
            <Badge value={j.status} />,
            j.claimed_by || "—",
            formatUtc(j.scheduled_for, defaultTimezone),
            formatUtc(j.created_at, defaultTimezone),
            formatUtc(j.started_at, defaultTimezone),
            formatUtc(j.finished_at, defaultTimezone),
            j.hosts_found,
            j.findings_count,
          ])}
        />
      </div>
      {selectedJob && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-sm space-y-2">
          <div className="flex justify-between">
            <h3 className="font-medium">Run #{selectedJob.id}</h3>
            <button className="text-slate-400" onClick={() => setSelectedJob(null)}>
              Close
            </button>
          </div>
          <div>Revision {selectedJob.definition_revision} · snapshot {selectedJob.snapshot_version || "legacy"}</div>
          <pre className="text-xs overflow-auto bg-slate-950 p-3 rounded max-h-80">
            {JSON.stringify(
              {
                snapshot: selectedJob.execution_snapshot,
                provenance: selectedJob.runtime_provenance,
              },
              null,
              2
            )}
          </pre>
        </div>
      )}
    </div>
  );
}

function Findings({ tenantId }: { tenantId: number }) {
  const [rows, setRows] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState("");
  function load() {
    const qs = new URLSearchParams();
    if (severity) qs.set("severity", severity);
    api<Finding[]>(`/api/tenants/${tenantId}/findings?${qs}`).then(setRows);
  }
  useEffect(load, [tenantId, severity]);
  return (
    <div className="space-y-4">
      <div className="flex gap-3 items-end">
        <div>
          <label>Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <button
          className="text-cyan-400 text-sm"
          onClick={() => download(`/api/tenants/${tenantId}/findings/export`, `findings-${tenantId}.csv`)}
        >
          Export CSV
        </button>
      </div>
      <Table
        headers={["When", "Severity", "Hostname", "Template", "Name"]}
        rows={rows.map((f) => [
          new Date(f.found_at).toLocaleString(),
          <Badge value={f.severity} />,
          <div>
            <div>{f.hostname || "—"}</div>
            <div className="font-mono text-[11px] text-slate-500">{f.ip || f.host || f.matched_at}</div>
          </div>,
          <span className="font-mono text-xs">{f.template_id}</span>,
          f.name,
        ])}
      />
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label>{label}</label>
      <input className="w-full" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} required />
    </div>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return (
    <div className="overflow-auto border border-slate-800 rounded-xl">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-slate-400 text-left">
          <tr>
            {headers.map((h) => (
              <th key={h} className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td className="px-3 py-4 text-slate-500" colSpan={headers.length}>
                None yet.
              </td>
            </tr>
          )}
          {rows.map((row, i) => (
            <tr key={i} className="border-t border-slate-800">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 align-top">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
