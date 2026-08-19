import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { ControlMapping } from "../components/ControlMapping";
import { Alerts } from "./Alerts";
import { formatUtc, useTimezone } from "../timezone";
import type {
  Agent,
  AssetFinding,
  AssetFindingDetail,
  FindingTreatment,
  AuthorizedWanTarget,
  Network,
  Scan,
  ScanExclusion,
  ScanArtifact,
  ScanJob,
  Site,
  PolicyEvaluation,
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
        <Stat label="P1 findings" value={data.priorities?.p1 || 0} />
        <Stat label="P2 findings" value={data.priorities?.p2 || 0} />
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
  const [jobArtifacts, setJobArtifacts] = useState<ScanArtifact[]>([]);
  const [step, setStep] = useState(1);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const { defaultTimezone } = useTimezone();
  const emptyForm = {
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
    naabu_rate: "1000",
    naabu_concurrency: "25",
    naabu_timeout_ms: "1000",
    naabu_retries: "3",
    httpx_rate: "150",
    httpx_threads: "50",
    httpx_timeout: "10",
    httpx_retries: "1",
    nuclei_rate: "150",
    nuclei_concurrency: "25",
    nuclei_timeout: "10",
    nuclei_retries: "1",
    schedule_type: "manual",
    hour: "2",
    minute: "0",
    weekday: "0",
    day: "1",
    cron: "",
    exclusion_value: "",
    exclusion_type: "cidr",
  };
  const [form, setForm] = useState(emptyForm);

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
  useEffect(() => {
    if (!selectedJob) {
      setJobArtifacts([]);
      return;
    }
    api<ScanArtifact[]>(`/api/jobs/${selectedJob.id}/artifacts`)
      .then(setJobArtifacts)
      .catch(() => setJobArtifacts([]));
  }, [selectedJob]);

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

  const selectedWanTargets = wanTargets.filter((t) => !t.archived_at && form.wan_target_ids.includes(t.id));

  function intensityPayload() {
    if (form.intensity !== "custom") return { preset: form.intensity };
    return {
      preset: "custom",
      naabu_rate: Number(form.naabu_rate),
      naabu_concurrency: Number(form.naabu_concurrency),
      naabu_timeout_ms: Number(form.naabu_timeout_ms),
      naabu_retries: Number(form.naabu_retries),
      httpx_rate: Number(form.httpx_rate),
      httpx_threads: Number(form.httpx_threads),
      httpx_timeout: Number(form.httpx_timeout),
      httpx_retries: Number(form.httpx_retries),
      nuclei_rate: Number(form.nuclei_rate),
      nuclei_concurrency: Number(form.nuclei_concurrency),
      nuclei_timeout: Number(form.nuclei_timeout),
      nuclei_retries: Number(form.nuclei_retries),
    };
  }

  function beginEdit(scan: Scan) {
    const stages = (scan.stage_config || {}) as Record<string, unknown>;
    const intensity = (scan.intensity_config || {}) as Record<string, unknown>;
    const schedule = (scan.schedule_config || {}) as Record<string, unknown>;
    setEditingId(scan.id);
    setForm({
      ...emptyForm,
      name: scan.name,
      scope: scan.scope,
      site_id: scan.site_id ? String(scan.site_id) : "",
      network_ids: scan.network_ids || [],
      wan_target_ids: scan.wan_target_ids || [],
      discovery: Boolean(stages.discovery ?? true),
      port_mode: String(stages.port_mode || "common"),
      custom_ports: Array.isArray(stages.custom_ports) ? (stages.custom_ports as string[]).join(",") : String(stages.custom_ports || ""),
      fingerprint: Boolean(stages.fingerprint ?? true),
      vulnerability: Boolean(stages.vulnerability),
      nuclei_severities: String(stages.nuclei_severities || scan.nuclei_severities),
      nuclei_tags: String(stages.nuclei_tags || scan.nuclei_tags || ""),
      intensity: String(intensity.preset || "normal"),
      naabu_rate: String(intensity.naabu_rate ?? 1000),
      naabu_concurrency: String(intensity.naabu_concurrency ?? 25),
      naabu_timeout_ms: String(intensity.naabu_timeout_ms ?? 1000),
      naabu_retries: String(intensity.naabu_retries ?? 3),
      httpx_rate: String(intensity.httpx_rate ?? 150),
      httpx_threads: String(intensity.httpx_threads ?? 50),
      httpx_timeout: String(intensity.httpx_timeout ?? 10),
      httpx_retries: String(intensity.httpx_retries ?? 1),
      nuclei_rate: String(intensity.nuclei_rate ?? 150),
      nuclei_concurrency: String(intensity.nuclei_concurrency ?? 25),
      nuclei_timeout: String(intensity.nuclei_timeout ?? 10),
      nuclei_retries: String(intensity.nuclei_retries ?? 1),
      schedule_type: String(schedule.type || (scan.interval_minutes ? "legacy_interval" : "manual")),
      hour: String(schedule.hour ?? 2),
      minute: String(schedule.minute ?? 0),
      weekday: String(schedule.weekday ?? 0),
      day: String(schedule.day ?? 1),
      cron: String(schedule.expression || ""),
    });
    setStep(1);
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (form.scope === "wan" && form.wan_target_ids.length === 0) {
      setError("Select at least one authorized WAN target");
      return;
    }
    if (form.scope === "lan" && form.network_ids.length === 0) {
      setError("Select at least one network");
      return;
    }
    const body = {
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
      intensity_config: intensityPayload(),
      schedule_config:
        form.schedule_type === "manual"
          ? { type: "manual" }
          : form.schedule_type === "cron"
            ? { type: "cron", expression: form.cron }
            : form.schedule_type === "legacy_interval"
              ? undefined
              : {
                  type: form.schedule_type,
                  hour: Number(form.hour),
                  minute: Number(form.minute),
                  weekday: Number(form.weekday),
                  day: Number(form.day),
                },
    };
    try {
      if (editingId) {
        await api(`/api/scans/${editingId}`, { method: "PATCH", body: JSON.stringify(body) });
      } else {
        await api(`/api/tenants/${tenantId}/scans`, { method: "POST", body: JSON.stringify(body) });
      }
      setForm(emptyForm);
      setEditingId(null);
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
          <div className="flex justify-between items-center">
            <h3 className="font-medium">{editingId ? `Edit scan definition #${editingId}` : "New scan definition"}</h3>
            {editingId && (
              <button type="button" className="text-slate-400 text-sm" onClick={() => { setEditingId(null); setForm(emptyForm); }}>
                Cancel edit
              </button>
            )}
          </div>
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
                <option value="custom">Custom</option>
              </select>
              {form.intensity === "custom" && (
                <div className="grid md:grid-cols-3 gap-3 mt-3">
                  <Field label="Naabu rate" value={form.naabu_rate} onChange={(v) => setForm({ ...form, naabu_rate: v })} />
                  <Field label="Naabu concurrency" value={form.naabu_concurrency} onChange={(v) => setForm({ ...form, naabu_concurrency: v })} />
                  <Field label="Naabu timeout ms" value={form.naabu_timeout_ms} onChange={(v) => setForm({ ...form, naabu_timeout_ms: v })} />
                  <Field label="Naabu retries" value={form.naabu_retries} onChange={(v) => setForm({ ...form, naabu_retries: v })} />
                  <Field label="httpx rate" value={form.httpx_rate} onChange={(v) => setForm({ ...form, httpx_rate: v })} />
                  <Field label="httpx threads" value={form.httpx_threads} onChange={(v) => setForm({ ...form, httpx_threads: v })} />
                  <Field label="httpx timeout" value={form.httpx_timeout} onChange={(v) => setForm({ ...form, httpx_timeout: v })} />
                  <Field label="httpx retries" value={form.httpx_retries} onChange={(v) => setForm({ ...form, httpx_retries: v })} />
                  <Field label="Nuclei rate" value={form.nuclei_rate} onChange={(v) => setForm({ ...form, nuclei_rate: v })} />
                  <Field label="Nuclei concurrency" value={form.nuclei_concurrency} onChange={(v) => setForm({ ...form, nuclei_concurrency: v })} />
                  <Field label="Nuclei timeout" value={form.nuclei_timeout} onChange={(v) => setForm({ ...form, nuclei_timeout: v })} />
                  <Field label="Nuclei retries" value={form.nuclei_retries} onChange={(v) => setForm({ ...form, nuclei_retries: v })} />
                </div>
              )}
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
              {form.scope === "lan" ? (
                <div>
                  Site: {sites.find((s) => String(s.id) === form.site_id)?.name || "—"} · Networks:{" "}
                  {selectedNetworks.map((n) => `${n.name} (${n.cidr})`).join(", ") || "none selected"}
                </div>
              ) : (
                <div>
                  WAN targets: {selectedWanTargets.map((t) => `${t.name} (${t.normalized_value})`).join(", ") || "none selected"}
                </div>
              )}
              <div>Dispatch: {dispatchLabel}</div>
              <div>Stages: discovery {form.discovery ? "on" : "off"}, ports {form.port_mode}, fingerprint {form.fingerprint ? "on" : "off"}, vuln {form.vulnerability ? "on" : "off"}</div>
              <div>Intensity: {form.intensity}</div>
              <div>Schedule: {form.schedule_type}</div>
              <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2 px-4 mt-2">
                {editingId ? "Save scan definition" : "Create scan definition"}
              </button>
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
                <button className="text-cyan-400 text-sm" onClick={() => beginEdit(s)}>
                  Edit
                </button>
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
          <div>
            <h4 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Raw evidence</h4>
            {jobArtifacts.length === 0 ? (
              <p className="text-slate-400">No retained raw artifacts are recorded for this run.</p>
            ) : (
              <div className="space-y-2">
                {jobArtifacts.map((artifact) => (
                  <div key={artifact.id} className="border border-slate-800 rounded-lg p-3 space-y-1">
                    <div>Tool: {artifact.tool}</div>
                    <div>Stage: {artifact.stage}</div>
                    <div>Size: {artifact.size_bytes} bytes</div>
                    <div>Created: {formatUtc(artifact.created_at, defaultTimezone)}</div>
                    <div>Retain until: {formatUtc(artifact.retention_expires_at, defaultTimezone)}</div>
                    <div>Status: {artifact.available ? "Available" : "Expired"}</div>
                    <div className="break-all">SHA-256: {artifact.sha256}</div>
                    {artifact.available && (
                      <button
                        className="text-cyan-400"
                        onClick={() =>
                          download(
                            `/api/scan-artifacts/${artifact.id}/download`,
                            artifact.download_filename
                          )
                        }
                      >
                        Download
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div>
            <h4 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Related controls</h4>
            <ControlMapping tenantId={tenantId} subjectType="scan_job" subjectId={selectedJob.id} />
          </div>
        </div>
      )}
    </div>
  );
}

function dash(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function percentileLabel(value: number | null | undefined) {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 100)}th percentile`;
}

function Findings({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const { defaultTimezone } = useTimezone();
  const [rows, setRows] = useState<AssetFinding[]>([]);
  const [severity, setSeverity] = useState("");
  const [technicalState, setTechnicalState] = useState("open");
  const [priority, setPriority] = useState("");
  const [kev, setKev] = useState("");
  const [treatmentState, setTreatmentState] = useState("");
  const [reviewOverdue, setReviewOverdue] = useState("");
  const [selected, setSelected] = useState<AssetFindingDetail | null>(null);
  const [evidenceId, setEvidenceId] = useState<number | null>(null);
  const [policyEval, setPolicyEval] = useState<PolicyEvaluation | null>(null);
  function load() {
    const qs = new URLSearchParams();
    if (severity) qs.set("severity", severity);
    if (technicalState) qs.set("technical_state", technicalState);
    if (priority) qs.set("priority", priority);
    if (kev) qs.set("kev", kev);
    if (treatmentState) qs.set("treatment_state", treatmentState);
    if (reviewOverdue) qs.set("treatment_review_overdue", reviewOverdue);
    api<AssetFinding[]>(`/api/tenants/${tenantId}/asset-findings?${qs}`).then(setRows);
  }
  useEffect(load, [tenantId, severity, technicalState, priority, kev, treatmentState, reviewOverdue]);
  async function openDetail(id: number) {
    const detail = await api<AssetFindingDetail>(`/api/tenants/${tenantId}/asset-findings/${id}`);
    setSelected(detail);
    setEvidenceId(detail.evidence[0]?.id ?? null);
    api<PolicyEvaluation>(`/api/tenants/${tenantId}/asset-findings/${id}/policy-evaluation`).then(setPolicyEval);
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label>State</label>
          <select value={technicalState} onChange={(e) => setTechnicalState(e.target.value)}>
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
        <div>
          <label>Priority</label>
          <select value={priority} onChange={(e) => setPriority(e.target.value)}>
            <option value="">All</option>
            {["p1", "p2", "p3", "p4"].map((item) => (
              <option key={item} value={item}>
                {item.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label>Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label>CISA KEV</label>
          <select value={kev} onChange={(e) => setKev(e.target.value)}>
            <option value="">All</option>
            <option value="true">KEV</option>
            <option value="false">Not KEV</option>
          </select>
        </div>
        <div>
          <label>Treatment</label>
          <select value={treatmentState} onChange={(e) => setTreatmentState(e.target.value)}>
            <option value="">All</option>
            <option value="unaddressed">Unaddressed</option>
            <option value="mitigated">Mitigated</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="false_positive">False positive</option>
          </select>
        </div>
        <div>
          <label>Review</label>
          <select value={reviewOverdue} onChange={(e) => setReviewOverdue(e.target.value)}>
            <option value="">All</option>
            <option value="true">Review overdue</option>
          </select>
        </div>
        <button
          className="text-cyan-400 text-sm"
          onClick={() => download(`/api/tenants/${tenantId}/findings/export`, `detection-evidence-${tenantId}.csv`)}
        >
          Export detection evidence CSV
        </button>
      </div>
      <div className="overflow-auto border border-slate-800 rounded-xl">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400 text-left">
            <tr>
              {["Priority", "Asset", "Finding", "CVE / identity", "CVSS", "EPSS", "KEV", "State", "Treatment", "Last seen"].map((h) => (
                <th key={h} className="px-3 py-2 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td className="px-3 py-4 text-slate-500" colSpan={10}>
                  None yet.
                </td>
              </tr>
            )}
            {rows.map((f) => (
              <tr
                key={f.id}
                className="border-t border-slate-800 cursor-pointer hover:bg-slate-800/40"
                onClick={() => openDetail(f.id)}
              >
                <td className="px-3 py-2">
                  {f.priority ? <Badge value={f.priority} /> : <span className="text-slate-500">—</span>}
                </td>
                <td className="px-3 py-2">{f.asset_hostname || f.asset_display_name || `Asset #${f.asset_id}`}</td>
                <td className="px-3 py-2">{f.title || "—"}</td>
                <td className="px-3 py-2 font-mono text-xs">{f.identity_label}</td>
                <td className="px-3 py-2">{dash(f.cvss_base_score)}</td>
                <td className="px-3 py-2">{f.epss_score == null ? "—" : Number(f.epss_score).toFixed(3)}</td>
                <td className="px-3 py-2">{f.kev == null ? "—" : f.kev ? "KEV" : "No"}</td>
                <td className="px-3 py-2">
                  <Badge value={f.technical_state} />
                </td>
                <td className="px-3 py-2">
                  <Badge value={f.treatment_display_status || f.treatment_state} />
                </td>
                <td className="px-3 py-2">{formatUtc(f.last_seen, defaultTimezone)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
          <div className="flex justify-between gap-3">
            <div>
              <h3 className="font-semibold">{selected.title || selected.identity_label}</h3>
              <p className="text-slate-400 text-sm">
                {selected.identity_label} · Asset #{selected.asset_id} {selected.asset_hostname || selected.asset_display_name}
              </p>
            </div>
            <button className="text-cyan-400 text-sm" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {selected.priority && <Badge value={selected.priority} />}
            <Badge value={selected.technical_state} />
            <Badge value={selected.severity} />
            <Badge value={selected.treatment_state} />
          </div>
          <section className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
            <h4 className="text-sm uppercase tracking-wide text-slate-400">Intelligence & Priority</h4>
            <div className="text-lg font-semibold">
              {(selected.priority || "—").toUpperCase()}
              {selected.priority_score != null ? ` — Score ${selected.priority_score}` : ""}
            </div>
            <p className="text-xs text-slate-500">
              Nuclei Dashboard operational priority using NVD, FIRST EPSS, and CISA KEV as inputs. This is not an NVD,
              FIRST, or CISA risk rating.
            </p>
            <div>
              <h5 className="text-sm font-medium mb-2">Why this priority</h5>
              <div className="space-y-1 text-sm">
                {(selected.priority_explanation?.factors || []).map((factor, index) => (
                  <div key={`${factor.factor}-${index}`} className="flex gap-3">
                    <span className="w-12 text-slate-400">{factor.points && factor.points > 0 ? `+${factor.points}` : factor.points || "+0"}</span>
                    <span>
                      {factor.factor.replaceAll("_", " ")}
                      {factor.value !== undefined && factor.value !== null && factor.value !== ""
                        ? `: ${String(factor.value)}`
                        : ""}
                      {factor.note ? ` — ${factor.note}` : ""}
                    </span>
                  </div>
                ))}
                {(selected.priority_explanation?.overrides || []).map((item, index) => (
                  <div key={`override-${index}`} className="text-rose-200">
                    Override: {item.reason || item.type} → {(item.priority || "").toUpperCase()}
                  </div>
                ))}
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-2 text-sm text-slate-300">
              <div>CVSS: {dash(selected.cvss_base_score)} {selected.cvss_base_severity || ""} {selected.cvss_version ? `(v${selected.cvss_version})` : ""}</div>
              <div>Vector: {dash(selected.cvss_vector)}</div>
              <div>EPSS probability: {selected.epss_score == null ? "—" : Number(selected.epss_score).toFixed(4)}</div>
              <div>EPSS percentile: {percentileLabel(selected.epss_percentile)}</div>
              <div>CISA KEV: {selected.kev == null ? "—" : selected.kev ? "Yes" : "No"}</div>
              <div>KEV added: {selected.kev_date_added || "—"}</div>
              <div>Ransomware campaign use: {selected.kev_known_ransomware_campaign_use == null ? "—" : selected.kev_known_ransomware_campaign_use ? "Known" : "Unknown"}</div>
              <div>CWE: {(selected.cwe_ids || []).join(", ") || "—"}</div>
              <div>NVD fetched: {selected.nvd_fetched_at ? formatUtc(selected.nvd_fetched_at, defaultTimezone) : "—"}</div>
              <div>EPSS fetched: {selected.epss_fetched_at ? formatUtc(selected.epss_fetched_at, defaultTimezone) : "—"}</div>
              <div>KEV fetched: {selected.kev_fetched_at ? formatUtc(selected.kev_fetched_at, defaultTimezone) : "—"}</div>
            </div>
          </section>
          {policyEval?.actions.resolution_clean_scans && (
            <section className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-2">
              <h4 className="text-sm uppercase tracking-wide text-slate-400">Policy Evaluation</h4>
              <div className="text-sm">
                Resolve after {String(policyEval.actions.resolution_clean_scans.value)} consecutive applicable clean scans
              </div>
              <div className="text-sm text-slate-400">
                {policyEval.actions.resolution_clean_scans.source === "policy"
                  ? `Winning rule: ${policyEval.actions.resolution_clean_scans.rule_name} (${policyEval.actions.resolution_clean_scans.scope_type}, priority ${policyEval.actions.resolution_clean_scans.priority})`
                  : "Fallback: global setting"}
              </div>
            </section>
          )}
          <TreatmentPanel
            tenantId={tenantId}
            selected={selected}
            write={write}
            timezone={defaultTimezone}
            onChanged={() => openDetail(selected.id)}
          />
          <div className="grid md:grid-cols-2 gap-2 text-sm text-slate-300">
            <div>First seen: {formatUtc(selected.first_seen, defaultTimezone)}</div>
            <div>Last seen: {formatUtc(selected.last_seen, defaultTimezone)}</div>
            <div>Resolved: {selected.resolved_at ? formatUtc(selected.resolved_at, defaultTimezone) : "—"}</div>
            <div>Clean scans: {selected.consecutive_clean_scans}</div>
            <div>Reopened: {selected.reopened_count}</div>
            <div>
              Detector: {selected.detector_type || "—"} {selected.detector_key || ""}
            </div>
          </div>
          <div>
            <h4 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Lifecycle history</h4>
            <Table
              headers={["When", "Transition", "From", "To", "Run"]}
              rows={selected.history.map((row) => [
                formatUtc(row.occurred_at, defaultTimezone),
                <Badge value={row.transition_type} />,
                row.previous_technical_state || "—",
                row.new_technical_state,
                row.scan_job_id ? `#${row.scan_job_id}` : "—",
              ])}
            />
          </div>
          <div>
            <h4 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Detection evidence</h4>
            <Table
              headers={["When", "Severity", "Template", "Host", "Run"]}
              rows={selected.evidence.map((row) => [
                <button className="text-cyan-400" onClick={() => setEvidenceId(row.id)}>
                  {formatUtc(row.found_at, defaultTimezone)}
                </button>,
                <Badge value={row.severity} />,
                row.template_id || row.detector_key || "—",
                row.host || row.matched_at || row.hostname || "—",
                row.scan_job_id ? `#${row.scan_job_id}` : "—",
              ])}
            />
            {evidenceId && (
              <div className="mt-3">
                <h5 className="text-sm font-medium mb-2">Related controls for detection evidence #{evidenceId}</h5>
                <ControlMapping tenantId={tenantId} subjectType="finding" subjectId={evidenceId} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function treatmentLabel(value: string) {
  return value.replaceAll("_", " ");
}

function TreatmentPanel({
  tenantId,
  selected,
  write,
  timezone,
  onChanged,
}: {
  tenantId: number;
  selected: AssetFindingDetail;
  write: boolean;
  timezone: string;
  onChanged: () => void;
}) {
  const current = selected.current_treatment;
  const [kind, setKind] = useState("mitigated");
  const [rationale, setRationale] = useState("");
  const [notes, setNotes] = useState("");
  const [controlName, setControlName] = useState("");
  const [controlDesc, setControlDesc] = useState("");
  const [reviewDue, setReviewDue] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState("");

  async function createTreatment(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/asset-findings/${selected.id}/treatments`, {
        method: "POST",
        body: JSON.stringify({
          treatment_type: kind,
          rationale,
          evidence_notes: notes,
          review_due_at: reviewDue ? new Date(reviewDue).toISOString() : null,
          expires_at: expires ? new Date(expires).toISOString() : null,
        }),
      });
      setRationale("");
      setNotes("");
      setReviewDue("");
      setExpires("");
      onChanged();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to record treatment");
    }
  }

  async function act(path: string, body: Record<string, string>) {
    await api(`/api/tenants/${tenantId}/asset-findings/${selected.id}/treatments/${current?.id}/${path}`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    onChanged();
  }

  return (
    <section className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
      <h4 className="text-sm uppercase tracking-wide text-slate-400">Treatment & Compliance</h4>
      <p className="text-xs text-slate-500">
        Technical state and treatment are separate. A documented mitigation or accepted risk does not resolve the
        technical finding. Control mappings are evidence references, not a compliance or certification result.
      </p>
      <div className="flex flex-wrap gap-2">
        <Badge value={selected.treatment_state} />
        <Badge value={selected.treatment_display_status || "unaddressed"} />
      </div>
      {current ? (
        <div className="text-sm text-slate-300 space-y-1">
          <div>Status: {treatmentLabel(current.display_status)}</div>
          <div>Rationale: {current.rationale}</div>
          <div>Created by: {current.created_by_username || "—"} · {formatUtc(current.created_at, timezone)}</div>
          <div>Reviewed by: {current.reviewed_by_username || "—"} {current.reviewed_at ? `· ${formatUtc(current.reviewed_at, timezone)}` : ""}</div>
          <div>Review due: {current.review_due_at ? formatUtc(current.review_due_at, timezone) : "—"}</div>
          <div>Expires: {current.expires_at ? formatUtc(current.expires_at, timezone) : "—"}</div>
          {current.evidence_notes && <div>Evidence notes: {current.evidence_notes}</div>}
        </div>
      ) : (
        <div className="text-sm text-slate-500">No current treatment. This finding is unaddressed.</div>
      )}
      {write && (
        <div className="flex flex-wrap gap-2">
          {current?.status === "pending_review" && (
            <button className="text-cyan-400 text-sm" onClick={() => act("approve", { review_notes: "Approved" })}>
              Review / approve
            </button>
          )}
          {current && (current.status === "active" || current.status === "pending_review") && (
            <button
              className="text-rose-300 text-sm"
              onClick={() => {
                const reason = window.prompt("Why is this treatment being revoked?");
                if (reason) act("revoke", { reason });
              }}
            >
              Revoke
            </button>
          )}
        </div>
      )}
      <div>
        <h5 className="text-sm font-medium mb-2">Compensating controls</h5>
        {(current?.compensating_controls || []).length === 0 && <div className="text-sm text-slate-500">None documented.</div>}
        {(current?.compensating_controls || []).map((row) => (
          <div key={row.id} className="text-sm border border-slate-800 rounded p-2 mb-2">
            <div className="flex gap-2">
              <Badge value={row.status} />
              <span>{row.name}</span>
            </div>
            <div className="text-slate-400">{row.description}</div>
            {row.evidence_notes && <div>Evidence: {row.evidence_notes}</div>}
            {write && current && row.status === "active" && (
              <button
                className="text-rose-300 text-sm"
                onClick={() => {
                  const reason = window.prompt("Why is this compensating control being retired?");
                  if (!reason) return;
                  api(
                    `/api/tenants/${tenantId}/asset-findings/${selected.id}/treatments/${current.id}/compensating-controls/${row.id}/retire`,
                    { method: "POST", body: JSON.stringify({ reason }) }
                  ).then(onChanged);
                }}
              >
                Retire
              </button>
            )}
          </div>
        ))}
        {write && current && (
          <form
            className="grid md:grid-cols-3 gap-2"
            onSubmit={async (event) => {
              event.preventDefault();
              await api(`/api/tenants/${tenantId}/asset-findings/${selected.id}/treatments/${current.id}/compensating-controls`, {
                method: "POST",
                body: JSON.stringify({ name: controlName, description: controlDesc }),
              });
              setControlName("");
              setControlDesc("");
              onChanged();
            }}
          >
            <input className="w-full" placeholder="Control name" value={controlName} onChange={(e) => setControlName(e.target.value)} required />
            <input className="w-full" placeholder="Description" value={controlDesc} onChange={(e) => setControlDesc(e.target.value)} />
            <button className="text-cyan-400 text-sm">Add compensating control</button>
          </form>
        )}
      </div>
      <div>
        <h5 className="text-sm font-medium mb-2">Related controls</h5>
        <ControlMapping tenantId={tenantId} subjectType="asset_finding" subjectId={selected.id} />
        {current && <ControlMapping tenantId={tenantId} subjectType="treatment" subjectId={current.id} />}
      </div>
      {(selected.treatments || []).length > 1 && (
        <details className="text-sm text-slate-400">
          <summary>Treatment history</summary>
          {(selected.treatments || []).map((row: FindingTreatment) => (
            <div key={row.id} className="py-1">
              {treatmentLabel(row.treatment_type)} · {treatmentLabel(row.status)} · {formatUtc(row.created_at, timezone)}
            </div>
          ))}
        </details>
      )}
      {write && (
        <form className="space-y-2 border border-slate-800 rounded-lg p-3" onSubmit={createTreatment}>
          <h5 className="text-sm font-medium">Document a treatment</h5>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={`px-3 py-1 rounded ${kind === "mitigated" ? "bg-cyan-800" : "bg-slate-800"}`} onClick={() => setKind("mitigated")}>
              Add mitigation
            </button>
            <button type="button" className={`px-3 py-1 rounded ${kind === "accepted_risk" ? "bg-cyan-800" : "bg-slate-800"}`} onClick={() => setKind("accepted_risk")}>
              Accept risk
            </button>
            <button type="button" className={`px-3 py-1 rounded ${kind === "false_positive" ? "bg-cyan-800" : "bg-slate-800"}`} onClick={() => setKind("false_positive")}>
              Mark false positive
            </button>
          </div>
          <textarea className="w-full" placeholder="Rationale" value={rationale} onChange={(e) => setRationale(e.target.value)} required />
          <textarea className="w-full" placeholder="Evidence notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          <div className="grid md:grid-cols-2 gap-2">
            <div>
              <label>Review due</label>
              <input className="w-full" type="datetime-local" value={reviewDue} onChange={(e) => setReviewDue(e.target.value)} />
            </div>
            <div>
              <label>Expires</label>
              <input className="w-full" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
            </div>
          </div>
          {kind !== "mitigated" && <p className="text-xs text-slate-500">Accepted risk and false positive stay pending until explicitly reviewed.</p>}
          {error && <div className="text-rose-300 text-sm">{error}</div>}
          <button className="bg-cyan-700 text-white rounded-md px-3 py-1.5 text-sm">Save decision</button>
        </form>
      )}
    </section>
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
