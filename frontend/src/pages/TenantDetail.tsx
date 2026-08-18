import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { Alerts } from "./Alerts";
import type { Agent, Device, DeviceDetail, Finding, Scan, ScanJob, Subnet, Tenant, TenantSummary } from "../types";

type Tab = "overview" | "subnets" | "agents" | "scans" | "devices" | "findings" | "alerts";

export function TenantDetail() {
  const { id } = useParams();
  const tenantId = Number(id);
  const [tab, setTab] = useState<Tab>("overview");
  const [tenant, setTenant] = useState<Tenant | null>(null);

  useEffect(() => {
    api<Tenant>(`/api/tenants/${tenantId}`).then(setTenant);
  }, [tenantId]);

  if (!tenant) return <div className="text-slate-400">Loading…</div>;

  const tabs: Tab[] = ["overview", "subnets", "agents", "scans", "devices", "findings", "alerts"];

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
            {t}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview tenantId={tenantId} />}
      {tab === "subnets" && <Subnets tenantId={tenantId} />}
      {tab === "agents" && <Agents tenantId={tenantId} />}
      {tab === "scans" && <Scans tenantId={tenantId} />}
      {tab === "devices" && <Devices tenantId={tenantId} />}
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
        <Stat label="New devices" value={data.devices.new} />
        <Stat label="Known devices" value={data.devices.known} />
        <Stat label="Stale devices" value={data.devices.stale} />
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

function Subnets({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const [rows, setRows] = useState<Subnet[]>([]);
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [scope, setScope] = useState<"wan" | "lan">("lan");
  const [error, setError] = useState("");

  function load() {
    api<Subnet[]>(`/api/tenants/${tenantId}/subnets`).then(setRows);
  }
  useEffect(load, [tenantId]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/subnets`, {
        method: "POST",
        body: JSON.stringify({ name, cidr, scope }),
      });
      setName("");
      setCidr("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-4">
      {write && (
        <form onSubmit={onCreate} className="grid md:grid-cols-4 gap-3 items-end bg-slate-900 border border-slate-800 rounded-xl p-4">
          <Field label="Name" value={name} onChange={setName} />
          <Field label="CIDR" value={cidr} onChange={setCidr} placeholder="10.0.0.0/24" />
          <div>
            <label>Scope</label>
            <select className="w-full" value={scope} onChange={(e) => setScope(e.target.value as "wan" | "lan")}>
              <option value="lan">LAN (site agent)</option>
              <option value="wan">WAN (central scanner)</option>
            </select>
          </div>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Add subnet</button>
        </form>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <Table
        headers={["Name", "CIDR", "Scope", ""]}
        rows={rows.map((s) => [
          s.name,
          <span className="font-mono">{s.cidr}</span>,
          <Badge value={s.scope} />,
          write ? (
            <button className="text-rose-300 text-sm" onClick={() => api(`/api/subnets/${s.id}`, { method: "DELETE" }).then(load)}>
              Delete
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
  const [name, setName] = useState("");
  const [created, setCreated] = useState<Agent | null>(null);

  function load() {
    api<Agent[]>(`/api/tenants/${tenantId}/agents`).then(setRows);
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
      body: JSON.stringify({ name }),
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
            <label>Site name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required placeholder="HQ LAN" />
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
        headers={["Name", "Status", "Online", "Host", "Last seen", ""]}
        rows={rows.map((a) => [
          <div>
            <div>{a.name}</div>
            <div className="font-mono text-[11px] text-slate-500">{a.uuid}</div>
          </div>,
          <Badge value={a.status} />,
          <Badge value={a.online ? "online" : "offline"} />,
          a.hostname || "—",
          a.last_heartbeat ? new Date(a.last_heartbeat).toLocaleString() : "—",
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
  const [subnets, setSubnets] = useState<Subnet[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [form, setForm] = useState({
    name: "",
    scope: "lan" as "lan" | "wan",
    agent_id: "",
    profile: "discovery",
    interval_minutes: "",
    subnet_ids: [] as number[],
  });

  function load() {
    api<Scan[]>(`/api/tenants/${tenantId}/scans`).then(setScans);
    api<ScanJob[]>(`/api/tenants/${tenantId}/jobs`).then(setJobs);
    api<Subnet[]>(`/api/tenants/${tenantId}/subnets`).then(setSubnets);
    api<Agent[]>(`/api/tenants/${tenantId}/agents`).then(setAgents);
  }
  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [tenantId]);

  const scopedSubnets = useMemo(
    () => subnets.filter((s) => s.scope === form.scope),
    [subnets, form.scope]
  );

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    await api(`/api/tenants/${tenantId}/scans`, {
      method: "POST",
      body: JSON.stringify({
        name: form.name,
        scope: form.scope,
        agent_id: form.scope === "lan" ? Number(form.agent_id) : null,
        profile: form.profile,
        interval_minutes: form.interval_minutes ? Number(form.interval_minutes) : null,
        subnet_ids: form.subnet_ids,
        is_enabled: true,
      }),
    });
    setForm({ ...form, name: "" });
    load();
  }

  return (
    <div className="space-y-6">
      {write && (
        <form onSubmit={onCreate} className="grid md:grid-cols-3 gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
          <Field label="Scan name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} />
          <div>
            <label>Scope</label>
            <select className="w-full" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as "lan" | "wan", subnet_ids: [] })}>
              <option value="lan">LAN (agent)</option>
              <option value="wan">WAN (central)</option>
            </select>
          </div>
          {form.scope === "lan" && (
            <div>
              <label>Agent</label>
              <select className="w-full" value={form.agent_id} onChange={(e) => setForm({ ...form, agent_id: e.target.value })} required>
                <option value="">Select agent</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.status})
                  </option>
                ))}
              </select>
            </div>
          )}
          <div>
            <label>Profile</label>
            <select className="w-full" value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value })}>
              <option value="discovery">Discovery only</option>
              <option value="discovery_nuclei">Discovery + Nuclei</option>
            </select>
          </div>
          <div>
            <label>Interval (minutes, blank = manual)</label>
            <input className="w-full" value={form.interval_minutes} onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })} />
          </div>
          <div className="md:col-span-3">
            <label>Subnets (leave empty for all {form.scope.toUpperCase()})</label>
            <div className="flex flex-wrap gap-3 mt-1">
              {scopedSubnets.map((s) => (
                <label key={s.id} className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
                  <input
                    type="checkbox"
                    checked={form.subnet_ids.includes(s.id)}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        subnet_ids: e.target.checked
                          ? [...form.subnet_ids, s.id]
                          : form.subnet_ids.filter((id) => id !== s.id),
                      })
                    }
                  />
                  {s.name} ({s.cidr})
                </label>
              ))}
            </div>
          </div>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Create scan</button>
        </form>
      )}
      <div>
        <h3 className="font-medium mb-2">Scan definitions</h3>
        <Table
          headers={["Name", "Scope", "Profile", "Schedule", ""]}
          rows={scans.map((s) => [
            s.name,
            <Badge value={s.scope} />,
            s.profile === "discovery_nuclei" ? "Discovery + Nuclei" : "Discovery",
            s.interval_minutes ? `Every ${s.interval_minutes}m` : "Manual",
            write ? (
              <button className="text-cyan-400 text-sm" onClick={() => api(`/api/scans/${s.id}/run`, { method: "POST" }).then(load)}>
                Run now
              </button>
            ) : (
              ""
            ),
          ])}
        />
      </div>
      <div>
        <h3 className="font-medium mb-2">Job history</h3>
        <Table
          headers={["Job", "Scan", "Status", "Hosts", "Findings", "Created"]}
          rows={jobs.map((j) => [
            `#${j.id}`,
            j.scan_name || j.scan_id,
            <Badge value={j.status} />,
            j.hosts_found,
            j.findings_count,
            new Date(j.created_at).toLocaleString(),
          ])}
        />
      </div>
    </div>
  );
}

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

function Devices({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const [rows, setRows] = useState<Device[]>([]);
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [selected, setSelected] = useState<DeviceDetail | None>(null);

  function openDevice(id: number) {
    api<DeviceDetail>(`/api/devices/${id}`).then(setSelected);
  }

  function load() {
    const qs = new URLSearchParams();
    if (status) qs.set("status", status);
    if (q) qs.set("q", q);
    api<Device[]>(`/api/tenants/${tenantId}/devices?${qs}`).then(setRows);
  }
  useEffect(load, [tenantId, status]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label>Status</label>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All</option>
            <option value="new">New</option>
            <option value="known">Known</option>
            <option value="stale">Stale</option>
          </select>
        </div>
        <div>
          <label>Search</label>
          <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
        </div>
        <button className="text-cyan-400 text-sm" onClick={load}>
          Search
        </button>
        <button
          className="text-cyan-400 text-sm"
          onClick={() => download(`/api/tenants/${tenantId}/devices/export`, `devices-${tenantId}.csv`)}
        >
          Export CSV
        </button>
      </div>
      <Table
        headers={["Hostname", "IP", "Scope", "Status", "Class", "Description", "Label", "Ports", "CVEs", "Last seen", ""]}
        rows={rows.map((d) => [
          <button className="text-cyan-400 text-left" onClick={() => openDevice(d.id)}>
            {d.hostname || "—"}
          </button>,
          <span className="font-mono">{d.ip}</span>,
          <Badge value={d.scope} />,
          <Badge value={d.status} />,
          write ? (
            <select
              className="min-w-[11rem]"
              value={DEVICE_CLASSES.includes(d.classification) ? d.classification : "Unknown"}
              onChange={(e) =>
                api(`/api/devices/${d.id}`, {
                  method: "PATCH",
                  body: JSON.stringify({ classification: e.target.value }),
                }).then(load)
              }
            >
              {DEVICE_CLASSES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          ) : (
            d.classification || "Unknown"
          ),
          write ? (
            <input
              className="w-48"
              placeholder="Custom details"
              value={notes[d.id] ?? d.description ?? ""}
              onChange={(e) => setNotes({ ...notes, [d.id]: e.target.value })}
              onBlur={() =>
                api(`/api/devices/${d.id}`, {
                  method: "PATCH",
                  body: JSON.stringify({ description: notes[d.id] ?? d.description ?? "" }),
                }).then(load)
              }
            />
          ) : (
            d.description || "—"
          ),
          d.auto_label || "—",
          (d.ports || []).join(", ") || "—",
          <button className="text-cyan-400 text-sm" onClick={() => openDevice(d.id)}>
            {d.findings_count ?? 0}
          </button>,
          new Date(d.last_seen).toLocaleString(),
          write && d.status === "new" ? (
            <button
              className="text-cyan-400 text-sm"
              onClick={() => api(`/api/devices/${d.id}`, { method: "PATCH", body: JSON.stringify({ status: "known" }) }).then(load)}
            >
              Mark known
            </button>
          ) : (
            ""
          ),
        ])}
      />
      {selected && (
        <div className="fixed inset-0 z-20 bg-black/60 flex justify-end" onClick={() => setSelected(null)}>
          <div
            className="w-full max-w-xl h-full bg-slate-950 border-l border-slate-800 p-5 overflow-auto space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-start gap-3">
              <div>
                <h2 className="text-lg font-semibold">{selected.hostname || selected.ip}</h2>
                <p className="text-slate-400 text-sm font-mono">{selected.ip}</p>
              </div>
              <button className="text-slate-400" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
            <div className="text-sm text-slate-300 space-y-1">
              <div>Class: {selected.classification || "Unknown"}</div>
              <div>Label: {selected.auto_label || selected.title || "—"}</div>
              <div>Ports: {(selected.ports || []).join(", ") || "—"}</div>
            </div>
            <h3 className="text-sm uppercase tracking-wide text-slate-400">CVEs / findings</h3>
            {selected.findings.length === 0 ? (
              <p className="text-slate-500 text-sm">No findings stored for this hostname yet.</p>
            ) : (
              <Table
                headers={["When", "Severity", "Name"]}
                rows={selected.findings.map((f) => [
                  new Date(f.found_at).toLocaleString(),
                  <Badge value={f.severity} />,
                  <div>
                    <div>{f.name || f.template_id}</div>
                    <div className="font-mono text-[11px] text-slate-500">{f.template_id}</div>
                  </div>,
                ])}
              />
            )}
          </div>
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
