import { FormEvent, ReactNode, useEffect, useState } from "react";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { formatUtc, useTimezone } from "../timezone";
import type { Agent, Network, Site } from "../types";

const COMMON_TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Anchorage",
  "Pacific/Honolulu",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Australia/Sydney",
];

export function SitesPanel({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const { defaultTimezone } = useTimezone();
  const [sites, setSites] = useState<Site[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [name, setName] = useState("");
  const [timezone, setTimezone] = useState("");
  const [error, setError] = useState("");

  function load() {
    api<Site[]>(`/api/tenants/${tenantId}/sites?include_archived=${showArchived}`).then((rows) => {
      setSites(rows);
      setSelectedId((current) => current ?? rows[0]?.id ?? null);
    });
  }
  useEffect(load, [tenantId, showArchived]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const site = await api<Site>(`/api/tenants/${tenantId}/sites`, {
        method: "POST",
        body: JSON.stringify({ name, timezone: timezone || null }),
      });
      setName("");
      setTimezone("");
      setSelectedId(site.id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  const selected = sites.find((s) => s.id === selectedId) || null;

  return (
    <div className="space-y-4">
      {write && (
        <form onSubmit={onCreate} className="grid md:grid-cols-3 gap-3 items-end bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div>
            <label>Site name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Boston HQ" />
          </div>
          <TimezoneField label="Timezone override" value={timezone} onChange={setTimezone} allowEmpty />
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Create site</button>
        </form>
      )}
      <label className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
        <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />
        Show archived sites
      </label>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <div className="grid lg:grid-cols-[280px_1fr] gap-4">
        <div className="space-y-2">
          {sites.map((site) => (
            <button
              key={site.id}
              onClick={() => setSelectedId(site.id)}
              className={`w-full text-left rounded-xl border p-3 ${
                site.id === selectedId ? "border-cyan-600 bg-slate-900" : "border-slate-800 bg-slate-950"
              }`}
            >
              <div className="font-medium">{site.name}</div>
              <div className="text-xs text-slate-400 mt-1">
                {site.network_count} networks · {site.agent_count} agents
              </div>
              <div className="text-xs text-slate-500">{site.effective_timezone}</div>
              {site.is_archived && <Badge value="archived" />}
            </button>
          ))}
          {sites.length === 0 && <div className="text-slate-500 text-sm">No sites yet. Create one to add LAN networks and agents.</div>}
        </div>
        {selected && (
          <SiteDetail
            site={selected}
            tenantId={tenantId}
            write={write}
            defaultTimezone={defaultTimezone}
            onChanged={load}
          />
        )}
      </div>
    </div>
  );
}

function SiteDetail({
  site,
  tenantId,
  write,
  defaultTimezone,
  onChanged,
}: {
  site: Site;
  tenantId: number;
  write: boolean;
  defaultTimezone: string;
  onChanged: () => void;
}) {
  const [name, setName] = useState(site.name);
  const [timezone, setTimezone] = useState(site.timezone || "");
  const [networks, setNetworks] = useState<Network[]>([]);
  const [siteAgents, setSiteAgents] = useState<Agent[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    setName(site.name);
    setTimezone(site.timezone || "");
  }, [site.id, site.name, site.timezone]);

  function load() {
    api<Network[]>(`/api/sites/${site.id}/networks?include_archived=true`).then(setNetworks);
    api<Agent[]>(`/api/sites/${site.id}/agents`).then(setSiteAgents);
  }
  useEffect(load, [site.id]);

  async function saveSite(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/sites/${site.id}`, {
        method: "PATCH",
        body: JSON.stringify({ name, timezone: timezone || null }),
      });
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-5">
      <form onSubmit={saveSite} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex justify-between gap-3 items-start">
          <div>
            <h3 className="font-medium">{site.name}</h3>
            <p className="text-xs text-slate-400">
              Effective timezone: {site.effective_timezone}
              {!site.timezone ? ` (global default ${defaultTimezone})` : ""}
            </p>
          </div>
          {site.is_archived && <Badge value="archived" />}
        </div>
        {write && (
          <div className="grid md:grid-cols-2 gap-3 items-end">
            <div>
              <label>Name</label>
              <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <TimezoneField label="Timezone override" value={timezone} onChange={setTimezone} allowEmpty />
            <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Save site</button>
            {site.is_archived ? (
              <button
                type="button"
                className="text-emerald-300 text-sm"
                onClick={() => api(`/api/sites/${site.id}/unarchive`, { method: "POST" }).then(onChanged)}
              >
                Unarchive site
              </button>
            ) : (
              <button
                type="button"
                className="text-rose-300 text-sm"
                onClick={() => api(`/api/sites/${site.id}/archive`, { method: "POST" }).then(onChanged)}
              >
                Archive site
              </button>
            )}
          </div>
        )}
        {error && <div className="text-rose-300 text-sm">{error}</div>}
      </form>
      <NetworkList site={site} networks={networks} agents={siteAgents} write={write} onChanged={() => { load(); onChanged(); }} />
      <SiteAgents
        site={site}
        tenantId={tenantId}
        agents={siteAgents}
        write={write}
        onChanged={() => { load(); onChanged(); }}
      />
    </div>
  );
}

function NetworkList({
  site,
  networks,
  agents,
  write,
  onChanged,
}: {
  site: Site;
  networks: Network[];
  agents: Agent[];
  write: boolean;
  onChanged: () => void;
}) {
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [error, setError] = useState("");

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/sites/${site.id}/networks`, {
        method: "POST",
        body: JSON.stringify({ name, cidr, dispatch_mode: "any_available" }),
      });
      setName("");
      setCidr("");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-3">
      <h3 className="font-medium">Networks</h3>
      {write && !site.is_archived && (
        <form onSubmit={onCreate} className="grid md:grid-cols-3 gap-3 items-end">
          <div>
            <label>Name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Server VLAN" />
          </div>
          <div>
            <label>CIDR</label>
            <input className="w-full" value={cidr} onChange={(e) => setCidr(e.target.value)} required placeholder="192.168.1.0/24" />
          </div>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2">Add network</button>
        </form>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <div className="space-y-3">
        {networks.map((network) => (
          <NetworkCard key={network.id} network={network} agents={agents} write={write} onChanged={onChanged} />
        ))}
        {networks.length === 0 && <div className="text-slate-500 text-sm">No networks on this site.</div>}
      </div>
    </div>
  );
}

function NetworkCard({
  network,
  agents,
  write,
  onChanged,
}: {
  network: Network;
  agents: Agent[];
  write: boolean;
  onChanged: () => void;
}) {
  const [name, setName] = useState(network.name);
  const [cidr, setCidr] = useState(network.cidr);
  const [mode, setMode] = useState(network.dispatch_mode);
  const [preferred, setPreferred] = useState(network.preferred_agent_id ? String(network.preferred_agent_id) : "");
  const [selected, setSelected] = useState<number[]>(network.authorized_agent_ids);
  const [error, setError] = useState("");

  useEffect(() => {
    setName(network.name);
    setCidr(network.cidr);
    setMode(network.dispatch_mode);
    setPreferred(network.preferred_agent_id ? String(network.preferred_agent_id) : "");
    setSelected(network.authorized_agent_ids);
  }, [network]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/networks/${network.id}/authorized-agents`, {
        method: "PUT",
        body: JSON.stringify({ agent_ids: selected }),
      });
      await api(`/api/networks/${network.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name,
          cidr,
          dispatch_mode: mode,
          preferred_agent_id: mode === "preferred_failover" && preferred ? Number(preferred) : null,
        }),
      });
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <form onSubmit={save} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
      <div className="flex justify-between gap-3">
        <div>
          <div className="font-medium">{network.name}</div>
          <div className="font-mono text-xs text-slate-400">{network.cidr}</div>
        </div>
        {network.is_archived && <Badge value="archived" />}
      </div>
      {write && (
        <>
          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <label>Name</label>
              <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div>
              <label>CIDR</label>
              <input className="w-full" value={cidr} onChange={(e) => setCidr(e.target.value)} required />
            </div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-400 mb-2">Authorized agents</div>
            <div className="flex flex-wrap gap-3">
              {agents.map((agent) => (
                <label key={agent.id} className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
                  <input
                    type="checkbox"
                    checked={selected.includes(agent.id)}
                    onChange={(e) =>
                      setSelected(e.target.checked ? [...selected, agent.id] : selected.filter((id) => id !== agent.id))
                    }
                  />
                  {agent.name}
                </label>
              ))}
              {agents.length === 0 && <div className="text-slate-500 text-sm">No agents at this site yet.</div>}
            </div>
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <label>Dispatch</label>
              <select className="w-full" value={mode} onChange={(e) => setMode(e.target.value as Network["dispatch_mode"])}>
                <option value="any_available">Any Available</option>
                <option value="preferred_failover">Preferred + Failover</option>
              </select>
            </div>
            {mode === "preferred_failover" && (
              <div>
                <label>Preferred agent</label>
                <select className="w-full" value={preferred} onChange={(e) => setPreferred(e.target.value)} required>
                  <option value="">Select agent</option>
                  {agents
                    .filter((agent) => selected.includes(agent.id))
                    .map((agent) => (
                      <option key={agent.id} value={agent.id}>
                        {agent.name}
                      </option>
                    ))}
                </select>
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-3 items-center">
            <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2">Save network</button>
            {network.is_archived ? (
              <button type="button" className="text-emerald-300 text-sm" onClick={() => api(`/api/networks/${network.id}/unarchive`, { method: "POST" }).then(onChanged)}>
                Unarchive
              </button>
            ) : (
              <button type="button" className="text-rose-300 text-sm" onClick={() => api(`/api/networks/${network.id}/archive`, { method: "POST" }).then(onChanged)}>
                Archive
              </button>
            )}
          </div>
        </>
      )}
      {!write && (
        <div className="text-sm text-slate-400">
          Authorized: {agents.filter((a) => network.authorized_agent_ids.includes(a.id)).map((a) => a.name).join(", ") || "none"}
          <div>
            Dispatch: {network.dispatch_mode === "preferred_failover" ? "Preferred + Failover" : "Any Available"}
          </div>
        </div>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
    </form>
  );
}

function SiteAgents({
  site,
  tenantId,
  agents,
  write,
  onChanged,
}: {
  site: Site;
  tenantId: number;
  agents: Agent[];
  write: boolean;
  onChanged: () => void;
}) {
  const { defaultTimezone } = useTimezone();
  const [name, setName] = useState("");
  const [created, setCreated] = useState<Agent | null>(null);
  const [error, setError] = useState("");

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const agent = await api<Agent>(`/api/tenants/${tenantId}/agents`, {
        method: "POST",
        body: JSON.stringify({ name, site_id: site.id }),
      });
      setName("");
      setCreated(agent);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-3">
      <h3 className="font-medium">Agents</h3>
      {write && !site.is_archived && (
        <form onSubmit={onCreate} className="flex gap-3 items-end">
          <div className="flex-1">
            <label>Agent name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Agent-HQ-01" />
          </div>
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2">Create agent</button>
        </form>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      {created && (
        <div className="bg-amber-950/40 border border-amber-800 rounded-xl p-4 text-sm space-y-2">
          <div className="font-medium">Agent created — download compose before the site comes online.</div>
          <div className="font-mono text-xs break-all">UUID: {created.uuid}</div>
          {created.enrollment_secret && <div className="font-mono text-xs break-all">Enrollment secret: {created.enrollment_secret}</div>}
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
        headers={["Name", "Status", "Online", "Last seen", ""]}
        rows={agents.map((a) => [
          <div>
            <div>{a.name}</div>
            <div className="font-mono text-[11px] text-slate-500">{a.uuid}</div>
          </div>,
          <Badge value={a.status} />,
          <Badge value={a.online ? "online" : "offline"} />,
          formatUtc(a.last_heartbeat, site.effective_timezone),
          write ? <MoveAgent agent={a} tenantId={tenantId} currentSiteId={site.id} onChanged={onChanged} /> : "",
        ])}
      />
    </div>
  );
}

function MoveAgent({
  agent,
  tenantId,
  currentSiteId,
  onChanged,
}: {
  agent: Agent;
  tenantId: number;
  currentSiteId: number;
  onChanged: () => void;
}) {
  const [sites, setSites] = useState<Site[]>([]);
  useEffect(() => {
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then(setSites);
  }, [tenantId]);
  return (
    <select
      className="text-sm"
      value={currentSiteId}
      onChange={(e) =>
        api(`/api/agents/${agent.id}`, {
          method: "PATCH",
          body: JSON.stringify({ site_id: Number(e.target.value) }),
        }).then(onChanged)
      }
    >
      {sites.map((site) => (
        <option key={site.id} value={site.id}>
          {site.name}
        </option>
      ))}
    </select>
  );
}

export function TimezoneField({
  label,
  value,
  onChange,
  allowEmpty,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  allowEmpty?: boolean;
}) {
  const [zones, setZones] = useState<string[]>(COMMON_TIMEZONES);
  useEffect(() => {
    api<{ timezones: string[] }>("/api/timezones")
      .then((data) => setZones(data.timezones))
      .catch(() => setZones(COMMON_TIMEZONES));
  }, []);
  const options = value && !zones.includes(value) ? [value, ...zones] : zones;
  return (
    <div>
      <label>{label}</label>
      <select className="w-full" value={value} onChange={(e) => onChange(e.target.value)}>
        {allowEmpty && <option value="">Use global default</option>}
        {options.map((zone) => (
          <option key={zone} value={zone}>
            {zone}
          </option>
        ))}
      </select>
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
