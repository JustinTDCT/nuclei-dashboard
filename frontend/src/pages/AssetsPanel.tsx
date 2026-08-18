import { FormEvent, ReactNode, useEffect, useState } from "react";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { formatUtc, useTimezone } from "../timezone";
import type {
  Asset,
  AssetDetail,
  AssetObservation,
  HistoryPage,
  Site,
  Tag,
} from "../types";

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

const DISPOSITIONS = ["unreviewed", "approved", "unauthorized", "ignored"] as const;
const CRITICALITIES = ["low", "normal", "high", "critical"] as const;

export function AssetsPanel({ tenantId }: { tenantId: number }) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const { defaultTimezone } = useTimezone();
  const [rows, setRows] = useState<Asset[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [q, setQ] = useState("");
  const [siteId, setSiteId] = useState("");
  const [disposition, setDisposition] = useState("");
  const [selected, setSelected] = useState<AssetDetail | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  function load() {
    const qs = new URLSearchParams();
    if (q) qs.set("q", q);
    if (siteId) qs.set("site_id", siteId);
    if (disposition) qs.set("disposition", disposition);
    api<Asset[]>(`/api/tenants/${tenantId}/assets?${qs}`).then(setRows);
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then(setSites);
  }
  useEffect(load, [tenantId, siteId, disposition]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label>Site</label>
          <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
            <option value="">All sites</option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label>Disposition</label>
          <select value={disposition} onChange={(e) => setDisposition(e.target.value)}>
            <option value="">All</option>
            {DISPOSITIONS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
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
          onClick={() => download(`/api/tenants/${tenantId}/assets/export`, `assets-${tenantId}.csv`)}
        >
          Export CSV
        </button>
        {write && (
          <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-3 py-2 text-sm" onClick={() => setShowCreate(true)}>
            Expected asset
          </button>
        )}
      </div>
      <Table
        headers={["Name", "Address", "Site", "Class", "Lifecycle", "Disposition", "Criticality", "Tags", "Last seen", ""]}
        rows={rows.map((asset) => [
          <button className="text-cyan-400 text-left" onClick={() => api<AssetDetail>(`/api/assets/${asset.id}`).then(setSelected)}>
            <div>{asset.display_name || asset.hostname || "—"}</div>
            {asset.is_not_yet_observed && <div className="text-[11px] text-amber-300">Expected / Not Yet Observed</div>}
          </button>,
          <span className="font-mono text-xs">{asset.current_addresses.join(", ") || "—"}</span>,
          asset.site_name || (asset.site_id ? `#${asset.site_id}` : "WAN / none"),
          asset.classification || "Unknown",
          <Badge value={asset.lifecycle_state} />,
          <Badge value={asset.disposition} />,
          <Badge value={asset.criticality} />,
          <TagList tags={asset.tags} />,
          formatUtc(asset.last_seen, defaultTimezone),
          write ? (
            <select
              className="min-w-[8rem]"
              value={asset.disposition}
              onChange={(e) =>
                api(`/api/assets/${asset.id}`, {
                  method: "PATCH",
                  body: JSON.stringify({ disposition: e.target.value }),
                }).then(load)
              }
            >
              {DISPOSITIONS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          ) : (
            ""
          ),
        ])}
      />
      {showCreate && write && (
        <ExpectedForm
          tenantId={tenantId}
          sites={sites}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}
      {selected && (
        <AssetDrawer
          asset={selected}
          write={write}
          timezone={defaultTimezone}
          onClose={() => setSelected(null)}
          onChanged={() => {
            load();
            api<AssetDetail>(`/api/assets/${selected.id}`).then(setSelected);
          }}
        />
      )}
    </div>
  );
}

function ExpectedForm({
  tenantId,
  sites,
  onClose,
  onCreated,
}: {
  tenantId: number;
  sites: Site[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState({
    site_id: sites[0] ? String(sites[0].id) : "",
    display_name: "",
    hostname: "",
    mac: "",
    ip: "",
    classification: "Unknown",
    criticality: "normal",
    description: "",
    tags: "",
  });
  const [error, setError] = useState("");

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/assets`, {
        method: "POST",
        body: JSON.stringify({
          site_id: Number(form.site_id),
          display_name: form.display_name,
          hostname: form.hostname,
          mac: form.mac,
          ip: form.ip,
          classification: form.classification,
          criticality: form.criticality,
          description: form.description,
          tags: form.tags
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
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
        className="w-full max-w-xl bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold">Create expected asset</h2>
        <p className="text-sm text-slate-400">Saved as Expected / Not Yet Observed. Scanner results will not auto-merge with this record.</p>
        <div>
          <label>Site</label>
          <select className="w-full" value={form.site_id} onChange={(e) => setForm({ ...form, site_id: e.target.value })} required>
            <option value="">Select site</option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.name}
              </option>
            ))}
          </select>
        </div>
        <div className="grid md:grid-cols-2 gap-3">
          <Field label="Display name" value={form.display_name} onChange={(v) => setForm({ ...form, display_name: v })} />
          <Field label="Expected hostname" value={form.hostname} onChange={(v) => setForm({ ...form, hostname: v })} required={false} />
          <Field label="Expected MAC" value={form.mac} onChange={(v) => setForm({ ...form, mac: v })} required={false} />
          <Field label="Expected IP" value={form.ip} onChange={(v) => setForm({ ...form, ip: v })} required={false} />
        </div>
        <div className="grid md:grid-cols-2 gap-3">
          <div>
            <label>Classification</label>
            <select className="w-full" value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}>
              {DEVICE_CLASSES.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </div>
          <div>
            <label>Criticality</label>
            <select className="w-full" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
              {CRITICALITIES.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </div>
        </div>
        <Field label="Description" value={form.description} onChange={(v) => setForm({ ...form, description: v })} required={false} />
        <Field label="Tags (comma separated)" value={form.tags} onChange={(v) => setForm({ ...form, tags: v })} required={false} />
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

function AssetDrawer({
  asset,
  write,
  timezone,
  onClose,
  onChanged,
}: {
  asset: AssetDetail;
  write: boolean;
  timezone: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [observations, setObservations] = useState<AssetObservation[]>([]);
  const [classification, setClassification] = useState(asset.classification);
  const [description, setDescription] = useState(asset.description);
  const [criticality, setCriticality] = useState(asset.criticality);
  const [disposition, setDisposition] = useState(asset.disposition);
  const [tagName, setTagName] = useState("");

  useEffect(() => {
    setClassification(asset.classification);
    setDescription(asset.description);
    setCriticality(asset.criticality);
    setDisposition(asset.disposition);
    api<HistoryPage<AssetObservation>>(`/api/assets/${asset.id}/observations?limit=50`).then((page) =>
      setObservations(page.items)
    );
  }, [asset.id, asset.classification, asset.description, asset.criticality, asset.disposition]);

  async function saveMeta() {
    await api(`/api/assets/${asset.id}`, {
      method: "PATCH",
      body: JSON.stringify({ classification, description, criticality, disposition }),
    });
    onChanged();
  }

  return (
    <div className="fixed inset-0 z-20 bg-black/60 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl h-full bg-slate-950 border-l border-slate-800 p-5 overflow-auto space-y-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-start gap-3">
          <div>
            <h2 className="text-lg font-semibold">{asset.display_name}</h2>
            <p className="text-slate-400 text-sm">{asset.site_name || "No site"} · {asset.current_addresses.join(", ") || "No address"}</p>
            {asset.is_not_yet_observed && <Badge value="expected" />}
          </div>
          <button className="text-slate-400" onClick={onClose}>
            Close
          </button>
        </div>

        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">Overview</h3>
          {write ? (
            <div className="grid md:grid-cols-2 gap-3">
              <div>
                <label>Classification</label>
                <select className="w-full" value={classification} onChange={(e) => setClassification(e.target.value)}>
                  {DEVICE_CLASSES.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Criticality</label>
                <select className="w-full" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
                  {CRITICALITIES.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Disposition</label>
                <select className="w-full" value={disposition} onChange={(e) => setDisposition(e.target.value)}>
                  {DISPOSITIONS.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Description</label>
                <input className="w-full" value={description} onChange={(e) => setDescription(e.target.value)} />
              </div>
              <button type="button" className="bg-cyan-600 text-slate-950 font-medium rounded-md py-2" onClick={saveMeta}>
                Save
              </button>
            </div>
          ) : (
            <div className="text-sm text-slate-300 space-y-1">
              <div>Class: {asset.classification}</div>
              <div>Lifecycle: {asset.lifecycle_state}</div>
              <div>Disposition: {asset.disposition}</div>
              <div>Criticality: {asset.criticality}</div>
              <div>Description: {asset.description || "—"}</div>
            </div>
          )}
          <div className="text-sm text-slate-400">
            First seen: {formatUtc(asset.first_seen, timezone)} · Last seen: {formatUtc(asset.last_seen, timezone)}
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">Tags</h3>
          <div className="flex flex-wrap gap-2 items-center">
            <TagList tags={asset.tags} />
            {write &&
              asset.tags.map((tag) => (
                <button key={tag.id} className="text-rose-300 text-xs" onClick={() => api(`/api/assets/${asset.id}/tags/${tag.id}`, { method: "DELETE" }).then(onChanged)}>
                  Remove {tag.name}
                </button>
              ))}
          </div>
          {write && (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                api(`/api/assets/${asset.id}/tags`, { method: "POST", body: JSON.stringify({ name: tagName }) }).then(() => {
                  setTagName("");
                  onChanged();
                });
              }}
            >
              <input className="flex-1" value={tagName} onChange={(e) => setTagName(e.target.value)} placeholder="Add tag" />
              <button className="text-cyan-400 text-sm">Add</button>
            </form>
          )}
        </section>

        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Identifiers</h3>
          <Table
            headers={["Type", "Value", "Source"]}
            rows={asset.identifiers.map((row) => [row.identifier_type, row.value, row.source])}
          />
        </section>
        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Addresses</h3>
          <Table
            headers={["IP", "Family", "Source", "Last seen"]}
            rows={asset.addresses.map((row) => [row.ip, row.address_family, row.source, formatUtc(row.last_seen, timezone)])}
          />
        </section>
        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Services</h3>
          <Table
            headers={["Port", "Proto", "Title", "Last seen"]}
            rows={asset.services.map((row) => [`${row.ip}:${row.port}`, row.protocol, row.web_title || row.product || "—", formatUtc(row.last_seen, timezone)])}
          />
        </section>
        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Observations</h3>
          <Table
            headers={["When", "Source", "Scope", "Host", "IP"]}
            rows={observations.map((row) => [formatUtc(row.observed_at, timezone), row.source, row.scope || "—", row.hostname || "—", row.ip || "—"])}
          />
        </section>
        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Existing findings</h3>
          <Table
            headers={["When", "Severity", "Name"]}
            rows={asset.findings.map((finding) => [
              formatUtc(finding.found_at, timezone),
              <Badge value={finding.severity} />,
              finding.name || finding.template_id,
            ])}
          />
        </section>
      </div>
    </div>
  );
}

export function TagList({ tags }: { tags?: Tag[] }) {
  if (!tags || tags.length === 0) return <span className="text-slate-500">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((tag) => (
        <span key={tag.id} className="inline-flex px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-200">
          {tag.name}
        </span>
      ))}
    </div>
  );
}

export function TagEditor({
  write,
  tags,
  onAdd,
  onRemove,
}: {
  write: boolean;
  tags?: Tag[];
  onAdd: (name: string) => Promise<void>;
  onRemove: (tagId: number) => Promise<void>;
}) {
  const [name, setName] = useState("");
  return (
    <div className="space-y-2">
      <TagList tags={tags} />
      {write && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim()) return;
            onAdd(name.trim()).then(() => setName(""));
          }}
        >
          <input className="flex-1" value={name} onChange={(e) => setName(e.target.value)} placeholder="Add tag" />
          <button className="text-cyan-400 text-sm">Add</button>
        </form>
      )}
      {write &&
        (tags || []).map((tag) => (
          <button key={tag.id} className="text-rose-300 text-xs mr-2" onClick={() => onRemove(tag.id)}>
            Remove {tag.name}
          </button>
        ))}
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  required = true,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
}) {
  return (
    <div>
      <label>{label}</label>
      <input className="w-full" value={value} onChange={(e) => onChange(e.target.value)} required={required} />
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
