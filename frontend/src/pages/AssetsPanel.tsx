import { FormEvent, ReactNode, useEffect, useState } from "react";
import { api, download } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { ControlMapping } from "../components/ControlMapping";
import { PageNav } from "../components/PageNav";
import { formatUtc, useTimezone } from "../timezone";
import type {
  Asset,
  AssetDetail,
  AssetObservation,
  DomainEvent,
  HistoryPage,
  PolicyEvaluation,
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
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const pageSize = 50;

  function load(nextOffset = offset) {
    const qs = new URLSearchParams();
    if (q) qs.set("q", q);
    if (siteId) qs.set("site_id", siteId);
    if (disposition) qs.set("disposition", disposition);
    qs.set("limit", String(pageSize));
    qs.set("offset", String(nextOffset));
    api<HistoryPage<Asset>>(`/api/tenants/${tenantId}/assets?${qs}`).then((page) => {
      setRows(page.items);
      setTotal(page.total);
      setOffset(page.offset);
    });
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then(setSites);
  }
  useEffect(() => {
    setOffset(0);
    load(0);
  }, [tenantId, siteId, disposition]);

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
        <button className="text-cyan-400 text-sm" onClick={() => { setOffset(0); load(0); }}>
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
          asset.lifecycle_state ? <Badge value={asset.lifecycle_state} /> : "—",
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
                }).then(() => load())
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
      <PageNav offset={offset} limit={pageSize} total={total} onPage={(next) => { setOffset(next); load(next); }} />
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
          tenantId={tenantId}
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
        <p className="text-sm text-slate-400">
          Saved as Expected / Not Yet Observed. A later scan correlates only when evidence is confident (not IP alone).
        </p>
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
  tenantId,
  asset,
  write,
  timezone,
  onClose,
  onChanged,
}: {
  tenantId: number;
  asset: AssetDetail;
  write: boolean;
  timezone: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [observations, setObservations] = useState<AssetObservation[]>([]);
  const [events, setEvents] = useState<DomainEvent[]>(asset.recent_events || []);
  const [classification, setClassification] = useState(asset.classification);
  const [description, setDescription] = useState(asset.description);
  const [criticality, setCriticality] = useState(asset.criticality);
  const [disposition, setDisposition] = useState(asset.disposition);
  const [tagName, setTagName] = useState("");
  const [mergeIds, setMergeIds] = useState("");
  const [splitIds, setSplitIds] = useState("");
  const [moveSiteId, setMoveSiteId] = useState("");
  const [correctId, setCorrectId] = useState("");
  const [correctReason, setCorrectReason] = useState("");
  const [correctReplacement, setCorrectReplacement] = useState("");
  const [reassignObs, setReassignObs] = useState("");
  const [reassignTarget, setReassignTarget] = useState("");
  const [confirmAction, setConfirmAction] = useState("");
  const [actionError, setActionError] = useState("");
  const [policyEval, setPolicyEval] = useState<PolicyEvaluation | null>(null);

  useEffect(() => {
    setClassification(asset.classification);
    setDescription(asset.description);
    setCriticality(asset.criticality);
    setDisposition(asset.disposition);
    api<HistoryPage<AssetObservation>>(`/api/assets/${asset.id}/observations?limit=50`).then((page) =>
      setObservations(page.items)
    );
    api<HistoryPage<DomainEvent>>(`/api/assets/${asset.id}/events?limit=20`).then((page) => setEvents(page.items));
    api<PolicyEvaluation>(`/api/tenants/${tenantId}/assets/${asset.id}/policy-evaluation`).then(setPolicyEval);
  }, [asset.id, asset.classification, asset.description, asset.criticality, asset.disposition, tenantId]);

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
            {asset.merged_into_asset_id && <Badge value={`merged into #${asset.merged_into_asset_id}`} />}
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
              <div>Lifecycle: {asset.lifecycle_state || "—"}</div>
              <div>Disposition: {asset.disposition}</div>
              <div>Criticality: {asset.criticality}</div>
              <div>Description: {asset.description || "—"}</div>
            </div>
          )}
          <div className="text-sm text-slate-400">
            First seen: {formatUtc(asset.first_seen, timezone)} · Last seen: {formatUtc(asset.last_seen, timezone)}
          </div>
        </section>

        {policyEval && (
          <section className="space-y-2">
            <h3 className="text-sm uppercase tracking-wide text-slate-400">Policy Evaluation</h3>
            <div className="text-sm space-y-2">
              {(["classification", "disposition", "inactive_after_days"] as const).map((key) => {
                const action = policyEval.actions[key];
                if (!action) return null;
                return (
                  <div key={key} className="border border-slate-800 rounded-lg p-3">
                    <div className="font-medium">
                      {key === "inactive_after_days" ? "Inactive after" : key.replace(/^./, (c) => c.toUpperCase())}: {String(action.value)}
                      {key === "inactive_after_days" ? " days" : ""}
                    </div>
                    <div className="text-slate-400">
                      {action.source === "policy"
                        ? `Winning rule: ${action.rule_name} (${action.scope_type}, priority ${action.priority})`
                        : `Fallback: ${action.source.replaceAll("_", " ")}`}
                    </div>
                    {action.matched_conditions.length > 0 && (
                      <div className="text-slate-500">Why: {action.matched_conditions.map((item) => item.detail).join("; ")}</div>
                    )}
                    {action.overrode && (
                      <div className="text-slate-500">
                        Overrode: {action.overrode.rule_name} ({action.overrode.scope_type})
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        )}

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

        <section className="space-y-2">
          <h3 className="text-sm uppercase tracking-wide text-slate-400">Related controls</h3>
          <ControlMapping tenantId={tenantId} subjectType="asset" subjectId={asset.id} />
        </section>

        {asset.latest_correlation && (
          <section className="space-y-2">
            <h3 className="text-sm uppercase tracking-wide text-slate-400">Correlation</h3>
            <div className="text-sm text-slate-300">
              Confidence: <Badge value={asset.latest_correlation.confidence} /> · Decision: {asset.latest_correlation.decision} ·
              Score {asset.latest_correlation.score}
            </div>
            <ul className="text-sm text-slate-300 list-disc pl-5">
              {(asset.latest_correlation.evidence || []).map((item, idx) => (
                <li key={idx}>
                  {item.polarity === "minus" ? "−" : "+"} {item.label}
                </li>
              ))}
            </ul>
            {asset.latest_correlation.decision === "ambiguous" && (
              <div className="text-sm">
                <div className="text-amber-300 mb-1">Possible matches — not auto-selected</div>
                <Table
                  headers={["Asset", "Score", "Confidence"]}
                  rows={(asset.possible_matches || asset.latest_correlation.candidates || []).map((row) => [
                    `${row.display_name} #${row.asset_id}`,
                    String(row.score),
                    row.confidence,
                  ])}
                />
              </div>
            )}
          </section>
        )}

        <section>
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Identifiers</h3>
          <Table
            headers={["Type", "Value", "Source", "State"]}
            rows={asset.identifiers.map((row) => [row.identifier_type, row.value, row.source, row.validity || "active"])}
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
          <h3 className="text-sm uppercase tracking-wide text-slate-400 mb-2">Lifecycle events</h3>
          <Table
            headers={["When", "Event"]}
            rows={events.map((row) => [formatUtc(row.occurred_at, timezone), row.event_type])}
          />
        </section>

        {write && !asset.merged_into_asset_id && (
          <section className="space-y-3 border border-slate-800 rounded-xl p-3">
            <h3 className="text-sm uppercase tracking-wide text-slate-400">Identity corrections</h3>
            <p className="text-xs text-slate-500">History is preserved. Confirm before merge, split, or identifier correction.</p>
            {actionError && <div className="text-rose-300 text-sm">{actionError}</div>}
            <div className="grid gap-2">
              <Field label="Merge source asset IDs (comma)" value={mergeIds} onChange={setMergeIds} required={false} />
              <button
                type="button"
                className="text-cyan-400 text-sm text-left"
                onClick={() => setConfirmAction("merge")}
              >
                Merge into this asset
              </button>
              <Field label="Split observation IDs (comma)" value={splitIds} onChange={setSplitIds} required={false} />
              <button type="button" className="text-cyan-400 text-sm text-left" onClick={() => setConfirmAction("split")}>
                Split selected observations into a new asset
              </button>
              <Field label="Identifier ID to mark incorrect" value={correctId} onChange={setCorrectId} required={false} />
              <Field label="Correction reason" value={correctReason} onChange={setCorrectReason} required={false} />
              <Field label="Replacement identifier (optional)" value={correctReplacement} onChange={setCorrectReplacement} required={false} />
              <button type="button" className="text-cyan-400 text-sm text-left" onClick={() => setConfirmAction("correct")}>
                Mark identifier incorrect
              </button>
              <Field label="Move to site ID" value={moveSiteId} onChange={setMoveSiteId} required={false} />
              <button type="button" className="text-cyan-400 text-sm text-left" onClick={() => setConfirmAction("move")}>
                Move asset to another site
              </button>
              <Field label="Reassign observation ID" value={reassignObs} onChange={setReassignObs} required={false} />
              <Field label="Reassign to asset ID" value={reassignTarget} onChange={setReassignTarget} required={false} />
              <button type="button" className="text-cyan-400 text-sm text-left" onClick={() => setConfirmAction("reassign")}>
                Reassign observation
              </button>
            </div>
            {confirmAction && (
              <div className="bg-slate-900 border border-amber-700 rounded-md p-3 text-sm space-y-2">
                <div>Confirm {confirmAction}? Historical evidence is kept; this does not physically delete records.</div>
                <div className="flex gap-3">
                  <button
                    type="button"
                    className="bg-cyan-600 text-slate-950 font-medium rounded-md px-3 py-1"
                    onClick={async () => {
                      setActionError("");
                      try {
                        if (confirmAction === "merge") {
                          await api(`/api/assets/${asset.id}/merge`, {
                            method: "POST",
                            body: JSON.stringify({
                              source_asset_ids: mergeIds.split(",").map((v) => Number(v.trim())).filter(Boolean),
                              reason: "manual merge",
                            }),
                          });
                        } else if (confirmAction === "split") {
                          await api(`/api/assets/${asset.id}/split`, {
                            method: "POST",
                            body: JSON.stringify({
                              observation_ids: splitIds.split(",").map((v) => Number(v.trim())).filter(Boolean),
                              reason: "manual split",
                            }),
                          });
                        } else if (confirmAction === "correct") {
                          await api(`/api/assets/${asset.id}/identifiers/${Number(correctId)}/correct`, {
                            method: "POST",
                            body: JSON.stringify({ reason: correctReason, replacement_value: correctReplacement }),
                          });
                        } else if (confirmAction === "move") {
                          await api(`/api/assets/${asset.id}/move-site`, {
                            method: "POST",
                            body: JSON.stringify({ site_id: Number(moveSiteId), reason: "manual site move" }),
                          });
                        } else if (confirmAction === "reassign") {
                          await api(`/api/assets/${asset.id}/observations/${Number(reassignObs)}/reassociate`, {
                            method: "POST",
                            body: JSON.stringify({ target_asset_id: Number(reassignTarget), reason: "manual reassignment" }),
                          });
                        }
                        setConfirmAction("");
                        onChanged();
                      } catch (err) {
                        setActionError(err instanceof Error ? err.message : "Failed");
                      }
                    }}
                  >
                    Confirm
                  </button>
                  <button type="button" className="text-slate-400" onClick={() => setConfirmAction("")}>
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </section>
        )}

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
