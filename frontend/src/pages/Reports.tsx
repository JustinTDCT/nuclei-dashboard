import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, download } from "../api";
import { useAuth } from "../auth";
import type { ComplianceFramework, ReportCatalogItem, ReportPreview, Site, Tenant } from "../types";

export function Reports() {
  const { user } = useAuth();
  const [catalog, setCatalog] = useState<ReportCatalogItem[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [selected, setSelected] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [severity, setSeverity] = useState("");
  const [priority, setPriority] = useState("");
  const [kev, setKev] = useState("");
  const [lifecycle, setLifecycle] = useState("");
  const [disposition, setDisposition] = useState("");
  const [criticality, setCriticality] = useState("");
  const [includeMerged, setIncludeMerged] = useState(false);
  const [treatmentType, setTreatmentType] = useState("");
  const [treatmentStatus, setTreatmentStatus] = useState("");
  const [includeFalsePositives, setIncludeFalsePositives] = useState(false);
  const [frameworkId, setFrameworkId] = useState("");
  const [includeRemoved, setIncludeRemoved] = useState(false);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const spec = useMemo(() => catalog.find((item) => item.key === selected), [catalog, selected]);

  useEffect(() => {
    api<ReportCatalogItem[]>("/api/reports/catalog").then((rows) => {
      setCatalog(rows);
      if (rows[0]) setSelected(rows[0].key);
    });
    api<Tenant[]>("/api/tenants").then(setTenants);
    api<ComplianceFramework[]>("/api/compliance/frameworks").then(setFrameworks).catch(() => undefined);
  }, []);

  useEffect(() => {
    setSiteId("");
    setSites([]);
    if (!tenantId) return;
    api<Site[]>(`/api/tenants/${tenantId}/sites`).then(setSites).catch(() => setSites([]));
  }, [tenantId]);

  function hasFilter(key: string) {
    return Boolean(spec?.supported_filters.some((item) => item.key === key));
  }

  function query(extra = "") {
    const params = new URLSearchParams();
    if (tenantId) params.set("tenant_id", tenantId);
    if (siteId) params.set("site_id", siteId);
    if (dateFrom) params.set("date_from", new Date(dateFrom).toISOString());
    if (dateTo) params.set("date_to", new Date(dateTo).toISOString());
    if (hasFilter("severity") && severity) params.set("severity", severity);
    if (hasFilter("priority") && priority) params.set("priority", priority);
    if (hasFilter("kev") && kev) params.set("kev", kev);
    if (hasFilter("lifecycle_state") && lifecycle) params.set("lifecycle_state", lifecycle);
    if (hasFilter("disposition") && disposition) params.set("disposition", disposition);
    if (hasFilter("criticality") && criticality) params.set("criticality", criticality);
    if (hasFilter("include_merged") && includeMerged) params.set("include_merged", "true");
    if (hasFilter("treatment_type") && treatmentType) params.set("treatment_type", treatmentType);
    if (hasFilter("treatment_status") && treatmentStatus) params.set("treatment_status", treatmentStatus);
    if (hasFilter("include_false_positives") && includeFalsePositives) params.set("include_false_positives", "true");
    if (hasFilter("framework_id") && frameworkId) params.set("framework_id", frameworkId);
    if (hasFilter("include_removed") && includeRemoved) params.set("include_removed", "true");
    return `${params.toString()}${extra ? `&${extra}` : ""}`;
  }

  async function loadPreview(nextPage = 1) {
    if (!selected) return;
    setError("");
    setLoading(true);
    try {
      const data = await api<ReportPreview>(`/api/reports/${selected}/preview?${query(`page=${nextPage}&page_size=50`)}`);
      setPreview(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Preview failed");
    } finally {
      setLoading(false);
    }
  }

  async function onPreview(e: FormEvent) {
    e.preventDefault();
    await loadPreview(1);
  }

  function exportReport(format: string) {
    if (!selected) return;
    download(`/api/reports/${selected}/export?format=${format}&${query()}`, `${selected}.${format}`);
  }

  if (user?.role === "viewer" && user.has_tenant_access === false) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h1 className="text-2xl font-semibold mb-2">Reports</h1>
        <p className="text-slate-400">No tenant access has been assigned to this account.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Reports</h1>
        <p className="text-slate-400 text-sm">
          Preview and export authorized tenant data. Reports do not certify compliance or invent a risk score.
        </p>
      </div>
      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3">
        {catalog.map((item) => (
          <button
            key={item.key}
            className={`text-left rounded-xl border p-4 ${selected === item.key ? "border-cyan-600 bg-slate-900" : "border-slate-800 bg-slate-950"}`}
            onClick={() => {
              setSelected(item.key);
              setPreview(null);
            }}
          >
            <div className="font-medium">{item.display_name}</div>
            <div className="text-xs text-slate-400 mt-1">{item.description}</div>
          </button>
        ))}
      </div>
      <form onSubmit={onPreview} className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-4 gap-3 items-end">
        <div>
          <label>Tenant</label>
          <select className="w-full" value={tenantId} onChange={(e) => setTenantId(e.target.value)} required={spec?.key === "control_evidence"}>
            <option value="">{spec?.key === "control_evidence" ? "Select one tenant" : "Authorized scope"}</option>
            {tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label>Site</label>
          <select className="w-full" value={siteId} onChange={(e) => setSiteId(e.target.value)} disabled={!tenantId}>
            <option value="">{tenantId ? "All sites" : "Select a tenant first"}</option>
            {sites.map((site) => (
              <option key={site.id} value={site.id}>
                {site.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label>From</label>
          <input className="w-full" type="datetime-local" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
        </div>
        <div>
          <label>To</label>
          <input className="w-full" type="datetime-local" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
        </div>
        {hasFilter("severity") && (
          <div>
            <label>Severity</label>
            <select className="w-full" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Any</option>
              {["critical", "high", "medium", "low", "info"].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
        )}
        {hasFilter("priority") && (
          <div>
            <label>Priority</label>
            <select className="w-full" value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">Any</option>
              {["p1", "p2", "p3", "p4"].map((item) => (
                <option key={item} value={item}>
                  {item.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        )}
        {hasFilter("kev") && (
          <div>
            <label>KEV</label>
            <select className="w-full" value={kev} onChange={(e) => setKev(e.target.value)}>
              <option value="">Any</option>
              <option value="true">KEV only</option>
              <option value="false">Not KEV</option>
            </select>
          </div>
        )}
        {hasFilter("lifecycle_state") && (
          <div>
            <label>Lifecycle</label>
            <select className="w-full" value={lifecycle} onChange={(e) => setLifecycle(e.target.value)}>
              <option value="">Any</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
        )}
        {hasFilter("disposition") && (
          <div>
            <label>Disposition</label>
            <select className="w-full" value={disposition} onChange={(e) => setDisposition(e.target.value)}>
              <option value="">Any</option>
              <option value="unreviewed">Unreviewed</option>
              <option value="approved">Approved</option>
              <option value="unauthorized">Unauthorized</option>
              <option value="ignored">Ignored</option>
            </select>
          </div>
        )}
        {hasFilter("criticality") && (
          <div>
            <label>Criticality</label>
            <select className="w-full" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
              <option value="">Any</option>
              {["low", "normal", "high", "critical"].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
        )}
        {hasFilter("treatment_type") && (
          <div>
            <label>Treatment type</label>
            <select className="w-full" value={treatmentType} onChange={(e) => setTreatmentType(e.target.value)}>
              <option value="">Mitigated / accepted risk</option>
              <option value="mitigated">Mitigated</option>
              <option value="accepted_risk">Accepted risk</option>
            </select>
          </div>
        )}
        {hasFilter("treatment_status") && (
          <div>
            <label>Treatment status</label>
            <select className="w-full" value={treatmentStatus} onChange={(e) => setTreatmentStatus(e.target.value)}>
              <option value="">Any</option>
              {["pending_review", "active", "expired", "revoked", "superseded"].map((item) => (
                <option key={item} value={item}>
                  {item.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>
        )}
        {hasFilter("framework_id") && (
          <div>
            <label>Framework</label>
            <select className="w-full" value={frameworkId} onChange={(e) => setFrameworkId(e.target.value)} required>
              <option value="">Select a framework</option>
              {frameworks.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} {item.version}
                </option>
              ))}
            </select>
          </div>
        )}
        {hasFilter("include_merged") && (
          <label className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
            <input type="checkbox" checked={includeMerged} onChange={(e) => setIncludeMerged(e.target.checked)} />
            Include merged assets
          </label>
        )}
        {hasFilter("include_false_positives") && (
          <label className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
            <input type="checkbox" checked={includeFalsePositives} onChange={(e) => setIncludeFalsePositives(e.target.checked)} />
            Include false positives
          </label>
        )}
        {hasFilter("include_removed") && (
          <label className="flex items-center gap-2 text-sm text-slate-300 normal-case tracking-normal">
            <input type="checkbox" checked={includeRemoved} onChange={(e) => setIncludeRemoved(e.target.checked)} />
            Include removed evidence
          </label>
        )}
        <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2" disabled={loading}>
          {loading ? "Loading…" : "Preview"}
        </button>
      </form>
      {spec && (
        <div className="flex gap-3">
          {spec.supported_formats.includes("csv") && (
            <button className="text-cyan-400 text-sm" onClick={() => exportReport("csv")}>
              Export CSV
            </button>
          )}
          {spec.supported_formats.includes("pdf") && (
            <button className="text-cyan-400 text-sm" onClick={() => exportReport("pdf")}>
              Export PDF
            </button>
          )}
        </div>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      {preview && (
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
          <div>
            <h2 className="font-medium">{preview.title}</h2>
            <p className="text-xs text-slate-500">
              {preview.scope} · {new Date(preview.generated_at).toLocaleString()} · {preview.timezone} · {preview.total} rows
            </p>
          </div>
          {preview.summary && Object.keys(preview.summary).length > 0 && (
            <div className="text-sm text-slate-300 space-y-1">
              {Object.entries(preview.summary).map(([key, value]) => (
                <div key={key}>
                  <span className="text-slate-500">{key.replace(/_/g, " ")}:</span> {typeof value === "object" ? JSON.stringify(value) : String(value)}
                </div>
              ))}
            </div>
          )}
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="text-slate-400 text-left">
                <tr>
                  {preview.columns.map((col) => (
                    <th key={col} className="px-2 py-2 whitespace-nowrap">
                      {col.replace(/_/g, " ")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {preview.rows.map((row, idx) => (
                  <tr key={idx} className="border-t border-slate-800">
                    {preview.columns.map((col) => (
                      <td key={col} className="px-2 py-2 whitespace-nowrap text-slate-200">
                        {String(row[col] ?? "")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {preview.rows.length === 0 && <div className="text-slate-500 text-sm py-4">No rows in this authorized scope.</div>}
          </div>
          <div className="flex items-center gap-3 text-sm text-slate-400">
            <button
              className="text-cyan-400 disabled:text-slate-600"
              disabled={loading || preview.page <= 1}
              onClick={() => loadPreview(preview.page - 1)}
            >
              Previous
            </button>
            <span>
              Page {preview.page} of {Math.max(1, Math.ceil(preview.total / preview.page_size))}
            </span>
            <button
              className="text-cyan-400 disabled:text-slate-600"
              disabled={loading || preview.page * preview.page_size >= preview.total}
              onClick={() => loadPreview(preview.page + 1)}
            >
              Next
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
