import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { ScanProgressBar } from "../components/ScanProgress";
import type { Dashboard } from "../types";

function Card({ label, value, to }: { label: string; value: number | string; to?: string }) {
  const inner = (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="text-3xl font-semibold mt-1">{value}</div>
    </div>
  );
  return to ? <Link to={to}>{inner}</Link> : inner;
}

export function Home() {
  const { user } = useAuth();
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Dashboard>("/api/dashboard")
      .then(setData)
      .catch((e) => setError(e.message));
    const id = setInterval(() => {
      api<Dashboard>("/api/dashboard").then(setData).catch(() => undefined);
    }, 8000);
    return () => clearInterval(id);
  }, []);

  if (error) return <div className="text-rose-300">{error}</div>;
  if (!data) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="text-slate-400 text-sm">
          {user?.role === "viewer" && user.has_tenant_access === false
            ? "No tenant access has been assigned to this account."
            : user?.role === "viewer"
              ? "Live status for tenants assigned to this account."
              : "Live status across all client tenants."}
        </p>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-7 gap-4">
        <Card label="Tenants" value={data.tenants} to="/tenants" />
        <Card label="Agents online" value={data.agents.online} />
        <Card label="Pending approval" value={data.agents.pending} />
        <Card label="New devices" value={data.new_devices} />
        <Card label="Open alerts" value={data.open_alerts} to="/alerts" />
        <Card label="Critical open" value={data.open_alerts_critical || 0} to="/alerts" />
        <Card label="High open" value={data.open_alerts_high || 0} to="/alerts" />
      </div>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <h2 className="font-medium mb-3">Open findings by operational priority</h2>
        <p className="text-xs text-slate-500 mb-3">
          P1–P4 is Nuclei Dashboard operational priority. Severity remains a separate metric.
        </p>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {(["p1", "p2", "p3", "p4"] as const).map((priority) => (
            <div key={priority} className="bg-slate-950 border border-slate-800 rounded-lg p-3">
              <div className="text-xs uppercase tracking-wide text-slate-400">{priority.toUpperCase()}</div>
              <div className="text-2xl font-semibold mt-1">{data.priorities?.[priority] || 0}</div>
            </div>
          ))}
        </div>
      </section>
      <div className="grid lg:grid-cols-2 gap-6">
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h2 className="font-medium mb-3">Recent alerts</h2>
          <div className="space-y-2">
            {data.recent_alerts.length === 0 && <div className="text-sm text-slate-500">No alerts yet.</div>}
            {data.recent_alerts.map((a) => (
              <div key={a.id} className="flex items-start justify-between gap-3 text-sm">
                <div>
                  <div>{a.title}</div>
                  <div className="text-xs text-slate-500">{new Date(a.created_at).toLocaleString()}</div>
                </div>
                <Badge value={a.severity || a.type} />
              </div>
            ))}
          </div>
        </section>
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h2 className="font-medium mb-3">Recent jobs</h2>
          <div className="space-y-2">
            {data.recent_jobs.length === 0 && <div className="text-sm text-slate-500">No scan jobs yet.</div>}
            {data.recent_jobs.map((j) => (
              <Link
                key={j.id}
                to={`/tenants/${j.tenant_id}?tab=scans&job=${j.id}`}
                className="flex items-center justify-between gap-3 text-sm hover:bg-slate-950/80 rounded-lg px-1 py-1"
              >
                <div>
                  Job #{j.id} · tenant {j.tenant_id}
                  <div className="text-xs text-slate-500">
                    {j.hosts_found} hosts · {j.findings_count} findings
                  </div>
                  <ScanProgressBar progress={j.progress} compact />
                </div>
                <Badge value={j.status} />
              </Link>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
