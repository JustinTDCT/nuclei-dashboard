import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { TimezoneField } from "./SitesPanel";
import type { IntelligenceStatus, Settings } from "../types";

const empty: Settings = {
  central_host: "",
  central_port: 8118,
  central_tls: true,
  smtp_host: "",
  smtp_port: 587,
  smtp_user: "",
  smtp_password: "",
  smtp_from: "",
  smtp_tls: true,
  stale_days: 14,
  asset_inactive_days: 30,
  default_nuclei_severities: "critical,high,medium",
  default_timezone: "UTC",
  preferred_agent_grace_seconds: 60,
  agent_job_wait_minutes: 30,
  scan_cap_naabu_rate: 5000,
  scan_cap_naabu_concurrency: 100,
  scan_cap_naabu_timeout_ms: 10000,
  scan_cap_naabu_retries: 5,
  scan_cap_httpx_rate: 500,
  scan_cap_httpx_threads: 150,
  scan_cap_httpx_timeout: 30,
  scan_cap_httpx_retries: 5,
  scan_cap_nuclei_rate: 500,
  scan_cap_nuclei_concurrency: 100,
  scan_cap_nuclei_timeout: 30,
  scan_cap_nuclei_retries: 5,
  finding_resolution_clean_scans: 2,
  vulnerability_intelligence_enabled: true,
  raw_scan_artifact_retention_days: 365,
  approved_scanner_runtime_version: "",
  approved_nuclei_version: "",
  approved_nuclei_templates_version: "",
  approved_naabu_version: "",
  approved_httpx_version: "",
};

export function AdminSettings() {
  const [form, setForm] = useState<Settings>(empty);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [intel, setIntel] = useState<IntelligenceStatus | null>(null);
  const [intelMessage, setIntelMessage] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  function loadIntel() {
    api<IntelligenceStatus>("/api/admin/vulnerability-intelligence/status").then(setIntel);
  }

  useEffect(() => {
    api<Settings>("/api/admin/settings").then(setForm);
    loadIntel();
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSaved(false);
    try {
      const next = await api<Settings>("/api/admin/settings", { method: "PUT", body: JSON.stringify(form) });
      setForm(next);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <form onSubmit={onSubmit} className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">System settings</h1>
        <p className="text-slate-400 text-sm">
          Central URL agents phone home to (baked into downloaded compose), plus SMTP and inventory defaults. Agents build from the public GitHub repo.
        </p>
      </div>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-2 gap-3">
        <div className="md:col-span-2 text-sm text-slate-400">
          Agents reach the dashboard at this host and port. Set the address they can route to, not localhost.
        </div>
        <Field
          label="Central host or IP"
          value={form.central_host}
          onChange={(v) => setForm({ ...form, central_host: v })}
        />
        <Field
          label="Central port"
          value={String(form.central_port)}
          onChange={(v) => setForm({ ...form, central_port: Number(v) || 8118 })}
        />
        <label className="flex items-center gap-2 text-sm text-slate-300 mt-6">
          <input
            type="checkbox"
            checked={form.central_tls}
            onChange={(e) => setForm({ ...form, central_tls: e.target.checked })}
          />
          Agents use HTTPS
        </label>
      </section>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-2 gap-3">
        <Field label="SMTP host" value={form.smtp_host} onChange={(v) => setForm({ ...form, smtp_host: v })} />
        <Field label="SMTP port" value={String(form.smtp_port)} onChange={(v) => setForm({ ...form, smtp_port: Number(v) || 587 })} />
        <Field label="SMTP user" value={form.smtp_user} onChange={(v) => setForm({ ...form, smtp_user: v })} />
        <div>
          <label>SMTP password</label>
          <input className="w-full" type="password" value={form.smtp_password} onChange={(e) => setForm({ ...form, smtp_password: e.target.value })} />
        </div>
        <Field label="From address" value={form.smtp_from} onChange={(v) => setForm({ ...form, smtp_from: v })} />
        <label className="flex items-center gap-2 text-sm text-slate-300 mt-6">
          <input type="checkbox" checked={form.smtp_tls} onChange={(e) => setForm({ ...form, smtp_tls: e.target.checked })} />
          Use STARTTLS
        </label>
      </section>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-2 gap-3">
        <Field label="Stale after (days)" value={String(form.stale_days)} onChange={(v) => setForm({ ...form, stale_days: Number(v) || 14 })} />
        <Field
          label="Asset inactive after (days)"
          value={String(form.asset_inactive_days ?? 30)}
          onChange={(v) => setForm({ ...form, asset_inactive_days: Number(v) || 30 })}
        />
        <Field
          label="Default Nuclei severities"
          value={form.default_nuclei_severities}
          onChange={(v) => setForm({ ...form, default_nuclei_severities: v })}
        />
        <TimezoneField
          label="Global default timezone"
          value={form.default_timezone || "UTC"}
          onChange={(v) => setForm({ ...form, default_timezone: v || "UTC" })}
        />
        <div className="text-sm text-slate-400 mt-6">
          Timestamps stay in UTC. The UI displays them in this timezone unless a Site overrides it.
        </div>
        <Field
          label="Resolve finding after consecutive clean applicable scans"
          value={String(form.finding_resolution_clean_scans ?? 2)}
          onChange={(v) => setForm({ ...form, finding_resolution_clean_scans: Number(v) || 0 })}
        />
        <Field
          label="Raw scan artifact retention (days)"
          value={String(form.raw_scan_artifact_retention_days ?? 365)}
          onChange={(v) => setForm({ ...form, raw_scan_artifact_retention_days: Number(v) || 0 })}
        />
        <div className="md:col-span-2 text-sm text-slate-400">
          Raw scanner files (Naabu, httpx, Nuclei JSONL) are deleted after this many days. Normalized
          historical findings, assets, and scan history remain. Changing this value applies to newly
          stored artifacts.
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300 mt-6">
          <input
            type="checkbox"
            checked={form.vulnerability_intelligence_enabled !== false}
            onChange={(e) => setForm({ ...form, vulnerability_intelligence_enabled: e.target.checked })}
          />
          Enable vulnerability intelligence refresh
        </label>
      </section>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-2 gap-3">
        <div className="md:col-span-2">
          <h2 className="font-medium">Approved scanner versions</h2>
          <p className="text-sm text-slate-400 mt-1">
            These are the centrally approved scanner runtime and tool versions. Changing them updates
            match/mismatch status for Agents and reports. It does not upgrade remote Agents, rebuild
            containers, or replace template volumes.
          </p>
        </div>
        <Field
          label="Scanner runtime"
          value={form.approved_scanner_runtime_version ?? ""}
          onChange={(v) => setForm({ ...form, approved_scanner_runtime_version: v })}
        />
        <Field
          label="Nuclei"
          value={form.approved_nuclei_version ?? ""}
          onChange={(v) => setForm({ ...form, approved_nuclei_version: v })}
        />
        <Field
          label="Nuclei templates"
          value={form.approved_nuclei_templates_version ?? ""}
          onChange={(v) => setForm({ ...form, approved_nuclei_templates_version: v })}
        />
        <Field
          label="Naabu"
          value={form.approved_naabu_version ?? ""}
          onChange={(v) => setForm({ ...form, approved_naabu_version: v })}
        />
        <Field
          label="httpx"
          value={form.approved_httpx_version ?? ""}
          onChange={(v) => setForm({ ...form, approved_httpx_version: v })}
        />
      </section>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div>
          <h2 className="font-medium">Vulnerability intelligence</h2>
          <p className="text-sm text-slate-400">
            NVD, FIRST EPSS, and CISA KEV enrich the Vulnerability catalog. No tenant, asset, IP, or hostname data is
            sent to those sources. The optional NVD API key stays in server environment configuration and is never shown.
          </p>
        </div>
        <div className="text-sm text-slate-300">NVD API key configured: {intel?.nvd_api_key_configured ? "Yes" : "No"}</div>
        {(["nvd", "epss", "cisa_kev"] as const).map((source) => {
          const row = intel?.sources?.[source];
          const title = source === "nvd" ? "NVD" : source === "epss" ? "FIRST EPSS" : "CISA KEV";
          return (
            <div key={source} className="border border-slate-800 rounded-lg p-3 text-sm space-y-1">
              <div className="font-medium">{title}</div>
              <div>Last successful update: {row?.last_success_at || "—"}</div>
              {source === "epss" && (
                <>
                  <div>Score date: {typeof row?.metadata?.score_date === "string" ? row.metadata.score_date : "—"}</div>
                  <div>Model/version: {typeof row?.metadata?.model_version === "string" ? row.metadata.model_version : "—"}</div>
                </>
              )}
              {source === "cisa_kev" && (
                <div>Catalog/source update: {row?.source_updated_at || "—"}</div>
              )}
              <div className="text-rose-300">Last error: {row?.last_error || "—"}</div>
            </div>
          );
        })}
        <div className="flex gap-3 items-center">
          <button
            type="button"
            className="bg-slate-800 text-slate-100 rounded-md px-3 py-2 text-sm"
            disabled={refreshing}
            onClick={async () => {
              setRefreshing(true);
              setIntelMessage("");
              try {
                await api("/api/admin/vulnerability-intelligence/refresh", { method: "POST" });
                await loadIntel();
                setIntelMessage("Refresh completed through the intelligence service.");
              } catch (err) {
                setIntelMessage(err instanceof Error ? err.message : "Refresh failed");
              } finally {
                setRefreshing(false);
              }
            }}
          >
            {refreshing ? "Refreshing…" : "Refresh intelligence"}
          </button>
          {intelMessage && <div className="text-sm text-slate-400">{intelMessage}</div>}
        </div>
      </section>
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-2 gap-3">
        <div className="md:col-span-2 text-sm text-slate-400">
          Agent wait / failover and maximum intensity values Users cannot exceed. Over-cap scan values are rejected, not clamped.
        </div>
        <Field
          label="Preferred agent grace (seconds)"
          value={String(form.preferred_agent_grace_seconds ?? 60)}
          onChange={(v) => setForm({ ...form, preferred_agent_grace_seconds: Number(v) || 0 })}
        />
        <Field
          label="Agent job wait (minutes)"
          value={String(form.agent_job_wait_minutes ?? 30)}
          onChange={(v) => setForm({ ...form, agent_job_wait_minutes: Number(v) || 1 })}
        />
        <Field label="Cap Naabu rate" value={String(form.scan_cap_naabu_rate ?? 5000)} onChange={(v) => setForm({ ...form, scan_cap_naabu_rate: Number(v) || 0 })} />
        <Field label="Cap Naabu concurrency" value={String(form.scan_cap_naabu_concurrency ?? 100)} onChange={(v) => setForm({ ...form, scan_cap_naabu_concurrency: Number(v) || 0 })} />
        <Field label="Cap httpx rate" value={String(form.scan_cap_httpx_rate ?? 500)} onChange={(v) => setForm({ ...form, scan_cap_httpx_rate: Number(v) || 0 })} />
        <Field label="Cap Nuclei rate" value={String(form.scan_cap_nuclei_rate ?? 500)} onChange={(v) => setForm({ ...form, scan_cap_nuclei_rate: Number(v) || 0 })} />
      </section>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      {saved && <div className="text-emerald-300 text-sm">Saved.</div>}
      <button className="bg-cyan-600 text-slate-950 font-medium rounded-md px-4 py-2">Save settings</button>
    </form>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div>
      <label>{label}</label>
      <input className="w-full" value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
