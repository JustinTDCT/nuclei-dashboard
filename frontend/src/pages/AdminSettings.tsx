import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { TimezoneField } from "./SitesPanel";
import type { Settings } from "../types";

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
};

export function AdminSettings() {
  const [form, setForm] = useState<Settings>(empty);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Settings>("/api/admin/settings").then(setForm);
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
