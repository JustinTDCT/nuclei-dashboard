import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge } from "../components/Badge";
import type { ComplianceControl, ComplianceFramework } from "../types";

export function Compliance() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [selected, setSelected] = useState<ComplianceFramework | null>(null);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [q, setQ] = useState("");
  const [family, setFamily] = useState("");
  const [error, setError] = useState("");

  function load() {
    api<ComplianceFramework[]>("/api/compliance/frameworks?include_archived=true").then(setFrameworks);
  }
  useEffect(load, []);

  async function openFramework(id: number) {
    const detail = await api<ComplianceFramework>(`/api/compliance/frameworks/${id}`);
    setSelected(detail);
    setControls(detail.controls || []);
    setQ("");
    setFamily("");
  }

  async function search() {
    if (!selected) return;
    const qs = new URLSearchParams();
    if (q) qs.set("q", q);
    if (family) qs.set("family", family);
    const rows = await api<ComplianceControl[]>(`/api/compliance/frameworks/${selected.id}/controls?${qs}`);
    setControls(rows);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Compliance frameworks</h1>
        <p className="text-slate-400 text-sm max-w-3xl">
          Catalog of frameworks and controls for evidence mapping. Linking an asset, finding, treatment, or scan run to a
          control means the evidence is related to that control. It does not mean the organization is compliant, certified,
          or that the control is satisfied.
        </p>
      </div>
      <div className="grid lg:grid-cols-[320px_1fr] gap-6">
        <div className="space-y-3">
          {frameworks.map((item) => (
            <button
              key={item.id}
              className={`w-full text-left border rounded-xl p-3 ${selected?.id === item.id ? "border-cyan-600 bg-slate-900" : "border-slate-800"}`}
              onClick={() => openFramework(item.id)}
            >
              <div className="font-medium">{item.name}</div>
              <div className="text-sm text-slate-400">
                {item.version} · {item.publisher || "Unspecified publisher"}
              </div>
              <div className="flex gap-2 mt-2">
                {item.builtin && <Badge value="built-in" />}
                {item.archived_at ? <Badge value="archived" /> : <Badge value="current" />}
              </div>
            </button>
          ))}
          {admin && <CreateFramework onCreated={load} />}
        </div>
        <div>
          {!selected && <div className="text-slate-500">Select a framework to view controls.</div>}
          {selected && (
            <div className="space-y-4">
              <div>
                <h2 className="text-xl font-semibold">{selected.name}</h2>
                <div className="text-slate-400 text-sm">
                  {selected.version} · {selected.publisher}
                  {selected.source_release_date ? ` · Source date ${selected.source_release_date}` : ""}
                </div>
                {selected.source_url && (
                  <a className="text-cyan-400 text-sm" href={selected.source_url} target="_blank" rel="noreferrer">
                    Authoritative source
                  </a>
                )}
                <p className="text-sm text-slate-300 mt-2">{selected.description}</p>
                <p className="text-xs text-slate-500 mt-2">{selected.mapping_disclaimer}</p>
                {selected.slug === "nist-sp-800-171" && (
                  <p className="text-xs text-amber-200 mt-2">
                    This is NIST SP 800-171 {selected.version}. It is not current CMMC Level 2. Official DoD CMMC Level 2
                    self-assessment currently uses NIST SP 800-171 Revision 2.
                  </p>
                )}
              </div>
              <div className="flex flex-wrap gap-3 items-end">
                <div>
                  <label>Control ID</label>
                  <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="03.01.01 or title" />
                </div>
                <div>
                  <label>Family</label>
                  <input value={family} onChange={(e) => setFamily(e.target.value)} placeholder="Access Control" />
                </div>
                <button className="text-cyan-400 text-sm" onClick={search}>
                  Search
                </button>
                {admin && !selected.archived_at && (
                  <button
                    className="text-rose-300 text-sm"
                    onClick={async () => {
                      await api(`/api/compliance/frameworks/${selected.id}/archive`, { method: "POST" });
                      load();
                      openFramework(selected.id);
                    }}
                  >
                    Archive framework
                  </button>
                )}
              </div>
              {admin && !selected.archived_at && <CreateControl frameworkId={selected.id} onCreated={() => openFramework(selected.id)} />}
              <div className="overflow-auto border border-slate-800 rounded-xl">
                <table className="w-full text-sm">
                  <thead className="bg-slate-900 text-slate-400 text-left">
                    <tr>
                      {["Control ID", "Family", "Title"].map((h) => (
                        <th key={h} className="px-3 py-2 font-medium">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {controls.map((row) => (
                      <tr key={row.id} className="border-t border-slate-800 align-top">
                        <td className="px-3 py-2 font-mono">{row.control_key}</td>
                        <td className="px-3 py-2">{row.family || "—"}</td>
                        <td className="px-3 py-2">
                          <div>{row.title}</div>
                          {row.description && <div className="text-slate-500 text-xs mt-1 line-clamp-3">{row.description}</div>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
      {error && <div className="text-rose-300">{error}</div>}
    </div>
  );
}

function CreateFramework({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ slug: "", name: "", version: "", publisher: "", description: "" });
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api("/api/compliance/frameworks", { method: "POST", body: JSON.stringify(form) });
      setOpen(false);
      onCreated();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to create framework");
    }
  }
  if (!open) {
    return (
      <button className="text-cyan-400 text-sm" onClick={() => setOpen(true)}>
        Create custom framework
      </button>
    );
  }
  return (
    <form className="space-y-2 border border-slate-800 rounded-xl p-3" onSubmit={submit}>
      {["slug", "name", "version", "publisher"].map((key) => (
        <div key={key}>
          <label className="capitalize">{key}</label>
          <input className="w-full" value={form[key as keyof typeof form]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} required={key !== "publisher"} />
        </div>
      ))}
      <div>
        <label>Description</label>
        <textarea className="w-full" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
      </div>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <button className="bg-cyan-700 text-white rounded-md px-3 py-1.5 text-sm">Save framework</button>
    </form>
  );
}

function CreateControl({ frameworkId, onCreated }: { frameworkId: number; onCreated: () => void }) {
  const [form, setForm] = useState({ control_key: "", title: "", family: "", description: "" });
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api(`/api/compliance/frameworks/${frameworkId}/controls`, { method: "POST", body: JSON.stringify(form) });
      setForm({ control_key: "", title: "", family: "", description: "" });
      onCreated();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to create control");
    }
  }
  return (
    <form className="grid md:grid-cols-2 gap-3 border border-slate-800 rounded-xl p-3" onSubmit={submit}>
      <div>
        <label>Control ID</label>
        <input className="w-full" value={form.control_key} onChange={(e) => setForm({ ...form, control_key: e.target.value })} required />
      </div>
      <div>
        <label>Title</label>
        <input className="w-full" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required />
      </div>
      <div>
        <label>Family</label>
        <input className="w-full" value={form.family} onChange={(e) => setForm({ ...form, family: e.target.value })} />
      </div>
      <div>
        <label>Description</label>
        <input className="w-full" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
      </div>
      {error && <div className="text-rose-300 text-sm md:col-span-2">{error}</div>}
      <div className="md:col-span-2">
        <button className="bg-cyan-700 text-white rounded-md px-3 py-1.5 text-sm">Create custom control</button>
      </div>
    </form>
  );
}
