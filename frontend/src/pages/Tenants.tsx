import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { canWrite, useAuth } from "../auth";
import type { Tenant } from "../types";

export function Tenants() {
  const { user } = useAuth();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  function load() {
    api<Tenant[]>("/api/tenants").then(setTenants).catch((e) => setError(e.message));
  }

  useEffect(load, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api("/api/tenants", { method: "POST", body: JSON.stringify({ name, notes }) });
      setName("");
      setNotes("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Tenants</h1>
        <p className="text-slate-400 text-sm">Clients you manage. Each tenant has WAN/LAN subnets, agents, and scans.</p>
      </div>
      {canWrite(user?.role) && (
        <form onSubmit={onCreate} className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid md:grid-cols-[1fr_2fr_auto] gap-3 items-end">
          <div>
            <label>Name</label>
            <input className="w-full" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div>
            <label>Notes</label>
            <input className="w-full" value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
          <button className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-medium rounded-md px-4 py-2">
            Create tenant
          </button>
        </form>
      )}
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <div className="grid md:grid-cols-2 gap-4">
        {tenants.map((t) => (
          <Link key={t.id} to={`/tenants/${t.id}`} className="block bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-cyan-700">
            <div className="font-medium">{t.name}</div>
            <div className="text-sm text-slate-400 mt-1">{t.notes || "No notes"}</div>
          </Link>
        ))}
        {tenants.length === 0 && <div className="text-slate-500 text-sm">No tenants yet.</div>}
      </div>
    </div>
  );
}
