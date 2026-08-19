import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { Badge } from "../components/Badge";
import type { Role, StaffUser, Tenant } from "../types";

function viewerStatus(user: StaffUser) {
  if (user.role !== "viewer") return user.is_active ? "Active" : "Disabled";
  if (!user.is_active) return "Disabled";
  if (user.viewer_access_status === "expired") return "Expired";
  return "Active";
}

export function AdminUsers() {
  const [users, setUsers] = useState<StaffUser[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "user" as Role });
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  const [scope, setScope] = useState<"none" | "selected" | "all">("none");
  const [selected, setSelected] = useState<number[]>([]);
  const [expires, setExpires] = useState("");

  function load() {
    api<StaffUser[]>("/api/users").then(setUsers);
    api<Tenant[]>("/api/tenants").then(setTenants);
  }
  useEffect(load, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api("/api/users", { method: "POST", body: JSON.stringify(form) });
      setForm({ username: "", email: "", password: "", role: "user" });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  function startEdit(user: StaffUser) {
    setEditing(user.id);
    if (user.viewer_all_tenants) setScope("all");
    else if ((user.viewer_tenant_ids || []).length) setScope("selected");
    else setScope("none");
    setSelected(user.viewer_tenant_ids || []);
    setExpires(user.viewer_expires_at ? user.viewer_expires_at.slice(0, 16) : "");
  }

  async function saveScope(user: StaffUser) {
    setError("");
    try {
      await api(`/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          viewer_all_tenants: scope === "all",
          viewer_tenant_ids: scope === "selected" ? selected : [],
          viewer_expires_at: expires ? new Date(expires).toISOString() : null,
          clear_viewer_expiration: !expires,
        }),
      });
      setEditing(null);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Users</h1>
        <p className="text-slate-400 text-sm">
          Staff accounts. Viewers are read-only and see only explicitly granted tenants. Existing Viewer upgrades start with no tenant access.
        </p>
      </div>
      <form onSubmit={onCreate} className="grid md:grid-cols-5 gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div>
          <label>Username</label>
          <input className="w-full" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        </div>
        <div>
          <label>Email</label>
          <input className="w-full" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
        </div>
        <div>
          <label>Password</label>
          <input className="w-full" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={8} />
        </div>
        <div>
          <label>Role</label>
          <select className="w-full" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            <option value="admin">Admin</option>
            <option value="user">User</option>
            <option value="viewer">Viewer</option>
          </select>
        </div>
        <button className="bg-cyan-600 text-slate-950 font-medium rounded-md">Create user</button>
      </form>
      {error && <div className="text-rose-300 text-sm">{error}</div>}
      <div className="overflow-auto border border-slate-800 rounded-xl">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400 text-left">
            <tr>
              <th className="px-3 py-2">Username</th>
              <th className="px-3 py-2">Email</th>
              <th className="px-3 py-2">Role</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Access</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-slate-800 align-top">
                <td className="px-3 py-2">{u.username}</td>
                <td className="px-3 py-2">{u.email}</td>
                <td className="px-3 py-2">
                  <Badge value={u.role} />
                </td>
                <td className="px-3 py-2">{viewerStatus(u)}</td>
                <td className="px-3 py-2">
                  {u.role !== "viewer" && <span className="text-slate-500">Not applicable</span>}
                  {u.role === "viewer" && editing !== u.id && (
                    <div className="text-slate-300">
                      {u.viewer_all_tenants ? "All tenants" : (u.viewer_tenant_ids || []).length ? `Selected (${u.viewer_tenant_ids?.length})` : "No tenant access"}
                      {u.viewer_expires_at && <div className="text-xs text-slate-500">Expires {new Date(u.viewer_expires_at).toLocaleString()}</div>}
                    </div>
                  )}
                  {u.role === "viewer" && editing === u.id && (
                    <div className="space-y-2">
                      <label className="flex items-center gap-2 text-slate-300 normal-case tracking-normal text-sm">
                        <input type="radio" checked={scope === "none"} onChange={() => setScope("none")} /> No Tenant Access
                      </label>
                      <label className="flex items-center gap-2 text-slate-300 normal-case tracking-normal text-sm">
                        <input type="radio" checked={scope === "selected"} onChange={() => setScope("selected")} /> Selected Tenants
                      </label>
                      {scope === "selected" && (
                        <div className="max-h-40 overflow-auto border border-slate-800 rounded p-2 space-y-1">
                          {tenants.map((tenant) => (
                            <label key={tenant.id} className="flex items-center gap-2 text-slate-300 normal-case tracking-normal text-sm">
                              <input
                                type="checkbox"
                                checked={selected.includes(tenant.id)}
                                onChange={(e) =>
                                  setSelected(e.target.checked ? [...selected, tenant.id] : selected.filter((id) => id !== tenant.id))
                                }
                              />
                              {tenant.name}
                            </label>
                          ))}
                        </div>
                      )}
                      <label className="flex items-center gap-2 text-slate-300 normal-case tracking-normal text-sm">
                        <input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /> All Tenants
                      </label>
                      <div>
                        <label>Expiration</label>
                        <input className="w-full" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
                      </div>
                      <button className="text-cyan-400 text-sm" onClick={() => saveScope(u)}>
                        Save access
                      </button>
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 text-right space-y-2">
                  {u.role === "viewer" && (
                    <button className="block ml-auto text-sm text-cyan-400" onClick={() => (editing === u.id ? setEditing(null) : startEdit(u))}>
                      {editing === u.id ? "Close" : "Access scope"}
                    </button>
                  )}
                  <button
                    className="text-sm text-cyan-400"
                    onClick={() =>
                      api(`/api/users/${u.id}`, {
                        method: "PATCH",
                        body: JSON.stringify({ is_active: !u.is_active }),
                      }).then(load)
                    }
                  >
                    {u.is_active ? "Disable" : "Enable"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
