import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { Badge } from "../components/Badge";
import type { Role, StaffUser } from "../types";

export function AdminUsers() {
  const [users, setUsers] = useState<StaffUser[]>([]);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "user" as Role });
  const [error, setError] = useState("");

  function load() {
    api<StaffUser[]>("/api/users").then(setUsers);
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Users</h1>
        <p className="text-slate-400 text-sm">Staff accounts. Admins manage the system; users operate tenants; viewers are read-only.</p>
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
              <th className="px-3 py-2">Active</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-slate-800">
                <td className="px-3 py-2">{u.username}</td>
                <td className="px-3 py-2">{u.email}</td>
                <td className="px-3 py-2">
                  <Badge value={u.role} />
                </td>
                <td className="px-3 py-2">{u.is_active ? "yes" : "no"}</td>
                <td className="px-3 py-2 text-right">
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
