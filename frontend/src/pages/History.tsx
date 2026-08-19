import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import type { HistoryPage, Tenant } from "../types";

interface AuditRow {
  id: number;
  created_at: string;
  tenant_name?: string | null;
  actor?: string | null;
  action: string;
  summary: string;
  details: Record<string, unknown>;
}

interface EventRow {
  id: number;
  occurred_at: string;
  tenant_name?: string | null;
  event_label: string;
  source: string;
  summary: string;
  details: Record<string, unknown>;
}

export function History() {
  const { user } = useAuth();
  const [tab, setTab] = useState<"audit" | "events">("audit");
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [eventType, setEventType] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [audit, setAudit] = useState<HistoryPage<AuditRow> | null>(null);
  const [events, setEvents] = useState<HistoryPage<EventRow> | null>(null);
  const [open, setOpen] = useState<number | null>(null);

  function load() {
    const auditQs = new URLSearchParams();
    const eventQs = new URLSearchParams();
    if (tenantId) {
      auditQs.set("tenant_id", tenantId);
      eventQs.set("tenant_id", tenantId);
    }
    if (actor) auditQs.set("actor", actor);
    if (action) auditQs.set("action", action);
    if (eventType) eventQs.set("event_type", eventType);
    if (dateFrom) {
      auditQs.set("date_from", new Date(dateFrom).toISOString());
      eventQs.set("date_from", new Date(dateFrom).toISOString());
    }
    if (dateTo) {
      auditQs.set("date_to", new Date(dateTo).toISOString());
      eventQs.set("date_to", new Date(dateTo).toISOString());
    }
    api<HistoryPage<AuditRow>>(`/api/audit-history?${auditQs}`).then(setAudit);
    api<HistoryPage<EventRow>>(`/api/domain-events?${eventQs}`).then(setEvents);
  }

  useEffect(() => {
    api<Tenant[]>("/api/tenants").then(setTenants);
  }, []);
  useEffect(load, [tenantId, actor, action, eventType, dateFrom, dateTo]);

  if (user?.role === "viewer" && user.has_tenant_access === false) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h1 className="text-2xl font-semibold mb-2">Audit & Events</h1>
        <p className="text-slate-400">No tenant access has been assigned to this account.</p>
      </div>
    );
  }

  const rows = tab === "audit" ? audit?.items ?? [] : events?.items ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Audit & Events</h1>
        <p className="text-slate-400 text-sm">Security/admin audit is separate from domain events.</p>
      </div>
      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label>Tenant</label>
          <select className="w-56" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
            <option value="">Authorized scope</option>
            {tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        </div>
        {tab === "audit" ? (
          <>
            <div>
              <label>Actor</label>
              <input className="w-40" value={actor} onChange={(e) => setActor(e.target.value)} placeholder="username" />
            </div>
            <div>
              <label>Action</label>
              <input className="w-48" value={action} onChange={(e) => setAction(e.target.value)} placeholder="report.export" />
            </div>
          </>
        ) : (
          <div>
            <label>Event type</label>
            <input className="w-48" value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder="new_asset" />
          </div>
        )}
        <div>
          <label>From</label>
          <input type="datetime-local" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
        </div>
        <div>
          <label>To</label>
          <input type="datetime-local" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
        </div>
        <button className={`px-3 py-2 rounded-md text-sm ${tab === "audit" ? "bg-cyan-700" : "bg-slate-800"}`} onClick={() => setTab("audit")}>
          Security / Admin Audit
        </button>
        <button className={`px-3 py-2 rounded-md text-sm ${tab === "events" ? "bg-cyan-700" : "bg-slate-800"}`} onClick={() => setTab("events")}>
          Domain Events
        </button>
      </div>
      <div className="overflow-auto border border-slate-800 rounded-xl">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400 text-left">
            <tr>
              <th className="px-3 py-2">When</th>
              <th className="px-3 py-2">Tenant</th>
              <th className="px-3 py-2">Actor / source</th>
              <th className="px-3 py-2">Action / event</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <Fragment key={row.id}>
                <tr className="border-t border-slate-800 cursor-pointer" onClick={() => setOpen(open === row.id ? null : row.id)}>
                  <td className="px-3 py-2 text-slate-300">
                    {new Date("created_at" in row ? row.created_at : "occurred_at" in row ? row.occurred_at : "").toLocaleString()}
                  </td>
                  <td className="px-3 py-2">{row.tenant_name || "—"}</td>
                  <td className="px-3 py-2">
                    {"actor" in row ? row.actor || "—" : "source" in row ? row.source : "—"}
                  </td>
                  <td className="px-3 py-2">{row.summary}</td>
                </tr>
                {open === row.id && (
                  <tr className="bg-slate-950">
                    <td colSpan={4} className="px-3 py-3 text-xs text-slate-400 whitespace-pre-wrap">
                      {JSON.stringify(row.details, null, 2)}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <div className="p-4 text-slate-500 text-sm">No history in this authorized scope.</div>}
      </div>
    </div>
  );
}
