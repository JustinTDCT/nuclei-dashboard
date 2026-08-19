import { useEffect, useState } from "react";
import { api } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { formatUtc, useTimezone } from "../timezone";
import type { AlertItem, Tenant } from "../types";

const EVENT_LABELS: Record<string, string> = {
  new_asset: "New Asset",
  asset_became_inactive: "Asset Became Inactive",
  previously_inactive_asset_returned: "Inactive Asset Returned",
  asset_disposition_changed: "Asset Disposition Changed",
  new_finding: "New Vulnerability / Finding",
  vulnerability_resolved: "Vulnerability Resolved",
  vulnerability_reopened: "Vulnerability Reopened",
  treatment_created: "Finding Treatment Created",
  treatment_expired: "Finding Treatment Expired",
  scan_failed: "Scan Failed",
  scan_missed_unavailable_agent: "Scan Missed — No Available Agent",
  agent_identity_mismatch: "Agent Identity Mismatch",
  wan_target_changed: "WAN Target Changed",
  policy_changed: "Policy Changed",
  new_device: "New Device (legacy)",
  impersonation: "Impersonation (legacy)",
};

function explanationText(alert: AlertItem): { policy: string; matched: string[]; actions: string[]; suppress: string } {
  const raw = (alert.policy_explanation || {}) as Record<string, unknown>;
  const actions = (raw.actions || {}) as Record<string, { source?: string; rule_name?: string; value?: unknown }>;
  const matched: string[] = [];
  const then: string[] = [];
  let policy = "System default";
  for (const [key, item] of Object.entries(actions)) {
    if (!item) continue;
    if (item.source === "policy" && item.rule_name) policy = item.rule_name;
    if (item.source === "system_default" && policy === "System default") policy = "System default";
    if (Array.isArray((item as { matched_conditions?: { detail: string; matched: boolean }[] }).matched_conditions)) {
      for (const cond of (item as { matched_conditions: { detail: string; matched: boolean }[] }).matched_conditions) {
        if (cond.matched) matched.push(cond.detail);
      }
    }
    then.push(`${key} = ${typeof item.value === "object" ? JSON.stringify(item.value) : String(item.value)}`);
  }
  const suppress = String((raw.effective as { suppress_for_minutes?: number } | undefined)?.suppress_for_minutes ?? 0);
  return { policy, matched: Array.from(new Set(matched)), actions: then, suppress };
}

export function Alerts({ tenantId }: { tenantId?: number }) {
  const { user } = useAuth();
  const { defaultTimezone } = useTimezone();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [openOnly, setOpenOnly] = useState(true);
  const [severity, setSeverity] = useState("");
  const [eventType, setEventType] = useState("");
  const [filterTenant, setFilterTenant] = useState(tenantId ? String(tenantId) : "");
  const [selected, setSelected] = useState<AlertItem | null>(null);

  function load() {
    const qs = new URLSearchParams();
    const tid = tenantId || (filterTenant ? Number(filterTenant) : undefined);
    if (tid) qs.set("tenant_id", String(tid));
    if (openOnly) qs.set("open_only", "true");
    if (severity) qs.set("severity", severity);
    if (eventType) qs.set("event_type", eventType);
    api<AlertItem[]>(`/api/alerts?${qs}`).then(setAlerts);
    if (!tenantId) api<Tenant[]>("/api/tenants").then(setTenants);
  }

  useEffect(load, [tenantId, openOnly, severity, eventType, filterTenant]);

  async function ack(id: number) {
    await api(`/api/alerts/${id}/ack`, { method: "POST" });
    if (selected?.id === id) {
      api<AlertItem>(`/api/alerts/${id}`).then(setSelected);
    }
    load();
  }

  async function ackAll() {
    const qs = new URLSearchParams();
    const tid = tenantId || (filterTenant ? Number(filterTenant) : undefined);
    if (tid) qs.set("tenant_id", String(tid));
    if (severity) qs.set("severity", severity);
    if (eventType) qs.set("event_type", eventType);
    await api(`/api/alerts/ack-all?${qs}`, { method: "POST" });
    setSelected(null);
    load();
  }

  async function openDetail(id: number) {
    const detail = await api<AlertItem>(`/api/alerts/${id}`);
    setSelected(detail);
  }

  return (
    <div className="space-y-4">
      {!tenantId && (
        <div>
          <h1 className="text-2xl font-semibold">Alerts</h1>
          <p className="text-slate-400 text-sm">Policy-driven dashboard alerts from domain events.</p>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} />
          Open only
        </label>
        {!tenantId && (
          <select value={filterTenant} onChange={(e) => setFilterTenant(e.target.value)}>
            <option value="">All tenants</option>
            {tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        )}
        <select value={eventType} onChange={(e) => setEventType(e.target.value)}>
          <option value="">All events</option>
          {Object.entries(EVENT_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((item) => (
            <option key={item}>{item}</option>
          ))}
        </select>
        {canWrite(user?.role) && (
          <button className="text-sm text-cyan-400" onClick={ackAll}>
            Acknowledge all
          </button>
        )}
      </div>
      <div className="grid lg:grid-cols-[1.3fr_1fr] gap-4">
        <div className="space-y-2">
          {alerts.map((a) => (
            <div
              key={a.id}
              className={`bg-slate-900 border rounded-xl p-4 cursor-pointer ${selected?.id === a.id ? "border-cyan-600" : "border-slate-800"}`}
              onClick={() => openDetail(a.id)}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium">{a.title}</div>
                  <div className="text-xs text-slate-500 mt-1">
                    {[a.tenant_name, a.site_name, a.event_type_label || EVENT_LABELS[a.type] || a.type]
                      .filter(Boolean)
                      .join(" · ")}
                    {a.occurrence_count && a.occurrence_count > 1 ? ` · ${a.occurrence_count} occurrences` : ""}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">{formatUtc(a.created_at, defaultTimezone)}</div>
                </div>
                <div className="flex flex-col items-end gap-2">
                  {a.severity && <Badge value={a.severity} />}
                  {a.is_acknowledged ? (
                    <Badge value="known" />
                  ) : (
                    canWrite(user?.role) && (
                      <button
                        className="text-sm text-cyan-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          ack(a.id);
                        }}
                      >
                        Acknowledge
                      </button>
                    )
                  )}
                </div>
              </div>
            </div>
          ))}
          {alerts.length === 0 && <div className="text-slate-500 text-sm">No alerts.</div>}
        </div>
        {selected && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 h-fit">
            <div className="flex justify-between gap-3">
              <h2 className="font-semibold">Why this alert existed</h2>
              <button className="text-slate-400 text-sm" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
            <div className="text-sm space-y-1">
              <div>Event: {selected.source_event?.event_type_label || EVENT_LABELS[selected.type] || selected.type}</div>
              <div>Severity: {selected.severity || "—"}</div>
              <div>Occurrences: {selected.occurrence_count || 1}</div>
              {selected.first_event_at && <div>First: {formatUtc(selected.first_event_at, defaultTimezone)}</div>}
              {selected.last_event_at && <div>Last: {formatUtc(selected.last_event_at, defaultTimezone)}</div>}
            </div>
            {(() => {
              const why = explanationText(selected);
              return (
                <div className="text-sm space-y-2">
                  <div>Policy: {why.policy}</div>
                  {why.matched.length > 0 && (
                    <div>
                      Matched:
                      <ul className="list-disc ml-5 text-slate-300">
                        {why.matched.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {why.actions.length > 0 && (
                    <div>
                      Actions:
                      <ul className="list-disc ml-5 text-slate-300">
                        {why.actions.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div>Suppression: {why.suppress} minutes</div>
                </div>
              );
            })()}
            {selected.deliveries && selected.deliveries.length > 0 && (
              <div className="text-sm">
                Deliveries:
                <ul className="list-disc ml-5 text-slate-300">
                  {selected.deliveries.map((item) => (
                    <li key={item.id}>
                      {item.channel} · {item.status}
                      {item.last_error ? ` · ${item.last_error}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
