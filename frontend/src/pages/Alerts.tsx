import { useEffect, useState } from "react";
import { api } from "../api";
import { canWrite, useAuth } from "../auth";
import { Badge } from "../components/Badge";
import type { AlertItem } from "../types";

export function Alerts({ tenantId }: { tenantId?: number }) {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [openOnly, setOpenOnly] = useState(true);

  function load() {
    const qs = new URLSearchParams();
    if (tenantId) qs.set("tenant_id", String(tenantId));
    if (openOnly) qs.set("open_only", "true");
    api<AlertItem[]>(`/api/alerts?${qs}`).then(setAlerts);
  }

  useEffect(load, [tenantId, openOnly]);

  async function ack(id: number) {
    await api(`/api/alerts/${id}/ack`, { method: "POST" });
    load();
  }

  async function ackAll() {
    const qs = tenantId ? `?tenant_id=${tenantId}` : "";
    await api(`/api/alerts/ack-all${qs}`, { method: "POST" });
    load();
  }

  return (
    <div className="space-y-4">
      {!tenantId && (
        <div>
          <h1 className="text-2xl font-semibold">Alerts</h1>
          <p className="text-slate-400 text-sm">New devices and agent impersonation attempts.</p>
        </div>
      )}
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} />
          Open only
        </label>
        {canWrite(user?.role) && (
          <button className="text-sm text-cyan-400" onClick={ackAll}>
            Acknowledge all
          </button>
        )}
      </div>
      <div className="space-y-2">
        {alerts.map((a) => (
          <div key={a.id} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-medium">{a.title}</div>
                <div className="text-sm text-slate-400 whitespace-pre-wrap mt-1">{a.body}</div>
                <div className="text-xs text-slate-500 mt-2">{new Date(a.created_at).toLocaleString()}</div>
              </div>
              <div className="flex flex-col items-end gap-2">
                <Badge value={a.type} />
                {a.is_acknowledged ? (
                  <Badge value="known" />
                ) : (
                  canWrite(user?.role) && (
                    <button className="text-sm text-cyan-400" onClick={() => ack(a.id)}>
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
    </div>
  );
}
