import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { canWrite, useAuth } from "../auth";
import { formatUtc, useTimezone } from "../timezone";
import type { ComplianceControl, ComplianceFramework, ControlReference } from "../types";
import { Badge } from "./Badge";

const SUBJECT_LABELS: Record<string, string> = {
  asset: "Asset",
  asset_finding: "Finding",
  finding: "Detection evidence",
  treatment: "Treatment",
  scan_job: "Scan run",
};

const REF_LABELS: Record<string, string> = {
  related: "Related control",
  evidence: "Evidence reference",
  supports: "Supporting evidence",
};

export function ControlMapping({
  tenantId,
  subjectType,
  subjectId,
}: {
  tenantId: number;
  subjectType: string;
  subjectId: number;
}) {
  const { user } = useAuth();
  const write = canWrite(user?.role);
  const { defaultTimezone } = useTimezone();
  const [rows, setRows] = useState<ControlReference[]>([]);
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [frameworkId, setFrameworkId] = useState("");
  const [controlId, setControlId] = useState("");
  const [referenceType, setReferenceType] = useState("related");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  function load() {
    api<ControlReference[]>(
      `/api/tenants/${tenantId}/control-references?subject_type=${subjectType}&subject_id=${subjectId}&include_removed=true`
    ).then(setRows);
  }
  useEffect(load, [tenantId, subjectType, subjectId]);
  useEffect(() => {
    api<ComplianceFramework[]>("/api/compliance/frameworks").then(setFrameworks);
  }, []);
  useEffect(() => {
    if (!frameworkId) {
      setControls([]);
      return;
    }
    api<ComplianceControl[]>(`/api/compliance/frameworks/${frameworkId}/controls`).then(setControls);
  }, [frameworkId]);

  const active = rows.filter((row) => !row.removed_at);
  const removed = rows.filter((row) => row.removed_at);

  async function add(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api(`/api/tenants/${tenantId}/control-references`, {
        method: "POST",
        body: JSON.stringify({
          control_id: Number(controlId),
          subject_type: subjectType,
          subject_id: subjectId,
          reference_type: referenceType,
          notes,
        }),
      });
      setNotes("");
      load();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to add mapping");
    }
  }

  async function remove(id: number) {
    const reason = window.prompt("Why is this mapping being removed?");
    if (!reason) return;
    await api(`/api/tenants/${tenantId}/control-references/${id}/remove`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
    load();
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">
        Mapped controls are related evidence only. This does not mean the control is implemented, assessed, or certified.
      </p>
      {active.length === 0 && <div className="text-sm text-slate-500">No active control mappings.</div>}
      {active.map((row) => (
        <div key={row.id} className="border border-slate-800 rounded-lg p-3 text-sm space-y-1">
          <div className="flex flex-wrap gap-2 items-center">
            <Badge value={REF_LABELS[row.reference_type] || row.reference_type} />
            <span className="font-mono">{row.control_key}</span>
            <span>{row.control_title}</span>
          </div>
          <div className="text-slate-400">
            {row.framework_name} {row.framework_version}
            {row.control_family ? ` · ${row.control_family}` : ""}
          </div>
          {row.notes && <div className="text-slate-300">{row.notes}</div>}
          {write && (
            <button className="text-cyan-400 text-sm" onClick={() => remove(row.id)}>
              Remove mapping
            </button>
          )}
        </div>
      ))}
      {removed.length > 0 && (
        <details className="text-sm text-slate-500">
          <summary>Removed mappings</summary>
          {removed.map((row) => (
            <div key={row.id} className="py-1">
              {row.control_key} · removed {row.removed_at ? formatUtc(row.removed_at, defaultTimezone) : ""} · {row.removal_reason}
            </div>
          ))}
        </details>
      )}
      {write && (
        <form className="grid md:grid-cols-2 gap-3" onSubmit={add}>
          <div>
            <label>Framework</label>
            <select className="w-full" value={frameworkId} onChange={(e) => setFrameworkId(e.target.value)} required>
              <option value="">Select framework</option>
              {frameworks.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} {item.version}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label>Control</label>
            <select className="w-full" value={controlId} onChange={(e) => setControlId(e.target.value)} required>
              <option value="">Select control</option>
              {controls.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.control_key} — {item.title}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label>Relationship</label>
            <select className="w-full" value={referenceType} onChange={(e) => setReferenceType(e.target.value)}>
              <option value="related">Related control</option>
              <option value="evidence">Evidence reference</option>
              <option value="supports">Supporting evidence</option>
            </select>
          </div>
          <div>
            <label>Notes</label>
            <input className="w-full" value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
          {error && <div className="text-rose-300 text-sm md:col-span-2">{error}</div>}
          <div className="md:col-span-2">
            <button className="bg-cyan-700 text-white rounded-md px-3 py-1.5 text-sm">
              Link {SUBJECT_LABELS[subjectType] || "object"} to control
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
