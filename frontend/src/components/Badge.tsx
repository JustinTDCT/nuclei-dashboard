const colors: Record<string, string> = {
  admin: "bg-violet-500/20 text-violet-200",
  user: "bg-cyan-500/20 text-cyan-200",
  viewer: "bg-slate-500/20 text-slate-200",
  new: "bg-amber-500/20 text-amber-200",
  known: "bg-emerald-500/20 text-emerald-200",
  stale: "bg-slate-500/20 text-slate-300",
  queued: "bg-slate-500/20 text-slate-200",
  running: "bg-cyan-500/20 text-cyan-200",
  done: "bg-emerald-500/20 text-emerald-200",
  failed: "bg-rose-500/20 text-rose-200",
  approved: "bg-emerald-500/20 text-emerald-200",
  pending_approval: "bg-amber-500/20 text-amber-200",
  pending_enrollment: "bg-slate-500/20 text-slate-200",
  revoked: "bg-rose-500/20 text-rose-200",
  critical: "bg-rose-600/30 text-rose-100",
  high: "bg-orange-500/20 text-orange-200",
  medium: "bg-amber-500/20 text-amber-200",
  low: "bg-sky-500/20 text-sky-200",
  info: "bg-slate-500/20 text-slate-200",
  wan: "bg-indigo-500/20 text-indigo-200",
  lan: "bg-teal-500/20 text-teal-200",
  online: "bg-emerald-500/20 text-emerald-200",
  offline: "bg-slate-500/20 text-slate-300",
  active: "bg-emerald-500/20 text-emerald-200",
  inactive: "bg-slate-500/20 text-slate-300",
  unreviewed: "bg-amber-500/20 text-amber-200",
  unauthorized: "bg-rose-500/20 text-rose-200",
  ignored: "bg-slate-500/20 text-slate-300",
  normal: "bg-slate-500/20 text-slate-200",
  expected: "bg-amber-500/20 text-amber-200",
  open: "bg-rose-500/20 text-rose-200",
  resolved: "bg-emerald-500/20 text-emerald-200",
  unaddressed: "bg-amber-500/20 text-amber-200",
  mitigated: "bg-sky-500/20 text-sky-200",
  accepted_risk: "bg-violet-500/20 text-violet-200",
  false_positive: "bg-slate-500/20 text-slate-300",
};

export function Badge({ value }: { value: string }) {
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wide ${colors[value] || "bg-slate-700 text-slate-200"}`}>
      {value.replaceAll("_", " ")}
    </span>
  );
}
