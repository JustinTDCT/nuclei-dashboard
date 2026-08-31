import type { ScanJob, ScanJobProgress } from "../types";

function formatElapsed(seconds: number | null | undefined): string {
  if (seconds == null) return "";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${rest}s`;
  return `${rest}s`;
}

function percentLabel(progress: ScanJobProgress): string {
  if (progress.percent == null) return "In progress";
  if (progress.approximate) return `~${progress.percent}%`;
  return `${progress.percent}%`;
}

export function ScanProgressBar({ progress, compact = false }: { progress?: ScanJobProgress | null; compact?: boolean }) {
  if (!progress) return compact ? <span className="text-slate-500">—</span> : null;
  const width = Math.max(0, Math.min(100, progress.percent ?? 0));
  const indeterminate = progress.approximate && (progress.percent == null || progress.percent <= 5);
  return (
    <div className={compact ? "min-w-[7rem]" : "space-y-1"}>
      <div className="flex items-center justify-between gap-2 text-xs text-slate-400">
        <span>{progress.label}</span>
        <span>{percentLabel(progress)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div
          className={`h-full rounded-full ${indeterminate ? "bg-cyan-400/70 animate-pulse w-1/3" : "bg-cyan-400"}`}
          style={indeterminate ? undefined : { width: `${width}%` }}
        />
      </div>
    </div>
  );
}

export function ScanProgressDetail({ job }: { job: ScanJob }) {
  const progress = job.progress;
  const live = ["running", "queued", "waiting_for_agent"].includes(job.status);
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Live progress</div>
          <div className="font-medium">{progress?.label || job.status}</div>
        </div>
        {live && <span className="text-xs text-cyan-300">Refreshing</span>}
      </div>
      <ScanProgressBar progress={progress} />
      <div className="text-xs text-slate-400 space-y-1">
        {progress?.elapsed_seconds != null && <div>Elapsed: {formatElapsed(progress.elapsed_seconds)}</div>}
        {progress?.message && <div>{progress.message}</div>}
        {progress?.approximate && (
          <div>This Agent is scanning. Exact stage percent appears after the next Agent image rebuild.</div>
        )}
      </div>
      {progress?.stages && progress.stages.length > 0 && (
        <ol className="space-y-1">
          {progress.stages.map((stage) => (
            <li key={stage.id} className="flex items-center gap-2 text-sm">
              <span
                className={`h-2 w-2 rounded-full ${
                  stage.state === "done" ? "bg-emerald-400" : stage.state === "active" ? "bg-cyan-400" : "bg-slate-600"
                }`}
              />
              <span className={stage.state === "pending" ? "text-slate-400" : ""}>{stage.label}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
