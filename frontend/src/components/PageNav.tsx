export function PageNav({
  offset,
  limit,
  total,
  onPage,
}: {
  offset: number;
  limit: number;
  total: number;
  onPage: (nextOffset: number) => void;
}) {
  return (
    <div className="flex items-center gap-3 text-sm text-slate-400">
      <button
        className="text-cyan-400 disabled:text-slate-600"
        disabled={offset <= 0}
        onClick={() => onPage(Math.max(0, offset - limit))}
      >
        Previous
      </button>
      <span>
        {total === 0 ? "0–0" : `${offset + 1}–${Math.min(offset + limit, total)}`} of {total}
      </span>
      <button
        className="text-cyan-400 disabled:text-slate-600"
        disabled={offset + limit >= total}
        onClick={() => onPage(offset + limit)}
      >
        Next
      </button>
    </div>
  );
}
