#!/usr/bin/env python3
"""Run the S2 ingest harness against the current production path.

Measures upsert_devices / store_detector_coverage / store_findings /
complete_scan_run (S2B Device/Asset caches included) and writes a JSON report.

Examples:
    cd backend
    python scripts/scale_s2a_benchmark.py --size small --out /tmp/s2a-small.json
    python scripts/scale_s2a_benchmark.py --size medium --out /tmp/s2a-medium.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from tests.conftest import POSTGRES_AVAILABLE, POSTGRES_SKIP_REASON  # noqa: E402

if not POSTGRES_AVAILABLE:
    raise SystemExit(f"S2A benchmark needs PostgreSQL: {POSTGRES_SKIP_REASON}")

from app.ingest_chunks import DEFAULT_INGEST_MAX_BYTES, DEFAULT_INGEST_MAX_ROWS  # noqa: E402
from tests.scale_s2.constants import CHUNKED_INGEST_PATH, CURRENT_INGEST_PATH, S1_BASELINE_SHA, WORKLOADS  # noqa: E402
from tests.scale_s2.harness import (  # noqa: E402
    hotspot_flags,
    prepare_and_ingest,
    prepare_and_ingest_chunked,
    workload_spec,
)
from tests.scale_s2.snapshot import capture_normalized_state  # noqa: E402
from tests.scale_s2.world import reset_schema  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="S2A current-path ingest benchmark")
    parser.add_argument("--size", choices=sorted(WORKLOADS), default="small")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--replay", action="store_true", help="ingest the same chunk a second time")
    parser.add_argument(
        "--chunk-rows",
        type=int,
        default=None,
        help="S2D: slice Device/Finding/coverage lists to this many rows per request",
    )
    parser.add_argument(
        "--chunk-bytes",
        type=int,
        default=None,
        help="S2D: slice lists so each encoded request stays under this many bytes",
    )
    args = parser.parse_args()

    from app.database import SessionLocal

    spec = workload_spec(args.size)
    reset_schema()
    db = SessionLocal()
    try:
        chunked = args.chunk_rows is not None or args.chunk_bytes is not None
        if chunked:
            result = prepare_and_ingest_chunked(
                db,
                spec,
                replay=args.replay,
                max_rows=args.chunk_rows or DEFAULT_INGEST_MAX_ROWS,
                max_bytes=args.chunk_bytes or DEFAULT_INGEST_MAX_BYTES,
            )
            ingest_path = CHUNKED_INGEST_PATH
        else:
            result = prepare_and_ingest(db, spec, replay=args.replay)
            ingest_path = CURRENT_INGEST_PATH
        if args.replay:
            from tests.scale_s2.snapshot import assert_equivalent

            replay_state = capture_normalized_state(db, result["world"].tenant_id)
            assert_equivalent(result["state"], replay_state, label=f"{spec.name} CLI replay")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "s1_baseline_sha": S1_BASELINE_SHA,
            "ingest_path": ingest_path,
            "workload": spec.name,
            "replay": args.replay,
            "counts": {name: len(rows) for name, rows in result["state"].items()},
            "metrics": result["metrics"].as_dict(),
            "hotspots": hotspot_flags(result["metrics"]),
        }
    finally:
        db.close()

    text = json.dumps(report, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
