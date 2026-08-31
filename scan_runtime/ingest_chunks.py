"""Client-side Device/Finding/coverage slicing (Scale S2D).

Keep these ceilings in lockstep with backend ``app.ingest_chunks`` defaults
and the ``INGEST_MAX_ROWS`` / ``INGEST_MAX_BYTES`` settings. The server
enforces the same limits; this module only prevents a whole-list POST from
exceeding them. A single record that cannot fit inside a JSON list
(``2 + encoded size > max_bytes``) is raised; it is never sent as an
unbounded one-record chunk.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterator

DEFAULT_INGEST_MAX_ROWS = 500
DEFAULT_INGEST_MAX_BYTES = 1_048_576


class IngestLimitError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def ingest_limits() -> tuple[int, int]:
    return (
        int(os.environ.get("INGEST_MAX_ROWS", str(DEFAULT_INGEST_MAX_ROWS))),
        int(os.environ.get("INGEST_MAX_BYTES", str(DEFAULT_INGEST_MAX_BYTES))),
    )


def encoded_bytes(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"))


def iter_ingest_chunks(
    rows: list[Any],
    *,
    max_rows: int | None = None,
    max_bytes: int | None = None,
    kind: str = "record",
) -> Iterator[list[Any]]:
    limit_rows, limit_bytes = ingest_limits()
    if max_rows is None:
        max_rows = limit_rows
    if max_bytes is None:
        max_bytes = limit_bytes
    chunk: list[Any] = []
    item_sizes: list[int] = []
    for row in rows:
        size = encoded_bytes(row)
        if 2 + size > max_bytes:
            raise IngestLimitError(f"single {kind} record exceeds {max_bytes}-byte limit")
        next_count = len(chunk) + 1
        next_bytes = 2 + sum(item_sizes) + size + len(chunk)
        if chunk and (next_count > max_rows or next_bytes > max_bytes):
            yield list(chunk)
            chunk = []
            item_sizes = []
        chunk.append(row)
        item_sizes.append(size)
    if chunk:
        yield list(chunk)


__all__ = [
    "DEFAULT_INGEST_MAX_BYTES",
    "DEFAULT_INGEST_MAX_ROWS",
    "IngestLimitError",
    "encoded_bytes",
    "ingest_limits",
    "iter_ingest_chunks",
]
