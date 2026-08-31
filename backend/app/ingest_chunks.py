"""Bounded Device/Finding/coverage transport (Scale S2D).

One ingest semantic: the existing list POST bodies. This module only
enforces row-count and encoded-byte ceilings and slices a list so each
slice stays inside those ceilings. A single record larger than the byte
limit is rejected; it is never emitted as an unbounded one-record chunk.
No schema change.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Iterator

from fastapi import HTTPException

from app.config import settings

DEFAULT_INGEST_MAX_ROWS = 500
DEFAULT_INGEST_MAX_BYTES = 1_048_576


class IngestLimitError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def record_payload(row: Any) -> Any:
    if hasattr(row, "model_dump"):
        return row.model_dump()
    return row


def encoded_bytes(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"))


def encoded_record_bytes(row: Any) -> int:
    return encoded_bytes(record_payload(row))


def encoded_list_bytes(rows: Iterable[Any]) -> int:
    return encoded_bytes([record_payload(row) for row in rows])


def ingest_limits() -> tuple[int, int]:
    return int(settings.ingest_max_rows), int(settings.ingest_max_bytes)


def validate_ingest_batch(rows: list[Any], *, kind: str, max_rows: int, max_bytes: int) -> None:
    if len(rows) > max_rows:
        raise IngestLimitError(f"{kind} batch exceeds {max_rows}-row limit")
    for row in rows:
        size = encoded_record_bytes(row)
        if size > max_bytes:
            raise IngestLimitError(f"single {kind} record exceeds {max_bytes}-byte limit")
    if encoded_list_bytes(rows) > max_bytes:
        raise IngestLimitError(f"{kind} batch exceeds {max_bytes}-byte limit")


def iter_ingest_chunks(
    rows: list[Any],
    *,
    max_rows: int,
    max_bytes: int,
    kind: str = "record",
) -> Iterator[list[Any]]:
    chunk: list[Any] = []
    item_sizes: list[int] = []
    for row in rows:
        size = encoded_record_bytes(row)
        if size > max_bytes:
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


def raise_ingest_limit(rows: list[Any], *, kind: str) -> None:
    max_rows, max_bytes = ingest_limits()
    try:
        validate_ingest_batch(rows, kind=kind, max_rows=max_rows, max_bytes=max_bytes)
    except IngestLimitError as exc:
        raise HTTPException(status_code=413, detail=exc.detail) from exc


__all__ = [
    "DEFAULT_INGEST_MAX_BYTES",
    "DEFAULT_INGEST_MAX_ROWS",
    "IngestLimitError",
    "encoded_bytes",
    "encoded_list_bytes",
    "encoded_record_bytes",
    "ingest_limits",
    "iter_ingest_chunks",
    "raise_ingest_limit",
    "record_payload",
    "validate_ingest_batch",
]
