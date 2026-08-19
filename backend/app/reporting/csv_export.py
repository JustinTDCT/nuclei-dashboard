"""Safe CSV generation for reports and compatibility exports."""

from __future__ import annotations

import csv
import io
import re
import tempfile
from collections.abc import Iterable, Sequence
from typing import Any

from fastapi.responses import StreamingResponse

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str) -> str:
    cleaned = SAFE_FILENAME.sub("-", name).strip("-._")
    return cleaned or "report"


def neutralize_formula(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in FORMULA_PREFIXES:
        return f"'{value}"
    return value


def cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return neutralize_formula(value)


def write_csv(output, headers: Sequence[str], rows: Iterable[Sequence[Any] | dict[str, Any]]) -> None:
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(list(headers))
    for row in rows:
        if isinstance(row, dict):
            values = [cell(row.get(key)) for key in headers]
        else:
            values = [cell(item) for item in row]
        writer.writerow(values)


def spool_csv(headers: Sequence[str], rows: Iterable[Sequence[Any] | dict[str, Any]]):
    spool = tempfile.SpooledTemporaryFile(max_size=2_000_000)
    text = io.TextIOWrapper(spool, encoding="utf-8", newline="")
    write_csv(text, headers, rows)
    text.flush()
    text.detach()
    spool.seek(0)
    return spool


def csv_response_from_spool(filename: str, spool) -> StreamingResponse:
    name = safe_filename(filename)
    if not name.lower().endswith(".csv"):
        name = f"{name}.csv"

    def chunks():
        try:
            while True:
                block = spool.read(65536)
                if not block:
                    break
                yield block
        finally:
            spool.close()

    return StreamingResponse(
        chunks(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def csv_streaming_response(
    filename: str,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any] | dict[str, Any]],
) -> StreamingResponse:
    return csv_response_from_spool(filename, spool_csv(headers, rows))
