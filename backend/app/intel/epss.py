"""FIRST EPSS daily dataset loader.

Official current file:
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

The daily CSV is the bulk mechanism FIRST recommends. The lookup API
is not used for catalog refresh.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from app.intel.http import DEFAULT_MAX_BYTES, FetchFn, IntelligenceHttpError, fetch_url, request_with_retry
from app.intel.nvd import normalize_cve

EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
COMMENT_RE = re.compile(
    r"model_version\s*[:=]\s*(?P<model>[^\s,]+).*?score_date\s*[:=]\s*(?P<date>\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


class EpssParseError(ValueError):
    pass


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    score: Decimal
    percentile: Decimal


@dataclass(frozen=True)
class EpssDataset:
    records: dict[str, EpssRecord]
    score_date: date | None
    model_version: str | None
    source_updated_at: datetime | None


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _parse_probability(value: str) -> Decimal:
    try:
        number = Decimal(value.strip())
    except (InvalidOperation, AttributeError) as exc:
        raise EpssParseError("EPSS value is not a decimal") from exc
    if number < 0 or number > 1:
        raise EpssParseError("EPSS value is outside 0..1")
    return number


def parse_epss_csv(raw: bytes | str) -> EpssDataset:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EpssParseError("EPSS CSV is not valid UTF-8") from exc
    else:
        text = raw
    if not text.strip():
        raise EpssParseError("EPSS CSV is empty")
    lines = text.splitlines()
    if len(lines) < 2:
        raise EpssParseError("EPSS CSV is truncated")
    model_version = None
    score_date = None
    start = 0
    if lines[0].lstrip().startswith("#"):
        match = COMMENT_RE.search(lines[0])
        if match:
            model_version = match.group("model")
            score_date = _parse_date(match.group("date"))
        start = 1
        if start >= len(lines):
            raise EpssParseError("EPSS CSV is missing the header row")
    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    if not reader.fieldnames:
        raise EpssParseError("EPSS CSV is missing column names")
    fields = {name.strip().lower(): name for name in reader.fieldnames if name}
    if "cve" not in fields or "epss" not in fields or "percentile" not in fields:
        raise EpssParseError("EPSS CSV is missing required columns")
    records: dict[str, EpssRecord] = {}
    bad_rows = 0
    seen_rows = 0
    for row in reader:
        seen_rows += 1
        if not isinstance(row, dict):
            bad_rows += 1
            continue
        try:
            cve = normalize_cve(str(row.get(fields["cve"]) or ""))
            if not cve:
                raise EpssParseError("invalid CVE")
            record = EpssRecord(
                cve_id=cve,
                score=_parse_probability(str(row.get(fields["epss"]) or "")),
                percentile=_parse_probability(str(row.get(fields["percentile"]) or "")),
            )
        except EpssParseError:
            bad_rows += 1
            continue
        records[cve] = record
    if seen_rows == 0:
        raise EpssParseError("EPSS CSV has no data rows")
    if bad_rows and not records:
        raise EpssParseError("EPSS CSV contained no valid scored rows")
    if bad_rows and bad_rows / seen_rows > 0.05:
        raise EpssParseError("EPSS CSV is truncated or malformed")
    source_updated = None
    if score_date:
        source_updated = datetime(score_date.year, score_date.month, score_date.day, tzinfo=timezone.utc)
    return EpssDataset(
        records=records,
        score_date=score_date,
        model_version=model_version,
        source_updated_at=source_updated,
    )


def parse_epss_payload(body: bytes) -> EpssDataset:
    if not body:
        raise EpssParseError("EPSS download is empty")
    try:
        if body[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as handle:
                text = handle.read(DEFAULT_MAX_BYTES + 1)
            if len(text) > DEFAULT_MAX_BYTES:
                raise EpssParseError("EPSS CSV exceeded the maximum allowed size")
        else:
            text = body
    except EpssParseError:
        raise
    except OSError as exc:
        raise EpssParseError("EPSS gzip payload is truncated or invalid") from exc
    return parse_epss_csv(text)


def fetch_epss_dataset(*, fetch: FetchFn = fetch_url, sleep=None) -> EpssDataset:
    response = request_with_retry(
        EPSS_CURRENT_URL,
        fetch=fetch,
        max_bytes=DEFAULT_MAX_BYTES,
        sleep=sleep or (lambda _: None),
    )
    try:
        return parse_epss_payload(response.body)
    except EpssParseError as exc:
        raise IntelligenceHttpError(str(exc), permanent=True) from exc


def filter_tracked(dataset: EpssDataset, tracked_cves: set[str]) -> dict[str, EpssRecord | None]:
    """Map tracked CVEs to current scores. Missing keys are explicit None."""
    return {cve: dataset.records.get(cve) for cve in tracked_cves}
