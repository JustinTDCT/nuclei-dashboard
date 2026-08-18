"""CISA Known Exploited Vulnerabilities catalog loader.

Official JSON feed:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from app.intel.http import FetchFn, IntelligenceHttpError, fetch_url, request_with_retry
from app.intel.nvd import normalize_cve

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevParseError(ValueError):
    pass


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    date_added: date | None
    due_date: date | None
    required_action: str | None
    known_ransomware_campaign_use: bool | None
    vendor_project: str | None
    product: str | None


@dataclass(frozen=True)
class KevCatalog:
    records: dict[str, KevRecord]
    catalog_version: str | None
    date_released: datetime | None
    complete: bool
    skipped_malformed: int


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    raw = str(value).strip()
    if "T" in raw:
        raw = raw.split("T", 1)[0]
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def _parse_datetime(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ransomware(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    token = str(value).strip().lower()
    if token in {"known", "yes", "true", "1"}:
        return True
    if token in {"unknown", "no", "false", "0"}:
        return False
    return None


def parse_kev_entry(item: Any) -> KevRecord:
    if not isinstance(item, dict):
        raise KevParseError("KEV entry must be an object")
    cve = normalize_cve(str(item.get("cveID") or item.get("cve_id") or item.get("cve") or ""))
    if not cve:
        raise KevParseError("KEV entry is missing a CVE ID")
    return KevRecord(
        cve_id=cve,
        date_added=_parse_date(item.get("dateAdded")),
        due_date=_parse_date(item.get("dueDate")),
        required_action=str(item.get("requiredAction") or "").strip() or None,
        known_ransomware_campaign_use=_ransomware(item.get("knownRansomwareCampaignUse")),
        vendor_project=str(item.get("vendorProject") or "").strip() or None,
        product=str(item.get("product") or "").strip() or None,
    )


def parse_kev_catalog(payload: Any) -> KevCatalog:
    if isinstance(payload, (bytes, bytearray, str)):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise KevParseError("KEV catalog is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise KevParseError("KEV catalog must be a JSON object")
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list):
        raise KevParseError("KEV catalog is missing vulnerabilities")
    if not rows:
        raise KevParseError("KEV catalog is empty")
    records: dict[str, KevRecord] = {}
    skipped = 0
    for item in rows:
        try:
            parsed = parse_kev_entry(item)
        except KevParseError:
            skipped += 1
            continue
        records[parsed.cve_id] = parsed
    if not records:
        raise KevParseError("KEV catalog contained no valid CVE entries")
    declared = payload.get("count")
    complete = skipped == 0
    if isinstance(declared, int) and declared != len(rows):
        complete = False
    return KevCatalog(
        records=records,
        catalog_version=str(payload.get("catalogVersion") or "").strip() or None,
        date_released=_parse_datetime(payload.get("dateReleased")),
        complete=complete,
        skipped_malformed=skipped,
    )


def fetch_kev_catalog(*, fetch: FetchFn = fetch_url, sleep=None) -> KevCatalog:
    response = request_with_retry(KEV_JSON_URL, fetch=fetch, sleep=sleep or (lambda _: None))
    try:
        return parse_kev_catalog(response.body)
    except KevParseError as exc:
        raise IntelligenceHttpError(str(exc), permanent=True) from exc
