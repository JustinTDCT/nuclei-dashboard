"""NVD CVE API 2.0 client and parser.

Official endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Batch lookup uses `cveIds` (max 100). Optional API key is sent as the
`apiKey` header and is never logged or persisted in Settings.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlencode

from app.intel.http import FetchFn, IntelligenceHttpError, fetch_url, request_with_retry
from app.models import CWE_PLACEHOLDERS

log = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_LIMIT = 50
NVD_MAX_CVE_IDS = 100
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
NVD_PRIMARY_SOURCE = "nvd@nist.gov"

CVSS_VERSION_RANK = {
    "4.0": 40,
    "4": 40,
    "3.1": 31,
    "3.0": 30,
    "3": 30,
    "2.0": 20,
    "2": 20,
}


@dataclass(frozen=True)
class SelectedCvss:
    version: str
    base_score: Decimal
    base_severity: str
    vector: str
    source: str


@dataclass
class ParsedNvdCve:
    cve_id: str
    status: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    description: str | None = None
    cvss: SelectedCvss | None = None
    cwes: list[tuple[str, str]] = field(default_factory=list)
    placeholder_cwes: list[tuple[str, str]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    rejected: bool = False


class NvdParseError(ValueError):
    pass


def normalize_cve(value: str | None) -> str | None:
    token = (value or "").strip().upper()
    if CVE_RE.match(token):
        return token
    return None


def _parse_nvd_datetime(value: Any) -> datetime | None:
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


def _decimal_score(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if score < 0 or score > 10:
        return None
    return score


def _metric_version_key(version: str) -> str:
    token = (version or "").strip()
    if token.startswith("4"):
        return "4.0"
    if token == "3.1":
        return "3.1"
    if token.startswith("3"):
        return "3.0"
    if token.startswith("2"):
        return "2.0"
    return token


def _metric_rank(version: str) -> int:
    return CVSS_VERSION_RANK.get(_metric_version_key(version), 0)


def _collect_metrics(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    if not isinstance(metrics, dict):
        return collected
    for key in ("cvssMetricV40", "cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict):
                collected.append(row)
    return collected


def select_cvss(metrics: dict[str, Any] | None) -> SelectedCvss | None:
    """Deterministic CVSS selection: v4 > v3.1 > v3.0 > v2; NVD Primary first."""
    candidates: list[tuple[int, int, int, SelectedCvss]] = []
    for index, row in enumerate(_collect_metrics(metrics or {})):
        data = row.get("cvssData") if isinstance(row.get("cvssData"), dict) else {}
        version = str(data.get("version") or "").strip()
        score = _decimal_score(data.get("baseScore"))
        vector = str(data.get("vectorString") or "").strip()
        severity = str(data.get("baseSeverity") or row.get("baseSeverity") or "").strip()
        source = str(row.get("source") or "").strip()
        metric_type = str(row.get("type") or "").strip()
        if score is None or not version:
            continue
        version_rank = _metric_rank(version)
        if version_rank == 0:
            continue
        source_rank = 0
        if metric_type.lower() == "primary" and source.lower() == NVD_PRIMARY_SOURCE:
            source_rank = 3
        elif metric_type.lower() == "primary":
            source_rank = 2
        elif source.lower() == NVD_PRIMARY_SOURCE:
            source_rank = 1
        selected = SelectedCvss(
            version=_metric_version_key(version),
            base_score=score,
            base_severity=severity or "",
            vector=vector,
            source=source or metric_type or "nvd",
        )
        candidates.append((version_rank, source_rank, -index, selected))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return candidates[0][3]


def extract_cwes(weaknesses: Any) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    real: list[tuple[str, str]] = []
    placeholders: list[tuple[str, str]] = []
    seen_real: set[tuple[str, str]] = set()
    seen_ph: set[tuple[str, str]] = set()
    if not isinstance(weaknesses, list):
        return real, placeholders
    for row in weaknesses:
        if not isinstance(row, dict):
            continue
        source = str(row.get("source") or "nvd").strip() or "nvd"
        descriptions = row.get("description")
        if not isinstance(descriptions, list):
            continue
        for item in descriptions:
            value = ""
            if isinstance(item, dict):
                value = str(item.get("value") or "").strip()
            elif item:
                value = str(item).strip()
            if not value:
                continue
            token = value.upper()
            if token in CWE_PLACEHOLDERS or token.startswith("NVD-CWE-"):
                key = (value, source)
                if key not in seen_ph:
                    placeholders.append(key)
                    seen_ph.add(key)
                continue
            if CWE_RE.match(value):
                # Keep the numeric portion as provided; only normalize the prefix.
                number = value.split("-", 1)[1]
                normalized = f"CWE-{number}"
                pair = (normalized, source)
                if pair not in seen_real:
                    real.append(pair)
                    seen_real.add(pair)
    return real, placeholders


def extract_references(references: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(references, list):
        return rows
    for item in references:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        source = str(item.get("source") or "").strip()
        if not url or len(url) > 2000:
            continue
        key = (url, source)
        if key in seen:
            continue
        seen.add(key)
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        rows.append(
            {
                "url": url,
                "source": source,
                "tags": [str(tag) for tag in tags if tag],
            }
        )
    return rows


def english_description(descriptions: Any) -> str | None:
    if not isinstance(descriptions, list):
        return None
    fallback = None
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        lang = str(item.get("lang") or "").lower()
        if lang in {"en", "en-us"}:
            return value
        if fallback is None:
            fallback = value
    return fallback


def parse_nvd_cve(item: Any) -> ParsedNvdCve:
    if not isinstance(item, dict):
        raise NvdParseError("CVE item must be an object")
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
    cve_id = normalize_cve(str(cve.get("id") or item.get("id") or ""))
    if not cve_id:
        raise NvdParseError("CVE item is missing a valid CVE ID")
    status = str(cve.get("vulnStatus") or "").strip() or None
    rejected = (status or "").lower() == "rejected"
    cvss = None if rejected else select_cvss(cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {})
    real_cwes, placeholder_cwes = extract_cwes(cve.get("weaknesses"))
    return ParsedNvdCve(
        cve_id=cve_id,
        status=status,
        published_at=_parse_nvd_datetime(cve.get("published")),
        last_modified_at=_parse_nvd_datetime(cve.get("lastModified")),
        description=english_description(cve.get("descriptions")),
        cvss=cvss,
        cwes=real_cwes,
        placeholder_cwes=placeholder_cwes,
        references=extract_references(cve.get("references")),
        rejected=rejected,
    )


def parse_nvd_response(payload: Any) -> list[ParsedNvdCve]:
    if isinstance(payload, (bytes, bytearray, str)):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise NvdParseError("NVD response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise NvdParseError("NVD response must be a JSON object")
    rows = payload.get("vulnerabilities")
    if rows is None:
        raise NvdParseError("NVD response is missing vulnerabilities")
    if not isinstance(rows, list):
        raise NvdParseError("NVD vulnerabilities must be a list")
    parsed: list[ParsedNvdCve] = []
    for item in rows:
        try:
            parsed.append(parse_nvd_cve(item))
        except NvdParseError:
            log.warning("Skipping malformed NVD CVE record")
    return parsed


def nvd_rate_delay(api_key_configured: bool) -> float:
    # Official recommendation: sleep several seconds between requests.
    # Public: 5 req / 30s. With key: 50 req / 30s.
    return 1.0 if api_key_configured else 6.0


def fetch_nvd_cves(
    cve_ids: list[str],
    *,
    api_key: str | None = None,
    fetch: FetchFn = fetch_url,
    sleep=None,
) -> list[ParsedNvdCve]:
    normalized: list[str] = []
    for raw in cve_ids:
        cve = normalize_cve(raw)
        if cve and cve not in normalized:
            normalized.append(cve)
    if not normalized:
        return []
    if len(normalized) > NVD_MAX_CVE_IDS:
        normalized = normalized[:NVD_MAX_CVE_IDS]
    query = urlencode({"cveIds": ",".join(normalized)})
    url = f"{NVD_CVE_API}?{query}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    response = request_with_retry(url, headers=headers, fetch=fetch, sleep=sleep or (lambda _: None))
    try:
        return parse_nvd_response(response.body)
    except NvdParseError as exc:
        raise IntelligenceHttpError(str(exc), permanent=True) from exc
