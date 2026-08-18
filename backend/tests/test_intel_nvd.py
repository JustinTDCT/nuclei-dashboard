from __future__ import annotations

import io
import logging

import pytest

from app.intel.http import HttpResponse, IntelligenceHttpError
from app.intel.nvd import (
    NvdParseError,
    extract_cwes,
    fetch_nvd_cves,
    parse_nvd_response,
    select_cvss,
)


def _metric(version: str, score: float, severity: str, vector: str, source="nvd@nist.gov", typ="Primary"):
    key = {
        "4.0": "cvssMetricV40",
        "3.1": "cvssMetricV31",
        "3.0": "cvssMetricV30",
        "2.0": "cvssMetricV2",
    }[version]
    data = {"version": version, "baseScore": score, "vectorString": vector}
    row = {"source": source, "type": typ, "cvssData": data}
    if version == "2.0":
        row["baseSeverity"] = severity
    else:
        data["baseSeverity"] = severity
    return key, row


def _metrics(*items):
    payload = {}
    for version, score, severity, vector, *rest in items:
        source = rest[0] if rest else "nvd@nist.gov"
        typ = rest[1] if len(rest) > 1 else "Primary"
        key, row = _metric(version, score, severity, vector, source, typ)
        payload.setdefault(key, []).append(row)
    return payload


def _cve(cve="CVE-2024-1234", metrics=None, status="Analyzed", weaknesses=None, description="Example"):
    return {
        "cve": {
            "id": cve,
            "vulnStatus": status,
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": "2024-02-01T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": metrics or {},
            "weaknesses": weaknesses or [],
            "references": [{"url": "https://example.test/ref", "source": "nvd@nist.gov", "tags": ["Patch"]}],
        }
    }


def test_cvss_v4_selected_over_v3():
    selected = select_cvss(
        _metrics(
            ("4.0", 9.3, "CRITICAL", "CVSS:4.0/AV:N"),
            ("3.1", 9.8, "CRITICAL", "CVSS:3.1/AV:N"),
        )
    )
    assert selected is not None
    assert selected.version == "4.0"
    assert float(selected.base_score) == 9.3


def test_cvss_v31_when_v4_absent():
    selected = select_cvss(_metrics(("3.1", 8.8, "HIGH", "CVSS:3.1/AV:N"), ("3.0", 9.0, "CRITICAL", "CVSS:3.0/AV:N")))
    assert selected.version == "3.1"


def test_cvss_v30_fallback():
    selected = select_cvss(_metrics(("3.0", 7.5, "HIGH", "CVSS:3.0/AV:N"), ("2.0", 10.0, "HIGH", "AV:N/AC:L")))
    assert selected.version == "3.0"


def test_cvss_v2_legacy_fallback():
    selected = select_cvss(_metrics(("2.0", 10.0, "HIGH", "AV:N/AC:L/Au:N/C:C/I:C/A:C")))
    assert selected.version == "2.0"
    assert float(selected.base_score) == 10.0


def test_multiple_metric_sources_prefer_nvd_primary():
    selected = select_cvss(
        _metrics(
            ("3.1", 5.0, "MEDIUM", "CVSS:3.1/AV:L", "vendor@example.test", "Primary"),
            ("3.1", 9.8, "CRITICAL", "CVSS:3.1/AV:N", "nvd@nist.gov", "Primary"),
        )
    )
    assert float(selected.base_score) == 9.8
    assert selected.source == "nvd@nist.gov"


def test_no_cvss():
    assert select_cvss({}) is None
    parsed = parse_nvd_response({"vulnerabilities": [_cve()]})
    assert parsed[0].cvss is None


def test_cwe_extraction_and_placeholders():
    real, placeholders = extract_cwes(
        [
            {
                "source": "nvd@nist.gov",
                "description": [
                    {"lang": "en", "value": "CWE-79"},
                    {"lang": "en", "value": "NVD-CWE-noinfo"},
                    {"lang": "en", "value": "NVD-CWE-Other"},
                ],
            }
        ]
    )
    assert real == [("CWE-79", "nvd@nist.gov")]
    assert ("NVD-CWE-noinfo", "nvd@nist.gov") in placeholders


def test_rejected_cve_has_no_cvss():
    parsed = parse_nvd_response(
        {
            "vulnerabilities": [
                _cve(status="Rejected", metrics=_metrics(("3.1", 9.8, "CRITICAL", "CVSS:3.1/AV:N")))
            ]
        }
    )
    assert parsed[0].rejected is True
    assert parsed[0].status == "Rejected"
    assert parsed[0].cvss is None


def test_malformed_json():
    with pytest.raises(NvdParseError):
        parse_nvd_response(b"not-json")


def test_timeout_and_429_and_5xx(caplog):
    def timeout(*_args, **_kwargs):
        raise IntelligenceHttpError("timeout")

    with pytest.raises(IntelligenceHttpError):
        fetch_nvd_cves(["CVE-2024-1234"], fetch=timeout, sleep=lambda _: None)

    calls = {"n": 0}

    def rate_limited(url, **kwargs):
        calls["n"] += 1
        return HttpResponse(429, b"slow down", {})

    with pytest.raises(IntelligenceHttpError):
        fetch_nvd_cves(["CVE-2024-1234"], fetch=rate_limited, sleep=lambda _: None)
    assert calls["n"] > 1

    transient = {"n": 0}

    def flaky(url, **kwargs):
        transient["n"] += 1
        if transient["n"] < 2:
            return HttpResponse(503, b"busy", {})
        return HttpResponse(200, b'{"vulnerabilities":[]}', {"Content-Type": "application/json"})

    rows = fetch_nvd_cves(["CVE-2024-1234"], fetch=flaky, sleep=lambda _: None)
    assert rows == []


def test_api_key_not_logged(caplog):
    caplog.set_level(logging.INFO)

    def handler(url, **kwargs):
        headers = kwargs.get("headers") or {}
        assert headers.get("apiKey") == "super-secret-nvd-key"
        return HttpResponse(200, b'{"vulnerabilities":[]}', {})

    fetch_nvd_cves(["CVE-2024-1234"], api_key="super-secret-nvd-key", fetch=handler, sleep=lambda _: None)
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "super-secret-nvd-key" not in text
