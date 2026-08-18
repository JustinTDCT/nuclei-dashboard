from __future__ import annotations

import gzip

import pytest

from app.intel.epss import EpssParseError, parse_epss_csv, parse_epss_payload


VALID_CSV = """#model_version:v2025.03.14,score_date:2026-08-18
cve,epss,percentile
CVE-2024-1234,0.420000000,0.972000000
CVE-2023-0001,0.010000000,0.400000000
"""


def test_current_csv_parses_score_percentile_and_metadata():
    dataset = parse_epss_csv(VALID_CSV)
    assert dataset.model_version == "v2025.03.14"
    assert dataset.score_date.isoformat() == "2026-08-18"
    record = dataset.records["CVE-2024-1234"]
    assert float(record.score) == pytest.approx(0.42)
    assert float(record.percentile) == pytest.approx(0.972)


def test_gzip_payload_parses():
    dataset = parse_epss_payload(gzip.compress(VALID_CSV.encode()))
    assert "CVE-2024-1234" in dataset.records


def test_only_tracked_cves_are_relevant():
    dataset = parse_epss_csv(VALID_CSV)
    assert set(dataset.records) == {"CVE-2024-1234", "CVE-2023-0001"}
    assert "CVE-1999-9999" not in dataset.records


def test_truncated_or_bad_csv_rejected():
    with pytest.raises(EpssParseError):
        parse_epss_csv("cve,epss,percentile\n")
    with pytest.raises(EpssParseError):
        parse_epss_csv("not,a,csv")
    with pytest.raises(EpssParseError):
        parse_epss_payload(b"\x1f\x8b truncated")


def test_score_range_validation():
    with pytest.raises(EpssParseError):
        parse_epss_csv("#model_version:v1,score_date:2026-08-18\ncve,epss,percentile\nCVE-2024-1,1.5,0.2\n")
    with pytest.raises(EpssParseError):
        parse_epss_csv("#model_version:v1,score_date:2026-08-18\ncve,epss,percentile\nCVE-2024-1,0.2,1.2\n")
