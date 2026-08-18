from __future__ import annotations

import pytest

from app.intel.kev import KevParseError, parse_kev_catalog


def _catalog(rows, count=None, **extra):
    payload = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.08.18",
        "dateReleased": "2026-08-18T12:00:00.000Z",
        "count": len(rows) if count is None else count,
        "vulnerabilities": rows,
    }
    payload.update(extra)
    return payload


def _entry(cve="CVE-2024-1234", ransomware="Known"):
    return {
        "cveID": cve,
        "vendorProject": "Example",
        "product": "Widget",
        "dateAdded": "2024-06-01",
        "dueDate": "2024-06-22",
        "requiredAction": "Apply updates",
        "knownRansomwareCampaignUse": ransomware,
    }


def test_matching_cve_becomes_kev_with_metadata():
    catalog = parse_kev_catalog(_catalog([_entry()]))
    assert catalog.complete is True
    record = catalog.records["CVE-2024-1234"]
    assert record.date_added.isoformat() == "2024-06-01"
    assert record.required_action == "Apply updates"
    assert record.known_ransomware_campaign_use is True
    assert record.vendor_project == "Example"
    assert record.product == "Widget"


def test_ransomware_unknown_parsed():
    catalog = parse_kev_catalog(_catalog([_entry(ransomware="Unknown")]))
    assert catalog.records["CVE-2024-1234"].known_ransomware_campaign_use is False


def test_malformed_record_does_not_poison_catalog():
    catalog = parse_kev_catalog(_catalog([{"vendorProject": "bad"}, _entry()], count=2))
    assert catalog.complete is False
    assert "CVE-2024-1234" in catalog.records
    assert catalog.skipped_malformed == 1


def test_empty_or_invalid_catalog_rejected():
    with pytest.raises(KevParseError):
        parse_kev_catalog(b"not-json")
    with pytest.raises(KevParseError):
        parse_kev_catalog({"title": "x"})
    with pytest.raises(KevParseError):
        parse_kev_catalog(_catalog([]))
