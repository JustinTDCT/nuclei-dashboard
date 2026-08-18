from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.intel.priority import calculate_asset_finding_priority
from app.models import PRIORITY_MODEL_VERSION, PRIORITY_P1, PRIORITY_P2, PRIORITY_P3, PRIORITY_P4


NOW = datetime(2026, 8, 18, tzinfo=timezone.utc)


def _calc(**kwargs):
    kwargs.setdefault("now", NOW)
    return calculate_asset_finding_priority(kwargs)


def test_cvss_98_contributes_40():
    result = _calc(cvss_base_score=9.8)
    factor = next(item for item in result["factors"] if item["factor"] == "cvss")
    assert factor["points"] == 40


def test_detector_critical_fallback_when_cvss_absent():
    result = _calc(detector_severity="critical")
    factor = next(item for item in result["factors"] if item["factor"] == "detector_severity")
    assert factor["points"] == 40
    assert not any(item["factor"] == "cvss" for item in result["factors"])


def test_cvss_prevents_double_counting_detector_severity():
    result = _calc(cvss_base_score=9.8, detector_severity="critical")
    assert any(item["factor"] == "cvss" for item in result["factors"])
    assert not any(item["factor"] == "detector_severity" for item in result["factors"])


def test_epss_percentile_thresholds():
    assert _calc(epss_percentile=0.98)["factors"][1]["points"] == 25
    assert _calc(epss_percentile=0.95)["factors"][1]["points"] == 20
    assert _calc(epss_percentile=0.90)["factors"][1]["points"] == 15
    assert _calc(epss_percentile=0.75)["factors"][1]["points"] == 10
    assert _calc(epss_percentile=0.50)["factors"][1]["points"] == 5
    assert _calc(epss_percentile=0.10)["factors"][1]["points"] == 0


def test_kev_produces_p1_override():
    result = _calc(detector_severity="low", kev=True)
    assert result["priority"] == PRIORITY_P1
    assert any("CISA KEV — known exploited vulnerability" in (item.get("reason") or "") for item in result["overrides"])


def test_asset_criticality_weighting():
    assert _calc(asset_criticality="critical")["factors"][3]["points"] == 20
    assert _calc(asset_criticality="high")["factors"][3]["points"] == 12
    assert _calc(asset_criticality="normal")["factors"][3]["points"] == 5
    assert _calc(asset_criticality="low")["factors"][3]["points"] == 0


def test_proven_wan_exposure_weighting():
    result = _calc(proven_wan_exposure=True)
    factor = next(item for item in result["factors"] if item["factor"] == "internet_exposure")
    assert factor["points"] == 15
    assert factor["value"] == "proven"


def test_ambiguous_exposure_gives_no_uplift():
    result = _calc(proven_wan_exposure=False)
    factor = next(item for item in result["factors"] if item["factor"] == "internet_exposure")
    assert factor["points"] == 0
    assert factor["value"] == "unknown"


def test_cui_tag_weighting():
    assert _calc(has_cui_tag=True)["factors"][5]["points"] == 10
    assert _calc(has_cui_tag=False)["factors"][5]["points"] == 0


def test_age_weighting():
    assert _calc(first_seen=NOW - timedelta(days=200))["factors"][6]["points"] == 10
    assert _calc(first_seen=NOW - timedelta(days=100))["factors"][6]["points"] == 7
    assert _calc(first_seen=NOW - timedelta(days=40))["factors"][6]["points"] == 4
    assert _calc(first_seen=NOW - timedelta(days=5))["factors"][6]["points"] == 0


def test_treatment_does_not_reduce_priority():
    untreated = _calc(cvss_base_score=9.8, treatment_state="unaddressed")
    treated = _calc(cvss_base_score=9.8, treatment_state="accepted_risk")
    assert untreated["score"] == treated["score"]
    assert next(item for item in treated["factors"] if item["factor"] == "treatment")["points"] == 0


def test_score_capped_at_100():
    result = _calc(
        cvss_base_score=9.8,
        epss_percentile=0.99,
        kev=True,
        asset_criticality="critical",
        proven_wan_exposure=True,
        has_cui_tag=True,
        first_seen=NOW - timedelta(days=200),
    )
    assert result["score"] == 100


def test_priority_boundaries():
    assert _calc(detector_severity="info", asset_criticality="low")["priority"] == PRIORITY_P4
    assert _calc(detector_severity="medium")["priority"] == PRIORITY_P3
    assert _calc(cvss_base_score=7.0, asset_criticality="critical", proven_wan_exposure=True)["priority"] == PRIORITY_P2
    assert _calc(cvss_base_score=9.8, epss_percentile=0.99, asset_criticality="critical")["priority"] == PRIORITY_P1


def test_critical_floor_at_least_p2():
    result = _calc(cvss_base_score=9.0, asset_criticality="low")
    assert result["priority"] == PRIORITY_P2
    assert any(item.get("type") == "severity_floor" for item in result["overrides"])


def test_high_floor_at_least_p3():
    result = _calc(detector_severity="high", asset_criticality="low")
    assert result["priority"] == PRIORITY_P3


def test_explanation_sums_to_score_and_identifies_overrides():
    result = _calc(cvss_base_score=9.8, kev=True, asset_criticality="low")
    assert result["explanation"]["factor_sum"] == result["score"] or result["score"] == 100
    assert result["model_version"] == PRIORITY_MODEL_VERSION
    assert result["explanation"]["priority"] == result["priority"]
    assert any("CISA KEV" in (item.get("reason") or "") for item in result["overrides"])


def test_non_cve_local_context_priority():
    result = _calc(
        detector_severity="high",
        asset_criticality="critical",
        proven_wan_exposure=True,
        has_cui_tag=True,
    )
    assert result["priority"] in {PRIORITY_P1, PRIORITY_P2}
    assert not any(item["factor"] == "cvss" for item in result["factors"])
    assert next(item for item in result["factors"] if item["factor"] == "detector_severity")["points"] == 30
