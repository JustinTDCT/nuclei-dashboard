"""S2C: Finding/coverage batch resolver. Lifecycle meaning stays frozen."""

from __future__ import annotations

from tests.conftest import requires_postgres
from tests.scale_s2.constants import CURRENT_INGEST_PATH, WORKLOADS
from tests.scale_s2.harness import (
    counts_from_state,
    hotspot_flags,
    ingest_current_path,
    prepare_and_ingest,
)
from tests.scale_s2.snapshot import assert_equivalent, capture_normalized_state
from tests.scale_s2.world import reset_schema


def test_s2c_path_label():
    assert CURRENT_INGEST_PATH == "s2c_finding_coverage_index"


def test_s2c_has_no_schema_revision():
    from pathlib import Path

    versions = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    names = [path.name for path in versions.glob("*.py")]
    assert "0017_security_h6_h8.py" in names
    assert not any(name.startswith("0018_") for name in names)


@requires_postgres
def test_s2c_small_path_collapses_finding_coverage_selects_and_stays_replay_safe(reset_db):
    from app.database import SessionLocal

    reset_schema()
    db = SessionLocal()
    try:
        once = prepare_and_ingest(db, WORKLOADS["small"], replay=False)
        once_state = once["state"]
        ingest_current_path(db, once["world"], once["workload"], collect_metrics=False)
        replay_state = capture_normalized_state(db, once["world"].tenant_id)
        assert_equivalent(once_state, replay_state, label="s2c same-run replay")
        metrics = once["metrics"]
        hotspots = hotspot_flags(metrics)
        counts = counts_from_state(once_state)
        assert counts["assets"] == 100
        assert counts["devices"] == 100
        assert counts["findings"] == 100
        assert counts["asset_observations"] == 100
        assert counts["scan_run_detector_coverage"] == 200
        assert hotspots["finding_stage_observation_selects"] < 10
        assert hotspots["finding_stage_device_selects"] < 10
        assert hotspots["coverage_stage_coverage_selects"] < 10
        assert hotspots["finding_coverage_selects_collapsed"] is True
        assert hotspots["per_finding_population_reload"] is False
        assert hotspots["finding_stage_finding_selects"] < 70
        assert hotspots["historical_raw_evidence_scan"] is False
        assert hotspots["device_asset_selects_collapsed"] is True
        assert metrics.prefetch_identifier_rows >= 0
        assert metrics.prefetch_device_rows >= 0
    finally:
        db.close()

    reset_schema()
    db = SessionLocal()
    try:
        isolated = prepare_and_ingest(db, WORKLOADS["small"], replay=False)
        assert_equivalent(once_state, isolated["state"], label="s2c isolated ingest")
    finally:
        db.close()
