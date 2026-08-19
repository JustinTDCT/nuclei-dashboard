"""S2A constants. 312e0d0 is the frozen S1 performance/semantics baseline."""

from __future__ import annotations

from dataclasses import dataclass

S1_BASELINE_SHA = "312e0d0"
CURRENT_INGEST_PATH = "s1_checkpoint"
CORRELATION_ALGORITHM_MUST_REMAIN = "1c.3"

PORT_POOL = (22, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379)


@dataclass(frozen=True)
class WorkloadSpec:
    name: str
    devices: int
    ports_per_device: int
    findings: int
    historical_findings: int
    distinct_detectors: int


WORKLOADS = {
    "tiny": WorkloadSpec(
        name="tiny",
        devices=8,
        ports_per_device=2,
        findings=8,
        historical_findings=12,
        distinct_detectors=4,
    ),
    "small": WorkloadSpec(
        name="small",
        devices=100,
        ports_per_device=5,
        findings=100,
        historical_findings=50,
        distinct_detectors=20,
    ),
    "medium": WorkloadSpec(
        name="medium",
        devices=5_000,
        ports_per_device=9,
        findings=10_000,
        historical_findings=2_000,
        distinct_detectors=300,
    ),
    "large": WorkloadSpec(
        name="large",
        devices=10_000,
        ports_per_device=10,
        findings=25_000,
        historical_findings=10_000,
        distinct_detectors=300,
    ),
}

SNAPSHOT_COLLECTIONS = (
    "assets",
    "asset_identifiers",
    "asset_addresses",
    "asset_services",
    "asset_observations",
    "asset_correlation_decisions",
    "devices",
    "vulnerabilities",
    "vulnerability_detector_mappings",
    "findings",
    "asset_findings",
    "asset_finding_history",
    "asset_finding_run_evaluations",
    "scan_run_detector_coverage",
    "domain_events",
    "alerts",
    "event_alert_queue",
    "scan_jobs",
)
