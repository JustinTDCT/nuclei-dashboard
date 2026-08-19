from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReportFilter:
    key: str
    label: str
    kind: str
    required: bool = False


@dataclass(frozen=True)
class ReportSpec:
    key: str
    title: str
    description: str
    formats: tuple[str, ...]
    filters: tuple[ReportFilter, ...] = field(default_factory=tuple)
    require_single_tenant: bool = False
    default_page_size: int = 50
    max_page_size: int = 200


COMMON_FILTERS = (
    ReportFilter("tenant_id", "Tenant", "tenant"),
    ReportFilter("site_id", "Site", "site"),
    ReportFilter("date_from", "From date", "datetime"),
    ReportFilter("date_to", "To date", "datetime"),
)

REPORTS: dict[str, ReportSpec] = {
    "executive": ReportSpec(
        key="executive",
        title="Executive Vulnerability Summary",
        description="Current security posture metrics for authorized tenants. Does not assign a risk score or claim compliance.",
        formats=("pdf", "csv"),
        filters=COMMON_FILTERS,
    ),
    "asset_inventory": ReportSpec(
        key="asset_inventory",
        title="Asset Inventory",
        description="One row per canonical Asset, including inactive historical Assets.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS
        + (
            ReportFilter("lifecycle_state", "Lifecycle", "enum"),
            ReportFilter("disposition", "Disposition", "enum"),
            ReportFilter("criticality", "Criticality", "enum"),
            ReportFilter("include_merged", "Include merged assets", "boolean"),
        ),
    ),
    "asset_changes": ReportSpec(
        key="asset_changes",
        title="New / Changed Assets",
        description="Historical new-asset and change facts from Domain Events and audited Asset actions. Service open/close history is not currently recorded.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS,
    ),
    "open_findings": ReportSpec(
        key="open_findings",
        title="Open Vulnerabilities",
        description="AssetFindings whose technical state is OPEN. Treatment does not change technical state.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS
        + (
            ReportFilter("severity", "Severity", "enum"),
            ReportFilter("priority", "Priority", "enum"),
            ReportFilter("kev", "KEV", "boolean"),
        ),
    ),
    "resolved_findings": ReportSpec(
        key="resolved_findings",
        title="Resolved Vulnerabilities",
        description="AssetFindings whose technical state is RESOLVED, with actual resolution history.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS,
    ),
    "treatments": ReportSpec(
        key="treatments",
        title="Mitigated / Accepted Risk",
        description="Normalized FindingTreatment records. Expired treatments remain visible and are not treated as valid.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS
        + (
            ReportFilter("treatment_type", "Treatment type", "enum"),
            ReportFilter("treatment_status", "Treatment status", "enum"),
            ReportFilter("include_false_positives", "Include false positives", "boolean"),
        ),
    ),
    "cve_aging": ReportSpec(
        key="cve_aging",
        title="CVE Aging",
        description="OPEN CVE findings aged from AssetFinding first_seen, not NVD publication date.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS + (ReportFilter("priority", "Priority", "enum"), ReportFilter("kev", "KEV", "boolean")),
    ),
    "scan_history": ReportSpec(
        key="scan_history",
        title="Scan History",
        description="Immutable Scan Job / run metadata. Missing provenance is reported as Not Recorded.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS,
    ),
    "agent_health": ReportSpec(
        key="agent_health",
        title="Agent Health",
        description="Canonical Agent health. Enrollment secrets are never included.",
        formats=("csv", "pdf"),
        filters=COMMON_FILTERS[:2],
    ),
    "control_evidence": ReportSpec(
        key="control_evidence",
        title="CMMC / Control Evidence",
        description="Generic Framework/Control evidence mappings for exactly one Tenant. Mapping is not a compliance or certification claim.",
        formats=("pdf", "csv"),
        filters=(
            ReportFilter("tenant_id", "Tenant", "tenant", required=True),
            ReportFilter("framework_id", "Framework", "framework", required=True),
            ReportFilter("include_removed", "Include removed evidence", "boolean"),
        ),
        require_single_tenant=True,
    ),
}


def catalog() -> list[ReportSpec]:
    return list(REPORTS.values())


def get_spec(report_key: str) -> ReportSpec:
    spec = REPORTS.get(report_key)
    if spec is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Report not found")
    return spec
