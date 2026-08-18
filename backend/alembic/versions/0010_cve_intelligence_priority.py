"""Phase 2B CVE intelligence and operational priority.

Revision ID: 0010_cve_intelligence_priority
Revises: 0009_phase2a_detector_identity_partition
Create Date: 2026-08-18 20:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0009.

Adds normalized Vulnerability intelligence (NVD/CVSS/CWE/EPSS/KEV),
source sync state, and AssetFinding operational priority projection.

No external HTTP. No fabricated CVSS/EPSS/KEV/CWE values.
Existing catalog identity, mappings, findings, evidence, lifecycle,
and evaluations are unchanged. Existing AssetFindings start with
priority NULL.

Downgrade is refused: reverting would destroy intelligence and
priority explanation history.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_cve_intelligence_priority"
down_revision: str | None = "0009_phase2a_detector_identity_partition"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vulnerability_intelligence",
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("nvd_status", sa.String(length=80), nullable=True),
        sa.Column("nvd_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nvd_last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_version", sa.String(length=16), nullable=True),
        sa.Column("cvss_base_score", sa.Numeric(4, 1), nullable=True),
        sa.Column("cvss_base_severity", sa.String(length=20), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("cvss_source", sa.String(length=120), nullable=True),
        sa.Column("epss_score", sa.Numeric(12, 11), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(12, 11), nullable=True),
        sa.Column("epss_score_date", sa.Date(), nullable=True),
        sa.Column("epss_model_version", sa.String(length=40), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=True),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("kev_required_action", sa.Text(), nullable=True),
        sa.Column("kev_known_ransomware_campaign_use", sa.Boolean(), nullable=True),
        sa.Column("kev_vendor_project", sa.String(length=255), nullable=True),
        sa.Column("kev_product", sa.String(length=255), nullable=True),
        sa.Column("nvd_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("epss_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_vulnerability_intelligence_epss_score",
        ),
        sa.CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)",
            name="ck_vulnerability_intelligence_epss_percentile",
        ),
        sa.CheckConstraint(
            "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)",
            name="ck_vulnerability_intelligence_cvss_base_score",
        ),
    )

    op.create_table(
        "vulnerability_cwes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cwe_id", sa.String(length=40), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "cwe_id", "source", name="uq_vulnerability_cwes_vuln_cwe_source"),
    )
    op.create_index("ix_vulnerability_cwes_vulnerability_id", "vulnerability_cwes", ["vulnerability_id"])
    op.create_index("ix_vulnerability_cwes_cwe_id", "vulnerability_cwes", ["cwe_id"])

    op.create_table(
        "vulnerability_references",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "url", "source", name="uq_vulnerability_references_vuln_url_source"),
    )
    op.create_index("ix_vulnerability_references_vulnerability_id", "vulnerability_references", ["vulnerability_id"])

    op.create_table(
        "vulnerability_intelligence_sync",
        sa.Column("source", sa.String(length=40), primary_key=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_seen", sa.Integer(), nullable=True),
        sa.Column("records_updated", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("source IN ('nvd', 'epss', 'cisa_kev')", name="ck_vulnerability_intelligence_sync_source"),
    )

    op.add_column("asset_findings", sa.Column("priority", sa.String(length=8), nullable=True))
    op.add_column("asset_findings", sa.Column("priority_score", sa.Integer(), nullable=True))
    op.add_column("asset_findings", sa.Column("priority_model_version", sa.String(length=32), nullable=True))
    op.add_column("asset_findings", sa.Column("priority_explanation", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("asset_findings", sa.Column("priority_calculated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_asset_findings_priority",
        "asset_findings",
        "priority IS NULL OR priority IN ('p1', 'p2', 'p3', 'p4')",
    )
    op.create_index(
        "ix_asset_findings_tenant_id_technical_state_priority",
        "asset_findings",
        ["tenant_id", "technical_state", "priority"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0010_cve_intelligence_priority: "
        "it would destroy normalized CVE intelligence and AssetFinding "
        "operational priority explanations. Restore from backup instead."
    )
