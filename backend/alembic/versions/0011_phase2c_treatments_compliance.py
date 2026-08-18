"""Phase 2C treatments, compensating controls, and compliance.

Revision ID: 0011_phase2c_treatments_compliance
Revises: 0010_cve_intelligence_priority
Create Date: 2026-08-18 22:30:00.000000+00:00

Do not import live application models. Do not edit 0001–0010.

Adds evidence-bearing finding treatments, compensating controls,
generic Framework/Control catalog tables, and relational control
references. Existing Vulnerability identity, detector mappings,
Asset/AssetFinding IDs, Detection Evidence, lifecycle history,
run evaluations, intelligence, and priority values are unchanged.

Any pre-existing non-unaddressed AssetFinding.treatment_state is
preserved as a legacy_projection treatment record without inventing
a reviewer or original rationale.

Downgrade is refused: reverting would destroy treatment, compensating
control, and compliance-evidence history.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_phase2c_treatments_compliance"
down_revision: str | None = "0010_cve_intelligence_priority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LEGACY_RATIONALE = (
    "Imported from pre-Phase-2C treatment projection; original rationale "
    "and reviewer were not recorded."
)


def upgrade() -> None:
    op.create_table(
        "finding_treatments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "asset_finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("treatment_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_notes", sa.Text(), server_default="", nullable=False),
        sa.Column("source", sa.String(length=32), server_default="manual", nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "treatment_type IN ('mitigated', 'accepted_risk', 'false_positive')",
            name="ck_finding_treatments_treatment_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'active', 'expired', 'revoked', 'superseded')",
            name="ck_finding_treatments_status",
        ),
        sa.CheckConstraint(
            "source IN ('manual', 'legacy_projection')",
            name="ck_finding_treatments_source",
        ),
    )
    op.create_index("ix_finding_treatments_tenant_id", "finding_treatments", ["tenant_id"])
    op.create_index("ix_finding_treatments_asset_finding_id", "finding_treatments", ["asset_finding_id"])
    op.create_index("ix_finding_treatments_status", "finding_treatments", ["status"])
    op.create_index("ix_finding_treatments_expires_at", "finding_treatments", ["expires_at"])
    op.create_index("ix_finding_treatments_review_due_at", "finding_treatments", ["review_due_at"])
    op.create_index("ix_finding_treatments_status_expires_at", "finding_treatments", ["status", "expires_at"])
    op.create_index(
        "uq_finding_treatments_one_active",
        "finding_treatments",
        ["asset_finding_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "compensating_controls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "treatment_id",
            sa.Integer(),
            sa.ForeignKey("finding_treatments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("evidence_notes", sa.Text(), server_default="", nullable=False),
        sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("retirement_reason", sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('active', 'retired')", name="ck_compensating_controls_status"),
    )
    op.create_index("ix_compensating_controls_tenant_id", "compensating_controls", ["tenant_id"])
    op.create_index("ix_compensating_controls_treatment_id", "compensating_controls", ["treatment_id"])

    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("publisher", sa.String(length=255), server_default="", nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("source_url", sa.String(length=2000), server_default="", nullable=False),
        sa.Column("source_release_date", sa.Date(), nullable=True),
        sa.Column("source_metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("builtin", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("slug", "version", name="uq_compliance_frameworks_slug_version"),
    )
    op.create_index("ix_compliance_frameworks_slug", "compliance_frameworks", ["slug"])

    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "framework_id",
            sa.Integer(),
            sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_key", sa.String(length=80), nullable=False),
        sa.Column("family", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=500), server_default="", nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("source_metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("framework_id", "control_key", name="uq_compliance_controls_framework_id_control_key"),
    )
    op.create_index("ix_compliance_controls_framework_id", "compliance_controls", ["framework_id"])
    op.create_index("ix_compliance_controls_control_key", "compliance_controls", ["control_key"])
    op.create_index("ix_compliance_controls_family", "compliance_controls", ["family"])

    op.create_table(
        "compliance_control_references",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "control_id",
            sa.Integer(),
            sa.ForeignKey("compliance_controls.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column(
            "asset_finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
        sa.Column(
            "treatment_id",
            sa.Integer(),
            sa.ForeignKey("finding_treatments.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True),
        sa.Column("reference_type", sa.String(length=20), server_default="related", nullable=False),
        sa.Column("notes", sa.Text(), server_default="", nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("removal_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "("
            "(CASE WHEN asset_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN asset_finding_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN finding_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN treatment_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN scan_job_id IS NOT NULL THEN 1 ELSE 0 END)"
            ") = 1",
            name="ck_compliance_control_references_exactly_one_subject",
        ),
        sa.CheckConstraint(
            "reference_type IN ('related', 'evidence', 'supports')",
            name="ck_compliance_control_references_reference_type",
        ),
    )
    op.create_index("ix_compliance_control_references_tenant_id", "compliance_control_references", ["tenant_id"])
    op.create_index("ix_compliance_control_references_control_id", "compliance_control_references", ["control_id"])
    op.create_index("ix_compliance_control_references_asset_id", "compliance_control_references", ["asset_id"])
    op.create_index(
        "ix_compliance_control_references_asset_finding_id",
        "compliance_control_references",
        ["asset_finding_id"],
    )
    op.create_index("ix_compliance_control_references_finding_id", "compliance_control_references", ["finding_id"])
    op.create_index(
        "ix_compliance_control_references_treatment_id",
        "compliance_control_references",
        ["treatment_id"],
    )
    op.create_index(
        "ix_compliance_control_references_scan_job_id",
        "compliance_control_references",
        ["scan_job_id"],
    )
    for column in ("asset_id", "asset_finding_id", "finding_id", "treatment_id", "scan_job_id"):
        op.create_index(
            f"uq_compliance_control_references_active_{column}",
            "compliance_control_references",
            ["control_id", column],
            unique=True,
            postgresql_where=sa.text(f"{column} IS NOT NULL AND removed_at IS NULL"),
        )

    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO finding_treatments (
                tenant_id, asset_finding_id, treatment_type, status, rationale,
                evidence_notes, source, created_at, updated_at
            )
            SELECT
                tenant_id,
                id,
                treatment_state,
                'active',
                :rationale,
                '',
                'legacy_projection',
                NOW(),
                NOW()
            FROM asset_findings
            WHERE treatment_state IN ('mitigated', 'accepted_risk', 'false_positive')
            """
        ),
        {"rationale": LEGACY_RATIONALE},
    )


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0011_phase2c_treatments_compliance: "
        "reverting would destroy treatment, compensating-control, and "
        "compliance-evidence history. Restore from backup instead."
    )
