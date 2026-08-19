"""Candidate Tranche B raw scan evidence metadata.

Revision ID: 0015_raw_scan_evidence
Revises: 0014_reports_auditor_access
Create Date: 2026-08-19 00:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0014.

Adds scan_artifacts metadata only. Artifact bytes live on the central
filesystem, not in PostgreSQL. Existing ScanJobs receive ZERO fabricated
artifact rows.

An empty scan_artifacts table may downgrade to 0014. A populated table
must refuse rather than destroy evidence metadata. This revision never
touches filesystem artifact bytes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_raw_scan_evidence"
down_revision: str | None = "0014_reports_auditor_access"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_job_id",
            sa.Integer(),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.Integer(),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("artifact_key", sa.String(128), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("media_type", sa.String(128), nullable=False),
        sa.Column("content_encoding", sa.String(32), nullable=False),
        sa.Column("storage_key", sa.String(512), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delete_reason", sa.String(64), nullable=True),
        sa.Column("provenance", postgresql.JSONB(), nullable=True),
        sa.UniqueConstraint("scan_job_id", "artifact_key", name="uq_scan_artifacts_job_id_artifact_key"),
        sa.UniqueConstraint("storage_key", name="uq_scan_artifacts_storage_key"),
    )
    op.create_index("ix_scan_artifacts_scan_job_id", "scan_artifacts", ["scan_job_id"])
    op.create_index("ix_scan_artifacts_tenant_id", "scan_artifacts", ["tenant_id"])
    op.create_index(
        "ix_scan_artifacts_scan_job_id_created_at",
        "scan_artifacts",
        ["scan_job_id", "created_at"],
    )
    op.create_index(
        "ix_scan_artifacts_tenant_id_created_at",
        "scan_artifacts",
        ["tenant_id", "created_at"],
    )
    op.create_index(
        "ix_scan_artifacts_retention_expires_at_active",
        "scan_artifacts",
        ["retention_expires_at"],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def _artifact_row_count(bind) -> int:
    return int(bind.execute(sa.text("SELECT COUNT(*) FROM scan_artifacts")).scalar_one())


def downgrade() -> None:
    bind = op.get_bind()
    count = _artifact_row_count(bind)
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0015_raw_scan_evidence: scan_artifacts contains "
            f"{count} row(s) of raw evidence metadata. Restore from backup instead "
            "of silently destroying raw scan evidence metadata. This downgrade "
            "does not delete filesystem artifact bytes."
        )
    op.drop_index("ix_scan_artifacts_retention_expires_at_active", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_tenant_id_created_at", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_scan_job_id_created_at", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_tenant_id", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_scan_job_id", table_name="scan_artifacts")
    op.drop_table("scan_artifacts")
