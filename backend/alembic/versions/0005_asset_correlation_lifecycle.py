"""Phase 1C asset correlation, lineage, events, and Device locality.

Revision ID: 0005_asset_correlation_lifecycle
Revises: 0004_asset_observation_integrity
Create Date: 2026-08-18 13:40:00.000000+00:00

Do not import live application models. Do not edit 0001–0004.

Adds correlation decision history, domain events, identifier validity,
Asset merge lineage, and Device.site_id for locality-safe compatibility.

Existing Asset identities are left unchanged. This revision must not
infer that two Assets are the same from IP or hostname.

Device.site_id is backfilled only from a trustworthy Asset.site_id
relationship. Site is never inferred from a private IP.

Downgrade is refused: reverting would destroy correlation history,
lineage, domain events, and identifier correction metadata.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0005_asset_correlation_lifecycle"
down_revision: str | None = "0004_asset_observation_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("merged_into_asset_id", sa.Integer(), nullable=True),
    )
    op.add_column("assets", sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        "assets_merged_into_asset_id_fkey",
        "assets",
        "assets",
        ["merged_into_asset_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_assets_merged_into_asset_id", "assets", ["merged_into_asset_id"], unique=False)

    op.add_column(
        "asset_identifiers",
        sa.Column("validity", sa.String(length=20), nullable=False, server_default="active"),
    )
    op.add_column("asset_identifiers", sa.Column("corrected_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("asset_identifiers", sa.Column("corrected_by_id", sa.Integer(), nullable=True))
    op.add_column(
        "asset_identifiers",
        sa.Column("correction_reason", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column("asset_identifiers", sa.Column("replacement_identifier_id", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_asset_identifiers_validity",
        "asset_identifiers",
        "validity IN ('active', 'incorrect')",
    )
    op.create_foreign_key(
        "asset_identifiers_corrected_by_id_fkey",
        "asset_identifiers",
        "users",
        ["corrected_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "asset_identifiers_replacement_identifier_id_fkey",
        "asset_identifiers",
        "asset_identifiers",
        ["replacement_identifier_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_asset_identifiers_active_lookup",
        "asset_identifiers",
        ["tenant_id", "identifier_type", "normalized_value"],
        unique=False,
        postgresql_where=sa.text("validity = 'active'"),
    )
    op.alter_column("asset_identifiers", "validity", server_default=None)
    op.alter_column("asset_identifiers", "correction_reason", server_default=None)

    op.add_column("devices", sa.Column("site_id", sa.Integer(), nullable=True))
    op.create_index("ix_devices_site_id", "devices", ["site_id"], unique=False)
    op.create_index(
        "ix_devices_tenant_id_site_id_scope",
        "devices",
        ["tenant_id", "site_id", "scope"],
        unique=False,
    )
    op.create_foreign_key(
        "devices_site_id_fkey",
        "devices",
        "sites",
        ["site_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        text(
            """
            UPDATE devices AS d
            SET site_id = a.site_id
            FROM assets AS a
            WHERE d.asset_id = a.id
              AND d.scope = 'lan'
              AND a.site_id IS NOT NULL
              AND d.site_id IS NULL
            """
        )
    )
    op.drop_constraint("uq_device_tenant_hostname_scope", "devices", type_="unique")
    op.create_unique_constraint(
        "uq_device_tenant_hostname_scope",
        "devices",
        ["tenant_id", "hostname", "scope", "site_id", "asset_id"],
    )

    op.create_table(
        "asset_correlation_decisions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("scan_job_id", sa.Integer(), nullable=True),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("source_device_id", sa.Integer(), nullable=True),
        sa.Column("selected_asset_id", sa.Integer(), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("algorithm_version", sa.String(length=32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("candidates", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "decision IN ('linked_existing', 'created_new', 'ambiguous')",
            name="ck_asset_correlation_decisions_decision",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_asset_correlation_decisions_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="asset_correlation_decisions_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["site_id"], ["sites.id"], name="asset_correlation_decisions_site_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name="asset_correlation_decisions_scan_job_id_fkey",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_device_id"],
            ["devices.id"],
            name="asset_correlation_decisions_source_device_id_fkey",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["selected_asset_id"],
            ["assets.id"],
            name="asset_correlation_decisions_selected_asset_id_fkey",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "observation_key", name="uq_asset_correlation_decisions_job_key"),
    )
    op.create_index(
        "ix_asset_correlation_decisions_tenant_id",
        "asset_correlation_decisions",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_correlation_decisions_site_id",
        "asset_correlation_decisions",
        ["site_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_correlation_decisions_scan_job_id",
        "asset_correlation_decisions",
        ["scan_job_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_correlation_decisions_tenant_id_created_at",
        "asset_correlation_decisions",
        ["tenant_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_asset_correlation_decisions_selected_asset_id",
        "asset_correlation_decisions",
        ["selected_asset_id"],
        unique=False,
    )

    op.create_table(
        "domain_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("idempotence_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="domain_events_tenant_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="domain_events_site_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], name="domain_events_asset_id_fkey", ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotence_key", name="uq_domain_events_idempotence_key"),
    )
    op.create_index("ix_domain_events_event_type", "domain_events", ["event_type"], unique=False)
    op.create_index("ix_domain_events_tenant_id", "domain_events", ["tenant_id"], unique=False)
    op.create_index("ix_domain_events_site_id", "domain_events", ["site_id"], unique=False)
    op.create_index(
        "ix_domain_events_tenant_id_event_type_occurred_at",
        "domain_events",
        ["tenant_id", "event_type", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_domain_events_asset_id_occurred_at",
        "domain_events",
        ["asset_id", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0005_asset_correlation_lifecycle: this would destroy "
        "correlation decisions, domain events, Asset merge lineage, identifier "
        "correction history, and Device locality. Restore from backup instead."
    )
