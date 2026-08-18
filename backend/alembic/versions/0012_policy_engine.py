"""Phase 3A deterministic policy engine.

Revision ID: 0012_policy_engine
Revises: 0011_phase2c_treatments_compliance
Create Date: 2026-08-18 23:30:00.000000+00:00

Do not import live application models. Do not edit 0001–0011.

Adds policy_rules only. Existing Tenant/Site/Network, Asset identity,
correlation, findings, treatments, compliance, priority, and global
fallback settings are unchanged. Global asset_inactive_days and
finding_resolution_clean_scans remain fallbacks and are not seeded
as PolicyRule rows.

Downgrade is refused when policy_rules contain rows so configured
policy history cannot be silently destroyed. An empty table may drop.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_policy_engine"
down_revision: str | None = "0011_phase2c_treatments_compliance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("scope_type", sa.String(length=20), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=True),
        sa.Column("network_id", sa.Integer(), sa.ForeignKey("networks.id", ondelete="CASCADE"), nullable=True),
        sa.Column("priority", sa.Integer(), server_default="100", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("conditions", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("actions", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("archive_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "category IN ('asset_handling', 'asset_inactivity', 'finding_lifecycle')",
            name="ck_policy_rules_category",
        ),
        sa.CheckConstraint(
            "scope_type IN ('global', 'tenant', 'site', 'network')",
            name="ck_policy_rules_scope_type",
        ),
        sa.CheckConstraint(
            "("
            "(scope_type = 'global' AND tenant_id IS NULL AND site_id IS NULL AND network_id IS NULL) OR "
            "(scope_type = 'tenant' AND tenant_id IS NOT NULL AND site_id IS NULL AND network_id IS NULL) OR "
            "(scope_type = 'site' AND tenant_id IS NOT NULL AND site_id IS NOT NULL AND network_id IS NULL) OR "
            "(scope_type = 'network' AND tenant_id IS NOT NULL AND site_id IS NOT NULL AND network_id IS NOT NULL)"
            ")",
            name="ck_policy_rules_scope_shape",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_policy_rules_revision"),
    )
    op.create_index(
        "ix_policy_rules_category_enabled_archived",
        "policy_rules",
        ["category", "enabled", "archived_at"],
    )
    op.create_index(
        "ix_policy_rules_scope_lookup",
        "policy_rules",
        ["scope_type", "tenant_id", "site_id", "network_id"],
    )
    op.create_index(
        "ix_policy_rules_category_scope_tenant",
        "policy_rules",
        ["category", "scope_type", "tenant_id"],
    )
    op.create_index(
        "ix_policy_rules_enabled_archived_category_priority",
        "policy_rules",
        ["enabled", "archived_at", "category", "priority"],
    )
    op.create_index("ix_policy_rules_tenant_id", "policy_rules", ["tenant_id"])
    op.create_index("ix_policy_rules_site_id", "policy_rules", ["site_id"])
    op.create_index("ix_policy_rules_network_id", "policy_rules", ["network_id"])


def downgrade() -> None:
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT COUNT(*) FROM policy_rules")).scalar_one()
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0012_policy_engine: policy_rules contains "
            f"{count} configured policy row(s). Restore from backup instead of "
            "silently destroying policy history."
        )
    op.drop_index("ix_policy_rules_network_id", table_name="policy_rules")
    op.drop_index("ix_policy_rules_site_id", table_name="policy_rules")
    op.drop_index("ix_policy_rules_tenant_id", table_name="policy_rules")
    op.drop_index("ix_policy_rules_enabled_archived_category_priority", table_name="policy_rules")
    op.drop_index("ix_policy_rules_category_scope_tenant", table_name="policy_rules")
    op.drop_index("ix_policy_rules_scope_lookup", table_name="policy_rules")
    op.drop_index("ix_policy_rules_category_enabled_archived", table_name="policy_rules")
    op.drop_table("policy_rules")
