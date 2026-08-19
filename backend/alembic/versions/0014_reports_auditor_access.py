"""Phase 3C reports and auditor access.

Revision ID: 0014_reports_auditor_access
Revises: 0013_event_alert_engine
Create Date: 2026-08-19 00:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0013.

Adds Viewer all-tenant / selected-tenant grants and optional expiration.
Existing Viewer accounts receive ZERO Tenant grants (fail-closed). They
may authenticate but see no Tenant-scoped data until an Admin grants
access. Admin and User behavior is unchanged.

Downgrade is refused when Viewer authorization has been configured.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_reports_auditor_access"
down_revision: str | None = "0013_event_alert_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "viewer_all_tenants",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("viewer_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_viewer_expires_at", "users", ["viewer_expires_at"])
    op.create_table(
        "viewer_tenant_grants",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "granted_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_viewer_tenant_grants_tenant_id", "viewer_tenant_grants", ["tenant_id"])
    op.create_index("ix_viewer_tenant_grants_user_id", "viewer_tenant_grants", ["user_id"])
    op.create_index(
        "ix_audit_logs_tenant_id_created_at_id",
        "audit_logs",
        ["tenant_id", "created_at", "id"],
    )
    op.create_index(
        "ix_domain_events_tenant_id_occurred_at_id",
        "domain_events",
        ["tenant_id", "occurred_at", "id"],
    )


def _configured_viewer_scope_count(bind) -> int:
    all_tenants = bind.execute(
        sa.text("SELECT COUNT(*) FROM users WHERE viewer_all_tenants IS TRUE")
    ).scalar_one()
    expires = bind.execute(
        sa.text("SELECT COUNT(*) FROM users WHERE viewer_expires_at IS NOT NULL")
    ).scalar_one()
    grants = bind.execute(sa.text("SELECT COUNT(*) FROM viewer_tenant_grants")).scalar_one()
    return int(all_tenants) + int(expires) + int(grants)


def downgrade() -> None:
    bind = op.get_bind()
    count = _configured_viewer_scope_count(bind)
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0014_reports_auditor_access: configured Viewer "
            f"authorization exists ({count} marker row(s)). Restore from backup "
            "instead of silently destroying Viewer Tenant grants or expiration."
        )
    op.drop_index("ix_domain_events_tenant_id_occurred_at_id", table_name="domain_events")
    op.drop_index("ix_audit_logs_tenant_id_created_at_id", table_name="audit_logs")
    op.drop_index("ix_viewer_tenant_grants_user_id", table_name="viewer_tenant_grants")
    op.drop_index("ix_viewer_tenant_grants_tenant_id", table_name="viewer_tenant_grants")
    op.drop_table("viewer_tenant_grants")
    op.drop_index("ix_users_viewer_expires_at", table_name="users")
    op.drop_column("users", "viewer_expires_at")
    op.drop_column("users", "viewer_all_tenants")
