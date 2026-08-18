"""Phase 1A Site / Network / agent authorization.

Revision ID: 0002_sites_networks
Revises: 0001_baseline
Create Date: 2026-08-18 12:00:00.000000+00:00

Do not import live application models. This revision is immutable once shipped.

Existing LAN subnets and agents are assigned to a deterministic compatibility
Site named "Imported Site". WAN subnets stay on the subnets table and are not
converted into Networks. scans.subnet_ids keep their original numeric IDs.

Downgrade is refused: reverting this revision would destroy Site, Network,
authorization, and audit rows.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0002_sites_networks"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COMPATIBILITY_SITE_NAME = "Imported Site"


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("timezone", sa.String(length=80), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="sites_tenant_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_sites_tenant_id_name"),
    )
    op.create_index("ix_sites_tenant_id", "sites", ["tenant_id"], unique=False)

    op.add_column("agents", sa.Column("site_id", sa.Integer(), nullable=True))
    op.create_index("ix_agents_site_id", "agents", ["site_id"], unique=False)
    op.create_foreign_key("agents_site_id_fkey", "agents", "sites", ["site_id"], ["id"], ondelete="CASCADE")

    op.create_table(
        "networks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("cidr", sa.String(length=80), nullable=False),
        sa.Column("dispatch_mode", sa.String(length=32), nullable=False),
        sa.Column("preferred_agent_id", sa.Integer(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "dispatch_mode IN ('any_available', 'preferred_failover')",
            name="ck_networks_dispatch_mode",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="networks_tenant_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="networks_site_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["preferred_agent_id"],
            ["agents.id"],
            name="networks_preferred_agent_id_fkey",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site_id", "name", name="uq_networks_site_id_name"),
    )
    op.create_index("ix_networks_tenant_id", "networks", ["tenant_id"], unique=False)
    op.create_index("ix_networks_site_id", "networks", ["site_id"], unique=False)

    op.create_table(
        "network_agents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"], name="network_agents_network_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name="network_agents_agent_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("network_id", "agent_id", name="uq_network_agents_network_id_agent_id"),
    )
    op.create_index("ix_network_agents_network_id", "network_agents", ["network_id"], unique=False)
    op.create_index("ix_network_agents_agent_id", "network_agents", ["agent_id"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=80), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("object_type", sa.String(length=40), nullable=False),
        sa.Column("object_id", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], name="audit_logs_actor_user_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="audit_logs_tenant_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="audit_logs_site_id_fkey", ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_object_type", "audit_logs", ["object_type"], unique=False)
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"], unique=False)
    op.create_index("ix_audit_logs_site_id", "audit_logs", ["site_id"], unique=False)
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False)

    op.add_column("subnets", sa.Column("site_id", sa.Integer(), nullable=True))
    op.add_column("subnets", sa.Column("network_id", sa.Integer(), nullable=True))
    op.create_index("ix_subnets_site_id", "subnets", ["site_id"], unique=False)
    op.create_index("ix_subnets_network_id", "subnets", ["network_id"], unique=False)
    op.create_foreign_key("subnets_site_id_fkey", "subnets", "sites", ["site_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key(
        "subnets_network_id_fkey", "subnets", "networks", ["network_id"], ["id"], ondelete="SET NULL"
    )

    _migrate_existing_rows()

    op.alter_column("agents", "site_id", existing_type=sa.Integer(), nullable=False)


def _migrate_existing_rows() -> None:
    conn = op.get_bind()
    tenants = conn.execute(
        text(
            """
            SELECT id FROM tenants
            WHERE EXISTS (SELECT 1 FROM subnets WHERE tenant_id = tenants.id AND scope = 'lan')
               OR EXISTS (SELECT 1 FROM agents WHERE tenant_id = tenants.id)
            ORDER BY id
            """
        )
    ).fetchall()

    for (tenant_id,) in tenants:
        site_id = conn.execute(
            text(
                """
                INSERT INTO sites (tenant_id, name, timezone, archived_at, created_at)
                VALUES (:tenant_id, :name, NULL, NULL, now())
                RETURNING id
                """
            ),
            {"tenant_id": tenant_id, "name": COMPATIBILITY_SITE_NAME},
        ).scalar_one()

        lan_subnets = conn.execute(
            text(
                """
                SELECT id, name, cidr, created_at
                FROM subnets
                WHERE tenant_id = :tenant_id AND scope = 'lan'
                ORDER BY id
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()

        used_names: set[str] = set()
        for subnet_id, name, cidr, created_at in lan_subnets:
            network_name = (name or "").strip() or f"LAN {subnet_id}"
            candidate = network_name
            suffix = 2
            while candidate in used_names:
                candidate = f"{network_name} ({suffix})"
                suffix += 1
            used_names.add(candidate)
            network_id = conn.execute(
                text(
                    """
                    INSERT INTO networks (
                        tenant_id, site_id, name, cidr, dispatch_mode,
                        preferred_agent_id, archived_at, created_at
                    )
                    VALUES (
                        :tenant_id, :site_id, :name, :cidr, 'any_available',
                        NULL, NULL, :created_at
                    )
                    RETURNING id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "site_id": site_id,
                    "name": candidate,
                    "cidr": cidr,
                    "created_at": created_at,
                },
            ).scalar_one()
            conn.execute(
                text("UPDATE subnets SET site_id = :site_id, network_id = :network_id WHERE id = :id"),
                {"site_id": site_id, "network_id": network_id, "id": subnet_id},
            )

        conn.execute(
            text("UPDATE agents SET site_id = :site_id WHERE tenant_id = :tenant_id"),
            {"site_id": site_id, "tenant_id": tenant_id},
        )
        conn.execute(
            text(
                """
                INSERT INTO network_agents (network_id, agent_id, created_at)
                SELECT n.id, a.id, now()
                FROM networks n
                JOIN agents a ON a.site_id = n.site_id AND a.tenant_id = n.tenant_id
                WHERE n.site_id = :site_id
                """
            ),
            {"site_id": site_id},
        )


def downgrade() -> None:
    raise NotImplementedError(
        "Refusing to downgrade 0002_sites_networks: this would destroy Site, "
        "Network, Network-Agent authorization, and audit data. Restore from a "
        "database backup instead."
    )
