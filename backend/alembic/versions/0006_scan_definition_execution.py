"""Phase 1D scan definition / immutable execution snapshot.

Revision ID: 0006_scan_definition_execution
Revises: 0005_asset_correlation_lifecycle
Create Date: 2026-08-18 15:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0005.

Evolves existing scans into editable Scan Definitions and scan_jobs into
immutable Scan Runs. Legacy Scan IDs and ScanJob IDs are preserved.

WAN Subnet rows become AuthorizedWanTarget records. Empty legacy WAN
subnet_ids (meaning all WAN) are materialized to the then-current WAN
targets. LAN subnet_ids become scan_network_targets. Site is taken only
from a trustworthy Agent/Site relationship.

Historical ScanJobs are not given fabricated snapshots.

Downgrade is refused: reverting would destroy authorization, snapshot,
exclusion, and schedule history.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0006_scan_definition_execution"
down_revision: str | None = "0005_asset_correlation_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("site_id", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("definition_revision", sa.Integer(), server_default="1", nullable=False))
    op.add_column("scans", sa.Column("stage_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("scans", sa.Column("intensity_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("scans", sa.Column("schedule_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("scans", sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("needs_review", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("scans", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_foreign_key(
        "scans_site_id_fkey",
        "scans",
        "sites",
        ["site_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scans_site_id", "scans", ["site_id"], unique=False)
    op.create_index("ix_scans_next_run_at", "scans", ["next_run_at"], unique=False)

    op.add_column("scan_jobs", sa.Column("execution_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("scan_jobs", sa.Column("snapshot_version", sa.String(length=32), nullable=True))
    op.add_column("scan_jobs", sa.Column("definition_revision", sa.Integer(), nullable=True))
    op.add_column("scan_jobs", sa.Column("trigger_type", sa.String(length=20), nullable=True))
    op.add_column("scan_jobs", sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_jobs", sa.Column("claimed_agent_id", sa.Integer(), nullable=True))
    op.add_column("scan_jobs", sa.Column("waiting_since", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_jobs", sa.Column("wait_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_jobs", sa.Column("runtime_provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_foreign_key(
        "scan_jobs_claimed_agent_id_fkey",
        "scan_jobs",
        "agents",
        ["claimed_agent_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scan_jobs_claimed_agent_id", "scan_jobs", ["claimed_agent_id"], unique=False)
    op.create_index("ix_scan_jobs_status_created_at", "scan_jobs", ["status", "created_at"], unique=False)
    op.create_unique_constraint("uq_scan_jobs_scan_id_scheduled_for", "scan_jobs", ["scan_id", "scheduled_for"])

    op.create_table(
        "authorized_wan_targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("normalized_value", sa.String(length=255), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="authorized_wan_targets_tenant_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("target_type IN ('ip', 'cidr', 'fqdn')", name="ck_authorized_wan_targets_type"),
    )
    op.create_index("ix_authorized_wan_targets_tenant_id", "authorized_wan_targets", ["tenant_id"], unique=False)
    op.create_index(
        "ix_authorized_wan_targets_tenant_id_normalized",
        "authorized_wan_targets",
        ["tenant_id", "normalized_value"],
        unique=False,
    )

    op.create_table(
        "scan_network_targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="scan_network_targets_scan_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], name="scan_network_targets_network_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "network_id", name="uq_scan_network_targets_scan_id_network_id"),
    )
    op.create_index("ix_scan_network_targets_scan_id", "scan_network_targets", ["scan_id"], unique=False)
    op.create_index("ix_scan_network_targets_network_id", "scan_network_targets", ["network_id"], unique=False)

    op.create_table(
        "scan_wan_targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("authorized_wan_target_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="scan_wan_targets_scan_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["authorized_wan_target_id"],
            ["authorized_wan_targets.id"],
            name="scan_wan_targets_authorized_wan_target_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "authorized_wan_target_id", name="uq_scan_wan_targets_scan_id_target_id"),
    )
    op.create_index("ix_scan_wan_targets_scan_id", "scan_wan_targets", ["scan_id"], unique=False)
    op.create_index(
        "ix_scan_wan_targets_authorized_wan_target_id",
        "scan_wan_targets",
        ["authorized_wan_target_id"],
        unique=False,
    )

    op.create_table(
        "scan_exclusions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False),
        sa.Column("exclusion_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("normalized_value", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("site_id", sa.Integer(), nullable=True),
        sa.Column("network_id", sa.Integer(), nullable=True),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="scan_exclusions_tenant_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="scan_exclusions_site_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], name="scan_exclusions_network_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="scan_exclusions_scan_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("scope IN ('global', 'tenant', 'site', 'network', 'scan')", name="ck_scan_exclusions_scope"),
        sa.CheckConstraint("exclusion_type IN ('ip', 'cidr', 'range')", name="ck_scan_exclusions_type"),
        sa.CheckConstraint(
            "("
            "scope = 'global' AND tenant_id IS NULL AND site_id IS NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'tenant' AND tenant_id IS NOT NULL AND site_id IS NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'site' AND tenant_id IS NOT NULL AND site_id IS NOT NULL "
            "AND network_id IS NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'network' AND tenant_id IS NOT NULL AND site_id IS NOT NULL "
            "AND network_id IS NOT NULL AND scan_id IS NULL"
            ") OR ("
            "scope = 'scan' AND tenant_id IS NOT NULL AND scan_id IS NOT NULL"
            ")",
            name="ck_scan_exclusions_scope_keys",
        ),
    )
    op.create_index("ix_scan_exclusions_tenant_id", "scan_exclusions", ["tenant_id"], unique=False)
    op.create_index("ix_scan_exclusions_site_id", "scan_exclusions", ["site_id"], unique=False)
    op.create_index("ix_scan_exclusions_network_id", "scan_exclusions", ["network_id"], unique=False)
    op.create_index("ix_scan_exclusions_scan_id", "scan_exclusions", ["scan_id"], unique=False)
    op.create_index("ix_scan_exclusions_tenant_id_scope", "scan_exclusions", ["tenant_id", "scope"], unique=False)

    bind = op.get_bind()
    bind.execute(
        text(
            """
            INSERT INTO authorized_wan_targets (tenant_id, name, target_type, value, normalized_value)
            SELECT s.tenant_id, s.name, 'cidr', s.cidr, host(network(s.cidr::cidr)) || '/' || masklen(s.cidr::cidr)
            FROM subnets s
            WHERE s.scope = 'wan'
            """
        )
    )
    bind.execute(
        text(
            """
            UPDATE scans
            SET
                definition_revision = 1,
                stage_config = CASE
                    WHEN profile = 'discovery_nuclei' THEN
                        jsonb_build_object(
                            'discovery', true,
                            'port_mode', 'common',
                            'custom_ports', '[]'::jsonb,
                            'fingerprint', true,
                            'vulnerability', true,
                            'nuclei_severities', COALESCE(nuclei_severities, 'critical,high,medium'),
                            'nuclei_tags', COALESCE(nuclei_tags, '')
                        )
                    ELSE
                        jsonb_build_object(
                            'discovery', true,
                            'port_mode', 'common',
                            'custom_ports', '[]'::jsonb,
                            'fingerprint', true,
                            'vulnerability', false,
                            'nuclei_severities', COALESCE(nuclei_severities, 'critical,high,medium'),
                            'nuclei_tags', COALESCE(nuclei_tags, '')
                        )
                END,
                intensity_config = jsonb_build_object('preset', 'normal'),
                schedule_config = CASE
                    WHEN interval_minutes IS NOT NULL AND interval_minutes > 0 THEN
                        jsonb_build_object('type', 'legacy_interval', 'interval_minutes', interval_minutes)
                    ELSE jsonb_build_object('type', 'manual')
                END,
                updated_at = NOW()
            """
        )
    )
    bind.execute(
        text(
            """
            UPDATE scans sc
            SET site_id = a.site_id
            FROM agents a
            WHERE sc.scope = 'lan'
              AND sc.agent_id = a.id
              AND sc.tenant_id = a.tenant_id
              AND a.site_id IS NOT NULL
            """
        )
    )
    bind.execute(
        text(
            """
            INSERT INTO scan_network_targets (scan_id, network_id)
            SELECT sc.id, sn.network_id
            FROM scans sc
            CROSS JOIN LATERAL jsonb_array_elements(COALESCE(sc.subnet_ids, '[]'::jsonb)) AS elem(value)
            JOIN subnets sn ON sn.id = (elem.value)::int AND sn.tenant_id = sc.tenant_id AND sn.scope = 'lan'
            WHERE sc.scope = 'lan'
              AND sn.network_id IS NOT NULL
            ON CONFLICT (scan_id, network_id) DO NOTHING
            """
        )
    )
    bind.execute(
        text(
            """
            INSERT INTO scan_network_targets (scan_id, network_id)
            SELECT sc.id, n.id
            FROM scans sc
            JOIN agents a ON a.id = sc.agent_id AND a.tenant_id = sc.tenant_id
            JOIN networks n ON n.site_id = a.site_id AND n.tenant_id = sc.tenant_id AND n.archived_at IS NULL
            JOIN network_agents na ON na.network_id = n.id AND na.agent_id = a.id
            WHERE sc.scope = 'lan'
              AND (sc.subnet_ids IS NULL OR sc.subnet_ids = '[]'::jsonb)
              AND NOT EXISTS (
                  SELECT 1 FROM scan_network_targets snt WHERE snt.scan_id = sc.id
              )
            ON CONFLICT (scan_id, network_id) DO NOTHING
            """
        )
    )
    bind.execute(
        text(
            """
            INSERT INTO scan_wan_targets (scan_id, authorized_wan_target_id)
            SELECT sc.id, awt.id
            FROM scans sc
            CROSS JOIN LATERAL jsonb_array_elements(COALESCE(sc.subnet_ids, '[]'::jsonb)) AS elem(value)
            JOIN subnets sn ON sn.id = (elem.value)::int AND sn.tenant_id = sc.tenant_id AND sn.scope = 'wan'
            JOIN authorized_wan_targets awt
              ON awt.tenant_id = sn.tenant_id
             AND awt.normalized_value = host(network(sn.cidr::cidr)) || '/' || masklen(sn.cidr::cidr)
             AND awt.archived_at IS NULL
            WHERE sc.scope = 'wan'
              AND sc.subnet_ids IS NOT NULL
              AND sc.subnet_ids <> '[]'::jsonb
            ON CONFLICT (scan_id, authorized_wan_target_id) DO NOTHING
            """
        )
    )
    bind.execute(
        text(
            """
            INSERT INTO scan_wan_targets (scan_id, authorized_wan_target_id)
            SELECT sc.id, awt.id
            FROM scans sc
            JOIN authorized_wan_targets awt
              ON awt.tenant_id = sc.tenant_id AND awt.archived_at IS NULL
            WHERE sc.scope = 'wan'
              AND (sc.subnet_ids IS NULL OR sc.subnet_ids = '[]'::jsonb)
            ON CONFLICT (scan_id, authorized_wan_target_id) DO NOTHING
            """
        )
    )
    bind.execute(
        text(
            """
            UPDATE scans sc
            SET is_enabled = false, needs_review = true
            WHERE sc.scope = 'lan'
              AND (
                  sc.site_id IS NULL
                  OR NOT EXISTS (
                      SELECT 1 FROM scan_network_targets snt WHERE snt.scan_id = sc.id
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM scan_network_targets snt
                      JOIN networks n ON n.id = snt.network_id
                      WHERE snt.scan_id = sc.id
                        AND (n.tenant_id <> sc.tenant_id OR n.site_id <> sc.site_id)
                  )
              )
            """
        )
    )
    bind.execute(
        text(
            """
            UPDATE scan_jobs
            SET snapshot_version = 'legacy_pre_1d'
            WHERE execution_snapshot IS NULL
            """
        )
    )


def downgrade() -> None:
    raise RuntimeError(
        "Refusing to downgrade 0006_scan_definition_execution: this would destroy "
        "authorized WAN targets, scan definition associations, exclusions, "
        "execution snapshots, and schedule history. Restore from backup instead."
    )
