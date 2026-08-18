"""Frozen Phase 0 application schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-18 11:33:00.000000+00:00

This revision is an immutable snapshot of the Phase 0 tables. Do not import
live application models here. Later schema changes belong in new revisions.

Downgrade drops these tables and is destructive.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="users_email_key"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="tenants_name_key"),
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=80), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "subnets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("cidr", sa.String(length=80), nullable=False),
        sa.Column("scope", sa.String(length=10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="subnets_tenant_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_subnets_tenant_id", "subnets", ["tenant_id"], unique=False)

    op.create_table(
        "agents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("enrollment_secret", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("last_ip", sa.String(length=80), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], name="agents_approved_by_id_fkey"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="agents_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"], unique=False)
    op.create_index("ix_agents_uuid", "agents", ["uuid"], unique=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope", sa.String(length=10), nullable=False),
        sa.Column("profile", sa.String(length=30), nullable=False),
        sa.Column("nuclei_severities", sa.String(length=80), nullable=False),
        sa.Column("nuclei_tags", sa.String(length=255), nullable=False),
        sa.Column("subnet_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], name="scans_agent_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="scans_tenant_id_fkey", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_tenant_id", "scans", ["tenant_id"], unique=False)

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("claimed_by", sa.String(length=80), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="scan_jobs_scan_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="scan_jobs_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_jobs_scan_id", "scan_jobs", ["scan_id"], unique=False)
    op.create_index("ix_scan_jobs_tenant_id", "scan_jobs", ["tenant_id"], unique=False)

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=80), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("scope", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("classification", sa.String(length=80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("auto_label", sa.String(length=200), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("tech", sa.Text(), nullable=False),
        sa.Column("ports", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_scan_job_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["last_scan_job_id"],
            ["scan_jobs.id"],
            name="devices_last_scan_job_id_fkey",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="devices_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "hostname", "scope", name="uq_device_tenant_hostname_scope"),
    )
    op.create_index("ix_devices_ip", "devices", ["ip"], unique=False)
    op.create_index("ix_devices_tenant_id", "devices", ["tenant_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("scan_job_id", sa.Integer(), nullable=True),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("template_id", sa.String(length=200), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("host", sa.String(length=500), nullable=False),
        sa.Column("matched_at", sa.String(length=500), nullable=False),
        sa.Column("tags", sa.String(length=500), nullable=False),
        sa.Column("found_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name="findings_device_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"], name="findings_scan_job_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="findings_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_hostname", "findings", ["hostname"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("ix_findings_template_id", "findings", ["template_id"], unique=False)
    op.create_index("ix_findings_tenant_id", "findings", ["tenant_id"], unique=False)

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("is_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_id"], ["users.id"], name="alerts_acknowledged_by_id_fkey"
        ),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], name="alerts_agent_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name="alerts_device_id_fkey", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="alerts_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"], unique=False)
    op.create_index("ix_alerts_type", "alerts", ["type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alerts_type", table_name="alerts")
    op.drop_index("ix_alerts_tenant_id", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_findings_tenant_id", table_name="findings")
    op.drop_index("ix_findings_template_id", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_hostname", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_devices_tenant_id", table_name="devices")
    op.drop_index("ix_devices_ip", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_scan_jobs_tenant_id", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_scan_id", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_scans_tenant_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_agents_uuid", table_name="agents")
    op.drop_index("ix_agents_tenant_id", table_name="agents")
    op.drop_table("agents")
    op.drop_index("ix_subnets_tenant_id", table_name="subnets")
    op.drop_table("subnets")
    op.drop_table("settings")
    op.drop_table("tenants")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
