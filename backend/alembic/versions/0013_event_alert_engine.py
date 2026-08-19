"""Phase 3B event and alert engine.

Revision ID: 0013_event_alert_engine
Revises: 0012_policy_engine
Create Date: 2026-08-19 00:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0012.

Evolves DomainEvent and Alert in place, extends PolicyRule category to
alerting, and adds routing/outbox, delivery, and routing-history tables.

Historical domain_events are NOT queued for notification. Legacy Alert
rows remain readable with domain_event_id NULL.

Downgrade is refused when Phase 3B history exists.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_event_alert_engine"
down_revision: str | None = "0012_policy_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "domain_events",
        "tenant_id",
        existing_type=sa.Integer(),
        nullable=True,
    )
    op.add_column(
        "domain_events",
        sa.Column("network_id", sa.Integer(), sa.ForeignKey("networks.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "domain_events",
        sa.Column(
            "asset_finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "domain_events",
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "domain_events",
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "domain_events",
        sa.Column(
            "treatment_id",
            sa.Integer(),
            sa.ForeignKey("finding_treatments.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "domain_events",
        sa.Column("policy_rule_id", sa.Integer(), sa.ForeignKey("policy_rules.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index(
        "ix_domain_events_site_id_event_type_occurred_at",
        "domain_events",
        ["site_id", "event_type", "occurred_at"],
    )
    op.create_index(
        "ix_domain_events_network_id_event_type_occurred_at",
        "domain_events",
        ["network_id", "event_type", "occurred_at"],
    )
    op.create_index(
        "ix_domain_events_asset_finding_id_occurred_at",
        "domain_events",
        ["asset_finding_id", "occurred_at"],
    )
    op.create_index("ix_domain_events_scan_job_id", "domain_events", ["scan_job_id"])
    op.create_index("ix_domain_events_agent_id", "domain_events", ["agent_id"])
    op.create_index("ix_domain_events_treatment_id", "domain_events", ["treatment_id"])

    op.drop_constraint("ck_policy_rules_category", "policy_rules", type_="check")
    op.create_check_constraint(
        "ck_policy_rules_category",
        "policy_rules",
        "category IN ('asset_handling', 'asset_inactivity', 'finding_lifecycle', 'alerting')",
    )

    op.add_column(
        "alerts",
        sa.Column("domain_event_id", sa.Integer(), sa.ForeignKey("domain_events.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "last_domain_event_id",
            sa.Integer(),
            sa.ForeignKey("domain_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column("alerts", sa.Column("severity", sa.String(length=20), nullable=True))
    op.add_column(
        "alerts",
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("network_id", sa.Integer(), sa.ForeignKey("networks.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "asset_finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "alerts",
        sa.Column("scan_job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column("alerts", sa.Column("policy_explanation", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column(
        "alerts",
        sa.Column("dashboard_visible", sa.Boolean(), server_default="true", nullable=False),
    )
    op.add_column("alerts", sa.Column("dedupe_key", sa.String(length=255), nullable=True))
    op.add_column(
        "alerts",
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column("alerts", sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("alerts", sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_alerts_tenant_id_dedupe_key_ack", "alerts", ["tenant_id", "dedupe_key", "is_acknowledged"])
    op.create_index(
        "ix_alerts_dashboard_open_severity",
        "alerts",
        ["dashboard_visible", "is_acknowledged", "severity"],
    )
    op.create_index("ix_alerts_tenant_id_severity_created_at", "alerts", ["tenant_id", "severity", "created_at"])
    op.create_index("ix_alerts_domain_event_id", "alerts", ["domain_event_id"])
    op.create_index("ix_alerts_asset_id", "alerts", ["asset_id"])
    op.create_index("ix_alerts_asset_finding_id", "alerts", ["asset_finding_id"])

    op.create_table(
        "event_alert_queue",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_event_id", sa.Integer(), sa.ForeignKey("domain_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("domain_event_id", name="uq_event_alert_queue_domain_event_id"),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'processed', 'failed')",
            name="ck_event_alert_queue_status",
        ),
    )
    op.create_index("ix_event_alert_queue_pending", "event_alert_queue", ["status", "next_attempt_at"])

    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("destination", sa.String(length=500), server_default="", nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column(
            "payload_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("alert_id", "channel", name="uq_alert_deliveries_alert_id_channel"),
        sa.CheckConstraint("channel IN ('email', 'webhook')", name="ck_alert_deliveries_channel"),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'sent', 'failed')",
            name="ck_alert_deliveries_status",
        ),
    )
    op.create_index("ix_alert_deliveries_pending", "alert_deliveries", ["status", "next_attempt_at"])
    op.create_index("ix_alert_deliveries_alert_id", "alert_deliveries", ["alert_id"])

    op.create_table(
        "alert_event_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain_event_id", sa.Integer(), sa.ForeignKey("domain_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("routing_result", sa.String(length=40), nullable=False),
        sa.Column(
            "effective_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "policy_explanation",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("domain_event_id", name="uq_alert_event_routes_domain_event_id"),
        sa.CheckConstraint(
            "routing_result IN ('alert_created', 'alert_coalesced', 'no_notification')",
            name="ck_alert_event_routes_result",
        ),
    )
    op.create_index("ix_alert_event_routes_alert_id", "alert_event_routes", ["alert_id"])


def _phase3b_history_count(bind) -> int:
    queue = bind.execute(sa.text("SELECT COUNT(*) FROM event_alert_queue")).scalar_one()
    deliveries = bind.execute(sa.text("SELECT COUNT(*) FROM alert_deliveries")).scalar_one()
    routes = bind.execute(sa.text("SELECT COUNT(*) FROM alert_event_routes")).scalar_one()
    evolved_alerts = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM alerts WHERE domain_event_id IS NOT NULL "
            "OR last_domain_event_id IS NOT NULL OR policy_explanation IS NOT NULL "
            "OR dedupe_key IS NOT NULL"
        )
    ).scalar_one()
    evolved_events = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM domain_events WHERE network_id IS NOT NULL "
            "OR asset_finding_id IS NOT NULL OR scan_job_id IS NOT NULL "
            "OR agent_id IS NOT NULL OR treatment_id IS NOT NULL OR policy_rule_id IS NOT NULL"
        )
    ).scalar_one()
    alerting_rules = bind.execute(
        sa.text("SELECT COUNT(*) FROM policy_rules WHERE category = 'alerting'")
    ).scalar_one()
    return int(queue + deliveries + routes + evolved_alerts + evolved_events + alerting_rules)


def downgrade() -> None:
    bind = op.get_bind()
    count = _phase3b_history_count(bind)
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0013_event_alert_engine: Phase 3B event/alert "
            f"history is populated ({count} row(s)). Restore from backup instead of "
            "silently destroying alert and event routing history."
        )
    op.drop_index("ix_alert_event_routes_alert_id", table_name="alert_event_routes")
    op.drop_table("alert_event_routes")
    op.drop_index("ix_alert_deliveries_alert_id", table_name="alert_deliveries")
    op.drop_index("ix_alert_deliveries_pending", table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
    op.drop_index("ix_event_alert_queue_pending", table_name="event_alert_queue")
    op.drop_table("event_alert_queue")
    op.drop_index("ix_alerts_asset_finding_id", table_name="alerts")
    op.drop_index("ix_alerts_asset_id", table_name="alerts")
    op.drop_index("ix_alerts_domain_event_id", table_name="alerts")
    op.drop_index("ix_alerts_tenant_id_severity_created_at", table_name="alerts")
    op.drop_index("ix_alerts_dashboard_open_severity", table_name="alerts")
    op.drop_index("ix_alerts_tenant_id_dedupe_key_ack", table_name="alerts")
    op.drop_column("alerts", "last_event_at")
    op.drop_column("alerts", "first_event_at")
    op.drop_column("alerts", "occurrence_count")
    op.drop_column("alerts", "dedupe_key")
    op.drop_column("alerts", "dashboard_visible")
    op.drop_column("alerts", "policy_explanation")
    op.drop_column("alerts", "scan_job_id")
    op.drop_column("alerts", "asset_finding_id")
    op.drop_column("alerts", "asset_id")
    op.drop_column("alerts", "network_id")
    op.drop_column("alerts", "site_id")
    op.drop_column("alerts", "severity")
    op.drop_column("alerts", "last_domain_event_id")
    op.drop_column("alerts", "domain_event_id")
    op.drop_constraint("ck_policy_rules_category", "policy_rules", type_="check")
    op.create_check_constraint(
        "ck_policy_rules_category",
        "policy_rules",
        "category IN ('asset_handling', 'asset_inactivity', 'finding_lifecycle')",
    )
    op.drop_index("ix_domain_events_treatment_id", table_name="domain_events")
    op.drop_index("ix_domain_events_agent_id", table_name="domain_events")
    op.drop_index("ix_domain_events_scan_job_id", table_name="domain_events")
    op.drop_index("ix_domain_events_asset_finding_id_occurred_at", table_name="domain_events")
    op.drop_index("ix_domain_events_network_id_event_type_occurred_at", table_name="domain_events")
    op.drop_index("ix_domain_events_site_id_event_type_occurred_at", table_name="domain_events")
    op.drop_column("domain_events", "policy_rule_id")
    op.drop_column("domain_events", "treatment_id")
    op.drop_column("domain_events", "agent_id")
    op.drop_column("domain_events", "scan_job_id")
    op.drop_column("domain_events", "asset_finding_id")
    op.drop_column("domain_events", "network_id")
    op.alter_column(
        "domain_events",
        "tenant_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
