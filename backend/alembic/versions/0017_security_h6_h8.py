"""Security H6–H8 durable challenges, lockouts, and scanner deadlines.

Revision ID: 0017_security_h6_h8
Revises: 0016_scanner_runtime_inventory
Create Date: 2026-08-20 00:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0016.

Adds:
- agent_challenges (multi-record, single-use, expiring Agent nonces)
- auth_throttles (login/challenge rate-limit and lockout state)
- scan_jobs.deadline_at and scan_jobs.cancel_requested_at

Downgrade refuses when challenge, throttle, or cancel/deadline history exists.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_security_h6_h8"
down_revision: str | None = "0016_scanner_runtime_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source_ip", sa.String(length=80), nullable=True),
        sa.UniqueConstraint("nonce", name="uq_agent_challenges_nonce"),
    )
    op.create_index("ix_agent_challenges_agent_id", "agent_challenges", ["agent_id"])
    op.create_index("ix_agent_challenges_agent_id_expires_at", "agent_challenges", ["agent_id", "expires_at"])
    op.create_index("ix_agent_challenges_expires_at", "agent_challenges", ["expires_at"])

    op.create_table(
        "auth_throttles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scope", sa.String(length=40), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("scope", "subject", name="uq_auth_throttles_scope_subject"),
    )

    op.add_column("scan_jobs", sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_jobs", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_scan_jobs_deadline_at", "scan_jobs", ["deadline_at"])
    op.create_index("ix_scan_jobs_cancel_requested_at", "scan_jobs", ["cancel_requested_at"])


def _history_count(bind) -> int:
    challenges = bind.execute(sa.text("SELECT COUNT(*) FROM agent_challenges")).scalar_one()
    throttles = bind.execute(sa.text("SELECT COUNT(*) FROM auth_throttles")).scalar_one()
    jobs = bind.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM scan_jobs
            WHERE deadline_at IS NOT NULL OR cancel_requested_at IS NOT NULL
            """
        )
    ).scalar_one()
    return int(challenges) + int(throttles) + int(jobs)


def downgrade() -> None:
    bind = op.get_bind()
    count = _history_count(bind)
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0017_security_h6_h8: "
            f"{count} challenge, throttle, or deadline/cancel row(s) exist. "
            "Restore from backup instead of silently destroying auth or job-control history."
        )
    op.drop_index("ix_scan_jobs_cancel_requested_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_deadline_at", table_name="scan_jobs")
    op.drop_column("scan_jobs", "cancel_requested_at")
    op.drop_column("scan_jobs", "deadline_at")
    op.drop_table("auth_throttles")
    op.drop_index("ix_agent_challenges_expires_at", table_name="agent_challenges")
    op.drop_index("ix_agent_challenges_agent_id_expires_at", table_name="agent_challenges")
    op.drop_index("ix_agent_challenges_agent_id", table_name="agent_challenges")
    op.drop_table("agent_challenges")
