"""Candidate Tranche C Agent runtime inventory columns.

Revision ID: 0016_scanner_runtime_inventory
Revises: 0015_raw_scan_evidence
Create Date: 2026-08-19 00:00:00.000000+00:00

Do not import live application models. Do not edit 0001–0015.

Adds nullable Agent.runtime_inventory and Agent.runtime_inventory_reported_at.
Existing Agent rows remain intact with NULL inventory (Not Reported).

An empty inventory (no Agent has inventory or a report timestamp) may
downgrade to 0015. Populated inventory must refuse rather than destroy
version evidence.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_scanner_runtime_inventory"
down_revision: str | None = "0015_raw_scan_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("runtime_inventory", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "agents",
        sa.Column("runtime_inventory_reported_at", sa.DateTime(timezone=True), nullable=True),
    )


def _inventory_row_count(bind) -> int:
    return int(
        bind.execute(
            sa.text(
                """
                SELECT COUNT(*) FROM agents
                WHERE runtime_inventory IS NOT NULL
                   OR runtime_inventory_reported_at IS NOT NULL
                """
            )
        ).scalar_one()
    )


def downgrade() -> None:
    bind = op.get_bind()
    count = _inventory_row_count(bind)
    if count:
        raise RuntimeError(
            "Refusing to downgrade 0016_scanner_runtime_inventory: "
            f"{count} agent row(s) have runtime inventory or a report timestamp. "
            "Restore from backup instead of silently destroying version evidence."
        )
    op.drop_column("agents", "runtime_inventory_reported_at")
    op.drop_column("agents", "runtime_inventory")
