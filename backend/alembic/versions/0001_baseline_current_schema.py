"""Baseline current application schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-18 11:33:00.000000+00:00

Represents the Phase 0 schema exactly as implemented by SQLAlchemy models.
Does not introduce Site, Asset, or other later-phase entities.

Fresh databases: this revision creates the current tables.
Existing pre-Alembic databases: stamp this revision after compatibility
columns/constraints are present; do not re-run create on occupied tables.

Downgrade drops the application schema and is destructive.
"""

from collections.abc import Sequence

from alembic import op

from app.database import Base
import app.models  # noqa: F401 — register metadata

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
