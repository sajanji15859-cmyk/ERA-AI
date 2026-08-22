"""Persist confirmation execution scope for stateful browser continuity.

Revision ID: 0005_phase_4a1_browser_hardening
Revises: 0004_phase_3h_schedules
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_phase_4a1_browser_hardening"
down_revision = "0004_phase_3h_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "pending_confirmation",
        sa.Column("execution_scope", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("pending_confirmation", "execution_scope")
