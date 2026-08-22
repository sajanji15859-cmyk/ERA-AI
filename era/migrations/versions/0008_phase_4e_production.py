"""Phase 4E — strong confirmation & production hardening.

Revision ID: 0008_phase_4e_production
Revises: 0007_phase_4d_operations

Adds:
* ``confirmation_approval`` — dual-approval records for FINANCIAL / BOOKING
  CONFIRM_STRONG confirmations. Each row records one actor's approval/denial
  with a sequence number and optional context hash (IP + UA fingerprint).
* ``scheduler_leader`` — DB-backed single-leader election row for the
  in-process scheduler, enabling multi-worker deployments without duplicating
  schedule ticks.

The migration is backward compatible (additive tables only). Downgrade drops
the new tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_phase_4e_production"
down_revision = "0007_phase_4d_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Dual-approval records for FINANCIAL / BOOKING confirmations.
    op.create_table(
        "confirmation_approval",
        sa.Column("id", sa.String(), primary_key=True, nullable=False),
        sa.Column("confirmation_id", sa.String(), nullable=False, index=True),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("context_hash", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False,
                  server_default=sa.text("('')")),
    )

    # Scheduler leader election singleton.
    op.create_table(
        "scheduler_leader",
        sa.Column("id", sa.String(), primary_key=True, nullable=False),
        sa.Column("leader_id", sa.String(), nullable=False),
        sa.Column("heartbeat_at", sa.String(), nullable=False,
                  server_default=sa.text("('')")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_table("scheduler_leader")
    op.drop_table("confirmation_approval")
