"""Add schedule table for recurring and scheduled jobs (Phase 3H).

Revision ID: 0004_phase_3h_schedules
Revises: 0003_phase_3g_reliability
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_phase_3h_schedules"
down_revision = "0003_phase_3g_reliability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "schedule",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("cron_expr", sa.String(), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("action_params", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_run_at", sa.String(), nullable=True),
        sa.Column("next_run_at", sa.String(), nullable=True),
        sa.Column("last_job_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_schedule_actor_id", "schedule", ["actor_id"])
    op.create_index("ix_schedule_enabled", "schedule", ["enabled"])
    op.create_index("ix_schedule_next_run_at", "schedule", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_schedule_next_run_at", table_name="schedule")
    op.drop_index("ix_schedule_enabled", table_name="schedule")
    op.drop_index("ix_schedule_actor_id", table_name="schedule")
    op.drop_table("schedule")
