"""Add durable, resumable workflow run tables (Phase 4C).

Revision ID: 0006_phase_4c_workflows
Revises: 0005_phase_4a1_browser_hardening

Adds ``workflow_run`` and ``workflow_step_run``. The migration is additive and
backward compatible; downgrade drops only the new tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_phase_4c_workflows"
down_revision = "0005_phase_4a1_browser_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_run",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("workflow_name", sa.String(), nullable=False),
        sa.Column("workflow_version", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("execution_scope", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("resume_token", sa.String(), nullable=True),
        sa.Column("run_token", sa.String(), nullable=False),
        sa.Column("definition_checksum", sa.String(), nullable=False),
        sa.Column("definition_redacted", sa.JSON(), nullable=False),
        sa.Column("run_params", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("actor_id", "run_token",
                            name="uq_workflow_actor_run_token"),
    )
    op.create_index("ix_workflow_run_actor_id", "workflow_run", ["actor_id"])

    op.create_table(
        "workflow_step_run",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("step_id", sa.String(), nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("params_redacted", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("confirmation_id", sa.String(), nullable=True),
        sa.Column("result_receipt", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(), nullable=True),
        sa.Column("error_message", sa.String(), nullable=True),
        sa.Column("started_at", sa.String(), nullable=True),
        sa.Column("finished_at", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["workflow_run.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_workflow_step_run_run_id", "workflow_step_run", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_workflow_step_run_run_id", table_name="workflow_step_run")
    op.drop_table("workflow_step_run")
    op.drop_index("ix_workflow_run_actor_id", table_name="workflow_run")
    op.drop_table("workflow_run")
