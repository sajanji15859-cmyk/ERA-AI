"""Phase 4D operations layer: schedules, templates, governance, DAG state.

Revision ID: 0007_phase_4d_operations
Revises: 0006_phase_4c_workflows

Adds the operations/governance tables (``workflow_schedule``,
``workflow_template``, ``workflow_governance_counter``) and additive columns on
``workflow_run`` / ``workflow_step_run`` for template identity, DAG/parallel
step state and governance recording. The migration is backward compatible;
downgrade drops only the new tables/columns.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_phase_4d_operations"
down_revision = "0006_phase_4c_workflows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- new additive columns on workflow_run --------------------------------
    op.add_column(
        "workflow_run", sa.Column("template_name", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("template_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("template_checksum", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("started_at", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("finished_at", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("source", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("step_graph", sa.JSON(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("parallel_cap", sa.Integer(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("governance_code", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_run", sa.Column("scheduled", sa.Boolean(), nullable=False,
                                  server_default=sa.false()),
    )
    op.add_column(
        "workflow_run", sa.Column("schedule_id", sa.String(), nullable=True),
    )

    # --- new additive columns on workflow_step_run --------------------------
    op.add_column(
        "workflow_step_run", sa.Column("depends_on", sa.JSON(), nullable=True),
    )
    op.add_column(
        "workflow_step_run", sa.Column("condition", sa.JSON(), nullable=True),
    )
    op.add_column(
        "workflow_step_run", sa.Column("parallel_group", sa.String(), nullable=True),
    )
    op.add_column(
        "workflow_step_run", sa.Column("parallel_index", sa.Integer(), nullable=True),
    )

    # --- workflow schedules --------------------------------------------------
    op.create_table(
        "workflow_schedule",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("actor_role", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("workflow_name", sa.String(), nullable=False),
        sa.Column("workflow_version", sa.Integer(), nullable=True),
        sa.Column("params_redacted", sa.JSON(), nullable=False),
        sa.Column("cron_expr", sa.String(), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_run_at", sa.String(), nullable=True),
        sa.Column("next_run_at", sa.String(), nullable=True),
        sa.Column("last_run_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("actor_id", "name",
                            name="uq_workflow_schedule_actor_name"),
    )
    op.create_index("ix_workflow_schedule_actor_id", "workflow_schedule", ["actor_id"])
    op.create_index("ix_workflow_schedule_next_run_at", "workflow_schedule",
                    ["next_run_at"])

    # --- workflow templates --------------------------------------------------
    op.create_table(
        "workflow_template",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("definition_redacted", sa.JSON(), nullable=False),
        sa.Column("params_schema", sa.JSON(), nullable=False),
        sa.Column("checksum", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("published_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version",
                            name="uq_workflow_template_name_version"),
    )
    op.create_index("ix_workflow_template_name", "workflow_template", ["name"])

    # --- governance counters ------------------------------------------------
    op.create_table(
        "workflow_governance_counter",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "scope",
                            name="uq_workflow_gov_kind_scope"),
    )


def downgrade() -> None:
    op.drop_table("workflow_governance_counter")
    op.drop_table("workflow_template")
    op.drop_index("ix_workflow_schedule_next_run_at", table_name="workflow_schedule")
    op.drop_index("ix_workflow_schedule_actor_id", table_name="workflow_schedule")
    op.drop_table("workflow_schedule")

    for column in ("parallel_index", "parallel_group", "condition", "depends_on"):
        op.drop_column("workflow_step_run", column)
    for column in (
        "schedule_id", "scheduled", "governance_code", "parallel_cap",
        "step_graph", "source", "finished_at", "started_at",
        "template_checksum", "template_version", "template_name",
    ):
        op.drop_column("workflow_run", column)
