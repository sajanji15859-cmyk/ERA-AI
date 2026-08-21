"""Add idempotency records and background job rows.

Revision ID: 0003_phase_3g_reliability
Revises: 0002_phase_3f_scale
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_phase_3g_reliability"
down_revision = "0002_phase_3f_scale"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "idempotency_record",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("request_hash", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("actor_id", "key_hash", name="uq_idempotency_actor_key"),
    )
    op.create_index("ix_idempotency_record_actor_id", "idempotency_record", ["actor_id"])

    op.create_table(
        "job",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(), nullable=True),
        sa.Column("request_hash", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("action_params", sa.JSON(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("credential_refs", sa.JSON(), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("actor_id", "idempotency_key_hash", name="uq_job_actor_idem_key"),
    )
    op.create_index("ix_job_actor_id", "job", ["actor_id"])
    op.create_index("ix_job_idempotency_key_hash", "job", ["idempotency_key_hash"])


def downgrade() -> None:
    op.drop_index("ix_job_idempotency_key_hash", table_name="job")
    op.drop_index("ix_job_actor_id", table_name="job")
    op.drop_table("job")
    op.drop_index("ix_idempotency_record_actor_id", table_name="idempotency_record")
    op.drop_table("idempotency_record")
