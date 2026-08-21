"""Add keyed audit signatures and persistent circuit-breaker state.

Revision ID: 0002_phase_3f_scale
Revises: 0001_initial_schema
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_phase_3f_scale"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("signing_algorithm", sa.String(), nullable=True))
    op.add_column("audit_log", sa.Column("signing_key_id", sa.String(), nullable=True))
    op.add_column("audit_log", sa.Column("signature", sa.String(), nullable=True))
    op.create_table(
        "circuit_breaker_state",
        sa.Column("provider_id", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("opened_at", sa.Float(), nullable=True),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("provider_id"),
    )


def downgrade() -> None:
    op.drop_table("circuit_breaker_state")
    op.drop_column("audit_log", "signature")
    op.drop_column("audit_log", "signing_key_id")
    op.drop_column("audit_log", "signing_algorithm")
