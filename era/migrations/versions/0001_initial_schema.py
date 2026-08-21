"""Create the pre-Phase-3F ERA schema.

Revision ID: 0001_initial_schema
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_run",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("goal", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("plan_json", sa.JSON(), nullable=True),
        sa.Column("tasks_json", sa.JSON(), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("pending_confirmations_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_run_actor_id", "agent_run", ["actor_id"])

    op.create_table(
        "api_key",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("prefix", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("last_used_at", sa.String(), nullable=True),
        sa.Column("revoked_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_key_key_hash", "api_key", ["key_hash"], unique=True)
    op.create_index("ix_api_key_user_id", "api_key", ["user_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("action_params", sa.JSON(), nullable=False),
        sa.Column("risk_level", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("confirmation_id", sa.String(), nullable=True),
        sa.Column("result", sa.String(), nullable=True),
        sa.Column("error_code", sa.String(), nullable=True),
        sa.Column("provider_id", sa.String(), nullable=True),
        sa.Column("capability_domain", sa.String(), nullable=True),
        sa.Column("credential_ref", sa.String(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("app_version", sa.String(), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(), nullable=False),
        sa.Column("entry_hash", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_action_type", "audit_log", ["action_type"])
    op.create_index("ix_audit_log_confirmation_id", "audit_log", ["confirmation_id"])
    op.create_index("ix_audit_log_error_code", "audit_log", ["error_code"])
    op.create_index("ix_audit_log_outcome", "audit_log", ["outcome"])
    op.create_index("ix_audit_log_seq", "audit_log", ["seq"], unique=True)

    op.create_table(
        "memory_entry",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("namespace", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "actor_id", "namespace", "key", name="uq_memory_actor_namespace_key"
        ),
    )
    op.create_index("ix_memory_entry_actor_id", "memory_entry", ["actor_id"])

    op.create_table(
        "pending_confirmation",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=True),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("action_hash", sa.String(), nullable=False),
        sa.Column("risk_level", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("challenge_hash", sa.String(), nullable=True),
        sa.Column("action_params_redacted", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.Column("used_at", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "policy_version",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("changed_by", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version"),
    )

    op.create_table(
        "user",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("credential_refs", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_username", "user", ["username"], unique=True)

    op.create_table(
        "vault_secret",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("owner_user_id", sa.String(), nullable=False),
        sa.Column("algorithm", sa.String(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("value_length", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", "name", name="uq_vault_domain_name"),
    )
    op.create_index("ix_vault_secret_domain", "vault_secret", ["domain"])
    op.create_index("ix_vault_secret_owner_user_id", "vault_secret", ["owner_user_id"])

    _install_append_only_guards()


def downgrade() -> None:
    _remove_append_only_guards()
    op.drop_table("vault_secret")
    op.drop_table("user")
    op.drop_table("policy_version")
    op.drop_table("pending_confirmation")
    op.drop_table("memory_entry")
    op.drop_table("audit_log")
    op.drop_table("api_key")
    op.drop_table("agent_run")


def _install_append_only_guards() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION era_reject_audit_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_log is append-only: % forbidden', TG_OP;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        op.execute(
            "CREATE TRIGGER era_audit_log_no_update BEFORE UPDATE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION era_reject_audit_mutation()"
        )
        op.execute(
            "CREATE TRIGGER era_audit_log_no_delete BEFORE DELETE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION era_reject_audit_mutation()"
        )
        return
    op.execute(
        "CREATE TRIGGER era_audit_log_no_update BEFORE UPDATE ON audit_log "
        "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE forbidden'); END"
    )
    op.execute(
        "CREATE TRIGGER era_audit_log_no_delete BEFORE DELETE ON audit_log "
        "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: DELETE forbidden'); END"
    )


def _remove_append_only_guards() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS era_audit_log_no_update ON audit_log")
        op.execute("DROP TRIGGER IF EXISTS era_audit_log_no_delete ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS era_reject_audit_mutation()")
        return
    op.execute("DROP TRIGGER IF EXISTS era_audit_log_no_update")
    op.execute("DROP TRIGGER IF EXISTS era_audit_log_no_delete")
