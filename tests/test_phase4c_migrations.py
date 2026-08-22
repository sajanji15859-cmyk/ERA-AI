"""Phase 4C migration tests for durable workflow run tables (0006)."""

from __future__ import annotations

from alembic import command
from sqlalchemy import inspect, text

from era.db import alembic_config, make_engine, migrate_database

HEAD = "0008_phase_4e_production"


def _downgrade_to(engine, revision: str) -> None:
    """Run a real Alembic downgrade to ``revision`` (drops only newer tables)."""
    with engine.connect() as connection:
        cfg = alembic_config(connection=connection, database_url=str(engine.url))
        command.downgrade(cfg, revision)
        connection.commit()


def _columns(engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {column["name"] for column in inspect(connection).get_columns(table)}


def _revision(engine) -> str:
    with engine.connect() as connection:
        return connection.execute(text("SELECT version_num FROM alembic_version")).scalar()


def test_phase4c_migration_reaches_head_with_workflow_tables(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4c.db")
    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert {"workflow_run", "workflow_step_run"} <= tables
    assert _columns(engine, "workflow_run") >= {
        "id", "workflow_name", "workflow_version", "actor_id", "execution_scope",
        "status", "current_step", "error", "resume_token", "run_token",
        "definition_checksum", "definition_redacted", "run_params",
        "created_at", "updated_at",
    }
    assert _columns(engine, "workflow_step_run") >= {
        "id", "run_id", "step_id", "step_index", "action_type",
        "params_redacted", "status", "attempt", "confirmation_id",
        "result_receipt", "error_code", "error_message", "started_at",
        "finished_at",
    }
    engine.dispose()


def test_phase4c_migration_downgrade_and_reupgrade(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4c-roundtrip.db")
    migrate_database(engine, "head")
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert "workflow_run" in tables

    _downgrade_to(engine, "0005_phase_4a1_browser_hardening")
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert "workflow_run" not in tables
    assert "workflow_step_run" not in tables
    # Phase 4A.1 and earlier tables survive the downgrade (backward compatible).
    assert "pending_confirmation" in tables
    assert "execution_scope" in _columns(engine, "pending_confirmation")

    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert "workflow_run" in tables
    engine.dispose()


def test_phase4c_legacy_database_upgrades_cleanly(tmp_path):
    """A pre-4C database (head of 0005) upgrades to 0006 without data loss."""
    engine = make_engine(f"sqlite:///{tmp_path}/legacy4c.db")
    migrate_database(engine, "0005_phase_4a1_browser_hardening")
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO policy_version "
            "(version, document, created_at, changed_by) "
            "VALUES (3, '{}', '2026-01-01T00:00:00+00:00', 'legacy4c')"
        ))
    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        version = connection.execute(text(
            "SELECT version FROM policy_version WHERE changed_by = 'legacy4c'"
        )).scalar()
        tables = set(inspect(connection).get_table_names())
    assert version == 3
    assert "workflow_run" in tables
    engine.dispose()
