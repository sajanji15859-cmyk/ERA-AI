"""Phase 4D migration tests for workflow operations schema (0007)."""

from __future__ import annotations

from alembic import command
from sqlalchemy import inspect, text

from era.db import alembic_config, make_engine, migrate_database

HEAD = "0008_phase_4e_production"


def _downgrade_to(engine, revision: str) -> None:
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


def test_phase4d_migration_reaches_head_with_operations_tables(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4d.db")
    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert {"workflow_schedule", "workflow_template", "workflow_governance_counter"} <= tables
    assert {"template_name", "template_version", "template_checksum", "step_graph",
            "scheduled", "schedule_id", "governance_code"} <= _columns(engine, "workflow_run")
    assert {"depends_on", "condition", "parallel_group", "parallel_index"} <= \
        _columns(engine, "workflow_step_run")
    engine.dispose()


def test_phase4d_migration_downgrade_and_reupgrade(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4d-roundtrip.db")
    migrate_database(engine, "head")
    _downgrade_to(engine, "0006_phase_4c_workflows")
    assert _revision(engine) == "0006_phase_4c_workflows"
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert "workflow_schedule" not in tables
    assert "workflow_template" not in tables
    assert "workflow_governance_counter" not in tables
    assert "workflow_run" in tables
    assert "template_name" not in _columns(engine, "workflow_run")

    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
    assert "workflow_schedule" in tables
    engine.dispose()


def test_phase4d_legacy_database_upgrades_cleanly(tmp_path):
    """A pre-4D database at 0006 upgrades to 0007 without data loss."""
    engine = make_engine(f"sqlite:///{tmp_path}/legacy4d.db")
    migrate_database(engine, "0006_phase_4c_workflows")
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO workflow_run (id, workflow_name, workflow_version, actor_id, "
            "status, current_step, run_token, definition_checksum, definition_redacted, "
            "run_params, created_at, updated_at) "
            "VALUES ('legacy-run', 'login', 1, 'legacy', 'completed', 5, 'tok', "
            "'check', '{}', '{}', '2026-01-01T00:00:00+00:00', "
            "'2026-01-01T00:00:00+00:00')"
        ))
    migrate_database(engine, "head")
    assert _revision(engine) == HEAD
    with engine.connect() as connection:
        row = connection.execute(text(
            "SELECT id FROM workflow_run WHERE id = 'legacy-run'"
        )).scalar()
        tables = set(inspect(connection).get_table_names())
    assert row == "legacy-run"
    assert "workflow_schedule" in tables
    engine.dispose()
