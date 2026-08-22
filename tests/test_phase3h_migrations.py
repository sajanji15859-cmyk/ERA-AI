"""Phase 3H Migration and Table Structure Tests."""

from __future__ import annotations

from sqlalchemy import inspect, text

from era.db import make_engine, migrate_database


def _columns(engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {column["name"] for column in inspect(connection).get_columns(table)}


def test_phase3h_schedule_table_created(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase3h.db")
    migrate_database(engine, "head")

    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()

    assert revision == "0004_phase_3h_schedules"
    assert "schedule" in tables

    cols = _columns(engine, "schedule")
    expected_cols = {
        "id", "actor_id", "name", "cron_expr", "interval_seconds",
        "action_type", "action_params", "enabled", "last_run_at",
        "next_run_at", "last_job_id", "created_at", "updated_at",
    }
    assert expected_cols.issubset(cols)
    engine.dispose()
