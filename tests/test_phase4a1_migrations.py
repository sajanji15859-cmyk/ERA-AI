"""Phase 4A.1 migration tests for stateful confirmation scope continuity."""

from __future__ import annotations

from sqlalchemy import inspect, text

from era.db import make_engine, migrate_database

HEAD = "0006_phase_4c_workflows"


def _confirmation_columns(engine) -> set[str]:
    with engine.connect() as connection:
        return {
            column["name"]
            for column in inspect(connection).get_columns("pending_confirmation")
        }


def test_phase4a1_migration_adds_execution_scope(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4a1.db")
    migrate_database(engine, "head")
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert revision == HEAD
    assert "execution_scope" in _confirmation_columns(engine)
    engine.dispose()


def test_phase4a1_migration_downgrade_and_reupgrade(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/phase4a1-roundtrip.db")
    migrate_database(engine, "head")
    migrate_database(engine, "base")
    migrate_database(engine, "0004_phase_3h_schedules")
    assert "execution_scope" not in _confirmation_columns(engine)
    migrate_database(engine, "head")
    assert "execution_scope" in _confirmation_columns(engine)
    engine.dispose()
