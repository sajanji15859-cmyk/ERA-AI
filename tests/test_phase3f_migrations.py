"""Alembic upgrade/downgrade and legacy-database migration tests."""

from __future__ import annotations

from sqlalchemy import inspect, text

from era.db import init_db, make_engine, migrate_database


def _columns(engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {column["name"] for column in inspect(connection).get_columns(table)}


def test_migration_upgrade_downgrade_round_trip(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/migration.db")
    migrate_database(engine, "head")

    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert revision == "0007_phase_4d_operations"
    assert "circuit_breaker_state" in tables
    assert "idempotency_record" in tables
    assert "job" in tables
    assert "schedule" in tables
    assert {"signature", "signing_key_id", "signing_algorithm"} <= _columns(
        engine, "audit_log"
    )

    migrate_database(engine, "base")
    with engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == {"alembic_version"}

    migrate_database(engine, "head")
    with engine.connect() as connection:
        assert "audit_log" in inspect(connection).get_table_names()
        assert "schedule" in inspect(connection).get_table_names()
    engine.dispose()


def test_pre_alembic_database_is_stamped_and_upgraded_without_data_loss(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/legacy.db")
    migrate_database(engine, "0001_initial_schema")
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO policy_version "
            "(version, document, created_at, changed_by) "
            "VALUES (7, '{}', '2026-01-01T00:00:00+00:00', 'legacy')"
        ))
        connection.exec_driver_sql("DROP TABLE alembic_version")

    init_db(engine)

    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        version = connection.execute(text(
            "SELECT version FROM policy_version WHERE changed_by = 'legacy'"
        )).scalar()
        tables = set(inspect(connection).get_table_names())
    assert revision == "0007_phase_4d_operations"
    assert version == 7
    assert "circuit_breaker_state" in tables
    assert "schedule" in tables
    assert "signature" in _columns(engine, "audit_log")
    engine.dispose()
