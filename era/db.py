"""Database engine, Alembic migration bootstrap and transaction helper."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

ALEMBIC_HEAD = "head"
LEGACY_BASELINE_REVISION = "0001_initial_schema"
_MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def make_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    # SQLAlchemy's bare postgresql:// default historically selected psycopg2;
    # Phase 3F standardizes on maintained psycopg 3 while preserving common DB URLs.
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg")

    kwargs: dict = {}
    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_pre_ping"] = True
    engine = create_engine(url, future=True, **kwargs)
    if url.get_backend_name() == "sqlite":
        _enable_sqlite_pragmas(engine)
    return engine


def _enable_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()


def alembic_config(*, connection=None, database_url: str | None = None) -> Config:
    """Return a package-relative Alembic config usable by runtime and tests."""
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS))
    if database_url:
        # ConfigParser treats percent as interpolation syntax.
        config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def migrate_database(engine: Engine, revision: str = ALEMBIC_HEAD) -> None:
    """Upgrade/downgrade an engine using Alembic, never ORM ``create_all``.

    Databases created before Phase 3F have all baseline tables but no
    ``alembic_version`` marker. They are stamped at the pre-3F baseline and then
    upgraded, preserving existing data. Fresh databases run every revision.
    """
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        # Inspector queries autobegin on SQLAlchemy 2.x. End that transaction so
        # Alembic owns a clean migration transaction on the supplied connection.
        connection.commit()
        config = alembic_config(connection=connection, database_url=str(engine.url))
        is_legacy = "audit_log" in tables and "alembic_version" not in tables
        if is_legacy:
            command.stamp(config, LEGACY_BASELINE_REVISION)
            connection.commit()
        if revision == "base":
            command.downgrade(config, "base")
        else:
            command.upgrade(config, revision)
        connection.commit()


def init_db(engine: Engine) -> None:
    """Bring the database schema to the current Alembic head."""
    migrate_database(engine, ALEMBIC_HEAD)


@contextmanager
def transaction(session_factory: sessionmaker) -> Iterator[Session]:
    """Yield a session inside a transaction; commit on success, rollback on error."""
    session: Session = session_factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
