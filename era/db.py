"""Database engine, session factory, bootstrap and transaction helper."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from era.models import Base
from era.security.append_only import install_append_only_triggers


def make_engine(database_url: str) -> Engine:
    kwargs: dict = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, future=True, **kwargs)
    if database_url.startswith("sqlite"):
        _enable_sqlite_pragmas(engine)
    return engine


def _enable_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()


def init_db(engine: Engine) -> None:
    """Create tables and install append-only triggers (idempotent)."""
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        install_append_only_triggers(conn)


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
