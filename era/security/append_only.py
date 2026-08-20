"""DB-level enforcement of append-only semantics for the audit log.

Installs BEFORE UPDATE/DELETE triggers that ABORT any mutation of ``audit_log``,
so immutability holds even against buggy or future code paths that bypass the
repository's append-only API.
"""

from __future__ import annotations

from sqlalchemy import Connection

_NO_UPDATE = "era_audit_log_no_update"
_NO_DELETE = "era_audit_log_no_delete"

_TRIGGERS = (
    (_NO_UPDATE, "UPDATE"),
    (_NO_DELETE, "DELETE"),
)


def install_append_only_triggers(connection: Connection) -> None:
    for name, op in _TRIGGERS:
        connection.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS {name} "
            f"BEFORE {op} ON audit_log "
            f"BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: {op} forbidden'); END;"
        )
