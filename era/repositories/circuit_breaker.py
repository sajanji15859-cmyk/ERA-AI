"""SQL-backed circuit state store adapter."""

from __future__ import annotations

from era.core.circuit_breaker import CircuitSnapshot, CircuitState
from era.db import transaction
from era.repositories.base import CircuitBreakerStateRepo


class SQLCircuitStateStore:
    """Persist snapshots through the selected repository implementation."""

    def __init__(self, session_factory, repository: CircuitBreakerStateRepo):
        self.session_factory = session_factory
        self.repository = repository

    def load(self, provider_id: str) -> CircuitSnapshot | None:
        with transaction(self.session_factory) as session:
            row = self.repository.get(session, provider_id)
            if row is None:
                return None
            return CircuitSnapshot(
                state=CircuitState(row.state),
                consecutive_failures=row.consecutive_failures,
                opened_at=row.opened_at,
            )

    def save(self, provider_id: str, snapshot: CircuitSnapshot) -> None:
        with transaction(self.session_factory) as session:
            self.repository.upsert(
                session,
                provider_id=provider_id,
                state=snapshot.state.value,
                consecutive_failures=snapshot.consecutive_failures,
                opened_at=snapshot.opened_at,
            )
