"""Phase 3F durable circuit-breaker state tests."""

from __future__ import annotations

from era.config import Settings
from era.container import build_container
from era.core.circuit_breaker import CircuitBreakerConfig, CircuitBreakerRegistry, CircuitState
from era.core.result import ProviderErrorCode
from era.db import transaction
from era.repositories.circuit_breaker import SQLCircuitStateStore


class Clock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_open_state_survives_registry_and_process_lifecycle(tmp_path):
    container = build_container(Settings(database_url=f"sqlite:///{tmp_path}/circuit.db"))
    store = SQLCircuitStateStore(
        container.session_factory,
        container.repositories.circuit_breaker_state,
    )
    config = CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=10.0)
    clock = Clock(100.0)

    first_registry = CircuitBreakerRegistry(config, now=clock, store=store)
    first = first_registry.get("durable-provider")
    first.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert first.state is CircuitState.OPEN

    # A fresh registry represents a new worker/process after restart. It reads
    # OPEN from SQL rather than silently resetting provider health to CLOSED.
    second_registry = CircuitBreakerRegistry(config, now=clock, store=store)
    second = second_registry.get("durable-provider")
    assert second.state is CircuitState.OPEN
    assert second.allow_request() is False

    with transaction(container.session_factory) as session:
        row = container.repositories.circuit_breaker_state.get(session, "durable-provider")
        assert row is not None
        assert row.state == "OPEN"
        assert row.opened_at == 100.0

    clock.value = 110.0
    assert second.allow_request() is True
    assert second.state is CircuitState.HALF_OPEN
    second.record_success()

    third_registry = CircuitBreakerRegistry(config, now=clock, store=store)
    third = third_registry.get("durable-provider")
    assert third.state is CircuitState.CLOSED
    assert third.consecutive_failures == 0
    container.engine.dispose()
