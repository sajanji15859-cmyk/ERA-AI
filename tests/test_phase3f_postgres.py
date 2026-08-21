"""Phase 3F PostgreSQL backend selection and optional live integration test."""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.db import make_engine, transaction
from era.models import AgentRun, MemoryEntry
from era.repositories.factory import build_repositories
from era.repositories.postgres import (
    PostgresAgentRunRepo,
    PostgresApiKeyRepo,
    PostgresAuditRepo,
    PostgresCircuitBreakerStateRepo,
    PostgresConfirmationRepo,
    PostgresMemoryRepo,
    PostgresPolicyRepo,
    PostgresUserRepo,
    PostgresVaultRepo,
)


def test_postgres_url_selects_every_postgres_repository():
    repositories = build_repositories(
        "postgresql://era:secret@db.example/era",
        genesis_hash="0" * 64,
    )
    assert repositories.backend == "postgresql"
    assert isinstance(repositories.audit, PostgresAuditRepo)
    assert isinstance(repositories.confirmation, PostgresConfirmationRepo)
    assert isinstance(repositories.policy, PostgresPolicyRepo)
    assert isinstance(repositories.user, PostgresUserRepo)
    assert isinstance(repositories.api_key, PostgresApiKeyRepo)
    assert isinstance(repositories.vault, PostgresVaultRepo)
    assert isinstance(repositories.agent_run, PostgresAgentRunRepo)
    assert isinstance(repositories.memory, PostgresMemoryRepo)
    assert isinstance(repositories.circuit_breaker_state, PostgresCircuitBreakerStateRepo)


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.getenv("ERA_TEST_POSTGRES_URL"),
    reason="set ERA_TEST_POSTGRES_URL for live PostgreSQL integration",
)
def test_live_postgres_all_repository_protocols_and_signed_audit():
    """Run in an isolated schema so the supplied PostgreSQL DB is not destroyed."""
    raw_url = os.environ["ERA_TEST_POSTGRES_URL"]
    schema = f"era_test_{uuid.uuid4().hex}"
    admin_engine = make_engine(raw_url)
    test_engine = None
    container = None
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        url = make_url(raw_url)
        url = url.update_query_dict({"options": f"-csearch_path={schema}"})
        test_url = url.render_as_string(hide_password=False)
        settings = Settings(
            database_url=test_url,
            audit_signing_algorithm="hmac-sha256",
            audit_signing_key="postgres-integration-signing-key-32-bytes",
            vault_master_key="11" * 32,
            rate_limit_enabled=False,
        )
        container = build_container(settings)
        test_engine = container.engine
        assert container.repositories.backend == "postgresql"

        user = container.auth_service.create_user(username="pg-user", role="user")
        key, raw_key = container.auth_service.create_api_key(user.id, "pg-key")
        assert container.auth_service.authenticate_token(raw_key).api_key.id == key.id

        result = container.execution_service.request(
            Action(action_type="stub.noop"),
            ExecutionContext(actor_id=user.id),
        )
        assert result.status == "executed"
        pending = container.execution_service.request(
            Action(action_type="email.send", params={"to": "pg@example.test"}),
            ExecutionContext(actor_id=user.id),
        )
        assert pending.status == "confirmation_required"

        with transaction(container.session_factory) as session:
            assert container.audit_service.verify(session).valid is True
            assert container.repositories.confirmation.get(
                session, pending.confirmation_id
            ) is not None
            assert container.repositories.circuit_breaker_state.get(
                session, "stub"
            ) is not None

            run = AgentRun(id=uuid.uuid4().hex, actor_id=user.id, goal="pg integration")
            container.repositories.agent_run.create(session, run)
            assert container.repositories.agent_run.get(session, run.id) is run

            memory = MemoryEntry(
                id=uuid.uuid4().hex,
                actor_id=user.id,
                namespace="test",
                key="phase",
                value_json={"value": "3F"},
            )
            container.repositories.memory.create(session, memory)
            assert container.repositories.memory.get(
                session, user.id, "test", "phase"
            ) is memory

        stored = container.vault_service.store_or_rotate_secret(
            domain="github", name="token", value="not-a-real-token", actor_id=user.id
        )
        assert container.repositories.vault.__class__ is PostgresVaultRepo
        assert stored.ciphertext != b"not-a-real-token"
    finally:
        if container is not None:
            container.engine.dispose()
        elif test_engine is not None:
            test_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
