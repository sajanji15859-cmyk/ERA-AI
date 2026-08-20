"""Application container: wires settings, storage, registry and services."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from era.config import Settings
from era.core.llm import LLMProvider
from era.core.tool_provider import ToolProvider
from era.core.tool_registry import ActionCatalog, ToolRegistry
from era.db import init_db, make_engine
from era.providers import StubProvider
from era.registry.actions import ACTION_CATALOG
from era.repositories.sqlite import (
    SQLiteAuditRepo,
    SQLiteConfirmationRepo,
    SQLitePolicyRepo,
)
from era.services.audit_service import AuditService
from era.services.confirmation_service import ConfirmationService
from era.services.execution_service import ExecutionService
from era.services.permission_engine import PermissionEngine
from era.services.policy import PolicyService


@dataclass
class Container:
    settings: Settings
    engine: Engine
    session_factory: sessionmaker
    catalog: ActionCatalog
    registry: ToolRegistry
    llm_provider: LLMProvider | None
    permission_engine: PermissionEngine
    audit_service: AuditService
    confirmation_service: ConfirmationService
    policy_service: PolicyService
    policy_repo: SQLitePolicyRepo
    execution_service: ExecutionService


def build_container(settings: Settings | None = None,
                    providers: list[ToolProvider] | None = None) -> Container:
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    init_db(engine)

    catalog = ACTION_CATALOG
    registry = ToolRegistry()
    if providers is None:
        providers = [StubProvider()]
    for provider in providers:
        registry.register(provider)

    audit_repo = SQLiteAuditRepo(genesis_hash=settings.audit_genesis_hash)
    confirmation_repo = SQLiteConfirmationRepo()
    policy_repo = SQLitePolicyRepo()

    audit_service = AuditService(audit_repo=audit_repo, catalog=catalog, settings=settings)
    confirmation_service = ConfirmationService(
        confirmation_repo=confirmation_repo, catalog=catalog, settings=settings,
    )
    policy_service = PolicyService(
        policy_repo=policy_repo, session_factory=session_factory,
        audit_service=audit_service, settings=settings,
    )
    permission_engine = PermissionEngine(catalog=catalog)
    execution_service = ExecutionService(
        session_factory=session_factory, catalog=catalog, registry=registry,
        permission_engine=permission_engine, audit_service=audit_service,
        confirmation_service=confirmation_service, policy_service=policy_service,
        settings=settings,
    )

    policy_service.bootstrap()

    return Container(
        settings=settings,
        engine=engine,
        session_factory=session_factory,
        catalog=catalog,
        registry=registry,
        llm_provider=None,  # real model wiring arrives in a later phase
        permission_engine=permission_engine,
        audit_service=audit_service,
        confirmation_service=confirmation_service,
        policy_service=policy_service,
        policy_repo=policy_repo,
        execution_service=execution_service,
    )
