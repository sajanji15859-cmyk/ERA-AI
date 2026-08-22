"""Application container: wires settings, storage, registry and services."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

if TYPE_CHECKING:  # pragma: no cover — import only for static analysis
    from era.services.agent_service import AgentService

from era.config import Settings
from era.core.circuit_breaker import CircuitBreakerConfig, CircuitBreakerRegistry
from era.core.llm import LLMProvider
from era.core.retry import RetryPolicy
from era.core.tool_provider import ToolProvider
from era.core.tool_registry import ActionCatalog, ToolRegistry
from era.db import init_db, make_engine
from era.providers import StubProvider
from era.registry.actions import ACTION_CATALOG
from era.repositories.base import PolicyRepo
from era.repositories.circuit_breaker import SQLCircuitStateStore
from era.repositories.factory import RepositoryBundle, build_repositories
from era.security.signing import build_audit_signer
from era.security.vault import parse_master_key
from era.services.audit_service import AuditService
from era.services.auth_service import AuthService
from era.services.confirmation_service import ConfirmationService
from era.services.confirmation_sweeper import ConfirmationSweeper
from era.services.dual_approval import DualApprovalService
from era.services.execution_service import ExecutionService
from era.services.idempotency import IdempotencyService
from era.services.jobs import JobService
from era.services.permission_engine import PermissionEngine
from era.services.policy import PolicyService
from era.services.scheduler_leader import SchedulerLeaderService
from era.services.schedules import ScheduleService
from era.services.vault_service import VaultService
from era.services.workflow_ops_service import (
    WorkflowGovernanceService,
    WorkflowScheduleService,
    WorkflowTemplateService,
)
from era.services.workflow_service import WorkflowService
from era.workflows.catalog import WorkflowCatalog, build_default_catalog


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
    policy_repo: PolicyRepo
    repositories: RepositoryBundle
    auth_service: AuthService
    execution_service: ExecutionService
    #: Phase 3C: credential vault. Always built; ``enabled`` is False (and all
    #: store/resolve operations fail closed) unless a master key is set.
    vault_service: VaultService
    #: Phase 3G: replay-safe synchronous execution (idempotency keys).
    idempotency_service: IdempotencyService
    #: Phase 3G: durable background execution (async jobs).
    job_service: JobService
    #: Phase 3H: scheduled and recurring jobs.
    schedule_service: ScheduleService
    #: Phase 4C: registered workflow catalog + durable workflow engine.
    workflow_catalog: WorkflowCatalog
    workflow_service: WorkflowService
    #: Phase 4D: workflow operations/governance.
    workflow_schedule_service: WorkflowScheduleService
    workflow_template_service: WorkflowTemplateService
    workflow_governance_service: WorkflowGovernanceService
    #: Phase 4E: dual-approval for FINANCIAL / BOOKING confirmations.
    dual_approval_service: DualApprovalService
    #: Phase 4E: DB-backed scheduler leader election.
    scheduler_leader_service: SchedulerLeaderService
    #: Phase 4E: confirmation expiry sweeper.
    confirmation_sweeper: ConfirmationSweeper
    #: Phase 3A: agent run lifecycle. ``None`` unless the agent runtime wired
    #: it (``build_agent_container``) — the default container stays unchanged.
    agent_service: AgentService | None = None


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

    audit_signer = build_audit_signer(
        settings.audit_signing_algorithm,
        key=settings.audit_signing_key,
        public_key=settings.audit_signing_public_key,
        key_id=settings.audit_signing_key_id,
    )
    repositories = build_repositories(
        settings.database_url,
        genesis_hash=settings.audit_genesis_hash,
        signer=audit_signer,
    )

    audit_service = AuditService(
        audit_repo=repositories.audit,
        catalog=catalog,
        settings=settings,
    )
    confirmation_service = ConfirmationService(
        confirmation_repo=repositories.confirmation, catalog=catalog, settings=settings,
    )
    policy_service = PolicyService(
        policy_repo=repositories.policy, session_factory=session_factory,
        audit_service=audit_service, settings=settings,
    )
    # Phase 3C: credential vault (disabled + fail-closed until a master key
    # is configured via ERA_VAULT_MASTER_KEY).
    vault_service = VaultService(
        session_factory=session_factory,
        vault_repo=repositories.vault,
        audit_service=audit_service,
        policy_service=policy_service,
        settings=settings,
        master_key=parse_master_key(settings.vault_master_key),
    )
    permission_engine = PermissionEngine(catalog=catalog)

    auth_service = AuthService(
        session_factory=session_factory, user_repo=repositories.user,
        api_key_repo=repositories.api_key, catalog=catalog, settings=settings,
    )

    # Phase 1F reliability layer: provider-agnostic retry policy + per-provider
    # circuit breakers, both derived from settings with safe bounded defaults.
    retry_policy = RetryPolicy(
        max_attempts=settings.provider_retry_max_attempts,
        base_backoff_seconds=settings.provider_retry_base_backoff_seconds,
        max_backoff_seconds=settings.provider_retry_max_backoff_seconds,
        backoff_factor=settings.provider_retry_backoff_factor,
    )
    circuit_store = None
    if settings.circuit_breaker_persistent:
        circuit_store = SQLCircuitStateStore(
            session_factory,
            repositories.circuit_breaker_state,
        )
    circuit_breakers = CircuitBreakerRegistry(
        CircuitBreakerConfig(
            failure_threshold=settings.circuit_breaker_failure_threshold,
            cooldown_seconds=settings.circuit_breaker_cooldown_seconds,
        ),
        # Persisted timestamps must remain meaningful across process restarts.
        now=time.time if circuit_store is not None else time.monotonic,
        store=circuit_store,
    )

    # Dual approval is a dispatch precondition for BOOKING/FINANCIAL actions,
    # so it must be wired into ExecutionService rather than only exposed to an
    # operator UI.
    dual_approval_service = DualApprovalService(
        session_factory=session_factory,
        approval_repo=repositories.confirmation_approval,
        confirmation_repo=repositories.confirmation,
    )
    execution_service = ExecutionService(
        session_factory=session_factory, catalog=catalog, registry=registry,
        permission_engine=permission_engine, audit_service=audit_service,
        confirmation_service=confirmation_service, policy_service=policy_service,
        settings=settings, retry_policy=retry_policy,
        circuit_breakers=circuit_breakers,
        dual_approval_service=dual_approval_service,
    )

    # Phase 3G: replay-safe sync execution + durable background jobs. Jobs left
    # queued/running by a previous process are failed here (never guessed at).
    idempotency_service = IdempotencyService(
        session_factory=session_factory,
        idempotency_repo=repositories.idempotency,
        settings=settings,
    )
    job_service = JobService(
        session_factory=session_factory,
        job_repo=repositories.job,
        execution_service=execution_service,
        settings=settings,
    )
    job_service.recover()

    # Phase 4C: registered workflow catalog (with reference workflows) + the
    # durable workflow engine. The engine only dispatches through the
    # execution service, so every inner step keeps its own permission,
    # confirmation, audit and reliability gates.
    workflow_catalog = build_default_catalog(catalog)

    # Phase 4D: governance + immutable template store + workflow schedules.
    workflow_governance_service = WorkflowGovernanceService(
        session_factory=session_factory,
        repo=repositories.workflow_governance,
        settings=settings,
    )
    workflow_template_service = WorkflowTemplateService(
        session_factory=session_factory,
        repo=repositories.workflow_template,
        workflow_catalog=workflow_catalog,
        settings=settings,
    )
    # Reference workflows become published templates (version 1) at startup,
    # idempotently — publishing is skipped if a version already exists.
    from era.workflows.reference import REFERENCE_WORKFLOWS
    for ref in REFERENCE_WORKFLOWS:
        if workflow_template_service.get_latest(ref.name) is None:
            workflow_template_service.publish(ref, created_by="system")

    workflow_service = WorkflowService(
        session_factory=session_factory,
        catalog=catalog,
        workflow_catalog=workflow_catalog,
        workflow_repo=repositories.workflow,
        execution_service=execution_service,
        confirmation_service=confirmation_service,
        audit_service=audit_service,
        idempotency_service=idempotency_service,
        settings=settings,
        governance_service=workflow_governance_service,
        template_service=workflow_template_service,
    )

    workflow_schedule_service = WorkflowScheduleService(
        session_factory=session_factory,
        repo=repositories.workflow_schedule,
        workflow_service=workflow_service,
        workflow_catalog=workflow_catalog,
        settings=settings,
        template_service=workflow_template_service,
    )

    schedule_service = ScheduleService(
        session_factory=session_factory,
        schedule_repo=repositories.schedule,
        job_service=job_service,
        catalog=catalog,
        settings=settings,
        workflow_schedule_service=workflow_schedule_service,
    )

    # Phase 4E: scheduler leader election for multi-worker coordination.
    scheduler_leader_service = SchedulerLeaderService(
        session_factory=session_factory,
        heartbeat_timeout_seconds=float(
            getattr(settings, "scheduler_heartbeat_timeout_seconds", 30.0)
        ),
    )
    # Phase 4E: confirmation expiry sweeper.
    confirmation_sweeper = ConfirmationSweeper(
        session_factory=session_factory,
        confirmation_repo=repositories.confirmation,
    )

    if settings.scheduler_enabled:
        schedule_service.start(interval_seconds=settings.scheduler_interval_seconds)

    policy_service.bootstrap()
    auth_service.bootstrap_admin()

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
        policy_repo=repositories.policy,
        repositories=repositories,
        auth_service=auth_service,
        execution_service=execution_service,
        vault_service=vault_service,
        idempotency_service=idempotency_service,
        job_service=job_service,
        schedule_service=schedule_service,
        workflow_catalog=workflow_catalog,
        workflow_service=workflow_service,
        workflow_schedule_service=workflow_schedule_service,
        workflow_template_service=workflow_template_service,
        workflow_governance_service=workflow_governance_service,
        dual_approval_service=dual_approval_service,
        scheduler_leader_service=scheduler_leader_service,
        confirmation_sweeper=confirmation_sweeper,
    )
