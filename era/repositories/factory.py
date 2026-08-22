"""Database-URL-driven repository backend selection."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.engine import make_url

from era.repositories.base import (
    AgentRunRepo,
    ApiKeyRepo,
    AuditRepo,
    CircuitBreakerStateRepo,
    ConfirmationApprovalRepo,
    ConfirmationRepo,
    IdempotencyRepo,
    JobRepo,
    MemoryRepo,
    PolicyRepo,
    ScheduleRepo,
    UserRepo,
    VaultSecretRepo,
    WorkflowGovernanceRepo,
    WorkflowRunRepo,
    WorkflowScheduleRepo,
    WorkflowTemplateRepo,
)
from era.security.signing import AuditSigner


@dataclass(frozen=True)
class RepositoryBundle:
    """One complete implementation of every persistence protocol."""

    audit: AuditRepo
    confirmation: ConfirmationRepo
    confirmation_approval: ConfirmationApprovalRepo
    policy: PolicyRepo
    user: UserRepo
    api_key: ApiKeyRepo
    vault: VaultSecretRepo
    agent_run: AgentRunRepo
    memory: MemoryRepo
    circuit_breaker_state: CircuitBreakerStateRepo
    idempotency: IdempotencyRepo
    job: JobRepo
    schedule: ScheduleRepo
    workflow: WorkflowRunRepo
    workflow_schedule: WorkflowScheduleRepo
    workflow_template: WorkflowTemplateRepo
    workflow_governance: WorkflowGovernanceRepo
    backend: str


def build_repositories(
    database_url: str,
    *,
    genesis_hash: str,
    signer: AuditSigner | None = None,
) -> RepositoryBundle:
    """Choose SQLite or PostgreSQL implementations from the SQLAlchemy URL."""
    backend = make_url(database_url).get_backend_name()
    if backend == "sqlite":
        from era.repositories.sqlite import (
            SQLiteAgentRunRepo,
            SQLiteApiKeyRepo,
            SQLiteAuditRepo,
            SQLiteCircuitBreakerStateRepo,
            SQLiteConfirmationApprovalRepo,
            SQLiteConfirmationRepo,
            SQLiteIdempotencyRepo,
            SQLiteJobRepo,
            SQLiteMemoryRepo,
            SQLitePolicyRepo,
            SQLiteScheduleRepo,
            SQLiteUserRepo,
            SQLiteVaultRepo,
            SQLiteWorkflowGovernanceRepo,
            SQLiteWorkflowRunRepo,
            SQLiteWorkflowScheduleRepo,
            SQLiteWorkflowTemplateRepo,
        )

        return RepositoryBundle(
            audit=SQLiteAuditRepo(genesis_hash, signer=signer),
            confirmation=SQLiteConfirmationRepo(),
            confirmation_approval=SQLiteConfirmationApprovalRepo(),
            policy=SQLitePolicyRepo(),
            user=SQLiteUserRepo(),
            api_key=SQLiteApiKeyRepo(),
            vault=SQLiteVaultRepo(),
            agent_run=SQLiteAgentRunRepo(),
            memory=SQLiteMemoryRepo(),
            circuit_breaker_state=SQLiteCircuitBreakerStateRepo(),
            idempotency=SQLiteIdempotencyRepo(),
            job=SQLiteJobRepo(),
            schedule=SQLiteScheduleRepo(),
            workflow=SQLiteWorkflowRunRepo(),
            workflow_schedule=SQLiteWorkflowScheduleRepo(),
            workflow_template=SQLiteWorkflowTemplateRepo(),
            workflow_governance=SQLiteWorkflowGovernanceRepo(),
            backend="sqlite",
        )
    if backend == "postgresql":
        from era.repositories.postgres import (
            PostgresAgentRunRepo,
            PostgresApiKeyRepo,
            PostgresAuditRepo,
            PostgresCircuitBreakerStateRepo,
            PostgresConfirmationApprovalRepo,
            PostgresConfirmationRepo,
            PostgresIdempotencyRepo,
            PostgresJobRepo,
            PostgresMemoryRepo,
            PostgresPolicyRepo,
            PostgresScheduleRepo,
            PostgresUserRepo,
            PostgresVaultRepo,
            PostgresWorkflowGovernanceRepo,
            PostgresWorkflowRunRepo,
            PostgresWorkflowScheduleRepo,
            PostgresWorkflowTemplateRepo,
        )

        return RepositoryBundle(
            audit=PostgresAuditRepo(genesis_hash, signer=signer),
            confirmation=PostgresConfirmationRepo(),
            confirmation_approval=PostgresConfirmationApprovalRepo(),
            policy=PostgresPolicyRepo(),
            user=PostgresUserRepo(),
            api_key=PostgresApiKeyRepo(),
            vault=PostgresVaultRepo(),
            agent_run=PostgresAgentRunRepo(),
            memory=PostgresMemoryRepo(),
            circuit_breaker_state=PostgresCircuitBreakerStateRepo(),
            idempotency=PostgresIdempotencyRepo(),
            job=PostgresJobRepo(),
            schedule=PostgresScheduleRepo(),
            workflow=PostgresWorkflowRunRepo(),
            workflow_schedule=PostgresWorkflowScheduleRepo(),
            workflow_template=PostgresWorkflowTemplateRepo(),
            workflow_governance=PostgresWorkflowGovernanceRepo(),
            backend="postgresql",
        )
    raise ValueError(
        f"unsupported database backend {backend!r}; use sqlite:// or postgresql://"
    )
