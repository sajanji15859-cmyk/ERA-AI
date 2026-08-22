"""Phase 4C — durable, resumable, exactly-once browser workflows.

This package defines the strict-schema workflow definition layer and the
registered workflow catalog. The execution engine lives in
:mod:`era.services.workflow_service` and only ever dispatches inner steps
through :class:`era.services.execution_service.ExecutionService`.
"""

from era.workflows.catalog import WorkflowCatalog
from era.workflows.definition import (
    WorkflowDefinition,
    WorkflowDefinitionError,
    WorkflowStep,
    WorkflowTarget,
    redact_run_params,
    render_workflow_params,
    validate_workflow_definition,
)

__all__ = [
    "WorkflowCatalog",
    "WorkflowDefinition",
    "WorkflowDefinitionError",
    "WorkflowStep",
    "WorkflowTarget",
    "redact_run_params",
    "render_workflow_params",
    "validate_workflow_definition",
]
