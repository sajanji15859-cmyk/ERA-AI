"""Registered workflow catalog (Phase 4C).

Workflows are registered here, validated at registration time against the
action catalog (fail closed). A workflow definition is a bounded, strict-schema
data structure — webpage content can never create, modify, start or alter a
workflow. The catalog is consulted by the workflow engine and the API layer;
only definitions that passed :func:`validate_workflow_definition` are ever run.
"""

from __future__ import annotations

from era.core.tool_registry import ActionCatalog
from era.security.hashing import canonical_json, sha256_hex
from era.workflows.definition import (
    DEFAULT_MAX_WORKFLOW_STEPS,
    WorkflowDefinition,
    WorkflowDefinitionError,
    validate_workflow_definition,
)


class WorkflowCatalog:
    """Name -> validated :class:`WorkflowDefinition` registry.

    Registering a definition runs the full registration-time validation and
    computes a stable checksum of the exact definition used, so a resumed run
    can verify it is still running the definition it started with.
    """

    def __init__(self, catalog: ActionCatalog, *,
                 max_steps: int = DEFAULT_MAX_WORKFLOW_STEPS):
        self.catalog = catalog
        self.max_steps = max_steps
        self._definitions: dict[str, WorkflowDefinition] = {}

    def register(self, definition: WorkflowDefinition,
                 *, max_steps: int | None = None) -> WorkflowDefinition:
        """Validate and register a workflow definition (idempotent by name).

        Re-registering the same name with an identical definition is allowed;
        a conflicting definition for an existing name is rejected.
        """
        step_cap = max_steps if max_steps is not None else self.max_steps
        validate_workflow_definition(definition, self.catalog, max_steps=step_cap)
        existing = self._definitions.get(definition.name)
        if existing is not None and self.checksum(existing) != self.checksum(definition):
            raise WorkflowDefinitionError(
                f"workflow {definition.name!r} is already registered with a "
                "different definition")
        self._definitions[definition.name] = definition
        return definition

    def get(self, name: str) -> WorkflowDefinition | None:
        return self._definitions.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._definitions

    def names(self) -> list[str]:
        return sorted(self._definitions)

    def list(self) -> list[WorkflowDefinition]:
        return [self._definitions[name] for name in self.names()]

    @staticmethod
    def checksum(definition: WorkflowDefinition) -> str:
        return sha256_hex(canonical_json(definition.model_dump(mode="json")))


def build_default_catalog(catalog: ActionCatalog) -> WorkflowCatalog:
    """Build the catalog pre-populated with the reference workflows."""
    from era.workflows.reference import REFERENCE_WORKFLOWS

    wf = WorkflowCatalog(catalog)
    for definition in REFERENCE_WORKFLOWS:
        wf.register(definition)
    return wf


__all__ = ["WorkflowCatalog", "build_default_catalog"]
