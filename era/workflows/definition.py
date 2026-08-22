"""Strict-schema workflow definition layer (Phase 4C).

A workflow is a bounded, ordered list of steps. Each step references exactly
one catalogued browser action with a *params template*. Steps may declare an
``expect`` post-condition (reusing the Phase 4B ``expect`` mechanism), a
``verify`` label (for observability), a target-acquisition descriptor
(``role``/``name``/``tag``) that the runtime resolves to a *fresh*
``element_ref`` at execution time, and a fail-closed denial policy.

Security rules enforced here at definition/registration time:

* Every step action must be a catalogued browser action from an explicit
  allowlist (``navigate``, ``inspect``, ``click``, ``fill``, ``submit``,
  ``download``, ``upload``, ``tabs``, ``activate_tab``, ``extract_dom``,
  ``screenshot``). Workflow actions can never contain themselves or each other
  (no unbounded recursion).
* ``browser.fill`` steps MUST use a ``vault:browser/<name>`` ``value_ref`` —
  plaintext ``text`` in a fill step is rejected (a plaintext secret step is
  never allowed). Browser observations are untrusted data and can never define
  or start a workflow.
* Every step's rendered params must satisfy the action's strict param schema
  (``additionalProperties: false``).
* Cycles, unknown dependencies, duplicate step ids and unbounded structures
  (over ``max_steps``, over-long params) are rejected.

Targets are acquired at run time by re-inspecting the current page; a workflow
definition NEVER carries a persisted ``element_ref`` value. ``{{name}}``
placeholders in params are rendered from the caller-supplied workflow params
at run time.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from era.core.result import ProviderErrorCode, ToolError
from era.core.tool_registry import ActionCatalog
from era.registry.actions import ActionType
from era.security.redaction import REDACTED, is_secret_key
from era.security.validation import ValidationError_, validate_param_schema, validate_params
from era.security.vault import parse_vault_ref

#: Actions a workflow step may reference (browser.* allowlist, exactly the
#: catalogued browser action set minus the workflow-run action itself).
ALLOWED_STEP_ACTIONS: frozenset[str] = frozenset({
    ActionType.BROWSER_NAVIGATE.value,
    ActionType.BROWSER_SCREENSHOT.value,
    ActionType.BROWSER_EXTRACT_DOM.value,
    ActionType.BROWSER_CLICK.value,
    ActionType.BROWSER_FILL.value,
    ActionType.BROWSER_SUBMIT.value,
    ActionType.BROWSER_INSPECT.value,
    ActionType.BROWSER_TABS.value,
    ActionType.BROWSER_ACTIVATE_TAB.value,
    ActionType.BROWSER_DOWNLOAD.value,
    ActionType.BROWSER_UPLOAD.value,
})

#: Mutating browser actions — a workflow containing any of these is treated as
#: a mutating workflow (its workflow-level default decision is conservatively
#: CONFIRM / MUTATING).
MUTATING_STEP_ACTIONS: frozenset[str] = frozenset({
    ActionType.BROWSER_CLICK.value,
    ActionType.BROWSER_FILL.value,
    ActionType.BROWSER_SUBMIT.value,
    ActionType.BROWSER_DOWNLOAD.value,
    ActionType.BROWSER_UPLOAD.value,
})

#: Default cap on the number of steps in a single workflow definition.
DEFAULT_MAX_WORKFLOW_STEPS = 50
#: Default cap on total rendered-param characters across all steps.
DEFAULT_MAX_WORKFLOW_PARAM_CHARS = 16384

#: Synthetic element_ref used ONLY for definition-time schema validation. It is
#: never persisted and never dispatched; the runtime replaces it with a fresh,
#: provider-issued ref after re-inspecting the current page.
_SYNTHETIC_REF = "er_" + "w" * 40

#: ``{{name}}`` placeholder pattern.
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_\-]+)\s*\}\}")

#: Step id / workflow name identifier constraint.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}$")

_TARGET_KEYS = frozenset({"role", "name", "tag", "input_type", "frame_id", "index"})

#: Expect keys are validated against the Phase 4B browser post-condition schema.
_EXPECT_KINDS = frozenset({"navigation", "tab_opened", "element_detached"})


class WorkflowDefinitionError(ValueError):
    """A workflow definition is malformed / unsafe (fail closed at registration)."""

    def __init__(self, message: str, *, code: str = "validation"):
        super().__init__(message)
        self.code = code


def _fail(message: str, *, code: str = "validation") -> None:
    raise WorkflowDefinitionError(message, code=code)


class WorkflowTarget(BaseModel):
    """Inspect-time target descriptor resolved to a fresh element_ref at run time.

    ``index`` disambiguates when several elements match (0-based). The runtime
    re-inspects the current page and requires exactly one matching element
    (or the indexed element when ``index`` is supplied) or the step fails
    closed with a deterministic error — it never invents a reference.
    """

    model_config = ConfigDict(extra="forbid")

    role: str | None = None
    name: str | None = None
    tag: str | None = None
    input_type: str | None = None
    frame_id: str | None = None
    #: 0-based index to disambiguate when several elements match. ``None``
    #: (default) means the descriptor must match exactly one element — a
    #: multi-match then fails closed rather than guessing.
    index: int | None = Field(default=None, ge=0)

    def matches(self, element: dict[str, Any]) -> bool:
        return (
            (self.role is None or element.get("role") == self.role)
            and (self.name is None or element.get("name") == self.name)
            and (self.tag is None or element.get("tag") == self.tag)
            and (self.input_type is None or element.get("input_type") == self.input_type)
            and (self.frame_id is None or element.get("frame_id") == self.frame_id)
        )


class WorkflowExpect(BaseModel):
    """Deterministic post-condition (reuses the Phase 4B ``expect`` mechanism)."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    url_contains: str | None = None


#: Allowed pure predicate kinds over prior step receipts/observations.
ALLOWED_CONDITION_KINDS = frozenset({
    "step_result",   # step_result of a prior step equals/not-equals value
    "url_contains",  # a prior inspect/navigate observation contains a string
    "element_present",  # a prior inspect observation matched an element
})
_CONDITION_OPS = frozenset({"==", "!="})


class WorkflowCondition(BaseModel):
    """A pure, schema-constrained predicate over prior step observations.

    Never arbitrary code and never driven by raw webpage text. The predicate is
    evaluated only against sanitized step receipts produced by the run itself
    (e.g. an ``inspect`` URL, a ``step_result`` value, an ``element_present``
    boolean) — never against unredacted page content.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str
    #: Prior step id for ``step_result`` / ``element_present``.
    step_id: str | None = None
    #: ``==`` or ``!=`` (only used by ``step_result``).
    op: str | None = None
    #: Scalar comparison value (string / bool / int / float / null).
    value: Any = None

    @model_validator(mode="after")
    def _validate(self) -> WorkflowCondition:
        if self.kind not in ALLOWED_CONDITION_KINDS:
            _fail(f"condition.kind must be one of {sorted(ALLOWED_CONDITION_KINDS)}")
        if self.op is not None and self.op not in _CONDITION_OPS:
            _fail("condition.op must be '==' or '!='")
        if self.kind == "step_result":
            if not self.step_id:
                _fail("step_result condition requires step_id")
            if self.op not in _CONDITION_OPS:
                _fail("step_result condition requires op '==' or '!='")
            if not isinstance(self.value, (str, bool, int, float)) and self.value is not None:
                _fail("step_result condition value must be a scalar or null")
        elif self.kind == "url_contains":
            if self.value is None or not isinstance(self.value, str) or not self.value:
                _fail("url_contains condition requires a non-empty string value")
            if len(self.value) > 1000:
                _fail("url_contains condition value too long")
        elif self.kind == "element_present":
            if not self.step_id:
                _fail("element_present condition requires step_id")
        return self


class WorkflowParallelBlock(BaseModel):
    """A bounded parallel group of existing steps (no new step kinds).

    ``depends_on`` lets an entire group wait on prior steps; ``max_concurrency``
    is the hard cap for the block (default 1 = the historical sequential
    behavior).
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    max_concurrency: int = Field(default=1, ge=1, le=8)

    @model_validator(mode="after")
    def _validate(self) -> WorkflowParallelBlock:
        if len(self.steps) < 2:
            _fail("parallel block must contain at least two steps")
        if len(set(self.steps)) != len(self.steps):
            _fail("parallel block contains duplicate step ids")
        for sid in self.steps + self.depends_on:
            if not _IDENTIFIER_RE.match(sid):
                _fail(f"parallel block references invalid step id {sid!r}")
        return self


class WorkflowStep(BaseModel):
    """One workflow step referencing exactly one catalogued browser action."""

    model_config = ConfigDict(extra="forbid")

    id: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)
    target: WorkflowTarget | None = None
    expect: WorkflowExpect | None = None
    #: ``"stop"`` (default) or ``"skip"`` when a required confirmation is denied.
    on_denied: str = Field(default="stop")
    #: Free-text description (observability only).
    description: str | None = None
    #: Optional name of a workflow param to capture a sanitized bit of the step
    #: result into (used by the reference verify step). Never secrets.
    outputs: dict[str, str] = Field(default_factory=dict)
    #: Phase 4D: explicit DAG dependency list (empty = before any dependent).
    depends_on: list[str] = Field(default_factory=list)
    #: Phase 4D: pure predicate over prior step receipts/observations.
    condition: WorkflowCondition | None = None

    @model_validator(mode="after")
    def _validate(self) -> WorkflowStep:
        if not _IDENTIFIER_RE.match(self.id):
            _fail("step id must be 1-64 chars of [A-Za-z0-9_-] starting alphanumeric")
        if self.action not in ALLOWED_STEP_ACTIONS:
            _fail(f"step {self.id!r} references a non-workflow/uncatalogued action "
                  f"{self.action!r}")
        if self.on_denied not in ("stop", "skip"):
            _fail("on_denied must be 'stop' or 'skip'")
        if self.expect is not None and self.expect.kind not in _EXPECT_KINDS:
            _fail("expect.kind must be navigation, tab_opened or element_detached")
        if self.target is not None and self.target.index is not None \
                and self.target.index < 0:
            _fail("target.index must be >= 0")
        if len(self.depends_on) > 8:
            _fail("step depends_on is limited to 8 dependencies (bounded fan-out)")
        if self.id in self.depends_on:
            _fail(f"step {self.id!r} cannot depend on itself")
        for dep in self.depends_on:
            if not _IDENTIFIER_RE.match(dep):
                _fail(f"step {self.id!r} references invalid dependency {dep!r}")
        if self.condition is not None and self.condition.step_id == self.id:
            _fail(f"step {self.id!r} condition cannot reference itself")
        return self


class WorkflowDefinition(BaseModel):
    """A bounded, declarative multi-step browser workflow definition."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: int = 1
    description: str | None = None
    #: Optional JSON-schema describing caller-supplied params (for placeholders).
    params_schema: dict[str, Any] = Field(default_factory=dict)
    steps: list[WorkflowStep] = Field(default_factory=list)
    #: Phase 4D: bounded parallel blocks over the declared steps.
    parallel: list[WorkflowParallelBlock] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> WorkflowDefinition:
        if not _IDENTIFIER_RE.match(self.name):
            _fail("workflow name must be 1-64 chars of [A-Za-z0-9_-] "
                  "starting alphanumeric")
        if not isinstance(self.version, int) or self.version < 1:
            _fail("workflow version must be a positive integer")
        if not self.steps:
            _fail("a workflow must have at least one step")
        ids: set[str] = set()
        for step in self.steps:
            if step.id in ids:
                _fail(f"duplicate step id: {step.id!r}")
            ids.add(step.id)
        if self.parallel:
            seen_parallel: set[str] = set()
            for block in self.parallel:
                for sid in block.steps:
                    if sid not in ids:
                        _fail(f"parallel block references unknown step {sid!r}")
                    if sid in seen_parallel:
                        _fail(f"step {sid!r} appears in more than one parallel block")
                    seen_parallel.add(sid)
        return self


#: Synthetic value used ONLY for definition-time shape validation of rendered
#: params (placeholders are substituted with a token; never dispatched).
_SYNTH_PLACEHOLDER = "wf-param"


def _render(value: Any, params: dict[str, Any] | None, *, path: str,
            lax: bool = False) -> Any:
    """Render ``{{name}}`` placeholders in a params template (fail closed).

    When ``lax`` is True (registration-time shape validation only) a placeholder
    is substituted with a synthetic token instead of requiring the workflow
    params; the token is never dispatched or persisted.
    """
    if isinstance(value, str):
        if not _PLACEHOLDER_RE.search(value):
            return value
        if lax:
            return _PLACEHOLDER_RE.sub(lambda _m: _SYNTH_PLACEHOLDER, value)
        if not params:
            _fail(f"step param placeholder referenced with no workflow params at {path}")
        rendered = _PLACEHOLDER_RE.sub(
            lambda m: _lookup(m.group(1), params, path), value)
        # Unknown placeholder left verbatim would pass through to the provider
        # as literal text; fail closed instead.
        if "{{" in rendered or "}}" in rendered:
            _fail(f"unresolved placeholder at {path}")
        return rendered
    if isinstance(value, dict):
        return {k: _render(v, params, path=f"{path}.{k}", lax=lax)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_render(x, params, path=f"{path}[{i}]", lax=lax)
                for i, x in enumerate(value)]
    return value


def _lookup(name: str, params: dict[str, Any], path: str) -> str:
    if name not in params:
        _fail(f"workflow param {name!r} not supplied (placeholder at {path})")
    value = params[name]
    if value is None:
        _fail(f"workflow param {name!r} is None (placeholder at {path})")
    if not isinstance(value, (str, int, float)):
        _fail(f"workflow param {name!r} is not a scalar (placeholder at {path})")
    return str(value)


def render_workflow_params(step: WorkflowStep, params: dict[str, Any],
                           *, lax: bool = False) -> dict[str, Any]:
    """Render a step's params template against the workflow-level params."""
    return _render(dict(step.params or {}), params, path=f"step.{step.id}", lax=lax)


def render_step_expect(step: WorkflowStep, params: dict[str, Any],
                       *, lax: bool = False) -> dict[str, Any] | None:
    """Render a step's ``expect`` post-condition (placeholders like url_contains)."""
    if step.expect is None:
        return None
    payload = step.expect.model_dump(mode="json")
    return _render(payload, params, path=f"step.{step.id}.expect", lax=lax)


def _is_vault_or_placeholder(ref: Any) -> bool:
    """True if ``ref`` is an opaque vault:browser ref or a ``{{name}}`` template."""
    if not isinstance(ref, str) or not ref.strip():
        return False
    if parse_vault_ref(ref) is not None:
        return True
    return bool(_PLACEHOLDER_RE.fullmatch(ref.strip()))


def _inject_target(step: WorkflowStep, rendered: dict[str, Any]) -> dict[str, Any]:
    """Inject the run-time target placeholder if the step declares a target.

    The caller replaces ``element_ref`` with a fresh, provider-issued ref after
    re-inspecting the current page. A synthetic ref is used only for the
    definition-time schema check; it is never dispatched or persisted.
    """
    effective = dict(rendered)
    if step.target is not None:
        # A target descriptor is the targeting mode; it must not also carry the
        # alternative target fields (element_ref/selector). ``text``/``value_ref``
        # are the fill value and are allowed alongside the injected ref.
        for forbidden in ("element_ref", "selector"):
            if forbidden in effective:
                _fail(f"step {step.id!r} declares a target and must not also set "
                      f"{forbidden!r}")
        effective["element_ref"] = _SYNTHETIC_REF
    return effective


def _char_budget(steps: list[WorkflowStep]) -> int:
    return sum(_approx_chars(s.params) for s in steps)


def _approx_chars(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(_approx_chars(v) for v in value.values())
    if isinstance(value, list):
        return sum(_approx_chars(v) for v in value)
    return len(str(value))


def _step_ids(definition: WorkflowDefinition) -> dict[str, WorkflowStep]:
    return {step.id: step for step in definition.steps}


def _validate_dag(definition: WorkflowDefinition) -> None:
    """Validate the bounded DAG: cycles, unknown deps, unbounded fan-out."""
    by_id = _step_ids(definition)
    if len(by_id) != len(definition.steps):
        _fail("duplicate step id")

    edges: dict[str, list[str]] = {sid: [] for sid in by_id}
    indegree: dict[str, int] = {sid: 0 for sid in by_id}
    for step in definition.steps:
        for dep in step.depends_on:
            if dep not in by_id:
                _fail(f"step {step.id!r} depends on unknown step {dep!r}")
            edges[dep].append(step.id)
            indegree[step.id] += 1

    # Unbounded fan-out rejection: no step may be depended on by > 8 steps.
    for sid, deps in edges.items():
        if len(deps) > 8:
            _fail(f"step {sid!r} has unbounded fan-out ({len(deps)} dependents)")

    # Kahn topological sort; a remaining node means a cycle (after counting
    # only declared edges).
    queue = deque(sid for sid, deg in indegree.items() if deg == 0)
    seen = 0
    while queue:
        node = queue.popleft()
        seen += 1
        for nxt in edges[node]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)
    if seen != len(by_id):
        _fail("workflow step dependency graph contains a cycle")


def _validate_parallel(definition: WorkflowDefinition) -> None:
    """Validate parallel blocks against the graph (bounded, fail closed)."""
    by_id = _step_ids(definition)
    step_to_block: dict[str, WorkflowParallelBlock] = {}
    for block in definition.parallel:
        for sid in block.steps:
            # A step can only live in one block (checked in model validator too).
            if sid in step_to_block:
                _fail(f"step {sid!r} appears in more than one parallel block")
            step_to_block[sid] = block
        for dep in block.depends_on:
            if dep not in by_id:
                _fail(f"parallel block depends on unknown step {dep!r}")

    for sid, block in step_to_block.items():
        step = by_id[sid]
        # Reject a dependency on a parallel sibling's conditional outcome: a
        # sibling's condition may divide the branch, so a sibling dependency
        # inside the same block is not deterministic.
        for dep in step.depends_on + list(block.depends_on):
            if dep in block.steps:
                _fail(f"step {sid!r} depends on a parallel sibling's conditional "
                      "outcome inside the same block")
        # A condition inside a parallel block must reference a completed
        # predecessor outside the block, never a sibling.
        if step.condition is not None and step.condition.step_id in block.steps:
            _fail(f"parallel step {sid!r} condition cannot reference a sibling")


def validate_workflow_definition(
    definition: WorkflowDefinition,
    catalog: ActionCatalog,
    *,
    max_steps: int = DEFAULT_MAX_WORKFLOW_STEPS,
    max_param_chars: int = DEFAULT_MAX_WORKFLOW_PARAM_CHARS,
) -> WorkflowDefinition:
    """Validate a definition against the catalog (fail closed). Idempotent.

    Performs all registration-time checks and returns the validated definition
    unchanged. Any failure raises :class:`WorkflowDefinitionError`.
    """
    if len(definition.steps) > max_steps:
        _fail(f"workflow exceeds the maximum of {max_steps} steps")
    if _char_budget(definition.steps) > max_param_chars:
        _fail(f"workflow params exceed the maximum of {max_param_chars} characters")

    seen_ids: set[str] = set()
    for step in definition.steps:
        if step.id in seen_ids:
            _fail(f"duplicate step id: {step.id!r}")
        seen_ids.add(step.id)
        spec = catalog.get(step.action)
        if spec is None:
            _fail(f"step {step.id!r} references unknown action {step.action!r}")
        if step.action not in ALLOWED_STEP_ACTIONS:
            _fail(f"step {step.id!r} references a non-workflow action {step.action!r}")

        # Fail-closed secret rule (Priority 8): a workflow fill that targets a
        # password (or whose sensitivity is unknown because no target is given)
        # MUST use an opaque vault:browser/<name> value_ref — never plaintext.
        # Non-secret text fills are permitted only when the target explicitly
        # declares a non-password input type. Browser observations are never a
        # value source.
        if step.action == ActionType.BROWSER_FILL.value:
            if step.target is not None and step.target.input_type == "password" \
                    and "value_ref" not in step.params:
                _fail(f"step {step.id!r} fills a password field but has no "
                      "value_ref — use vault:browser/<name>")
            if step.target is None and "value_ref" not in step.params:
                _fail(f"step {step.id!r} is a browser.fill with no target descriptor "
                      "and no value_ref — its sensitivity is unknown, so it must "
                      "reference vault:browser/<name>")
            if "value_ref" in step.params:
                value_ref = step.params.get("value_ref")
                if not _is_vault_or_placeholder(value_ref):
                    _fail(f"step {step.id!r} value_ref must be a "
                          "vault:browser/<name> reference or {{name}} template")
            if "text" in step.params and "value_ref" in step.params:
                _fail(f"step {step.id!r} sets both text and value_ref")

        # Validate the rendered params shape against the strict action schema.
        # ``lax`` renders ``{{name}}`` templates with synthetic tokens for shape
        # checking only (never dispatched / persisted).
        effective = _inject_target(step, render_workflow_params(step, None, lax=True))
        try:
            validate_params(effective)
            if spec.param_schema is not None:
                validate_param_schema(effective, spec.param_schema)
        except ValidationError_ as exc:
            _fail(f"step {step.id!r} params fail schema validation: {exc}")
        except Exception as exc:  # noqa: BLE001 - fail closed on any schema error
            _fail(f"step {step.id!r} params could not be validated: {exc}")

    # Phase 4D graph validation (cycles, unknown deps, bounded fan-out).
    _validate_dag(definition)
    _validate_parallel(definition)
    return definition


def redact_run_params(params: dict[str, Any]) -> dict[str, Any]:
    """Redact caller-supplied run params for durable storage.

    Opaque vault references (``vault:browser/<name>``) are always preserved —
    they are references, never secrets, and the engine must be able to re-render
    step templates on resume. Any value under a secret-hinting key that is NOT a
    vault reference is redacted.
    """
    def _is_vault(value: Any) -> bool:
        return isinstance(value, str) and parse_vault_ref(value) is not None

    def rec(v: Any) -> Any:
        if isinstance(v, dict):
            out: dict[str, Any] = {}
            for k, val in v.items():
                if _is_vault(val):
                    out[k] = val
                elif is_secret_key(k):
                    out[k] = REDACTED
                elif isinstance(val, (dict, list)):
                    out[k] = rec(val)
                else:
                    out[k] = val
            return out
        if isinstance(v, list):
            return [rec(x) if isinstance(x, (dict, list)) else x for x in v]
        return v

    return rec(dict(params or {}))


def redact_definition(definition: WorkflowDefinition) -> dict[str, Any]:
    """Redact a definition for durable storage / display.

    Workflow definitions already forbid plaintext secrets (fills use opaque
    vault refs), so this is a conservative deep redaction of any key whose name
    hints at a secret plus a sanitized step list. Vault references stay visible
    as opaque references so approvals can resubmit the exact hash-bound action.
    """
    from era.security.redaction import redact
    payload = definition.model_dump(mode="json")
    payload = redact(payload)
    # Opaque vault references must remain visible (they are not plaintext).
    return payload


def make_run_error(message: str, *, code: str = "workflow") -> ToolError:
    """A deterministic workflow-level error surfaced to callers."""
    try:
        error_code = ProviderErrorCode(code)
    except ValueError:
        error_code = ProviderErrorCode.PROVIDER_ERROR
    return ToolError(message, provider_id="workflow", code=error_code)


def is_mutating(definition: WorkflowDefinition) -> bool:
    """True if any inner step is mutating (drives the workflow-level risk)."""
    return any(step.action in MUTATING_STEP_ACTIONS for step in definition.steps)


REDACTED_MARKER = REDACTED
__all__ = [
    "ALLOWED_CONDITION_KINDS",
    "ALLOWED_STEP_ACTIONS",
    "DEFAULT_MAX_WORKFLOW_STEPS",
    "MUTATING_STEP_ACTIONS",
    "REDACTED_MARKER",
    "WorkflowCondition",
    "WorkflowDefinition",
    "WorkflowDefinitionError",
    "WorkflowExpect",
    "WorkflowParallelBlock",
    "WorkflowStep",
    "WorkflowTarget",
    "is_mutating",
    "make_run_error",
    "redact_definition",
    "redact_run_params",
    "render_step_expect",
    "render_workflow_params",
    "validate_workflow_definition",
]
