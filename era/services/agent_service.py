"""AgentService — run lifecycle: start, pause, continue, inspect (Phase 3A).

The service drives the :class:`era.agents.loop.AgentLoop` and persists run
state. It resolves paused confirmations **from the append-only audit log** —
the agent only continues a task when the audit log proves the operator's
approval was executed (EXECUTED) or rejected (FAILED/REJECTED/DENIED/EXPIRED).
A pending confirmation that is still unresolved keeps the run paused.

The service is the ONLY place the agent loop is entered; API routes call it
with the server-derived execution context.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from era.agents.budget import AgentBudget
from era.agents.loop import AgentLoop
from era.agents.models import ApprovalResolution, Plan, RunRecord, RunStatus
from era.core.context import ExecutionContext
from era.core.enums import Outcome
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import AgentRun
from era.models.confirmation import STATUS_DENIED, STATUS_EXPIRED, STATUS_USED

MAX_GOAL_LEN = 2000

#: Audit outcomes that prove a resolved (terminal) confirmation.
_RESOLVED_OUTCOMES = {
    Outcome.EXECUTED.value: "executed",
    Outcome.FAILED.value: "failed",
    Outcome.REJECTED.value: "failed",
    Outcome.DENIED_BY_USER.value: "denied",
    Outcome.EXPIRED.value: "expired",
}

PlannerFactory = Callable[[AgentBudget], Any]
BrainFactory = Callable[[AgentBudget], Any]


class AgentService:
    def __init__(self, *, session_factory, execution_service, confirmation_service,
                 audit_service, agent_run_repo, settings,
                 make_planner: PlannerFactory, make_brain: BrainFactory,
                 verifier, long_term_memory=None, max_replans: int = 1):
        self.session_factory = session_factory
        self.execution_service = execution_service
        self.confirmation_service = confirmation_service
        self.audit_service = audit_service
        self.agent_run_repo = agent_run_repo
        self.settings = settings
        self.make_planner = make_planner
        self.make_brain = make_brain
        self.verifier = verifier
        self.long_term_memory = long_term_memory
        self.max_replans = max_replans

    # -- run lifecycle -----------------------------------------------------------
    def start_run(self, goal: str, ctx: ExecutionContext,
                  approval_handler: Callable | None = None) -> RunRecord:
        goal = self._validate_goal(goal)
        run_id = uuid.uuid4().hex
        loop = self._new_loop(run_id, ctx, approval_handler)
        record = loop.run(goal, ctx)
        self._persist(run_id, ctx, record)
        return record

    def continue_run(self, run_id: str, ctx: ExecutionContext,
                     approval_handler: Callable | None = None) -> RunRecord | None:
        row = self._get_row(run_id)
        if row is None or row.actor_id != ctx.actor_id:
            return None
        record = self._record_from_row(row)
        if record.status is not RunStatus.WAITING_FOR_USER:
            return record  # idempotent: nothing to continue

        resolutions = self._resolve_confirmations(record.pending_confirmations)
        if not resolutions:
            return record  # still waiting for the operator

        loop = self._new_loop(run_id, ctx, approval_handler)
        record = loop.resume(record, ctx, resolutions)
        self._persist(run_id, ctx, record)
        return record

    def get_run(self, run_id: str, actor_id: str) -> RunRecord | None:
        row = self._get_row(run_id)
        if row is None or row.actor_id != actor_id:
            return None
        return self._record_from_row(row)

    def list_runs(self, actor_id: str, limit: int = 50) -> list[RunRecord]:
        with transaction(self.session_factory) as session:
            rows = self.agent_run_repo.list_by_actor(session, actor_id, limit=limit)
            return [self._record_from_row(r) for r in rows]

    # -- confirmation resolution ----------------------------------------------------
    def _resolve_confirmations(self, confirmation_ids: list[str]) -> list[ApprovalResolution]:
        resolutions: list[ApprovalResolution] = []
        for cid in confirmation_ids:
            resolution = self._resolve_one(cid)
            if resolution is not None:
                resolutions.append(resolution)
        return resolutions

    def _resolve_one(self, cid: str) -> ApprovalResolution | None:
        with transaction(self.session_factory) as session:
            entries = self.audit_service.list(session, confirmation_id=cid, limit=10)
            for entry in reversed(entries):  # newest first
                if entry.outcome in _RESOLVED_OUTCOMES:
                    outcome = _RESOLVED_OUTCOMES[entry.outcome]
                    return ApprovalResolution(
                        confirmation_id=cid, outcome=outcome,
                        note=entry.result or "",
                    )
            confirmation = self.confirmation_service.get(session, cid)
            if confirmation is not None and confirmation.status == STATUS_USED:
                # Approval was used but no terminal result was recorded —
                # fail closed rather than assume success.
                return ApprovalResolution(
                    confirmation_id=cid, outcome="failed",
                    note="approval used but no execution result recorded",
                )
            if confirmation is not None and confirmation.status in (STATUS_DENIED, STATUS_EXPIRED):
                outcome = "denied" if confirmation.status == STATUS_DENIED else "expired"
                return ApprovalResolution(confirmation_id=cid, outcome=outcome,
                                          note=f"confirmation {confirmation.status.lower()}")
        return None

    # -- persistence -----------------------------------------------------------------
    def _persist(self, run_id: str, ctx: ExecutionContext, record: RunRecord) -> None:
        with transaction(self.session_factory) as session:
            row = self.agent_run_repo.get(session, run_id)
            if row is None:
                row = AgentRun(id=run_id, actor_id=ctx.actor_id, goal=record.goal,
                               status=record.status.value)
                self.agent_run_repo.create(session, row)
            row.status = record.status.value
            row.plan_json = json.loads(record.plan.model_dump_json())
            row.tasks_json = json.loads(_tasks_json(record))
            row.result_json = json.loads(record.result.model_dump_json())
            row.pending_confirmations_json = list(record.pending_confirmations)
            row.error = record.error
            row.updated_at = utcnow_iso()
            self.agent_run_repo.update(session, row)

    def _get_row(self, run_id: str) -> AgentRun | None:
        with transaction(self.session_factory) as session:
            return self.agent_run_repo.get(session, run_id)

    @staticmethod
    def _record_from_row(row: AgentRun) -> RunRecord:
        plan_doc = row.plan_json or {}
        plan = Plan.model_validate(plan_doc) if plan_doc else Plan(goal=row.goal)
        tasks = []
        for doc in (row.tasks_json or []):
            from era.agents.models import Task
            try:
                tasks.append(Task.model_validate(doc))
            except Exception:  # noqa: BLE001,S112 — a corrupt row must not kill inspection
                continue
        from era.agents.models import AgentResult
        result_doc = row.result_json or {}
        result = AgentResult.model_validate(result_doc) if result_doc else AgentResult(
            status=RunStatus(row.status))
        return RunRecord(
            run_id=row.id, actor_id=row.actor_id, goal=row.goal,
            status=RunStatus(row.status), plan=plan, tasks=tasks, result=result,
            pending_confirmations=list(row.pending_confirmations_json or []),
            error=row.error,
        )

    # -- loop factory ----------------------------------------------------------------
    def _new_loop(self, run_id: str, ctx: ExecutionContext,
                  approval_handler: Callable | None) -> AgentLoop:
        budget = AgentBudget(
            max_iterations=int(self.settings.agent_max_iterations),
            max_tool_calls=int(self.settings.agent_max_tool_calls),
            max_retries_per_task=int(self.settings.agent_max_retries_per_task),
            max_llm_calls=int(self.settings.agent_max_llm_calls),
            max_llm_tokens_per_call=int(self.settings.agent_llm_max_tokens),
            timeout_seconds=float(self.settings.agent_run_timeout_seconds),
            cost_cap_usd=float(self.settings.agent_cost_cap_usd),
        )
        return AgentLoop(
            execution_service=self.execution_service,
            planner=self.make_planner(budget),
            brain=self.make_brain(budget),
            verifier=self.verifier,
            budget=budget,
            run_id=run_id,
            long_term_memory=self.long_term_memory,
            approval_handler=approval_handler,
            max_replans=self.max_replans,
        )

    # -- helpers -----------------------------------------------------------------------
    @staticmethod
    def _validate_goal(goal: str) -> str:
        if not isinstance(goal, str) or not goal.strip():
            raise ValueError("goal must be a non-empty string")
        goal = goal.strip()
        if len(goal) > MAX_GOAL_LEN:
            raise ValueError("goal too long")
        return goal


def _tasks_json(record: RunRecord) -> str:
    return json.dumps([json.loads(t.model_dump_json()) for t in record.tasks])
