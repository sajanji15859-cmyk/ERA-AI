"""AgentService — run lifecycle: start, pause, continue, inspect, stream (3A+3B).

The service drives the :class:`era.agents.loop.AgentLoop` and persists run
state. It resolves paused confirmations **from the append-only audit log** —
the agent only continues a task when the audit log proves the operator's
approval was executed (EXECUTED) or rejected (FAILED/REJECTED/DENIED/EXPIRED).
A pending confirmation that is still unresolved keeps the run paused.

Phase 3B adds:

* **Streaming** — ``start_run_stream`` / ``continue_run_stream`` yield typed
  :class:`~era.agents.events.AgentEvent`s as the loop executes (SSE-ready).
* **Role-based tool domain guard** — every tool call proposed by the model is
  checked against the RBAC capability-domain allowlist for the actor's role
  inside the loop itself, closing the gap between API-level RBAC and
  in-loop execution.
* **Event history** — a bounded, in-memory per-run event buffer (not
  persisted; replay is best-effort across a single server lifetime).

The service is the ONLY place the agent loop is entered; API routes call it
with the server-derived execution context.
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from typing import Any

from era.agents.budget import AgentBudget
from era.agents.events import AgentEvent, AgentEventType, EventBuffer
from era.agents.loop import AgentLoop
from era.agents.models import ApprovalResolution, Plan, RunRecord, RunStatus
from era.core.context import ExecutionContext
from era.core.enums import Outcome, RiskLevel
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import AgentRun
from era.models.confirmation import STATUS_DENIED, STATUS_EXPIRED, STATUS_USED
from era.security.rbac import role_domain_allowed

MAX_GOAL_LEN = 2000
MAX_BUFFERED_RUNS = 100

#: Audit outcomes that prove a resolved (terminal) confirmation.
_RESOLVED_OUTCOMES = {
    Outcome.EXECUTED.value: "executed",
    Outcome.FAILED.value: "failed",
    Outcome.REJECTED.value: "failed",
    Outcome.DENIED_BY_USER.value: "denied",
    Outcome.EXPIRED.value: "expired",
}

PlannerFactory = Callable[[AgentBudget, str], Any]
BrainFactory = Callable[[AgentBudget, str], Any]


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
        self._event_buffers: dict[str, deque[AgentEvent]] = defaultdict(
            lambda: deque(maxlen=EventBuffer().maxlen))
        self._buffers_lock = threading.Lock()

    # -- run lifecycle -----------------------------------------------------------
    def start_run(self, goal: str, ctx: ExecutionContext, *, role: str = "user",
                  approval_handler: Callable | None = None) -> RunRecord:
        goal = self._validate_goal(goal)
        run_id = uuid.uuid4().hex
        loop = self._new_loop(run_id, ctx, role, approval_handler, emit=None)
        record = loop.run(goal, ctx)
        self._persist(run_id, ctx, record)
        return record

    def continue_run(self, run_id: str, ctx: ExecutionContext, *, role: str = "user",
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

        loop = self._new_loop(run_id, ctx, role, approval_handler, emit=None)
        record = loop.resume(record, ctx, resolutions)
        self._persist(run_id, ctx, record)
        return record

    # -- streaming (Phase 3B) ------------------------------------------------------
    def start_run_stream(self, goal: str, ctx: ExecutionContext, *, role: str = "user",
                         approval_handler: Callable | None = None) -> Iterator[AgentEvent]:
        """Start a run, yielding its events live (SSE-ready)."""
        goal = self._validate_goal(goal)
        run_id = uuid.uuid4().hex

        def run_fn(emit):
            loop = self._new_loop(run_id, ctx, role, approval_handler, emit=emit)
            record = loop.run(goal, ctx)
            self._persist(run_id, ctx, record)
            return record

        yield from self._stream(run_id, run_fn)

    def continue_run_stream(self, run_id: str, ctx: ExecutionContext, *, role: str = "user"
                            ) -> Iterator[AgentEvent]:
        """Continue a paused run, yielding its events live (SSE-ready)."""
        row = self._get_row(run_id)
        if row is None or row.actor_id != ctx.actor_id:
            yield AgentEvent(run_id=run_id, seq=0, type=AgentEventType.ERROR,
                             data={"message": "agent run not found"})
            return
        record = self._record_from_row(row)
        if record.status is not RunStatus.WAITING_FOR_USER:
            yield self._final_event(record, len(self._events_of(run_id)))
            return
        resolutions = self._resolve_confirmations(record.pending_confirmations)
        if not resolutions:
            yield self._final_event(record, len(self._events_of(run_id)))
            return

        def run_fn(emit):
            loop = self._new_loop(run_id, ctx, role, None, emit=emit)
            resumed = loop.resume(record, ctx, resolutions)
            self._persist(run_id, ctx, resumed)
            return resumed

        yield from self._stream(run_id, run_fn)

    # -- inspection ---------------------------------------------------------------
    def get_run(self, run_id: str, actor_id: str) -> RunRecord | None:
        row = self._get_row(run_id)
        if row is None or row.actor_id != actor_id:
            return None
        return self._record_from_row(row)

    def list_runs(self, actor_id: str, limit: int = 50) -> list[RunRecord]:
        with transaction(self.session_factory) as session:
            rows = self.agent_run_repo.list_by_actor(session, actor_id, limit=limit)
            return [self._record_from_row(r) for r in rows]

    def get_events(self, run_id: str, actor_id: str) -> list[AgentEvent] | None:
        row = self._get_row(run_id)
        if row is None or row.actor_id != actor_id:
            return None
        return self._events_of(run_id)

    # -- streaming internals --------------------------------------------------------
    def _stream(self, run_id: str, run_fn: Callable[[Callable[[AgentEvent], None]], Any]
                ) -> Iterator[AgentEvent]:
        """Run ``run_fn`` on a worker thread; yield its events as they arrive."""
        q: queue.Queue[AgentEvent | None] = queue.Queue()
        buffer_cb = self._emit_callback(run_id)

        def sink(ev: AgentEvent) -> None:
            buffer_cb(ev)   # keep service history (replay endpoint)
            q.put(ev)       # live stream

        def worker() -> None:
            try:
                run_fn(sink)
            except Exception as exc:  # noqa: BLE001 — surface as an error event
                q.put(AgentEvent(run_id=run_id, seq=0, type=AgentEventType.ERROR,
                                 data={"message": f"agent run failed: {type(exc).__name__}: {exc}"}))
            finally:
                q.put(None)  # sentinel

        threading.Thread(target=worker, name=f"era-agent-run-{run_id[:8]}",
                         daemon=True).start()
        while True:
            item = q.get()
            if item is None:
                return
            yield item

    def _events_of(self, run_id: str) -> list[AgentEvent]:
        with self._buffers_lock:
            return sorted(self._event_buffers[run_id], key=lambda e: e.seq)

    def _emit_callback(self, run_id: str) -> Callable[[AgentEvent], None]:
        def cb(ev: AgentEvent) -> None:
            with self._buffers_lock:
                if len(self._event_buffers) > MAX_BUFFERED_RUNS and run_id not in self._event_buffers:
                    self._event_buffers.pop(next(iter(self._event_buffers)), None)
                self._event_buffers[run_id].append(ev)
        return cb

    def _final_event(self, record: RunRecord, seq: int) -> AgentEvent:
        result = record.result
        return AgentEvent(run_id=record.run_id, seq=seq, type=AgentEventType.RUN_FINISHED,
                          data={
                              "status": record.status.value,
                              "summary": result.summary,
                              "tasks_completed": result.tasks_completed,
                              "tasks_failed": result.tasks_failed,
                              "tasks_skipped": result.tasks_skipped,
                              "artifacts": result.artifacts,
                              "pending_confirmations": record.pending_confirmations,
                              "notes": result.notes,
                              "estimated_cost_usd": result.estimated_cost_usd,
                          })

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
            # Oldest-first: the FIRST terminal outcome is the truth. Later
            # "redundant resolution attempt" rejections (duplicate approve/
            # deny of an already-resolved confirmation) must never overwrite
            # the real outcome (Phase 3B fix).
            for entry in entries:  # oldest → newest
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
    def _new_loop(self, run_id: str, ctx: ExecutionContext, role: str,
                  approval_handler: Callable | None,
                  emit: Callable[[AgentEvent], None] | None) -> AgentLoop:
        budget = AgentBudget(
            max_iterations=int(self.settings.agent_max_iterations),
            max_tool_calls=int(self.settings.agent_max_tool_calls),
            max_retries_per_task=int(self.settings.agent_max_retries_per_task),
            max_llm_calls=int(self.settings.agent_max_llm_calls),
            max_llm_tokens_per_call=int(self.settings.agent_llm_max_tokens),
            timeout_seconds=float(self.settings.agent_run_timeout_seconds),
            cost_cap_usd=float(self.settings.agent_cost_cap_usd),
        )
        guard = self._domain_guard(role)
        sink = emit if emit is not None else self._emit_callback(run_id)
        return AgentLoop(
            execution_service=self.execution_service,
            planner=self.make_planner(budget, role),
            brain=self.make_brain(budget, role),
            verifier=self.verifier,
            budget=budget,
            run_id=run_id,
            long_term_memory=self.long_term_memory,
            approval_handler=approval_handler,
            max_replans=self.max_replans,
            emit=sink,
            domain_guard=guard,
            seq_start=len(self._events_of(run_id)),
        )

    def _domain_guard(self, role: str) -> Callable[[str], bool]:
        """RBAC capability-domain guard applied to every model-proposed tool."""
        catalog = self.execution_service.catalog

        def guard(action_type: str) -> bool:
            spec = catalog.get(action_type)
            if spec is None:
                return False
            if spec.risk_level is RiskLevel.FORBIDDEN:
                return False
            return role_domain_allowed(role, spec.capability_domain)

        return guard

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
