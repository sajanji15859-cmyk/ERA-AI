"""The ERA agent execution loop (Phase 3A, instrumented in 3B).

PLAN → EXECUTE → OBSERVE → VERIFY → SUCCESS
                      ↓ failure
                ANALYZE → RETRY (bounded) → RE-VERIFY
                      ↓ exhausted
                FAIL (→ one bounded replan with repair tasks)

Safety properties (enforced here, in code):

* Every tool call goes through the ExecutionService — the same permission
  engine, confirmation gate, audit-before-execute and reliability layer as any
  API caller. The loop never touches providers directly.
* Tool selection is gated *before* execution: the action must be catalogued,
  have a registered provider, pass the RBAC capability-domain guard for the
  actor's role, and not be FORBIDDEN. Gate rejections are final (no retry —
  they are not transient failures).
* The loop is a plain ``while`` bounded by the AgentBudget (iterations, tool
  calls, LLM calls, wall-clock timeout, cost cap). Any breach ends the run as
  ``BUDGET_EXCEEDED`` — an infinite loop is structurally impossible.
* ``confirmation_required`` pauses the loop (task → ``waiting_for_user``); the
  run resumes only with resolutions derived from the append-only audit log,
  so the agent can never "believe" an approval that did not happen.
* Every step emits typed events (3B) for streaming; event payloads are
  redacted and size-bounded.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any, Literal

from era.agents.budget import AgentBudget
from era.agents.events import AgentEvent, AgentEventType, summarize_params
from era.agents.memory import LongTermMemoryService, ShortTermMemory
from era.agents.models import (
    AgentResult,
    ApprovalResolution,
    Observation,
    Plan,
    RunRecord,
    RunStatus,
    Task,
    TaskStatus,
)
from era.agents.task_manager import TaskManager
from era.agents.verifier import Verifier
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import RiskLevel
from era.core.result import ToolError

ApprovalChoice = Literal["approve", "deny", "wait"]
ApprovalHandler = Callable[[Action, Any], ApprovalChoice]
EmitFn = Callable[[AgentEvent], None]
DomainGuard = Callable[[str], bool]

MAX_EVENTS_KEPT = 500


class AgentLoop:
    """Drives one run (or one resume segment) to completion or pause."""

    def __init__(self, *, execution_service, planner, brain, verifier: Verifier,
                 budget: AgentBudget, run_id: str,
                 long_term_memory: LongTermMemoryService | None = None,
                 approval_handler: ApprovalHandler | None = None,
                 max_replans: int = 1,
                 emit: EmitFn | None = None,
                 domain_guard: DomainGuard | None = None,
                 seq_start: int = 0):
        self.execution_service = execution_service
        self.planner = planner
        self.brain = brain
        self.verifier = verifier
        self.budget = budget
        self.run_id = run_id
        self.long_term_memory = long_term_memory
        self.approval_handler = approval_handler
        self.max_replans = max_replans
        self.emit = emit
        self.domain_guard = domain_guard
        self._seq = seq_start
        self.events: deque[AgentEvent] = deque(maxlen=MAX_EVENTS_KEPT)

    # -- event emission ----------------------------------------------------------
    def _emit(self, type_: AgentEventType, **data: Any) -> None:
        ev = AgentEvent(run_id=self.run_id, seq=self._seq, type=type_, data=data)
        self._seq += 1
        self.events.append(ev)
        if self.emit is not None:
            try:
                self.emit(ev)
            except Exception:  # noqa: BLE001,S110 — a broken sink must never break the run
                pass

    # -- entry points -----------------------------------------------------------
    def run(self, goal: str, ctx: ExecutionContext, plan: Plan | None = None) -> RunRecord:
        """Execute a fresh run for ``goal``."""
        self._emit(AgentEventType.RUN_STARTED, goal=goal, resumed=False)
        memory = ShortTermMemory(goal=goal)
        if plan is None:
            plan = self.planner.plan(goal)
        self._emit(AgentEventType.PLAN_CREATED, summary=plan.summary,
                   task_count=len(plan.tasks), created_by=plan.created_by)
        memory.remember("actor_id", ctx.actor_id)
        memory.remember("subject", _subject_of(plan))
        memory.remember("tool_catalog", _tool_catalog(self.execution_service))
        return self._drive(goal, ctx, plan, memory)

    def resume(self, previous: RunRecord, ctx: ExecutionContext,
               resolutions: list[ApprovalResolution]) -> RunRecord:
        """Resume a paused run after confirmation resolutions."""
        self._emit(AgentEventType.RUN_STARTED, goal=previous.goal, resumed=True)
        plan = previous.plan
        memory = ShortTermMemory(goal=previous.goal)
        memory.rebuild_from_tasks(previous.tasks)
        memory.remember("actor_id", ctx.actor_id)
        memory.remember("subject", _subject_of(plan))
        memory.remember("tool_catalog", _tool_catalog(self.execution_service))
        self.budget.restore(_budget_snapshot(previous))

        tm = TaskManager(previous.tasks)
        resolved = {r.confirmation_id: r for r in resolutions}
        for task in tm.waiting():
            entries = [resolved[cid] for cid in task.waiting_on if cid in resolved]
            if not entries:
                continue
            if any(r.outcome == "executed" for r in entries):
                tm.complete(task)
                self._emit(AgentEventType.TASK_COMPLETED, task_id=task.id,
                           note="approval executed (from audit log)")
            else:
                note = entries[-1].note or \
                    f"confirmation resolved as {entries[-1].outcome}"
                tm.fail(task, note)
                self._emit(AgentEventType.TASK_FAILED, task_id=task.id, error=note)
        return self._drive(previous.goal, ctx, plan, memory, tm)

    # -- the loop ---------------------------------------------------------------
    def _drive(self, goal: str, ctx: ExecutionContext, plan: Plan,
               memory: ShortTermMemory, tm: TaskManager | None = None) -> RunRecord:
        tm = tm or TaskManager(plan.tasks)
        replans = 0

        while True:
            # -- budget gate ---------------------------------------------------
            reason = self.budget.check()
            if reason is not None:
                return self._final(goal, ctx, plan, tm, memory, RunStatus.BUDGET_EXCEEDED,
                                   notes=[f"run stopped: {reason}"])

            # -- pick the next ready task --------------------------------------
            task = tm.next_ready()
            if task is None:
                if not tm.has_pending():
                    break
                # Deadlock handling: skip blocked tasks first; if nothing is
                # blocked but nothing is ready either (dependency cycle /
                # unknown dependency), skip the rest so the loop always
                # terminates — it can never spin forever.
                blocked = tm.blocked_pending()
                for dead in (blocked or tm.pending()):
                    tm.skip(dead, "dependency could not be satisfied "
                                  "(failed, cycle or unknown dependency)")
                    self._emit(AgentEventType.TASK_SKIPPED, task_id=dead.id,
                               reason=dead.error)
                continue

            self.budget.iterations += 1
            tm.mark_running(task)
            self._emit(AgentEventType.TASK_STARTED, task_id=task.id,
                       title=task.title, action_type=task.action_type,
                       attempt=task.attempt, required=task.required)

            # -- execute (brain → tool call → ExecutionService) -----------------
            try:
                params = self.brain.prepare(task, memory)
                calls = self.brain.propose_tool_calls(task, memory, params)
            except ToolError as exc:
                tm.record_observation(task, _obs(task.id, task.action_type,
                                                 "failed", error=str(exc)))
                self._emit(AgentEventType.OBSERVATION, task_id=task.id,
                           action_type=task.action_type, status="failed",
                           error=str(exc))
                self._settle_failure(tm, task, memory, str(exc))
                continue

            calls = [c for c in calls if c and c.action_type]
            if not calls:
                tm.fail(task, "brain proposed no tool call")
                self._emit(AgentEventType.TASK_FAILED, task_id=task.id,
                           error=task.error or "no tool call")
                continue

            # -- tool-selection gate (fail closed, final — never retried) ------
            gate_reason = self._gate_reject(calls[0].action_type)
            if gate_reason is not None:
                tm.fail(task, gate_reason)
                tm.record_observation(task, _obs(task.id, calls[0].action_type,
                                                 "denied", error=gate_reason))
                self._emit(AgentEventType.OBSERVATION, task_id=task.id,
                           action_type=calls[0].action_type, status="denied",
                           error=gate_reason)
                self._emit(AgentEventType.TASK_FAILED, task_id=task.id,
                           error=gate_reason)
                continue

            observation = None
            denied = False
            for call in calls:
                guard = self.budget.can_tool_call()
                if guard is not None:
                    return self._final(goal, ctx, plan, tm, memory,
                                       RunStatus.BUDGET_EXCEEDED, notes=[f"run stopped: {guard}"])
                self.budget.record_tool_call()

                self._emit(AgentEventType.TOOL_CALL, task_id=task.id,
                           action_type=call.action_type,
                           params=self._event_params(call.action_type, call.params))

                action = Action(action_type=call.action_type, params=call.params)
                response = self.execution_service.request(action, ctx)
                observation = _observation_from_response(task.id, call.action_type, response)
                tm.record_observation(task, observation.model_dump())
                memory.record_observation(observation.model_dump())
                self._emit(AgentEventType.OBSERVATION, task_id=task.id,
                           action_type=call.action_type, status=observation.status,
                           summary=observation.summary, error=observation.error)

                if response.status == "confirmation_required":
                    self._emit(AgentEventType.CONFIRMATION_REQUIRED,
                               task_id=task.id, action_type=call.action_type,
                               confirmation_id=response.confirmation_id,
                               decision=response.decision,
                               challenge=response.challenge,
                               params=self._event_params(call.action_type, call.params))
                    # -- human approval gate ------------------------------------
                    choice = self._ask_operator(action, response)
                    if choice == "wait":
                        tm.pause_for_user(task, response.confirmation_id or "")
                        record = self._final(goal, ctx, plan, tm, memory,
                                             RunStatus.WAITING_FOR_USER,
                                             notes=["run paused for user approval"])
                        record.pending_confirmations = _pending_ids(tm)
                        return record
                    if choice == "deny":
                        tm.record_observation(task, _obs(
                            task.id, call.action_type, "denied",
                            error="operator denied the pending confirmation"))
                        denied = True
                        observation = None
                        break
                    # approve: dispatch through the same gate
                    approved = self.execution_service.approve(
                        response.confirmation_id or "", action, ctx, response.challenge)
                    observation = _observation_from_response(task.id, call.action_type, approved)
                    tm.record_observation(task, observation.model_dump())
                    memory.record_observation(observation.model_dump())
                    self._emit(AgentEventType.OBSERVATION, task_id=task.id,
                               action_type=call.action_type, status=observation.status,
                               summary=observation.summary, error=observation.error)

                if observation.status != "executed":
                    break  # MVEA: one tool call per task; stop on failure

            if denied:
                # A human refusal is final — never retried (it would just
                # re-prompt the operator).
                tm.fail(task, "operator denied the pending confirmation")
                self._emit(AgentEventType.TASK_FAILED, task_id=task.id,
                           error=task.error or "denied")
                continue

            # -- verification -----------------------------------------------------
            verdict = self.verifier.verify(task, observation)
            self._emit(AgentEventType.VERDICT, task_id=task.id, ok=verdict.ok,
                       reason=verdict.reason)
            if verdict.ok:
                tm.complete(task)
                self._emit(AgentEventType.TASK_COMPLETED, task_id=task.id)
                self._remember_success(memory, task, observation)
                continue

            # -- failure → retry (bounded) or fail + replan ----------------------
            if tm.retry_allowed(task):
                tm.retry(task, verdict.reason)
                self._emit(AgentEventType.TASK_RETRYING, task_id=task.id,
                           reason=verdict.reason, attempt=task.attempt)
                memory.record_observation(_obs(task.id, task.action_type, "retrying",
                                               error=verdict.reason))
                continue

            tm.fail(task, f"verification failed: {verdict.reason}")
            self._emit(AgentEventType.TASK_FAILED, task_id=task.id,
                       error=task.error or "verification failed")
            if replans < self.max_replans:
                repairs = self.planner.repair(task, verdict.reason)
                if repairs:
                    for repair in repairs:
                        tm.add(repair)
                    replans += 1
                    memory.record_observation(_obs(
                        task.id, task.action_type, "replanning",
                        error=f"added {len(repairs)} repair task(s): {verdict.reason}"))

        return self._final(goal, ctx, plan, tm, memory, RunStatus.COMPLETED)

    # -- helpers -----------------------------------------------------------------
    def _gate_reject(self, action_type: str) -> str | None:
        """Return a rejection reason, or None if the call may proceed."""
        spec = self.execution_service.catalog.get(action_type)
        if spec is None:
            return f"unknown action type: {action_type}"
        if spec.risk_level is RiskLevel.FORBIDDEN:
            return f"action is permanently forbidden: {action_type}"
        if self.execution_service.registry.get(action_type) is None:
            return f"no provider registered for {action_type}"
        if self.domain_guard is not None and not self.domain_guard(action_type):
            return f"action not allowed for this role: {action_type}"
        return None

    def _event_params(self, action_type: str, params: dict[str, Any]) -> dict[str, Any]:
        spec = self.execution_service.catalog.get(action_type)
        secret_fields = spec.secret_fields if spec is not None else frozenset()
        return summarize_params(params or {}, secret_fields)

    def _ask_operator(self, action: Action, response: Any) -> ApprovalChoice:
        if self.approval_handler is None:
            return "wait"
        try:
            choice = self.approval_handler(action, response)
        except Exception:  # noqa: BLE001 — a broken operator hook must pause, not crash
            return "wait"
        return choice if choice in ("approve", "deny", "wait") else "wait"

    def _settle_failure(self, tm: TaskManager, task: Task, memory: ShortTermMemory,
                        error: str) -> None:
        """Handle a brain/prepare failure: bounded retry, then fail."""
        if tm.retry_allowed(task):
            tm.retry(task, error)
            self._emit(AgentEventType.TASK_RETRYING, task_id=task.id,
                       reason=error, attempt=task.attempt)
            memory.record_observation(_obs(task.id, task.action_type, "retrying",
                                           error=error))
        else:
            tm.fail(task, error)
            self._emit(AgentEventType.TASK_FAILED, task_id=task.id, error=error)

    def _remember_success(self, memory: ShortTermMemory, task: Task,
                          observation: Observation | None) -> None:
        if observation is None:
            return
        if task.action_type == "fs.write":
            path = task.params.get("path")
            if path:
                memory.record_artifact(str(path))
        if self.long_term_memory is not None and memory.recall("actor_id"):
            try:
                self.long_term_memory.put(
                    memory.recall("actor_id"), f"run:{self.run_id}",
                    f"task:{task.id}", {"status": "completed", "title": task.title})
            except (ValueError, OSError):
                pass  # memory must never fail the run

    def _final(self, goal: str, ctx: ExecutionContext, plan: Plan, tm: TaskManager,
               memory: ShortTermMemory, forced: RunStatus,
               notes: list[str] | None = None) -> RunRecord:
        counts = tm.counts()
        required_failed = [
            t for t in tm.snapshot()
            if t.required and t.status in (TaskStatus.FAILED, TaskStatus.SKIPPED)
        ]
        still_waiting = tm.waiting()
        if forced is RunStatus.BUDGET_EXCEEDED:
            status = forced
        elif forced is RunStatus.WAITING_FOR_USER or still_waiting:
            status = RunStatus.WAITING_FOR_USER
        elif required_failed:
            status = RunStatus.FAILED
        else:
            status = RunStatus.COMPLETED

        completed = counts.get(TaskStatus.COMPLETED.value, 0)
        failed = counts.get(TaskStatus.FAILED.value, 0)
        skipped = counts.get(TaskStatus.SKIPPED.value, 0)
        note_list = list(notes or [])
        if failed:
            note_list.append(f"{failed} task(s) failed (non-required failures are tolerated)")
        if skipped:
            note_list.append(f"{skipped} task(s) skipped")

        summary = _summarise(plan, status, completed, failed, skipped)
        result = AgentResult(
            status=status,
            goal=goal,
            summary=summary,
            tasks_completed=completed,
            tasks_failed=failed,
            tasks_skipped=skipped,
            tool_calls=self.budget.tool_calls,
            iterations=self.budget.iterations,
            llm_calls=self.budget.llm_calls,
            estimated_tokens=self.budget.tokens_used,
            estimated_cost_usd=round(self.budget.cost_used_usd, 6),
            artifacts=sorted(memory.artifacts),
            notes=note_list,
        )
        pending = _pending_ids(tm) if status is RunStatus.WAITING_FOR_USER else []
        self._emit(AgentEventType.RUN_FINISHED, status=status.value,
                   summary=summary, tasks_completed=completed, tasks_failed=failed,
                   tasks_skipped=skipped, artifacts=sorted(memory.artifacts),
                   pending_confirmations=pending, notes=note_list,
                   tool_calls=self.budget.tool_calls,
                   llm_calls=self.budget.llm_calls,
                   estimated_tokens=self.budget.tokens_used,
                   estimated_cost_usd=round(self.budget.cost_used_usd, 6))
        return RunRecord(
            run_id=self.run_id,
            actor_id=ctx.actor_id,
            goal=goal,
            status=status,
            plan=plan,
            tasks=tm.snapshot(),
            result=result,
            pending_confirmations=pending,
        )


# -- module helpers -------------------------------------------------------------

def _observation_from_response(task_id: str, action_type: str, response: Any) -> Observation:
    result = getattr(response, "result", None)
    data = result.data if result is not None and getattr(result, "data", None) else {}
    return Observation(
        task_id=task_id,
        action_type=action_type,
        status=response.status,
        summary=(result.summary if result is not None else "") or (response.message or ""),
        data=dict(data) if isinstance(data, dict) else {},
        confirmation_id=getattr(response, "confirmation_id", None),
        challenge=getattr(response, "challenge", None),
        error=response.message if response.status in ("failed", "rejected", "denied") else None,
    )


def _obs(task_id: str, action_type: str, status: str, error: str | None = None,
         summary: str = "") -> dict:
    return {"task_id": task_id, "action_type": action_type, "status": status,
            "summary": summary, "error": error}


def _pending_ids(tm: TaskManager) -> list[str]:
    ids: list[str] = []
    for task in tm.waiting():
        for cid in task.waiting_on:
            if cid not in ids:
                ids.append(cid)
    return ids


def _budget_snapshot(record: RunRecord) -> dict:
    return {
        "iterations": record.result.iterations,
        "tool_calls": record.result.tool_calls,
        "llm_calls": record.result.llm_calls,
        "tokens_used": record.result.estimated_tokens,
        "cost_used_usd": record.result.estimated_cost_usd,
    }


def _subject_of(plan: Plan) -> str:
    from era.agents.planner import _extract_subject  # local: shared helper
    subject = _extract_subject(plan.goal).strip()
    return subject or "topic"


def _tool_catalog(execution_service) -> str:
    lines = []
    for spec in sorted(execution_service.catalog, key=lambda s: s.action_type):
        lines.append(f"- {spec.action_type} ({spec.risk_level.value})")
    return "\n".join(lines)


def _summarise(plan: Plan, status: RunStatus, completed: int, failed: int,
               skipped: int) -> str:
    head = {
        RunStatus.COMPLETED: "Goal completed and verified",
        RunStatus.FAILED: "Goal not fully completed — some required tasks failed",
        RunStatus.WAITING_FOR_USER: "Run paused — waiting for user approval",
        RunStatus.BUDGET_EXCEEDED: "Run stopped — budget exceeded",
    }.get(status, str(status))
    return (f"{head}. {plan.summary} "
            f"[completed={completed}, failed={failed}, skipped={skipped}]")
