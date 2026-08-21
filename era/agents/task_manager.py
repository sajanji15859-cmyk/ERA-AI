"""Task manager — tracks task state through the agent loop (Phase 3A).

States (as specified for the ERA agent):

    pending → running → completed
                    → failed
                    → retrying → pending   (bounded by task.max_attempts)
                    → waiting_for_user → (completed | failed) on resolution
    pending → skipped                      (dependency failed / not required)

The manager is deliberately small and deterministic: no threading, no
scheduling — the AgentLoop drives it one step at a time.
"""

from __future__ import annotations

from era.agents.models import Task, TaskStatus

MAX_OBSERVATIONS_PER_TASK = 20


class TaskManager:
    def __init__(self, tasks: list[Task]):
        self._tasks: dict[str, Task] = {t.id: t for t in tasks}

    # -- queries ---------------------------------------------------------------
    def get(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def add(self, task: Task) -> None:
        if task.id in self._tasks:
            return
        self._tasks[task.id] = task

    def pending(self) -> list[Task]:
        return [t for t in self._tasks.values() if t.status is TaskStatus.PENDING]

    def waiting(self) -> list[Task]:
        return [t for t in self._tasks.values() if t.status is TaskStatus.WAITING_FOR_USER]

    def next_ready(self) -> Task | None:
        """First pending task whose dependencies are all completed."""
        for task in self._tasks.values():
            if task.status is not TaskStatus.PENDING:
                continue
            if all(self._dep_completed(d) for d in task.depends_on):
                return task
        return None

    def blocked_pending(self) -> list[Task]:
        """Pending tasks whose dependency failed/skipped/does not exist."""
        blocked = []
        for task in self._tasks.values():
            if task.status is not TaskStatus.PENDING:
                continue
            if any(self._dep_terminal_failed(d) for d in task.depends_on):
                blocked.append(task)
        return blocked

    def has_pending(self) -> bool:
        return any(t.status is TaskStatus.PENDING for t in self._tasks.values())

    def all_terminal(self) -> bool:
        terminal = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}
        return all(t.status in terminal for t in self._tasks.values())

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in TaskStatus}
        for task in self._tasks.values():
            counts[task.status.value] = counts.get(task.status.value, 0) + 1
        return counts

    def snapshot(self) -> list[Task]:
        return [t.model_copy(deep=True) for t in self._tasks.values()]

    # -- transitions -----------------------------------------------------------
    def mark_running(self, task: Task) -> None:
        task.status = TaskStatus.RUNNING

    def complete(self, task: Task) -> None:
        task.status = TaskStatus.COMPLETED

    def fail(self, task: Task, error: str) -> None:
        task.status = TaskStatus.FAILED
        task.error = error[:500]

    def skip(self, task: Task, reason: str) -> None:
        task.status = TaskStatus.SKIPPED
        task.error = reason[:500]

    def retry(self, task: Task, correction_note: str) -> bool:
        """Mark for retry (attempt+1 → pending). Returns False at the attempt cap."""
        task.attempt += 1
        if task.attempt >= task.max_attempts:
            return False
        task.status = TaskStatus.RETRYING
        task.correction_note = correction_note[:500]
        task.status = TaskStatus.PENDING
        return True

    def retry_allowed(self, task: Task) -> bool:
        return task.attempt + 1 < task.max_attempts

    def pause_for_user(self, task: Task, confirmation_id: str) -> None:
        task.status = TaskStatus.WAITING_FOR_USER
        if confirmation_id not in task.waiting_on:
            task.waiting_on.append(confirmation_id)

    def resolve_wait(self, task: Task, outcome: str, note: str = "") -> None:
        """Apply a resolved approval: 'executed' → completed, else failed."""
        if outcome == "executed":
            task.status = TaskStatus.COMPLETED
        else:
            task.status = TaskStatus.FAILED
            task.error = note or f"confirmation resolved as {outcome}"

    def record_observation(self, task: Task, observation: dict) -> None:
        task.observations.append(observation)
        if len(task.observations) > MAX_OBSERVATIONS_PER_TASK:
            task.observations = task.observations[-MAX_OBSERVATIONS_PER_TASK:]

    # -- internals -------------------------------------------------------------
    def _dep_completed(self, dep_id: str) -> bool:
        dep = self._tasks.get(dep_id)
        return dep is not None and dep.status is TaskStatus.COMPLETED

    def _dep_terminal_failed(self, dep_id: str) -> bool:
        dep = self._tasks.get(dep_id)
        if dep is None:
            return True  # an unknown dependency can never be satisfied
        return dep.status in (TaskStatus.FAILED, TaskStatus.SKIPPED)
