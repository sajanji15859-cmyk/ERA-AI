"""ERA agent subsystem (Phase 3A) — the MVEA (Minimum Viable ERA Agent).

Planner → TaskManager → Brain → ExecutionService (the existing permission/
confirmation/audit gate) → Observation → Verification → retry/replan → result.
All budget caps are enforced in code; the loop can never run unboundedly.
"""

from era.agents.loop import AgentLoop
from era.agents.models import AgentResult, Plan, RunRecord, RunStatus, Task, TaskStatus

__all__ = ["AgentLoop", "AgentResult", "Plan", "RunRecord", "RunStatus", "Task", "TaskStatus"]
