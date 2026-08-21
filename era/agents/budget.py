"""Agent run budget: hard, code-enforced resource caps (Phase 3A).

An autonomous loop must be unable to run forever, spam tools, exhaust tokens or
silently burn money. Every cap below is checked by :class:`AgentLoop` before
each step; exceeding any cap ends the run with ``BUDGET_EXCEEDED`` and a full
explanation — never with an endless loop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class AgentBudget:
    # Caps (all safe bounded defaults; settings can tighten them further).
    max_iterations: int = 25
    max_tool_calls: int = 40
    max_retries_per_task: int = 2
    max_llm_calls: int = 20
    max_llm_tokens_per_call: int = 2048
    timeout_seconds: float = 900.0
    cost_cap_usd: float = 0.10

    # Usage counters (restored from a previous pause when a run resumes).
    started_at: float = field(default_factory=time.monotonic)
    iterations: int = 0
    tool_calls: int = 0
    llm_calls: int = 0
    tokens_used: int = 0
    cost_used_usd: float = 0.0

    def check(self) -> str | None:
        """Return an abort reason when any cap is exceeded, else ``None``."""
        if time.monotonic() - self.started_at > self.timeout_seconds:
            return f"run timeout exceeded ({self.timeout_seconds:g}s)"
        if self.iterations > self.max_iterations:
            return f"max iterations exceeded ({self.max_iterations})"
        if self.tool_calls > self.max_tool_calls:
            return f"max tool calls exceeded ({self.max_tool_calls})"
        if self.llm_calls > self.max_llm_calls:
            return f"max LLM calls exceeded ({self.max_llm_calls})"
        if self.cost_used_usd > self.cost_cap_usd:
            return f"cost cap exceeded (${self.cost_used_usd:.4f} > ${self.cost_cap_usd})"
        return None

    def can_tool_call(self) -> str | None:
        if self.tool_calls >= self.max_tool_calls:
            return f"max tool calls exceeded ({self.max_tool_calls})"
        return self.check()

    def can_llm_call(self) -> str | None:
        if self.llm_calls >= self.max_llm_calls:
            return f"max LLM calls exceeded ({self.max_llm_calls})"
        return self.check()

    def record_tool_call(self) -> None:
        self.tool_calls += 1

    def record_llm_call(self, tokens: int = 0, cost_usd: float = 0.0) -> None:
        self.llm_calls += 1
        self.tokens_used += max(0, int(tokens))
        self.cost_used_usd += max(0.0, float(cost_usd))

    def snapshot(self) -> dict:
        """Counters only — used to restore the budget when a run resumes."""
        return {
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
            "tokens_used": self.tokens_used,
            "cost_used_usd": self.cost_used_usd,
        }

    def restore(self, snapshot: dict | None) -> None:
        if not snapshot:
            return
        for key in ("iterations", "tool_calls", "llm_calls", "tokens_used", "cost_used_usd"):
            value = snapshot.get(key)
            if isinstance(value, (int, float)):
                setattr(self, key, value)
