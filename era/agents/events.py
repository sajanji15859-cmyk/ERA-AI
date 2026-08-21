"""Agent run events (Phase 3B).

Typed, serialisable events emitted by the AgentLoop — the backbone of the SSE
streaming chat API. Guarantees:

* events never carry secrets — action params are redacted (secret fields via
  the catalog + conservative key hints) and long string values (e.g. file
  content) are summarised as length markers;
* every run emits exactly one terminal event (``run_finished``), so stream
  consumers always know when a run ended and why;
* a broken event sink can never break the run (emitters swallow sink errors).
"""

from __future__ import annotations

from collections import deque
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

MAX_EVENT_DATA_STR = 1000
MAX_EVENTS_PER_RUN = 500

#: Long string values are replaced by length markers at this threshold.
SUMMARY_STR_LIMIT = 200


class AgentEventType(StrEnum):
    RUN_STARTED = "run_started"
    PLAN_CREATED = "plan_created"
    TASK_STARTED = "task_started"
    TOOL_CALL = "tool_call"
    OBSERVATION = "observation"
    VERDICT = "verdict"
    TASK_RETRYING = "task_retrying"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_SKIPPED = "task_skipped"
    CONFIRMATION_REQUIRED = "confirmation_required"
    RUN_FINISHED = "run_finished"
    ERROR = "error"


class AgentEvent(BaseModel):
    """One event in a run's stream. ``seq`` increases monotonically per run."""

    run_id: str
    seq: int
    type: AgentEventType
    data: dict[str, Any] = Field(default_factory=dict)


def event(run_id: str, seq: int, type_: AgentEventType, **data: Any) -> AgentEvent:
    """Build an event with bounded, secret-free data."""
    return AgentEvent(run_id=run_id, seq=seq, type=type_, data=_bounded(data))


def _bounded(value: Any, depth: int = 0) -> Any:
    """Truncate long strings recursively so events stay small and safe."""
    if depth > 4:
        return "[truncated]"
    if isinstance(value, str):
        return value if len(value) <= MAX_EVENT_DATA_STR else value[:MAX_EVENT_DATA_STR] + "…"
    if isinstance(value, dict):
        return {str(k)[:64]: _bounded(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bounded(x, depth + 1) for x in value[:50]]
    return value


def summarize_params(params: dict[str, Any], secret_fields: frozenset[str] | None = None
                     ) -> dict[str, Any]:
    """Event-safe params: redacted secrets + long values as length markers.

    Reuses the canonical redaction layer so the same secret policy as the
    audit log applies to streams.
    """
    from era.security.redaction import redact
    safe = redact(params, secret_fields)
    out: dict[str, Any] = {}
    for key, value in safe.items():
        if isinstance(value, str) and len(value) > SUMMARY_STR_LIMIT:
            out[key] = f"<str:{len(value)} chars>"
        else:
            out[key] = value
    return out


class EventBuffer:
    """Bounded per-run event history (in-memory; not persisted)."""

    def __init__(self, maxlen: int = MAX_EVENTS_PER_RUN):
        self.maxlen = maxlen
        self._events: deque[AgentEvent] = deque(maxlen=maxlen)

    def add(self, ev: AgentEvent) -> None:
        self._events.append(ev)

    def list(self) -> list[AgentEvent]:
        return sorted(self._events, key=lambda e: e.seq)

    def __len__(self) -> int:
        return len(self._events)


def sse_format(events) -> str:
    """Format events as an SSE body (one ``data:`` frame per event)."""
    chunks = [f"data: {ev.model_dump_json()}\n\n" for ev in events]
    return "".join(chunks)
