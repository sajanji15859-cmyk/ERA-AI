"""Abstract LLM / tool-calling interfaces.

These are *interfaces only* in Phase 1C: a real model (OpenAI / Anthropic /
local / any provider) is wired in a later phase without touching the permission
architecture. The contract is explicit and enforced structurally:

* ``LLMProvider`` carries NO raw API keys — only an opaque ``model_ref``.
* ``AgentInterface`` (the orchestrator) receives only the ExecutionService
  handle, so every model-proposed tool call must pass the same permission gate.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class LLMRequest(BaseModel):
    """Provider-agnostic inference request. Carries NO raw credentials."""

    messages: list[dict[str, Any]] = Field(default_factory=list)
    model_ref: str = "default"  # opaque model/provider reference, not an API key
    max_tokens: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A tool call proposed by a model. Must be routed through ExecutionService."""

    id: str
    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


@runtime_checkable
class LLMProvider(Protocol):
    """A model provider. Owns its own API key; exposes only inference."""

    id: str

    def complete(self, req: LLMRequest) -> LLMResponse: ...

    def stream(self, req: LLMRequest) -> Iterator[LLMResponse]: ...


@runtime_checkable
class AgentInterface(Protocol):
    """The orchestrator: model -> tool calls -> ExecutionService -> model loop.

    Implemented in a later phase. It MUST route every model-proposed tool call
    through the ExecutionService — never directly to a ToolProvider (which is
    structurally impossible, since providers are not exposed to it).
    """

    def run(self, task: str, ctx: Any) -> Any: ...
