"""Core types and protocol for the provider-agnostic LLM interface."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """A single conversation message, provider-neutral.

    ``role="tool"`` carries tool results back to the model; ``content`` is always
    plain text in Phase 1.
    """

    role: Role
    content: str

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.role}: {self.content}"


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Optional token accounting, when the provider reports it."""

    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """A completed (non-streaming) model response.

    ``raw`` holds the provider payload for debugging and must never be logged
    verbatim (it may echo request metadata).
    """

    text: str
    model: str = ""
    usage: TokenUsage | None = None
    raw: Any = field(default=None, compare=False, repr=False)


@runtime_checkable
class LLMClient(Protocol):
    """The interface every LLM provider adapter implements."""

    def complete(
        self, messages: Sequence[ChatMessage], *, timeout_s: float | None = None
    ) -> LLMResponse:
        """Send ``messages`` and return the model's full response.

        Args:
            messages: conversation so far (system/user/assistant/tool roles).
            timeout_s: optional per-call timeout override, in seconds.

        Raises:
            LLMError: subclasses carry the failure category (connection, auth,
                timeout, malformed response).
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class LLMError(RuntimeError):
    """Base class for every LLM adapter failure.

    Messages are sanitized: they must never contain API keys, request headers
    or full request payloads.
    """


class LLMConnectionError(LLMError):
    """Network-level failure (DNS, refused connection, unreachable endpoint)."""


class LLMTimeoutError(LLMError):
    """The request exceeded its time budget."""


class LLMAuthError(LLMError):
    """The provider rejected our credentials (HTTP 401/403)."""


class LLMResponseError(LLMError):
    """The provider answered but the payload was unusable (bad JSON, missing
    fields, unexpected HTTP status)."""
