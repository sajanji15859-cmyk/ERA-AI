"""Provider-agnostic retry policy and loop (Phase 1F).

Retry is a *dispatch-reliability* concern, not a security concern: it runs only
inside the reliability layer of the execution service, strictly after
authorization has been durably recorded in the audit log and *outside* any
database transaction (see the two-phase execution model).

Guarantees:

* **Only explicitly retryable failures are retried.** A failure is retryable iff
  its :class:`~era.core.result.ProviderErrorCode` is in ``RetryPolicy.retryable_codes``
  (default: ``UNAVAILABLE`` and ``PROVIDER_ERROR``). Codes such as ``VALIDATION``,
  ``AUTH``, ``FORBIDDEN``, ``NOT_FOUND``, ``CONFLICT``, ``TIMEOUT``,
  ``NOT_IMPLEMENTED`` and ``INTERNAL`` are never retried — retrying them could
  duplicate side effects, mask authorization problems or hide bugs.
* **Bounded.** ``max_attempts`` is capped at ``MAX_ATTEMPTS_BOUND``; the loop is a
  plain ``for`` over that many attempts and can never run unboundedly.
* **Deterministic backoff.** Exponential backoff with no jitter, so behavior is
  reproducible and testable. Backoff is capped at ``max_backoff_seconds``.
* **Deadline aware.** When an absolute ``time.monotonic()`` deadline is supplied,
  the loop refuses to start an attempt (or take a backoff sleep) that would
  exceed it, raising ``ToolError(TIMEOUT)`` instead. Retrying can therefore never
  bypass a Phase 1E dispatch deadline.
* **Quiet by design.** ``with_retry`` performs no logging, so retry activity can
  never leak secrets; provider ``ToolError`` objects pass through unchanged
  (retry exhaustion re-raises the *original* error object with its original
  code).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from era.core.result import ProviderErrorCode, ToolError

T = TypeVar("T")

#: Failures considered safe to retry by default. A provider that wants its
#: failure *not* to be retried raises a specific non-transient code instead.
DEFAULT_RETRYABLE_CODES: frozenset[ProviderErrorCode] = frozenset({
    ProviderErrorCode.UNAVAILABLE,
    ProviderErrorCode.PROVIDER_ERROR,
})

#: Hard bound on ``max_attempts`` so a misconfiguration can never configure an
#: unbounded retry loop.
MAX_ATTEMPTS_BOUND = 10

#: Codes that must never be retried, regardless of ``retryable_codes``. This is
#: a fail-closed carve-out: retrying any of these could duplicate a side effect
#: (e.g. a payment/send) or mask an authorization/integrity problem.
NEVER_RETRY_CODES: frozenset[ProviderErrorCode] = frozenset({
    ProviderErrorCode.VALIDATION,
    ProviderErrorCode.AUTH,
    ProviderErrorCode.FORBIDDEN,
    ProviderErrorCode.NOT_FOUND,
    ProviderErrorCode.CONFLICT,
    ProviderErrorCode.TIMEOUT,
    ProviderErrorCode.NOT_IMPLEMENTED,
    ProviderErrorCode.INTERNAL,
})


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for the retry loop. Safe, bounded, deterministic defaults.

    Attributes
    ----------
    max_attempts:
        Maximum number of times the callable is invoked (1 = no retry).
        Clamped to ``[1, MAX_ATTEMPTS_BOUND]`` by validation.
    base_backoff_seconds:
        Backoff before the second attempt. Doubled by ``backoff_factor`` after
        each subsequent failure.
    max_backoff_seconds:
        Upper cap on a single backoff sleep.
    backoff_factor:
        Exponential growth of the backoff between attempts (>= 1.0).
    retryable_codes:
        The explicit set of codes eligible for retry. Codes in
        ``NEVER_RETRY_CODES`` are always excluded.
    """

    max_attempts: int = 3
    base_backoff_seconds: float = 0.1
    max_backoff_seconds: float = 2.0
    backoff_factor: float = 2.0
    retryable_codes: frozenset[ProviderErrorCode] = DEFAULT_RETRYABLE_CODES

    def __post_init__(self) -> None:
        if not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {self.max_attempts!r}")
        if self.max_attempts > MAX_ATTEMPTS_BOUND:
            raise ValueError(
                f"max_attempts must be <= {MAX_ATTEMPTS_BOUND} (bounded retry), "
                f"got {self.max_attempts!r}"
            )
        if self.base_backoff_seconds < 0:
            raise ValueError("base_backoff_seconds must be >= 0")
        if self.max_backoff_seconds < 0:
            raise ValueError("max_backoff_seconds must be >= 0")
        if self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0")

    def is_retryable(self, code: ProviderErrorCode | str) -> bool:
        """Return True only for explicitly retryable codes.

        Never-retry codes win over any configuration; unknown/string codes are
        coerced defensively and are not retried.
        """
        try:
            code = ProviderErrorCode(str(code)) if not isinstance(code, ProviderErrorCode) else code
        except ValueError:
            return False
        if code in NEVER_RETRY_CODES:
            return False
        return code in self.retryable_codes

    def backoff_for(self, attempt: int) -> float:
        """Deterministic exponential backoff (seconds) before attempt ``attempt+1``."""
        attempt = max(attempt, 1)
        delay = self.base_backoff_seconds * (self.backoff_factor ** (attempt - 1))
        return min(delay, self.max_backoff_seconds)


def with_retry(
    call: Callable[[], T],
    *,
    policy: RetryPolicy,
    deadline: float | None = None,
    provider_id: str | None = None,
    stage: str = "execute",
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run ``call`` with bounded, deadline-aware, deterministic retries.

    ``call`` raises :class:`ToolError` on failure. Only codes for which
    ``policy.is_retryable`` returns True are retried; everything else propagates
    immediately with its original code. Retry exhaustion re-raises the *last*
    :class:`ToolError` (same object, same code) so the caller/audit sees the
    original failure — not a synthetic one.

    ``deadline`` is an absolute ``time.monotonic()`` timestamp (as advertised on
    ``ExecutionContext.deadline``). The loop never starts an attempt and never
    sleeps past it; if the budget is exhausted it raises
    ``ToolError(TIMEOUT)`` — which itself is never retried, so the loop always
    terminates.

    ``now``/``sleep`` are injectable for deterministic tests.
    """
    last_error: ToolError | None = None

    for attempt in range(1, policy.max_attempts + 1):
        if deadline is not None:
            remaining = deadline - now()
            if remaining <= 0:
                raise ToolError(
                    f"provider {stage} retry budget exhausted (deadline reached)",
                    provider_id=provider_id,
                    code=ProviderErrorCode.TIMEOUT,
                )

        try:
            return call()
        except ToolError as exc:
            last_error = exc
            if not policy.is_retryable(exc.code):
                raise
            if attempt >= policy.max_attempts:
                raise  # exhaustion: original error object, original code

            delay = policy.backoff_for(attempt)
            if deadline is not None:
                remaining = deadline - now()
                if remaining <= 0 or delay > remaining:
                    # A backoff sleep would exceed the dispatch deadline:
                    # stop instead of overrunning the budget.
                    raise ToolError(
                        f"provider {stage} retry budget exhausted (backoff {delay:g}s "
                        f"exceeds remaining {max(remaining, 0):g}s)",
                        provider_id=provider_id,
                        code=ProviderErrorCode.TIMEOUT,
                    )
            sleep(delay)

    # Unreachable in practice (exhaustion raises inside the loop); kept for
    # type-safety and as a defensive fail-closed exit.
    if last_error is not None:
        raise last_error
    raise ToolError(
        f"provider {stage} retry loop terminated without result",
        provider_id=provider_id,
        code=ProviderErrorCode.INTERNAL,
    )
