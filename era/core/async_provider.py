"""Async provider interface foundation (Phase 1F).

Phase 1F introduces the *extension point* for asynchronous ToolProviders while
keeping the existing synchronous
:class:`~era.core.tool_provider.ToolProvider` SPI untouched. Nothing here makes
network calls, and no real async provider ships in Phase 1F.

Provided:

* :class:`AsyncToolProvider` — the async SPI mirroring ``ToolProvider``
  (``async validate`` / ``async execute``), so a future async Web/Email/...
  provider can implement the shape this phase locks in.
* :func:`to_async` / :func:`to_sync` — bidirectional adapters. Existing
  synchronous providers (e.g. ``StubProvider``) can be used from async code
  without modification, and async providers can be driven through the existing
  synchronous dispatch boundary. ``ExecutionContext`` (including
  ``ctx.deadline``) is passed through unchanged, preserving Phase 1E deadline
  semantics.
* :func:`run_async_with_timeout` — the async counterpart of
  :func:`era.core.timeout.run_with_timeout`: a hard wall-clock deadline that
  converts overrun into ``ToolError(TIMEOUT)`` and never retries.

NOTE: the synchronous adapters run blocking provider code on the calling
thread/event loop. That is intentional for compatibility and tests; real async
providers implement ``AsyncToolProvider`` directly so nothing blocks.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Protocol, runtime_checkable

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.core.tool_provider import ToolProvider


@runtime_checkable
class AsyncToolProvider(Protocol):
    """The async service-provider interface (SPI).

    Mirrors :class:`~era.core.tool_provider.ToolProvider` exactly, with
    coroutine methods. Implementations own credential access and execution, must
    not return secrets in results, and SHOULD observe ``ctx.deadline``
    cooperatively. ``describe()`` remains optional (see
    :func:`era.core.provider_info.describe_provider`).
    """

    id: str
    action_types: frozenset[str]

    async def validate(self, action: Action) -> None: ...

    async def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult: ...


def is_async_provider(obj: Any) -> bool:
    """True if ``obj`` exposes a coroutine ``execute`` (i.e. is async-native).

    ``runtime_checkable`` ``isinstance`` cannot distinguish async from sync
    methods (it only checks attribute presence), so adapters use this check to
    avoid double-wrapping.
    """
    execute = getattr(obj, "execute", None)
    return callable(execute) and inspect.iscoroutinefunction(execute)


class SyncToAsyncProviderAdapter:
    """Wrap a synchronous :class:`ToolProvider` behind ``AsyncToolProvider``.

    Lets existing synchronous providers run unchanged from async code. The
    sync methods execute on the caller's event loop (blocking it); this is a
    compatibility/test bridge — real async providers implement
    ``AsyncToolProvider`` directly. ``ctx`` (including ``ctx.deadline``) is
    forwarded untouched.
    """

    def __init__(self, provider: ToolProvider):
        self._provider = provider
        self.id = provider.id
        self.action_types = provider.action_types

    async def validate(self, action: Action) -> None:
        return self._provider.validate(action)

    async def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        return self._provider.execute(action, ctx)


class AsyncToSyncProviderAdapter:
    """Adapt an :class:`AsyncToolProvider` to the synchronous ``ToolProvider`` SPI.

    Each call runs a fresh event loop via :func:`asyncio.run`, so an async
    provider can be driven through the existing synchronous dispatch boundary
    (including the Phase 1E timeout and the Phase 1F reliability layer).
    ``ctx`` (including ``ctx.deadline``) is forwarded untouched.
    """

    def __init__(self, provider: AsyncToolProvider):
        self._provider = provider
        self.id = provider.id
        self.action_types = provider.action_types

    def validate(self, action: Action) -> None:
        asyncio.run(self._provider.validate(action))

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        return asyncio.run(self._provider.execute(action, ctx))


def to_async(provider: Any) -> Any:
    """Return an ``AsyncToolProvider`` view of ``provider``.

    Async-native providers pass through untouched; synchronous providers are
    wrapped in :class:`SyncToAsyncProviderAdapter`.
    """
    if is_async_provider(provider):
        return provider
    return SyncToAsyncProviderAdapter(provider)


def to_sync(provider: Any) -> Any:
    """Return a synchronous ``ToolProvider`` view of ``provider``.

    Synchronous providers pass through untouched; async providers are wrapped
    in :class:`AsyncToSyncProviderAdapter`.
    """
    if not is_async_provider(provider):
        return provider
    return AsyncToSyncProviderAdapter(provider)


async def run_async_with_timeout(
    call: Any,
    *,
    timeout_seconds: float,
    provider_id: str | None = None,
    stage: str = "execute",
) -> Any:
    """Await ``call()`` (an awaitable factory) under a hard wall-clock deadline.

    Overrun raises ``ToolError(TIMEOUT)`` — which the retry layer never retries.
    ``timeout_seconds`` <= 0 disables the deadline (stub/test paths). A
    ``ToolError`` raised by the callable itself propagates unchanged.
    """
    if timeout_seconds is None or timeout_seconds <= 0:
        return await call()

    try:
        return await asyncio.wait_for(call(), timeout=timeout_seconds)
    except TimeoutError as exc:
        raise ToolError(
            f"provider {stage} timed out after {timeout_seconds:g}s",
            provider_id=provider_id,
            code=ProviderErrorCode.TIMEOUT,
        ) from exc
