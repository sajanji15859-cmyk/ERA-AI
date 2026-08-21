"""Phase 1F: async provider interface foundation.

Locks in that the async abstraction is strictly additive: the synchronous
ToolProvider SPI and StubProvider behavior are untouched, and both directions of
adaptation preserve ExecutionContext (including the Phase 1E deadline).
"""

from __future__ import annotations

import asyncio

import pytest

from era.core.action import Action
from era.core.async_provider import (
    AsyncToolProvider,
    AsyncToSyncProviderAdapter,
    SyncToAsyncProviderAdapter,
    is_async_provider,
    run_async_with_timeout,
    to_async,
    to_sync,
)
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.core.tool_provider import ToolProvider
from era.providers.stub import StubProvider
from tests.provider_contract import assert_provider_contract


class AsyncEcho:
    """A small, genuinely-async provider used across the suite."""

    id = "async-echo"
    action_types = frozenset({"stub.noop"})

    async def validate(self, action: Action) -> None:
        await asyncio.sleep(0)

    async def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        await asyncio.sleep(0)
        return ActionResult(success=True, summary="async ok", data={"provider": self.id})

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id, action_types=self.action_types, version="0.1.0",
            display_name="Async echo (offline)", is_stub=True, capabilities=("async",),
        )


def _noop_action() -> Action:
    return Action(action_type="stub.noop")


# ---------------------------------------------------------------------------
# existing synchronous providers are untouched
# ---------------------------------------------------------------------------

def test_sync_provider_still_satisfies_tool_provider_contract():
    stub = StubProvider()
    assert isinstance(stub, ToolProvider)
    assert_provider_contract(stub)


def test_sync_provider_behavior_unchanged():
    stub = StubProvider()
    result = stub.execute(_noop_action(), ExecutionContext(actor_id="t"))
    assert result.success is True
    assert result.data.get("provider") == "stub"
    assert not is_async_provider(stub)  # still sync-native


# ---------------------------------------------------------------------------
# AsyncToolProvider shape
# ---------------------------------------------------------------------------

def test_async_provider_shape():
    p = AsyncEcho()
    assert isinstance(p, AsyncToolProvider)
    assert is_async_provider(p)
    assert asyncio.iscoroutinefunction(p.validate)
    assert asyncio.iscoroutinefunction(p.execute)


def test_sync_provider_is_not_async_native():
    # runtime_checkable isinstance alone cannot tell sync from async; the
    # adapter layer must use the coroutine-function check to avoid
    # double-wrapping. Assert the check does the right thing.
    assert not is_async_provider(StubProvider())
    assert is_async_provider(AsyncEcho())
    assert not is_async_provider(object())


# ---------------------------------------------------------------------------
# sync -> async adaptation
# ---------------------------------------------------------------------------

def test_to_async_wraps_sync_provider():
    wrapped = to_async(StubProvider())
    assert isinstance(wrapped, SyncToAsyncProviderAdapter)
    assert is_async_provider(wrapped)
    assert wrapped.id == "stub"
    assert wrapped.action_types == StubProvider.action_types

    result = asyncio.run(wrapped.execute(_noop_action(), ExecutionContext(actor_id="t")))
    assert result.success is True
    assert result.summary == "stub executed stub.noop"


def test_to_async_async_provider_passes_through():
    p = AsyncEcho()
    assert to_async(p) is p


def test_sync_to_async_preserves_deadline():
    seen: dict = {}

    class SyncCapture:
        id = "capture"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            seen["deadline"] = ctx.deadline
            return ActionResult(success=True)

    wrapped = to_async(SyncCapture())
    deadline = 1234.5
    asyncio.run(wrapped.execute(
        _noop_action(), ExecutionContext(actor_id="t", deadline=deadline),
    ))
    assert seen["deadline"] == deadline


# ---------------------------------------------------------------------------
# async -> sync adaptation
# ---------------------------------------------------------------------------

def test_to_sync_wraps_async_provider():
    wrapped = to_sync(AsyncEcho())
    assert isinstance(wrapped, AsyncToSyncProviderAdapter)
    assert not is_async_provider(wrapped)
    assert isinstance(wrapped, ToolProvider)  # usable at the sync boundary

    result = wrapped.execute(_noop_action(), ExecutionContext(actor_id="t"))
    assert result.success is True
    assert result.data.get("provider") == "async-echo"


def test_to_sync_sync_provider_passes_through():
    stub = StubProvider()
    assert to_sync(stub) is stub


def test_async_provider_passes_existing_contract_via_to_sync():
    # The reusable Phase 1D contract helper runs validate/execute and checks
    # for secret fragments — proof the async abstraction integrates with the
    # existing provider quality gate.
    assert_provider_contract(to_sync(AsyncEcho()))


def test_async_to_sync_preserves_deadline():
    seen: dict = {}

    class AsyncProbe:
        id = "probe"
        action_types = frozenset({"stub.noop"})

        async def validate(self, action):
            return None

        async def execute(self, action, ctx):
            await asyncio.sleep(0)
            seen["deadline"] = ctx.deadline
            return ActionResult(success=True)

    wrapped = to_sync(AsyncProbe())
    deadline = 99.0
    wrapped.execute(_noop_action(), ExecutionContext(actor_id="t", deadline=deadline))
    assert seen["deadline"] == deadline


def test_async_validate_failure_propagates_as_toolerror():
    class AsyncReject:
        id = "reject"
        action_types = frozenset({"stub.noop"})

        async def validate(self, action):
            raise ToolError("bad params", code=ProviderErrorCode.VALIDATION)

        async def execute(self, action, ctx):
            return ActionResult(success=True)

    wrapped = to_sync(AsyncReject())
    with pytest.raises(ToolError) as exc:
        wrapped.validate(_noop_action())
    assert exc.value.code is ProviderErrorCode.VALIDATION


# ---------------------------------------------------------------------------
# async deadline enforcement (mirror of Phase 1E run_with_timeout)
# ---------------------------------------------------------------------------

def test_run_async_with_timeout_success():
    async def quick():
        return 42

    assert asyncio.run(run_async_with_timeout(quick, timeout_seconds=1.0)) == 42


def test_run_async_with_timeout_overrun():
    async def slow():
        await asyncio.sleep(1.0)
        return 1

    with pytest.raises(ToolError) as exc:
        asyncio.run(run_async_with_timeout(slow, timeout_seconds=0.05, provider_id="p"))
    assert exc.value.code is ProviderErrorCode.TIMEOUT
    assert "timed out" in str(exc.value)
    assert exc.value.provider_id == "p"


def test_run_async_with_timeout_propagates_provider_toolerror():
    async def boom():
        raise ToolError("auth fail", code=ProviderErrorCode.AUTH, provider_id="p")

    with pytest.raises(ToolError) as exc:
        asyncio.run(run_async_with_timeout(boom, timeout_seconds=1.0))
    assert exc.value.code is ProviderErrorCode.AUTH


def test_run_async_with_timeout_zero_disables_deadline():
    async def ok():
        return "ok"

    assert asyncio.run(run_async_with_timeout(ok, timeout_seconds=0)) == "ok"
