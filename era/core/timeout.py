"""Provider dispatch timeout/deadline support (Phase 1E).

External provider work runs *outside* any database transaction (see the
two-phase execution model), but a hung network/device call must not be able to
block an execution worker indefinitely. :func:`run_with_timeout` enforces a hard
wall-clock deadline around a callable and converts overrun into
:class:`~era.core.result.ToolError` with code
:attr:`~era.core.result.ProviderErrorCode.TIMEOUT`.

A short-lived **daemon** thread runs the callable; on timeout we return
immediately without joining it (Python cannot forcibly kill a thread), so the
caller is never blocked waiting on the abandoned worker. Providers are expected
to honour ``ExecutionContext.deadline`` cooperatively — this is the safety net
when they do not. Daemon threads do not block interpreter shutdown.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TypeVar

from era.core.result import ProviderErrorCode, ToolError

T = TypeVar("T")

#: Default hard timeout (seconds) for a single provider validate/execute call.
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 30.0


def run_with_timeout(call: Callable[[], T], *, timeout_seconds: float,
                     provider_id: str | None = None, stage: str = "execute") -> T:
    """Run ``call`` and return its result, raising ``ToolError(TIMEOUT)`` on overrun.

    ``timeout_seconds`` <= 0 means "no hard timeout" (the call runs to
    completion). This is used only by the synchronous stub/mock paths and tests;
    real providers always get a positive deadline from settings.
    """

    if timeout_seconds is None or timeout_seconds <= 0:
        return call()

    result_box: dict[str, object] = {}

    def _worker() -> None:
        try:
            result_box["value"] = call()
        except BaseException as exc:  # noqa: BLE001 — surfaced to the caller via result_box
            result_box["error"] = exc

    thread = threading.Thread(
        target=_worker, name=f"era-prov-{stage}", daemon=True,
    )
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        # Overrun: abandon the daemon worker. Do not join — that would block the
        # caller on the very call we are timing out.
        raise ToolError(
            f"provider {stage} timed out after {timeout_seconds:g}s",
            provider_id=provider_id,
            code=ProviderErrorCode.TIMEOUT,
        )

    if "error" in result_box:
        exc = result_box["error"]
        if isinstance(exc, ToolError):
            raise exc
        raise ToolError(
            f"provider {stage} error: {type(exc).__name__}",
            provider_id=provider_id,
            code=ProviderErrorCode.INTERNAL,
        ) from exc

    return result_box["value"]  # type: ignore[return-value]
