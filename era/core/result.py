"""Provider execution results and error semantics.

Phase 1E introduces :class:`ProviderErrorCode` — a stable, machine-readable
taxonomy of provider failures. The free-text ``str(ToolError)`` is for humans;
``ToolError.code`` is for the execution service, audit log and callers to react
to deterministically (retry, surface, deny) without string matching.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ActionResult(BaseModel):
    """Result returned by a ToolProvider.

    Providers MUST NOT return raw secrets or credentials in ``data`` — results
    may end up in responses and (summarised) in the audit log.
    """

    success: bool = True
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ProviderErrorCode(StrEnum):
    """Stable error codes for provider failures.

    The set is intentionally small and provider-agnostic. Real providers (Web,
    Email, WhatsApp, Booking, File/Photo, Android) map their native errors onto
    these codes so the gate and audit log never depend on a vendor's error
    shape. Codes are strings so they serialise deterministically into JSON and
    the append-only hash chain.
    """

    #: The action params failed provider-side validation (rejected, not retried).
    VALIDATION = "VALIDATION"
    #: The provider could not authenticate / resolve a credential reference.
    AUTH = "AUTH"
    #: The provider is forbidden from the target by policy/allowlist (e.g. SSRF).
    FORBIDDEN = "FORBIDDEN"
    #: The downstream provider/resource was not found.
    NOT_FOUND = "NOT_FOUND"
    #: The downstream provider reported a conflict / precondition failure.
    CONFLICT = "CONFLICT"
    #: The provider exceeded its execution deadline.
    TIMEOUT = "TIMEOUT"
    #: The downstream provider is rate-limiting / temporarily unavailable.
    UNAVAILABLE = "UNAVAILABLE"
    #: The provider is offline / not configured (stub-only phases, disabled).
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    #: Any other provider-side failure.
    PROVIDER_ERROR = "PROVIDER_ERROR"
    #: A bug in the provider raised an unexpected exception (defensive catch).
    INTERNAL = "INTERNAL"


class ToolError(Exception):
    """Raised by a ToolProvider when execution or validation fails.

    ``code`` defaults to :attr:`ProviderErrorCode.PROVIDER_ERROR` so existing
    providers remain valid without changes; providers SHOULD set a specific
    code. The execution service records the code in the audit log alongside the
    human-readable message.
    """

    def __init__(self, message: str, *, provider_id: str | None = None,
                 code: ProviderErrorCode | str = ProviderErrorCode.PROVIDER_ERROR):
        super().__init__(message)
        self.provider_id = provider_id
        self.code = self._coerce_code(code)

    @staticmethod
    def _coerce_code(code: ProviderErrorCode | str) -> ProviderErrorCode:
        if isinstance(code, ProviderErrorCode):
            return code
        try:
            return ProviderErrorCode(str(code))
        except ValueError:
            return ProviderErrorCode.PROVIDER_ERROR
