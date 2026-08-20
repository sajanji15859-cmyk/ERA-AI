"""Provider execution results."""

from __future__ import annotations

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


class ToolError(Exception):
    """Raised by a ToolProvider when execution or validation fails."""

    def __init__(self, message: str, *, provider_id: str | None = None):
        super().__init__(message)
        self.provider_id = provider_id
