"""The Action model gated by the permission engine."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Action(BaseModel):
    """A single tool/action the agent wishes to perform.

    Carries no credentials — only parameter data. If an action needs a
    credential, the caller supplies an opaque reference via ``ExecutionContext``,
    never a raw secret.
    """

    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
