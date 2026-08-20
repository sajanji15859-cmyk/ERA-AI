"""Execution context carrying identity and (opaque) credential references."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CredentialScope(BaseModel):
    """Opaque credential references ONLY — never raw secrets.

    Keys are capability domains (e.g. ``"email"``, ``"whatsapp"``, ``"device"``);
    values are provider-scoped reference ids. The provider resolves the reference
    against its own secure store at execution time. The agent/LLM layer and the
    permission/audit core only ever see these references.
    """

    refs: dict[str, str] = Field(default_factory=dict)


class ExecutionContext(BaseModel):
    actor_id: str
    session_id: str | None = None
    credentials: CredentialScope = Field(default_factory=CredentialScope)
