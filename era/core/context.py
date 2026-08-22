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
    #: Internal execution scope. AgentService sets this to ``agent:<run_id>``
    #: so stateful providers isolate concurrent runs even when they share the
    #: same authenticated API-key session. It is server-derived and is never
    #: accepted from action request bodies.
    execution_scope: str | None = None
    credentials: CredentialScope = Field(default_factory=CredentialScope)
    #: Optional absolute deadline for the *provider dispatch* phase (Phase 1E),
    #: as a :func:`time.monotonic` timestamp. ``None`` means no cooperative
    #: deadline is advertised. The execution service additionally enforces a
    #: hard wall-clock timeout around providers; this field lets a cooperative
    #: provider observe remaining budget without holding a DB transaction.
    deadline: float | None = None
