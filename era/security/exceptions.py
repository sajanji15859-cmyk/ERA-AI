"""Authentication / authorization exceptions (Phase 2A).

These are intentionally distinct from provider errors and from
:class:`era.core.result.ToolError`: they describe *who is calling*, not whether
an action succeeded. The API layer maps them onto HTTP 401 / 403; the fail-closed
security model treats any unauthenticated or unpermissioned caller the same as a
denial — nothing is executed and nothing leaks.
"""

from __future__ import annotations


class AuthenticationError(Exception):
    """The caller could not be identified (missing / invalid / revoked key)."""


class AuthorizationError(Exception):
    """The caller is identified but lacks the required permission / role."""
