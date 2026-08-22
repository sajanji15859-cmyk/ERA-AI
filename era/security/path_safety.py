"""Workspace path containment (Phase 3A).

Every file operation an agent performs through a provider MUST be confined to
the agent workspace root. :class:`WorkspaceRoot` is the single helper providers
call before any read/write/move/delete:

* only relative paths — absolute paths and ``..`` traversal are rejected;
* containment is checked on the *resolved* path, so symlinks cannot escape;
* the root itself is resolved once at construction.

Violations raise :class:`~era.core.result.ToolError` with
:attr:`~era.core.result.ProviderErrorCode.FORBIDDEN` — the execution service
records them and never retries them.
"""

from __future__ import annotations

from pathlib import Path

from era.core.result import ProviderErrorCode, ToolError

MAX_PATH_LEN = 2048


class WorkspaceRoot:
    """Resolved workspace root with containment checks."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, rel_path: str) -> Path:
        """Resolve ``rel_path`` inside the workspace or raise ``ToolError``.

        * Empty/non-string/oversized paths -> ``VALIDATION``.
        * Absolute paths, ``..`` escapes and symlink escapes -> ``FORBIDDEN``
          (an attempted sandbox escape is a security event, not a typo).
        """
        if not isinstance(rel_path, str) or not rel_path:
            raise ToolError("path must be a non-empty string",
                            code=ProviderErrorCode.VALIDATION)
        if len(rel_path) > MAX_PATH_LEN:
            raise ToolError("path too long", code=ProviderErrorCode.VALIDATION)
        candidate = Path(rel_path)
        if candidate.is_absolute():
            raise ToolError("absolute paths are not allowed in the workspace",
                            code=ProviderErrorCode.FORBIDDEN)
        resolved = (self.root / candidate).resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise ToolError("path escapes the workspace sandbox",
                            code=ProviderErrorCode.FORBIDDEN)
        return resolved

    def path_of(self, resolved: Path) -> str:
        """Return the workspace-relative POSIX path of ``resolved``."""
        return resolved.relative_to(self.root).as_posix()


def is_safe_relative_path(rel_path: str) -> bool:
    """Check if ``rel_path`` is a safe relative path (not absolute, no .. traversal)."""
    if not isinstance(rel_path, str) or not rel_path.strip():
        return False
    if len(rel_path) > MAX_PATH_LEN:
        return False
    candidate = Path(rel_path)
    if candidate.is_absolute():
        return False
    return all(part != ".." for part in candidate.parts)
