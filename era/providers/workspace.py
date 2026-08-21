"""WorkspaceProvider — sandboxed file operations for the agent (Phase 3A).

The first *real* ToolProvider in ERA. Handles the catalogued ``fs.*`` and
``photo.*`` actions against a single workspace directory:

* every path is confined to the workspace root (traversal and symlink escapes
  are rejected as ``FORBIDDEN`` by :class:`era.security.path_safety.WorkspaceRoot`);
* writes are size-capped; reads reject files larger than the cap instead of
  silently truncating;
* ``fs.delete`` on the workspace root itself is impossible; directories must
  be empty;
* ``photo.*`` actions map onto the same sandboxed files (view → read,
  edit/upload → write, delete → delete) so no separate photo surface exists
  in MVEA.

Risk tiers stay exactly as catalogued: ``fs.write``/``fs.move`` are MUTATING
(→ CONFIRM under the default policy), ``fs.delete``/``photo.delete`` are
DESTRUCTIVE (→ CONFIRM_STRONG), ``fs.read``/``fs.list`` are SENSITIVE/SAFE.
The provider itself performs no authorization — the ExecutionService does.
"""

from __future__ import annotations

from pathlib import Path

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot

MAX_LIST_ENTRIES = 1000
DEFAULT_MAX_FILE_BYTES = 1_048_576  # 1 MiB

_ACTION_TYPES = frozenset({
    ActionType.FS_LIST.value,
    ActionType.FS_READ.value,
    ActionType.FS_WRITE.value,
    ActionType.FS_MOVE.value,
    ActionType.FS_DELETE.value,
    ActionType.PHOTO_VIEW.value,
    ActionType.PHOTO_EDIT.value,
    ActionType.PHOTO_UPLOAD.value,
    ActionType.PHOTO_DELETE.value,
})


class WorkspaceProvider:
    id = "workspace"

    def __init__(self, root: str | Path, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES):
        self.workspace = WorkspaceRoot(root)
        self.max_file_bytes = max(1, int(max_file_bytes))

    action_types = _ACTION_TYPES

    # -- SPI ---------------------------------------------------------------------
    def validate(self, action: Action) -> None:
        action_type = action.action_type
        params = action.params or {}
        path = params.get("path")
        if not isinstance(path, str) or not path:
            raise ToolError("'path' is required", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if action_type in (ActionType.FS_WRITE.value, ActionType.PHOTO_EDIT.value,
                           ActionType.PHOTO_UPLOAD.value):
            content = params.get("content")
            if not isinstance(content, str):
                raise ToolError("'content' (string) is required for writes",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            if len(content.encode("utf-8")) > self.max_file_bytes:
                raise ToolError(
                    f"content exceeds the workspace file cap ({self.max_file_bytes} bytes)",
                    provider_id=self.id, code=ProviderErrorCode.VALIDATION)
        if action_type == ActionType.FS_MOVE.value:
            dst = params.get("dst")
            if not isinstance(dst, str) or not dst:
                raise ToolError("'dst' is required for fs.move", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
        # Containment check (raises FORBIDDEN on any escape attempt).
        self.workspace.resolve(path)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        action_type = action.action_type
        path = self.workspace.resolve(str(action.params["path"]))
        if action_type == ActionType.FS_LIST.value:
            return self._list(path)
        if action_type == ActionType.FS_READ.value or action_type == ActionType.PHOTO_VIEW.value:
            return self._read(path)
        if action_type in (ActionType.FS_WRITE.value, ActionType.PHOTO_EDIT.value,
                           ActionType.PHOTO_UPLOAD.value):
            return self._write(path, str(action.params["content"]))
        if action_type == ActionType.FS_MOVE.value:
            dst = self.workspace.resolve(str(action.params["dst"]))
            return self._move(path, dst)
        if action_type in (ActionType.FS_DELETE.value, ActionType.PHOTO_DELETE.value):
            return self._delete(path)
        raise ToolError(f"workspace cannot handle {action_type}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.3.0",
            display_name="Workspace (sandboxed files)",
            is_stub=False,
            capabilities=("fs", "sandboxed", "offline"),
        )

    # -- operations ---------------------------------------------------------------
    def _list(self, path: Path) -> ActionResult:
        if not path.exists():
            raise ToolError(f"no such path: {self.workspace.path_of(path)}",
                            provider_id=self.id, code=ProviderErrorCode.NOT_FOUND)
        if not path.is_dir():
            raise ToolError("fs.list target is not a directory", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        entries = []
        for child in sorted(path.iterdir()):
            kind = "dir" if child.is_dir() else "file"
            size = child.stat().st_size if child.is_file() else None
            entries.append({"name": child.name, "kind": kind, "size": size})
            if len(entries) >= MAX_LIST_ENTRIES:
                break
        return ActionResult(success=True, summary=f"listed {len(entries)} entries",
                            data={"path": self.workspace.path_of(path), "entries": entries})

    def _read(self, path: Path) -> ActionResult:
        if not path.exists():
            raise ToolError(f"no such file: {self.workspace.path_of(path)}",
                            provider_id=self.id, code=ProviderErrorCode.NOT_FOUND)
        if not path.is_file():
            raise ToolError("fs.read target is not a file", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ToolError(f"file too large to read ({size} > {self.max_file_bytes} bytes)",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ToolError(f"read failed: {exc}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return ActionResult(success=True, summary=f"read {size} bytes",
                            data={"path": self.workspace.path_of(path),
                                  "bytes": size, "content": content})

    def _write(self, path: Path, content: str) -> ActionResult:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise ToolError(f"write failed: {exc}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        size = len(content.encode("utf-8"))
        return ActionResult(success=True, summary=f"wrote {size} bytes",
                            data={"path": self.workspace.path_of(path), "bytes": size})

    def _move(self, src: Path, dst: Path) -> ActionResult:
        if not src.exists():
            raise ToolError(f"no such file: {self.workspace.path_of(src)}",
                            provider_id=self.id, code=ProviderErrorCode.NOT_FOUND)
        if dst.exists():
            raise ToolError("destination already exists", provider_id=self.id,
                            code=ProviderErrorCode.CONFLICT)
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
        except OSError as exc:
            raise ToolError(f"move failed: {exc}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return ActionResult(success=True, summary="moved",
                            data={"from": self.workspace.path_of(src),
                                  "to": self.workspace.path_of(dst)})

    def _delete(self, path: Path) -> ActionResult:
        if path == self.workspace.root:
            raise ToolError("deleting the workspace root is forbidden",
                            provider_id=self.id, code=ProviderErrorCode.FORBIDDEN)
        if not path.exists():
            raise ToolError(f"no such path: {self.workspace.path_of(path)}",
                            provider_id=self.id, code=ProviderErrorCode.NOT_FOUND)
        try:
            if path.is_dir():
                path.rmdir()  # fails on non-empty directories
            else:
                path.unlink()
        except OSError as exc:
            raise ToolError(f"delete failed: {exc}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return ActionResult(success=True, summary="deleted",
                            data={"path": self.workspace.path_of(path)})
