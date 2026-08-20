"""Sandboxed file tools: ``fs.list``, ``fs.read``, ``fs.write``.

Security model (hard boundaries):

* Every path is resolved against the sandbox root and must stay inside it
  (rejects ``..`` escapes, absolute paths, and symlink escapes at access time).
* Inputs must be relative paths; the root comes from
  ``[tools.files] sandbox_root`` / ``ERA_SANDBOX_ROOT`` (default ``$ERA_HOME/sandbox``).
* Size caps on both reads and writes; UTF-8 text only.
* There is deliberately NO delete/move tool in Phase 1.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from era.tools.base import RiskLevel, Tool, ToolExecutionError, ToolResult


def resolve_in_sandbox(root: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` inside ``root``; raise if it escapes the sandbox.

    Notes:
        Resolution follows symlinks (``Path.resolve()``), so a symlink that
        points outside the root is rejected. TOCTOU races (swapping a symlink
        between check and open) are out of scope for Phase 1 and documented.
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        msg = "path must be a non-empty string"
        raise ToolExecutionError(msg)
    candidate = Path(rel_path)
    if candidate.is_absolute():
        msg = f"absolute paths are not allowed (use a path relative to the sandbox): {rel_path!r}"
        raise ToolExecutionError(msg)
    root_resolved = root.resolve()
    target = (root / candidate).resolve()
    if target != root_resolved and not target.is_relative_to(root_resolved):
        msg = f"path escapes the sandbox: {rel_path!r}"
        raise ToolExecutionError(msg)
    return target


def _resolve_or_result(
    root: Path, rel_path: str, tool_name: str
) -> tuple[Path | None, ToolResult | None]:
    """Resolve a sandbox path; on violation return (None, failure result)."""
    try:
        return resolve_in_sandbox(root, rel_path), None
    except ToolExecutionError as exc:
        return None, ToolResult.failure(str(exc), tool=tool_name)


class FileListTool(Tool):
    name = "fs.list"
    description = (
        "List entries of a directory inside the sandbox. "
        "Input: {path: string (relative directory, default '.')}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 300},
        },
        "additionalProperties": False,
    }
    risk_level = RiskLevel.READ_ONLY

    def __init__(self, sandbox_root: Path) -> None:
        self._root = sandbox_root

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        rel = args.get("path", ".")
        target = resolve_in_sandbox(self._root, rel)
        if not target.exists():
            return ToolResult.failure(f"directory does not exist: {rel!r}", tool=self.name)
        if not target.is_dir():
            return ToolResult.failure(f"not a directory: {rel!r}", tool=self.name)
        entries = []
        for child in sorted(target.iterdir()):
            kind = "dir" if child.is_dir() else "file"
            size = child.stat().st_size if child.is_file() else None
            entries.append({"name": child.name, "type": kind, "size": size})
        lines = [
            f"{e['type']:<4} {e['name']}" + (f" ({e['size']} bytes)" if e["size"] else "")
            for e in entries
        ]
        output = "\n".join(lines) if lines else "(empty directory)"
        return ToolResult.success(output, data={"path": rel, "entries": entries}, tool=self.name)


class FileReadTool(Tool):
    name = "fs.read"
    description = (
        "Read a UTF-8 text file inside the sandbox (truncated at the size cap). "
        "Input: {path: string, max_bytes?: integer}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 300},
            "max_bytes": {"type": "integer", "minimum": 1},
        },
        "required": ["path"],
        "additionalProperties": False,
    }
    risk_level = RiskLevel.READ_ONLY

    def __init__(self, sandbox_root: Path, max_bytes: int = 100_000) -> None:
        self._root = sandbox_root
        self._max_bytes = max_bytes

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        rel = args["path"]
        limit = min(int(args.get("max_bytes", self._max_bytes)), self._max_bytes)
        target, failure = _resolve_or_result(self._root, rel, self.name)
        if failure is not None:
            return failure
        if not target.exists():
            return ToolResult.failure(f"file does not exist: {rel!r}", tool=self.name)
        if target.is_dir():
            return ToolResult.failure(f"not a file (directory): {rel!r}", tool=self.name)
        try:
            with target.open("rb") as handle:
                raw = handle.read(limit + 1)
        except OSError as exc:
            return ToolResult.failure(f"cannot read {rel!r}: {exc}", tool=self.name)
        truncated = len(raw) > limit
        raw = raw[:limit]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            msg = f"{rel!r} is not valid UTF-8 text (binary files are not supported)"
            return ToolResult.failure(msg, tool=self.name)
        note = "\n[... truncated at size cap]" if truncated else ""
        return ToolResult.success(
            text + note,
            data={"path": rel, "bytes": len(raw), "truncated": truncated},
            tool=self.name,
        )


class FileWriteTool(Tool):
    name = "fs.write"
    description = (
        "Write a UTF-8 text file inside the sandbox. Fails if the file exists unless "
        "overwrite=true. Input: {path: string, content: string, overwrite?: boolean}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 300},
            "content": {"type": "string", "maxLength": 200_000},
            "overwrite": {"type": "boolean"},
        },
        "required": ["path", "content"],
        "additionalProperties": False,
    }
    risk_level = RiskLevel.LOW_RISK_WRITE

    def __init__(self, sandbox_root: Path, max_bytes: int = 100_000) -> None:
        self._root = sandbox_root
        self._max_bytes = max_bytes

    def risk_for(self, args: Mapping[str, Any]) -> RiskLevel:
        if args.get("overwrite") is True:
            return RiskLevel.LOW_RISK_WRITE  # 1C may escalate; kept explicit here
        return self.risk_level

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        rel = args["path"]
        content = args["content"]
        overwrite = args.get("overwrite") is True
        payload = content.encode("utf-8")
        if len(payload) > self._max_bytes:
            return ToolResult.failure(
                f"content is {len(payload)} bytes; the write cap is {self._max_bytes} bytes",
                tool=self.name,
            )
        target, failure = _resolve_or_result(self._root, rel, self.name)
        if failure is not None:
            return failure
        if target.exists() and not overwrite:
            msg = f"file already exists: {rel!r} (pass overwrite=true to replace it)"
            return ToolResult.failure(msg, tool=self.name)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        except OSError as exc:
            return ToolResult.failure(f"cannot write {rel!r}: {exc}", tool=self.name)
        return ToolResult.success(
            f"wrote {len(payload)} bytes to {rel!r}",
            data={"path": rel, "bytes": len(payload), "overwrote": target.exists() and overwrite},
            tool=self.name,
        )
