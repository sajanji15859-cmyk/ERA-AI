"""Tool registry: uniform lookup, validation, execution and sanitized call reports."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from era.config import Config, era_home
from era.logging import get_logger
from era.tools.base import (
    RiskLevel,
    Tool,
    ToolError,
    ToolNotFoundError,
    ToolResult,
)
from era.tools.files import FileListTool, FileReadTool, FileWriteTool
from era.tools.shell import ShellRunTool
from era.tools.web import WebFetchTool, WebSearchTool

_log = get_logger("tools.registry")

#: Argument keys whose values are never included in call descriptions.
_REDACTED_ARG_KEYS = frozenset({"content", "text", "body", "html"})
_MAX_ARG_PREVIEW = 80


def describe_call(name: str, args: Mapping[str, Any]) -> str:
    """Render a sanitized, audit-friendly description of a tool call.

    Never includes argument values for content-like keys, truncates long
    strings, and summarizes lists — safe for logs (Phase 1C audit).
    """
    parts: list[str] = []
    for key in sorted(args):
        value = args[key]
        if key in _REDACTED_ARG_KEYS:
            rendered = f"<{len(str(value))} chars>"
        elif isinstance(value, str) and len(value) > _MAX_ARG_PREVIEW:
            rendered = value[: _MAX_ARG_PREVIEW - 3] + "..."
        elif isinstance(value, (list, tuple)):
            rendered = f"[{len(value)} items]"
        else:
            rendered = repr(value)
        parts.append(f"{key}={rendered}")
    return f"{name}({', '.join(parts)})"


class ToolRegistry:
    """Central, name-keyed collection of tools with uniform execution."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name:
            msg = f"tool {type(tool).__name__} has an empty name"
            raise ToolError(msg)
        if tool.name in self._tools:
            msg = f"tool already registered: {tool.name}"
            raise ToolError(msg)
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            msg = f"unknown tool: {name!r} (available: {', '.join(sorted(self._tools))})"
            raise ToolNotFoundError(msg) from None

    def list_tools(self) -> list[dict[str, Any]]:
        """Specs of all registered tools, sorted by name (for prompts)."""
        return [self._tools[name].spec() for name in sorted(self._tools)]

    def execute(self, name: str, args: Mapping[str, Any]) -> ToolResult:
        """Validate and run a tool; never raises for tool-side failures."""
        try:
            tool = self.get(name)
        except ToolNotFoundError as exc:
            return ToolResult.failure(str(exc), tool=name)
        try:
            tool.validate(args)
        except ToolError as exc:
            return ToolResult.failure(str(exc), tool=name)
        try:
            result = tool.execute(dict(args))
        except ToolError as exc:
            _log.debug("tool %s failed: %s", name, exc)
            return ToolResult.failure(str(exc), tool=name)
        except Exception as exc:
            _log.debug("tool %s raised unexpectedly: %r", name, exc)
            return ToolResult.failure(
                f"unexpected failure in {name}: {type(exc).__name__}", tool=name
            )
        if not result.tool:
            result = ToolResult(
                ok=result.ok, output=result.output, error=result.error, data=result.data, tool=name
            )
        return result


def resolve_sandbox_root(config: Config) -> Path:
    """Sandbox root: setting wins, else ``$ERA_SANDBOX_ROOT``, else ``$ERA_HOME/sandbox``."""
    configured = config.tools.files.sandbox_root or os.environ.get("ERA_SANDBOX_ROOT", "")
    return Path(configured) if configured else era_home() / "sandbox"


def build_default_registry(config: Config, *, web_transport: Any | None = None) -> ToolRegistry:
    """Build the standard Phase 1B registry from ``config``.

    ``web_transport`` allows tests to inject a fake HTTP transport; production
    leaves it ``None`` for the real (redirect-guarded) opener.
    """
    settings = config.tools
    sandbox = resolve_sandbox_root(config)
    try:
        sandbox.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"cannot create sandbox root {sandbox}: {exc}"
        raise ToolError(msg) from exc

    registry = ToolRegistry()
    registry.register(FileListTool(sandbox))
    registry.register(FileReadTool(sandbox, max_bytes=settings.files.max_read_bytes))
    registry.register(FileWriteTool(sandbox, max_bytes=settings.files.max_write_bytes))
    registry.register(WebFetchTool(settings.web, transport=web_transport))
    registry.register(WebSearchTool(settings.web, transport=web_transport))
    registry.register(
        ShellRunTool(
            allowed_commands=tuple(settings.shell.allowed_commands),
            timeout_s=settings.shell.timeout_s,
            max_output_bytes=settings.shell.max_output_bytes,
            cwd=sandbox,
        )
    )
    return registry


__all__ = [
    "RiskLevel",
    "ToolRegistry",
    "build_default_registry",
    "describe_call",
    "resolve_sandbox_root",
]
