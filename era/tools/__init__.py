"""Phase 1B tool system: schema-validated tools behind one registry."""

from __future__ import annotations

from era.tools.base import (
    RiskLevel,
    Tool,
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolResult,
    ToolValidationError,
)
from era.tools.files import FileListTool, FileReadTool, FileWriteTool
from era.tools.registry import (
    ToolRegistry,
    build_default_registry,
    describe_call,
    resolve_sandbox_root,
)
from era.tools.schema import validate_schema
from era.tools.shell import ShellRunTool
from era.tools.web import WebFetchTool, WebSearchTool

__all__ = [
    "FileListTool",
    "FileReadTool",
    "FileWriteTool",
    "RiskLevel",
    "ShellRunTool",
    "Tool",
    "ToolError",
    "ToolExecutionError",
    "ToolNotFoundError",
    "ToolRegistry",
    "ToolResult",
    "ToolValidationError",
    "WebFetchTool",
    "WebSearchTool",
    "build_default_registry",
    "describe_call",
    "resolve_sandbox_root",
    "validate_schema",
]
