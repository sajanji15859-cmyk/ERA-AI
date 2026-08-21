"""Tool schemas for LLM function calling (Phase 3B).

JSON-schema-shaped tool definitions built from the authoritative action
catalog, so a model can only ever *see* (and therefore propose) tools that
are catalogued, registered and permitted:

* ``FORBIDDEN`` actions are never offered;
* actions without a registered provider are never offered;
* a caller-supplied guard (e.g. the RBAC capability-domain allowlist for the
  user's role) can additionally filter the set.

The catalog stays the single source of truth for risk/domains; this module
adds the *call shape* (parameters) the model needs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from era.core.enums import RiskLevel
from era.core.tool_registry import ActionCatalog, ToolRegistry

#: Parameter shapes for the tools with real providers in this phase.
#: ``required`` lists the parameters a call must include.
TOOL_PARAM_SCHEMAS: dict[str, dict[str, Any]] = {
    "web.search": {
        "type": "object",
        "properties": {"q": {"type": "string", "description": "search query"}},
        "required": ["q"],
    },
    "web.fetch": {
        "type": "object",
        "properties": {"url": {"type": "string", "description": "public http(s) URL"}},
        "required": ["url"],
    },
    "web.download": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "path": {"type": "string", "description": "workspace-relative file path"},
        },
        "required": ["url", "path"],
    },
    "fs.list": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "workspace directory"}},
        "required": ["path"],
    },
    "fs.read": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "workspace file"}},
        "required": ["path"],
    },
    "fs.write": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string", "description": "full file content"},
        },
        "required": ["path", "content"],
    },
    "fs.move": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "dst": {"type": "string"}},
        "required": ["path", "dst"],
    },
    "fs.delete": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "file/empty dir"}},
        "required": ["path"],
    },
}
TOOL_PARAM_SCHEMAS.update({
    "photo.view": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    "photo.edit": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
    "photo.upload": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
    "photo.delete": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
})

TOOL_DESCRIPTIONS: dict[str, str] = {
    "web.search": "Search the public web (keyless). Returns titles, URLs and snippets.",
    "web.fetch": "Fetch a public web page and extract its title and text.",
    "web.download": "Download a public file into the sandboxed workspace.",
    "fs.list": "List files and directories inside the sandboxed workspace.",
    "fs.read": "Read a workspace file (text).",
    "fs.write": "Write/overwrite a workspace file. Destructive overwrites need approval.",
    "fs.move": "Move/rename a workspace file.",
    "fs.delete": "Delete a workspace file or empty directory. REQUIRES strong approval.",
    "photo.view": "Read an image asset from the workspace.",
    "photo.edit": "Overwrite an image asset in the workspace (approval-gated).",
    "photo.upload": "Write a new image asset into the workspace (approval-gated).",
    "photo.delete": "Delete an image asset. REQUIRES strong approval.",
    "stub.noop": "No-op used for tests only.",
}

_GENERIC_PARAMS: dict[str, Any] = {"type": "object", "properties": {}}


def build_tools_json(catalog: ActionCatalog, registry: ToolRegistry,
                     allowed: Callable[[str], bool] | None = None) -> list[dict[str, Any]]:
    """OpenAI function-calling tool definitions for the offered actions."""
    tools: list[dict[str, Any]] = []
    for spec in sorted(catalog, key=lambda s: s.action_type):
        if spec.risk_level is RiskLevel.FORBIDDEN:
            continue  # never offer override-proof-forbidden actions
        if registry.get(spec.action_type) is None:
            continue  # never offer actions that cannot dispatch
        if allowed is not None and not allowed(spec.action_type):
            continue  # role/domain guard
        tools.append({
            "type": "function",
            "function": {
                "name": spec.action_type,
                "description": TOOL_DESCRIPTIONS.get(
                    spec.action_type,
                    f"Catalogued action {spec.action_type} "
                    f"(risk: {spec.risk_level.value}).",
                ),
                "parameters": TOOL_PARAM_SCHEMAS.get(spec.action_type, _GENERIC_PARAMS),
            },
        })
    return tools
