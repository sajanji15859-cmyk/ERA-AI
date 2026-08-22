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
from era.registry.actions import ACTION_PARAM_SCHEMAS

#: Parameter shapes for catalogued tools (Phase 3H: alias to authoritative ACTION_PARAM_SCHEMAS).
TOOL_PARAM_SCHEMAS: dict[str, dict[str, Any]] = ACTION_PARAM_SCHEMAS

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
    "email.read": "Read an email message by message_id.",
    "email.search": "Search emails by query.",
    "email.draft": "Create a draft email.",
    "email.send": "Send an email message via SMTP (approval-gated).",
    "whatsapp.read": "Read recent incoming WhatsApp messages.",
    "whatsapp.send": "Send a WhatsApp message (approval-gated).",
    "whatsapp.react": "React to a WhatsApp message with an emoji (approval-gated).",
    "booking.search": "Search trains or flights across routes and dates.",
    "booking.hold": "Create a temporary travel booking draft (approval-gated).",
    "booking.confirm": "Confirm and issue a travel reservation. REQUIRES strong approval.",
    "booking.cancel": "Cancel an existing travel reservation. REQUIRES strong approval.",
    "image.generate": "Generate an image from a prompt into the workspace (approval-gated).",
    "github.repo_get": "Get metadata for a GitHub repository (stars, forks, description).",
    "github.issue_list": "List issues in a GitHub repository.",
    "github.issue_get": "Get details of a specific GitHub issue.",
    "github.issue_create": "Create a new issue in a GitHub repository (approval-gated).",
    "github.issue_comment": "Add a comment to an existing GitHub issue (approval-gated).",
    "github.pr_list": "List pull requests in a GitHub repository.",
    "github.pr_get": "Get details of a specific GitHub pull request.",
    "github.pr_create": "Create a new pull request in a GitHub repository (approval-gated).",
    "github.file_get": "Read file contents from a GitHub repository.",
    "github.file_commit": "Create or update a file in a GitHub repository (approval-gated).",
    "code.run": "Execute Python code in a sandboxed, isolated subprocess with resource limits.",
    "code.exec": "Execute Python code in a sandboxed, isolated subprocess with resource limits.",
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
