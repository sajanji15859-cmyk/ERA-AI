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
    # Phase 3D: GitHub
    "github.repo_get": {
        "type": "object",
        "properties": {"repo": {"type": "string", "description": "owner/repo"}},
        "required": ["repo"],
    },
    "github.issue_list": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "state": {"type": "string", "description": "open|closed|all"},
        },
        "required": ["repo"],
    },
    "github.issue_get": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "issue_number": {"type": "integer", "description": "issue number"},
        },
        "required": ["repo", "issue_number"],
    },
    "github.issue_create": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "title": {"type": "string", "description": "issue title"},
            "body": {"type": "string", "description": "issue body"},
        },
        "required": ["repo", "title"],
    },
    "github.issue_comment": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "issue_number": {"type": "integer", "description": "issue number"},
            "body": {"type": "string", "description": "comment body"},
        },
        "required": ["repo", "issue_number", "body"],
    },
    "github.pr_list": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "state": {"type": "string", "description": "open|closed|all"},
        },
        "required": ["repo"],
    },
    "github.pr_get": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "pull_number": {"type": "integer", "description": "PR number"},
        },
        "required": ["repo", "pull_number"],
    },
    "github.pr_create": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "title": {"type": "string", "description": "PR title"},
            "head": {"type": "string", "description": "head branch"},
            "base": {"type": "string", "description": "base branch"},
            "body": {"type": "string", "description": "PR description"},
        },
        "required": ["repo", "title", "head", "base"],
    },
    "github.file_get": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "path": {"type": "string", "description": "file path in repo"},
            "ref": {"type": "string", "description": "branch, tag or commit SHA"},
        },
        "required": ["repo", "path"],
    },
    "github.file_commit": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "path": {"type": "string", "description": "file path in repo"},
            "message": {"type": "string", "description": "commit message"},
            "content": {"type": "string", "description": "file content to commit"},
            "branch": {"type": "string", "description": "target branch"},
        },
        "required": ["repo", "path", "message", "content"],
    },
    # Phase 3D: Code execution
    "code.run": {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code snippet to execute"},
            "language": {"type": "string", "description": "python"},
        },
        "required": ["code"],
    },
    "code.exec": {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code snippet to execute"},
            "language": {"type": "string", "description": "python"},
        },
        "required": ["code"],
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
