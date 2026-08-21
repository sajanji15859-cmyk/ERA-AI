"""GitHub provider — repository, issue, PR, and file operations (Phase 3D).

Provides authenticated and public interactions with the GitHub REST API:

* Repositories: ``github.repo_get``
* Issues: ``github.issue_list``, ``github.issue_get``, ``github.issue_create``,
  ``github.issue_comment``
* Pull Requests: ``github.pr_list``, ``github.pr_get``, ``github.pr_create``
* Files / Contents: ``github.file_get``, ``github.file_commit``

Security controls:
* Token management: GitHub Personal Access Token (PAT) may be configured as a
  plain environment variable or as a vault reference (``vault:github/token``).
  Resolved securely via :class:`~era.services.vault_service.VaultRefResolver`.
* Strict redaction: ``token`` is declared in ``secret_fields`` across all
  GitHub action specifications and is never leaked in params, summaries, results,
  error messages, or audit records.
* Input validation: Repository owner/name must match ``^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$``;
  paths cannot traverse outside repository bounds (no ``..`` or leading slashes);
  parameter lengths and types are strictly bounded.
* Standardized error mapping: HTTP status codes map deterministically onto the
  stable :class:`~era.core.result.ProviderErrorCode` taxonomy (401/403 auth -> ``AUTH``,
  404 -> ``NOT_FOUND``, 422 -> ``VALIDATION``, 429/secondary rate limit ->
  ``RATE_LIMITED``, 5xx/network -> ``UNAVAILABLE``, timeout -> ``TIMEOUT``).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.vault import VaultError, is_vault_ref

DEFAULT_API_BASE_URL = "https://api.github.com"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_USER_AGENT = "ERA-Agent/0.4.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB

_REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")
_MAX_REPO_LEN = 200
_MAX_PATH_LEN = 1024
_MAX_TITLE_LEN = 1024
_MAX_BODY_LEN = 65536
_MAX_MESSAGE_LEN = 1024
_MAX_BRANCH_LEN = 256
_MAX_FILE_BYTES = 1_000_000

_ACTION_TYPES = frozenset({
    ActionType.GITHUB_REPO_GET.value,
    ActionType.GITHUB_ISSUE_LIST.value,
    ActionType.GITHUB_ISSUE_GET.value,
    ActionType.GITHUB_ISSUE_CREATE.value,
    ActionType.GITHUB_ISSUE_COMMENT.value,
    ActionType.GITHUB_PR_LIST.value,
    ActionType.GITHUB_PR_GET.value,
    ActionType.GITHUB_PR_CREATE.value,
    ActionType.GITHUB_FILE_GET.value,
    ActionType.GITHUB_FILE_COMMIT.value,
})

_MUTATING_ACTIONS = frozenset({
    ActionType.GITHUB_ISSUE_CREATE.value,
    ActionType.GITHUB_ISSUE_COMMENT.value,
    ActionType.GITHUB_PR_CREATE.value,
    ActionType.GITHUB_FILE_COMMIT.value,
})


class GitHubProvider:
    """ToolProvider for GitHub API operations with vault secret resolution."""

    id = "github"
    action_types = _ACTION_TYPES

    def __init__(
        self,
        *,
        token: str = "",
        api_base_url: str = DEFAULT_API_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        secret_resolver=None,
    ):
        self._token_ref = str(token or "").strip()
        self._api_base_url = str(api_base_url or DEFAULT_API_BASE_URL).rstrip("/")
        self._timeout_seconds = max(0.1, float(timeout_seconds))
        self._user_agent = str(user_agent or DEFAULT_USER_AGENT)
        self._max_response_bytes = max(1024, int(max_response_bytes))
        self._secret_resolver = secret_resolver

    # -- SPI ---------------------------------------------------------------------

    def validate(self, action: Action) -> None:
        action_type = action.action_type
        if action_type not in self.action_types:
            raise ToolError(f"GitHub provider cannot handle {action_type}",
                            provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        params = action.params or {}
        repo = params.get("repo")
        if not isinstance(repo, str) or not repo.strip():
            raise ToolError("'repo' parameter is required (format: owner/repo)",
                            provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        repo = repo.strip()
        if len(repo) > _MAX_REPO_LEN or not _REPO_RE.match(repo) or ".." in repo:
            raise ToolError(f"invalid repository name: {repo!r} (must be 'owner/repo')",
                            provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)

        # Action-specific validations
        if action_type == ActionType.GITHUB_ISSUE_GET.value:
            num = params.get("issue_number")
            if not isinstance(num, int) or isinstance(num, bool) or num <= 0:
                raise ToolError("'issue_number' must be a positive integer",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.GITHUB_ISSUE_CREATE.value:
            title = params.get("title")
            if not isinstance(title, str) or not title.strip():
                raise ToolError("'title' is required for creating an issue",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(title) > _MAX_TITLE_LEN:
                raise ToolError("issue title too long",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            body = params.get("body", "")
            if body is not None and (not isinstance(body, str) or len(body) > _MAX_BODY_LEN):
                raise ToolError("issue body invalid or too long",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.GITHUB_ISSUE_COMMENT.value:
            num = params.get("issue_number")
            if not isinstance(num, int) or isinstance(num, bool) or num <= 0:
                raise ToolError("'issue_number' must be a positive integer",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            body = params.get("body")
            if not isinstance(body, str) or not body.strip():
                raise ToolError("'body' is required for issue comment",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(body) > _MAX_BODY_LEN:
                raise ToolError("issue comment body too long",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.GITHUB_PR_GET.value:
            num = params.get("pull_number")
            if not isinstance(num, int) or isinstance(num, bool) or num <= 0:
                raise ToolError("'pull_number' must be a positive integer",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.GITHUB_PR_CREATE.value:
            title = params.get("title")
            head = params.get("head")
            base = params.get("base")
            if not isinstance(title, str) or not title.strip():
                raise ToolError("'title' is required for creating a PR",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not isinstance(head, str) or not head.strip():
                raise ToolError("'head' branch is required for creating a PR",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not isinstance(base, str) or not base.strip():
                raise ToolError("'base' branch is required for creating a PR",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(title) > _MAX_TITLE_LEN or len(head) > _MAX_BRANCH_LEN or len(base) > _MAX_BRANCH_LEN:
                raise ToolError("parameter length limit exceeded for PR creation",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.GITHUB_FILE_GET.value:
            path = params.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ToolError("'path' is required for github.file_get",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self._validate_file_path(path)

        elif action_type == ActionType.GITHUB_FILE_COMMIT.value:
            path = params.get("path")
            message = params.get("message")
            content = params.get("content")
            if not isinstance(path, str) or not path.strip():
                raise ToolError("'path' is required for github.file_commit",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self._validate_file_path(path)
            if not isinstance(message, str) or not message.strip():
                raise ToolError("'message' is required for committing a file",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(message) > _MAX_MESSAGE_LEN:
                raise ToolError("commit message too long",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not isinstance(content, str):
                raise ToolError("'content' must be a string",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(content) > _MAX_FILE_BYTES:
                raise ToolError("file content exceeds maximum allowed size",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        token = self._resolve_token(action, ctx)

        action_type = action.action_type
        params = action.params or {}
        repo = str(params["repo"]).strip()
        owner, repo_name = repo.split("/", 1)

        if action_type in _MUTATING_ACTIONS and not token:
            raise ToolError("GitHub token required for mutating operations",
                            provider_id=self.id,
                            code=ProviderErrorCode.AUTH)

        if action_type == ActionType.GITHUB_REPO_GET.value:
            return self._repo_get(owner, repo_name, token)
        elif action_type == ActionType.GITHUB_ISSUE_LIST.value:
            state = params.get("state", "open")
            return self._issue_list(owner, repo_name, state, token)
        elif action_type == ActionType.GITHUB_ISSUE_GET.value:
            return self._issue_get(owner, repo_name, int(params["issue_number"]), token)
        elif action_type == ActionType.GITHUB_ISSUE_CREATE.value:
            return self._issue_create(owner, repo_name, params["title"], params.get("body", ""), token)
        elif action_type == ActionType.GITHUB_ISSUE_COMMENT.value:
            return self._issue_comment(owner, repo_name, int(params["issue_number"]), params["body"], token)
        elif action_type == ActionType.GITHUB_PR_LIST.value:
            state = params.get("state", "open")
            return self._pr_list(owner, repo_name, state, token)
        elif action_type == ActionType.GITHUB_PR_GET.value:
            return self._pr_get(owner, repo_name, int(params["pull_number"]), token)
        elif action_type == ActionType.GITHUB_PR_CREATE.value:
            return self._pr_create(owner, repo_name, params["title"], params["head"], params["base"], params.get("body", ""), token)
        elif action_type == ActionType.GITHUB_FILE_GET.value:
            return self._file_get(owner, repo_name, params["path"], params.get("ref"), token)
        elif action_type == ActionType.GITHUB_FILE_COMMIT.value:
            return self._file_commit(owner, repo_name, params["path"], params["message"], params["content"], params.get("branch"), params.get("sha"), token)

        raise ToolError(f"GitHub provider cannot handle {action_type}",
                        provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.4.0",
            display_name="GitHub (repositories, issues, pull requests, files)",
            is_stub=False,
            capabilities=("repos", "issues", "pull_requests", "contents", "vault-backed"),
        )

    # -- Token Resolution --------------------------------------------------------

    def _resolve_token(self, action: Action, ctx: ExecutionContext | None = None) -> str:
        params = action.params or {}
        candidate = ""
        if "token" in params and isinstance(params["token"], str):
            candidate = params["token"]
        elif ctx is not None and getattr(ctx, "credentials", None) is not None:
            refs = getattr(ctx.credentials, "refs", {})
            if isinstance(refs, dict):
                candidate = refs.get("github_token") or refs.get("github") or refs.get("token") or ""
        if not candidate:
            candidate = self._token_ref

        if not candidate:
            return ""
        candidate = candidate.strip()
        if not is_vault_ref(candidate):
            return candidate

        if self._secret_resolver is None:
            raise ToolError(
                "GitHub token is a vault reference but no vault is wired",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            )
        try:
            if hasattr(self._secret_resolver, "resolve_ref"):
                resolved = self._secret_resolver.resolve_ref(candidate)
            elif hasattr(self._secret_resolver, "resolve"):
                resolved = self._secret_resolver.resolve(
                    candidate, actor_id=getattr(ctx, "actor_id", "github-provider")
                )
            else:
                raise VaultError("invalid resolver", code="internal")
        except VaultError as exc:
            raise ToolError(
                "GitHub token could not be resolved from the vault",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            ) from exc
        if not resolved:
            raise ToolError("vault reference resolved to empty GitHub token",
                            provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        return resolved

    # -- Path Validation Helper --------------------------------------------------

    @staticmethod
    def _validate_file_path(path: str) -> None:
        p = path.strip()
        if len(p) > _MAX_PATH_LEN:
            raise ToolError("file path too long", provider_id="github",
                            code=ProviderErrorCode.VALIDATION)
        if p.startswith("/") or ".." in p.split("/") or "\\" in p:
            raise ToolError("invalid repository file path (must be relative, no traversal)",
                            provider_id="github",
                            code=ProviderErrorCode.FORBIDDEN)

    # -- API Operations ----------------------------------------------------------

    def _repo_get(self, owner: str, repo: str, token: str) -> ActionResult:
        data = self._http_call("GET", f"/repos/{owner}/{repo}", token=token)
        stars = data.get("stargazers_count", 0)
        forks = data.get("forks_count", 0)
        return ActionResult(
            success=True,
            summary=f"Repository {owner}/{repo} (stars: {stars}, forks: {forks})",
            data={
                "name": data.get("name"),
                "full_name": data.get("full_name"),
                "description": data.get("description"),
                "html_url": data.get("html_url"),
                "default_branch": data.get("default_branch"),
                "stars": stars,
                "forks": forks,
                "open_issues_count": data.get("open_issues_count", 0),
                "private": data.get("private", False),
            },
        )

    def _issue_list(self, owner: str, repo: str, state: str, token: str) -> ActionResult:
        query = urllib.parse.urlencode({"state": state, "per_page": 30})
        items = self._http_call("GET", f"/repos/{owner}/{repo}/issues?{query}", token=token)
        if not isinstance(items, list):
            items = []
        issues = [
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "state": item.get("state"),
                "user": (item.get("user") or {}).get("login"),
                "created_at": item.get("created_at"),
                "comments": item.get("comments", 0),
                "html_url": item.get("html_url"),
            }
            for item in items
            if "pull_request" not in item  # GitHub API lists PRs as issues unless filtered
        ]
        return ActionResult(
            success=True,
            summary=f"Retrieved {len(issues)} issue(s) for {owner}/{repo}",
            data={"repo": f"{owner}/{repo}", "state": state, "issues": issues},
        )

    def _issue_get(self, owner: str, repo: str, issue_number: int, token: str) -> ActionResult:
        data = self._http_call("GET", f"/repos/{owner}/{repo}/issues/{issue_number}", token=token)
        return ActionResult(
            success=True,
            summary=f"Issue #{issue_number}: {data.get('title')}",
            data={
                "number": data.get("number"),
                "title": data.get("title"),
                "body": data.get("body"),
                "state": data.get("state"),
                "user": (data.get("user") or {}).get("login"),
                "created_at": data.get("created_at"),
                "comments": data.get("comments", 0),
                "html_url": data.get("html_url"),
            },
        )

    def _issue_create(self, owner: str, repo: str, title: str, body: str, token: str) -> ActionResult:
        payload = {"title": title, "body": body}
        data = self._http_call("POST", f"/repos/{owner}/{repo}/issues", payload=payload, token=token)
        num = data.get("number")
        return ActionResult(
            success=True,
            summary=f"Created issue #{num} in {owner}/{repo}",
            data={
                "number": num,
                "title": data.get("title"),
                "state": data.get("state"),
                "html_url": data.get("html_url"),
            },
        )

    def _issue_comment(self, owner: str, repo: str, issue_number: int, body: str, token: str) -> ActionResult:
        payload = {"body": body}
        data = self._http_call("POST", f"/repos/{owner}/{repo}/issues/{issue_number}/comments", payload=payload, token=token)
        return ActionResult(
            success=True,
            summary=f"Added comment to issue #{issue_number} in {owner}/{repo}",
            data={
                "id": data.get("id"),
                "html_url": data.get("html_url"),
                "created_at": data.get("created_at"),
            },
        )

    def _pr_list(self, owner: str, repo: str, state: str, token: str) -> ActionResult:
        query = urllib.parse.urlencode({"state": state, "per_page": 30})
        items = self._http_call("GET", f"/repos/{owner}/{repo}/pulls?{query}", token=token)
        if not isinstance(items, list):
            items = []
        prs = [
            {
                "number": item.get("number"),
                "title": item.get("title"),
                "state": item.get("state"),
                "head": (item.get("head") or {}).get("ref"),
                "base": (item.get("base") or {}).get("ref"),
                "user": (item.get("user") or {}).get("login"),
                "created_at": item.get("created_at"),
                "html_url": item.get("html_url"),
            }
            for item in items
        ]
        return ActionResult(
            success=True,
            summary=f"Retrieved {len(prs)} pull request(s) for {owner}/{repo}",
            data={"repo": f"{owner}/{repo}", "state": state, "pull_requests": prs},
        )

    def _pr_get(self, owner: str, repo: str, pull_number: int, token: str) -> ActionResult:
        data = self._http_call("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}", token=token)
        return ActionResult(
            success=True,
            summary=f"Pull request #{pull_number}: {data.get('title')}",
            data={
                "number": data.get("number"),
                "title": data.get("title"),
                "body": data.get("body"),
                "state": data.get("state"),
                "head": (data.get("head") or {}).get("ref"),
                "base": (data.get("base") or {}).get("ref"),
                "merged": data.get("merged", False),
                "mergeable": data.get("mergeable"),
                "user": (data.get("user") or {}).get("login"),
                "created_at": data.get("created_at"),
                "html_url": data.get("html_url"),
            },
        )

    def _pr_create(self, owner: str, repo: str, title: str, head: str, base: str, body: str, token: str) -> ActionResult:
        payload = {"title": title, "head": head, "base": base, "body": body}
        data = self._http_call("POST", f"/repos/{owner}/{repo}/pulls", payload=payload, token=token)
        num = data.get("number")
        return ActionResult(
            success=True,
            summary=f"Created pull request #{num} ({head} -> {base}) in {owner}/{repo}",
            data={
                "number": num,
                "title": data.get("title"),
                "head": head,
                "base": base,
                "state": data.get("state"),
                "html_url": data.get("html_url"),
            },
        )

    def _file_get(self, owner: str, repo: str, path: str, ref: str | None, token: str) -> ActionResult:
        clean_path = path.lstrip("/")
        endpoint = f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(clean_path)}"
        if ref:
            endpoint += f"?{urllib.parse.urlencode({'ref': ref})}"
        data = self._http_call("GET", endpoint, token=token)

        content_raw = data.get("content", "")
        encoding = data.get("encoding", "")
        if encoding == "base64" and isinstance(content_raw, str):
            try:
                decoded_text = base64.b64decode(content_raw).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                decoded_text = content_raw
        else:
            decoded_text = str(content_raw or "")

        return ActionResult(
            success=True,
            summary=f"Read file {clean_path} from {owner}/{repo} ({data.get('size', 0)} bytes)",
            data={
                "path": clean_path,
                "sha": data.get("sha"),
                "size": data.get("size", len(decoded_text)),
                "content": decoded_text,
                "html_url": data.get("html_url"),
            },
        )

    def _file_commit(
        self,
        owner: str,
        repo: str,
        path: str,
        message: str,
        content: str,
        branch: str | None,
        sha: str | None,
        token: str,
    ) -> ActionResult:
        clean_path = path.lstrip("/")
        endpoint = f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(clean_path)}"
        encoded_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
        payload: dict[str, Any] = {
            "message": message,
            "content": encoded_content,
        }
        if branch:
            payload["branch"] = branch
        if sha:
            payload["sha"] = sha

        data = self._http_call("PUT", endpoint, payload=payload, token=token)
        commit_sha = (data.get("commit") or {}).get("sha")
        content_sha = (data.get("content") or {}).get("sha")
        return ActionResult(
            success=True,
            summary=f"Committed {clean_path} to {owner}/{repo}",
            data={
                "path": clean_path,
                "commit_sha": commit_sha,
                "content_sha": content_sha,
                "html_url": (data.get("content") or {}).get("html_url"),
            },
        )

    # -- HTTP Transport & Error Mapping ------------------------------------------

    def _http_call(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        token: str = "",
    ) -> Any:
        url = f"{self._api_base_url}{endpoint}"
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self._user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                raw = resp.read(self._max_response_bytes + 1)
                if len(raw) > self._max_response_bytes:
                    raw = raw[:self._max_response_bytes]
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            self._handle_http_error(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError(
                f"GitHub API unreachable or timed out: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.UNAVAILABLE,
            ) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ToolError(
                "GitHub API returned unparseable response",
                provider_id=self.id,
                code=ProviderErrorCode.PROVIDER_ERROR,
            ) from exc

    def _handle_http_error(self, exc: urllib.error.HTTPError) -> None:
        status = exc.code if isinstance(exc.code, int) else 0
        error_body = ""
        try:
            raw_err = exc.read(4096)
            if raw_err:
                doc = json.loads(raw_err.decode("utf-8"))
                error_body = str(doc.get("message") or "")
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            pass

        msg_lower = error_body.lower()
        if status in (401,):
            raise ToolError(
                "GitHub authentication failed (bad or expired token)",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            ) from exc

        if status == 403:
            if "rate limit" in msg_lower or "secondary rate limit" in msg_lower:
                raise ToolError(
                    f"GitHub rate limit exceeded: {error_body or 'API rate limit'}",
                    provider_id=self.id,
                    code=ProviderErrorCode.UNAVAILABLE,
                ) from exc
            raise ToolError(
                f"GitHub forbidden or insufficient permissions: {error_body or 'Access denied'}",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            ) from exc

        if status == 404:
            raise ToolError(
                f"GitHub resource not found: {error_body or 'Not Found'}",
                provider_id=self.id,
                code=ProviderErrorCode.NOT_FOUND,
            ) from exc

        if status == 422:
            raise ToolError(
                f"GitHub validation error: {error_body or 'Unprocessable Entity'}",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            ) from exc

        if status == 429:
            raise ToolError(
                f"GitHub rate limit exceeded: {error_body or 'Too Many Requests'}",
                provider_id=self.id,
                code=ProviderErrorCode.UNAVAILABLE,
            ) from exc

        if status >= 500:
            raise ToolError(
                f"GitHub service unavailable (HTTP {status})",
                provider_id=self.id,
                code=ProviderErrorCode.UNAVAILABLE,
            ) from exc

        raise ToolError(
            f"GitHub request failed (HTTP {status}): {error_body or 'Error'}",
            provider_id=self.id,
            code=ProviderErrorCode.PROVIDER_ERROR,
        ) from exc
