"""GitHub provider tests — API interactions, secret resolution, error mapping (Phase 3D).

All tests run fully offline using mocked HTTP calls — no network access required.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.github import GitHubProvider
from era.security.vault import VaultError
from tests.provider_contract import assert_provider_contract

CTX = ExecutionContext(actor_id="test-actor", credentials={"token": "test-pat-123"})


class _FakeHTTPResponse:
    def __init__(self, data: dict | list, status: int = 200, headers: dict | None = None):
        self._body = json.dumps(data).encode("utf-8")
        self.status = status
        self.code = status
        self.headers = headers or {}

    def read(self, amt: int | None = None) -> bytes:
        if amt is None or amt >= len(self._body):
            return self._body
        return self._body[:amt]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def provider():
    return GitHubProvider(token="default-pat-123", timeout_seconds=2.0)


# -- SPI Contract ----------------------------------------------------------------

def test_github_provider_contract(provider):
    sample = Action(action_type="github.repo_get", params={"repo": "owner/repo"})
    assert_provider_contract(provider, sample_action=sample)


def test_github_describe(provider):
    info = provider.describe()
    assert info.id == "github"
    assert "github.repo_get" in info.action_types
    assert "github.pr_create" in info.action_types
    assert "github.file_commit" in info.action_types
    assert not info.is_stub
    assert "repos" in info.capabilities
    assert "vault-backed" in info.capabilities


# -- Input Validation ------------------------------------------------------------

@pytest.mark.parametrize("bad_repo", [
    "",
    "   ",
    "no_slash",
    "too/many/slashes",
    "owner/../traversal",
    "../escape/repo",
    "owner/repo$bad",
    "x" * 201,
])
def test_validate_repo_format(provider, bad_repo):
    action = Action(action_type="github.repo_get", params={"repo": bad_repo})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


def test_validate_missing_repo(provider):
    action = Action(action_type="github.repo_get", params={})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


@pytest.mark.parametrize("action_type,params,err_code", [
    ("github.issue_get", {"repo": "o/r", "issue_number": -1}, ProviderErrorCode.VALIDATION),
    ("github.issue_get", {"repo": "o/r", "issue_number": 0}, ProviderErrorCode.VALIDATION),
    ("github.issue_get", {"repo": "o/r", "issue_number": "1"}, ProviderErrorCode.VALIDATION),
    ("github.issue_create", {"repo": "o/r", "title": ""}, ProviderErrorCode.VALIDATION),
    ("github.issue_create", {"repo": "o/r", "title": "x" * 1025}, ProviderErrorCode.VALIDATION),
    ("github.issue_comment", {"repo": "o/r", "issue_number": 1, "body": ""}, ProviderErrorCode.VALIDATION),
    ("github.pr_get", {"repo": "o/r", "pull_number": -5}, ProviderErrorCode.VALIDATION),
    ("github.pr_create", {"repo": "o/r", "title": "t", "head": ""}, ProviderErrorCode.VALIDATION),
    ("github.pr_create", {"repo": "o/r", "title": "t", "head": "h", "base": ""}, ProviderErrorCode.VALIDATION),
    ("github.file_get", {"repo": "o/r", "path": ""}, ProviderErrorCode.VALIDATION),
    ("github.file_get", {"repo": "o/r", "path": "/absolute/path"}, ProviderErrorCode.FORBIDDEN),
    ("github.file_get", {"repo": "o/r", "path": "path/../escape"}, ProviderErrorCode.FORBIDDEN),
    ("github.file_commit", {"repo": "o/r", "path": "p", "message": "", "content": "c"}, ProviderErrorCode.VALIDATION),
    ("github.file_commit", {"repo": "o/r", "path": "p", "message": "m", "content": "c" * 1_000_001}, ProviderErrorCode.VALIDATION),
])
def test_validate_action_specific_params(provider, action_type, params, err_code):
    action = Action(action_type=action_type, params=params)
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == err_code


def test_validate_unhandled_action_type(provider):
    action = Action(action_type="unknown.action", params={"repo": "o/r"})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.NOT_IMPLEMENTED


# -- Token Resolution & Vault Integration ---------------------------------------

def test_mutating_action_requires_token():
    p = GitHubProvider(token="")
    action = Action(action_type="github.issue_create", params={"repo": "o/r", "title": "t"})
    ctx = ExecutionContext(actor_id="t", credentials={})
    with pytest.raises(ToolError) as exc_info:
        p.execute(action, ctx)
    assert exc_info.value.code == ProviderErrorCode.AUTH
    assert "token required" in str(exc_info.value).lower()


def test_vault_token_resolution_success(monkeypatch):
    class FakeResolver:
        def resolve(self, ref, actor_id):
            assert ref == "vault:github/pat"
            assert actor_id == "vault-user"
            return "ghp_resolved_token_999"

    p = GitHubProvider(token="vault:github/pat", secret_resolver=FakeResolver())

    called_with_token = []
    def fake_call(self, method, endpoint, payload=None, token=""):
        called_with_token.append(token)
        return {"name": "r", "stargazers_count": 10, "forks_count": 2}

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)

    action = Action(action_type="github.repo_get", params={"repo": "owner/repo"})
    ctx = ExecutionContext(actor_id="vault-user")
    res = p.execute(action, ctx)
    assert res.success
    assert called_with_token == ["ghp_resolved_token_999"]


def test_vault_token_resolution_missing_resolver():
    p = GitHubProvider(token="vault:github/pat", secret_resolver=None)
    action = Action(action_type="github.repo_get", params={"repo": "owner/repo"})
    ctx = ExecutionContext(actor_id="user")
    with pytest.raises(ToolError) as exc_info:
        p.execute(action, ctx)
    assert exc_info.value.code == ProviderErrorCode.AUTH


def test_vault_token_resolution_failure():
    class BrokenResolver:
        def resolve(self, ref, actor_id):
            raise VaultError("secret not found", code="not_found")

    p = GitHubProvider(token="vault:github/pat", secret_resolver=BrokenResolver())
    action = Action(action_type="github.repo_get", params={"repo": "owner/repo"})
    ctx = ExecutionContext(actor_id="user")
    with pytest.raises(ToolError) as exc_info:
        p.execute(action, ctx)
    assert exc_info.value.code == ProviderErrorCode.AUTH


# -- Operations (Mocked HTTP calls) ---------------------------------------------

def test_repo_get_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert endpoint == "/repos/octocat/Hello-World"
        return {
            "name": "Hello-World",
            "full_name": "octocat/Hello-World",
            "description": "My first repo",
            "html_url": "https://github.com/octocat/Hello-World",
            "default_branch": "main",
            "stargazers_count": 42,
            "forks_count": 7,
            "open_issues_count": 1,
            "private": False,
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.repo_get", params={"repo": "octocat/Hello-World"})
    result = provider.execute(action, CTX)
    assert result.success
    assert "stars: 42" in result.summary
    assert result.data["stars"] == 42
    assert result.data["forks"] == 7
    assert result.data["default_branch"] == "main"


def test_issue_list_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert "/repos/octocat/Hello-World/issues?" in endpoint
        return [
            {"number": 1, "title": "Bug report", "state": "open", "user": {"login": "alice"}, "comments": 2},
            {"number": 2, "title": "PR in disguise", "state": "open", "pull_request": {}},  # should be filtered
        ]

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.issue_list", params={"repo": "octocat/Hello-World", "state": "open"})
    result = provider.execute(action, CTX)
    assert result.success
    assert len(result.data["issues"]) == 1
    assert result.data["issues"][0]["number"] == 1
    assert result.data["issues"][0]["user"] == "alice"


def test_issue_get_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert endpoint == "/repos/octocat/Hello-World/issues/42"
        return {
            "number": 42,
            "title": "Fix something",
            "body": "Detailed description",
            "state": "open",
            "user": {"login": "bob"},
            "comments": 3,
            "html_url": "https://github.com/octocat/Hello-World/issues/42",
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.issue_get", params={"repo": "octocat/Hello-World", "issue_number": 42})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["number"] == 42
    assert result.data["title"] == "Fix something"
    assert result.data["user"] == "bob"


def test_issue_create_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "POST"
        assert endpoint == "/repos/octocat/Hello-World/issues"
        assert payload["title"] == "New Issue"
        assert payload["body"] == "Issue body content"
        return {
            "number": 101,
            "title": "New Issue",
            "state": "open",
            "html_url": "https://github.com/octocat/Hello-World/issues/101",
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.issue_create", params={"repo": "octocat/Hello-World", "title": "New Issue", "body": "Issue body content"})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["number"] == 101
    assert "issue #101" in result.summary


def test_issue_comment_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "POST"
        assert endpoint == "/repos/octocat/Hello-World/issues/101/comments"
        assert payload["body"] == "Great idea!"
        return {
            "id": 999,
            "html_url": "https://github.com/octocat/Hello-World/issues/101#comment-999",
            "created_at": "2026-08-22T00:00:00Z",
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.issue_comment", params={"repo": "octocat/Hello-World", "issue_number": 101, "body": "Great idea!"})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["id"] == 999


def test_pr_list_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert "/repos/octocat/Hello-World/pulls?" in endpoint
        return [
            {"number": 10, "title": "Add feature", "state": "open", "head": {"ref": "feat"}, "base": {"ref": "main"}},
        ]

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.pr_list", params={"repo": "octocat/Hello-World"})
    result = provider.execute(action, CTX)
    assert result.success
    assert len(result.data["pull_requests"]) == 1
    assert result.data["pull_requests"][0]["head"] == "feat"


def test_pr_get_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert endpoint == "/repos/octocat/Hello-World/pulls/10"
        return {
            "number": 10,
            "title": "Add feature",
            "body": "PR description",
            "state": "open",
            "head": {"ref": "feat"},
            "base": {"ref": "main"},
            "merged": False,
            "mergeable": True,
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.pr_get", params={"repo": "octocat/Hello-World", "pull_number": 10})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["number"] == 10
    assert result.data["head"] == "feat"
    assert result.data["mergeable"] is True


def test_pr_create_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "POST"
        assert endpoint == "/repos/octocat/Hello-World/pulls"
        assert payload["title"] == "Phase 3D"
        assert payload["head"] == "feat/phase3d"
        assert payload["base"] == "main"
        return {
            "number": 20,
            "title": "Phase 3D",
            "state": "open",
            "html_url": "https://github.com/octocat/Hello-World/pull/20",
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.pr_create", params={"repo": "octocat/Hello-World", "title": "Phase 3D", "head": "feat/phase3d", "base": "main"})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["number"] == 20
    assert result.data["head"] == "feat/phase3d"


def test_file_get_operation(provider, monkeypatch):
    import base64
    content_b64 = base64.b64encode(b"print('hello github')\n").decode("ascii")

    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "GET"
        assert "/repos/octocat/Hello-World/contents/src/app.py" in endpoint
        return {
            "name": "app.py",
            "path": "src/app.py",
            "sha": "abc123456",
            "size": 22,
            "encoding": "base64",
            "content": content_b64,
            "html_url": "https://github.com/octocat/Hello-World/blob/main/src/app.py",
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.file_get", params={"repo": "octocat/Hello-World", "path": "src/app.py"})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["path"] == "src/app.py"
    assert result.data["content"] == "print('hello github')\n"
    assert result.data["sha"] == "abc123456"


def test_file_commit_operation(provider, monkeypatch):
    def fake_call(self, method, endpoint, payload=None, token=""):
        assert method == "PUT"
        assert "/repos/octocat/Hello-World/contents/README.md" in endpoint
        assert payload["message"] == "Update readme"
        return {
            "content": {"name": "README.md", "path": "README.md", "sha": "new_blob_sha", "html_url": "url"},
            "commit": {"sha": "new_commit_sha"},
        }

    monkeypatch.setattr(GitHubProvider, "_http_call", fake_call)
    action = Action(action_type="github.file_commit", params={"repo": "octocat/Hello-World", "path": "README.md", "message": "Update readme", "content": "# Hello World"})
    result = provider.execute(action, CTX)
    assert result.success
    assert result.data["commit_sha"] == "new_commit_sha"
    assert result.data["content_sha"] == "new_blob_sha"


# -- Error Handling & Taxonomy --------------------------------------------------

@pytest.mark.parametrize("status,msg,expected_code", [
    (401, "Bad credentials", ProviderErrorCode.AUTH),
    (403, "API rate limit exceeded for user", ProviderErrorCode.UNAVAILABLE),
    (403, "You have exceeded a secondary rate limit", ProviderErrorCode.UNAVAILABLE),
    (403, "Resource not accessible by integration", ProviderErrorCode.AUTH),
    (404, "Not Found", ProviderErrorCode.NOT_FOUND),
    (422, "Validation Failed", ProviderErrorCode.VALIDATION),
    (429, "Too Many Requests", ProviderErrorCode.UNAVAILABLE),
    (500, "Internal Server Error", ProviderErrorCode.UNAVAILABLE),
    (503, "Service Unavailable", ProviderErrorCode.UNAVAILABLE),
])
def test_http_error_mapping(provider, status, msg, expected_code):
    err_body = json.dumps({"message": msg}).encode("utf-8")
    exc = urllib.error.HTTPError("https://api.github.com/test", status, msg, {}, io.BytesIO(err_body))

    with pytest.raises(ToolError) as exc_info:
        provider._handle_http_error(exc)
    assert exc_info.value.code == expected_code


def test_network_timeout_mapped_to_unavailable(provider, monkeypatch):
    def timeout_open(req, timeout):
        raise TimeoutError("connection timed out")

    monkeypatch.setattr(urllib.request, "urlopen", timeout_open)
    action = Action(action_type="github.repo_get", params={"repo": "owner/repo"})
    with pytest.raises(ToolError) as exc_info:
        provider.execute(action, CTX)
    assert exc_info.value.code == ProviderErrorCode.UNAVAILABLE


def test_secret_not_in_error_or_output(provider, monkeypatch):
    def fake_open(req, timeout):
        raise urllib.error.HTTPError("url", 401, "Bad credentials", {}, io.BytesIO(b'{"message":"Bad credentials"}'))

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    secret_pat = "ghp_super_secret_pat_987654321"
    action = Action(action_type="github.repo_get", params={"repo": "owner/repo", "token": secret_pat})
    ctx = ExecutionContext(actor_id="test", credentials={"token": secret_pat})

    with pytest.raises(ToolError) as exc_info:
        provider.execute(action, ctx)

    err_str = str(exc_info.value)
    assert secret_pat not in err_str
    assert "ghp_" not in err_str
