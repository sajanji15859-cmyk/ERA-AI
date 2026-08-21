"""Code execution provider tests — sandboxed execution, security scrub, timeout (Phase 3D)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.code_exec import CodeExecProvider
from tests.provider_contract import assert_provider_contract

CTX = ExecutionContext(actor_id="test-actor")


@pytest.fixture
def provider(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    return CodeExecProvider(workspace_root=ws, timeout_seconds=5.0, max_output_bytes=1024)


# -- SPI Contract ----------------------------------------------------------------

def test_code_exec_contract(provider):
    sample = Action(action_type="code.run", params={"code": "print('hello')"})
    assert_provider_contract(provider, sample_action=sample)


def test_code_exec_describe(provider):
    info = provider.describe()
    assert info.id == "code-exec"
    assert "code.run" in info.action_types
    assert "code.exec" in info.action_types
    assert not info.is_stub
    assert "python" in info.capabilities
    assert "subprocess_isolation" in info.capabilities


# -- Input Validation ------------------------------------------------------------

@pytest.mark.parametrize("bad_code", ["", "   ", None])
def test_validate_empty_code(provider, bad_code):
    action = Action(action_type="code.run", params={"code": bad_code} if bad_code is not None else {})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


def test_validate_oversized_code(provider):
    action = Action(action_type="code.run", params={"code": "a" * 300_000})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


@pytest.mark.parametrize("bad_lang", ["javascript", "ruby", "bash", "c", "rust"])
def test_validate_unsupported_language(provider, bad_lang):
    action = Action(action_type="code.run", params={"code": "x = 1", "language": bad_lang})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


@pytest.mark.parametrize("bad_timeout", [-1, 0, 75, "10", False])
def test_validate_invalid_timeout(provider, bad_timeout):
    action = Action(action_type="code.run", params={"code": "x = 1", "timeout_seconds": bad_timeout})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


def test_validate_invalid_args(provider):
    action = Action(action_type="code.run", params={"code": "x = 1", "args": "not-a-list"})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.VALIDATION


def test_validate_unhandled_action(provider):
    action = Action(action_type="fs.write", params={"code": "x = 1"})
    with pytest.raises(ToolError) as exc_info:
        provider.validate(action)
    assert exc_info.value.code == ProviderErrorCode.NOT_IMPLEMENTED


# -- Execution -------------------------------------------------------------------

def test_execute_simple_python(provider):
    action = Action(action_type="code.run", params={"code": "print('Hello from Python!')"})
    res = provider.execute(action, CTX)
    assert res.success
    assert "Hello from Python!" in res.data["stdout"]
    assert res.data["exit_code"] == 0
    assert res.data["timed_out"] is False


def test_execute_code_exec_alias(provider):
    action = Action(action_type="code.exec", params={"code": "print(21 * 2)"})
    res = provider.execute(action, CTX)
    assert res.success
    assert "42" in res.data["stdout"]
    assert res.data["exit_code"] == 0


def test_execute_stderr_capture(provider):
    code = "import sys\nsys.stderr.write('Test error output\\n')\nprint('standard output')"
    action = Action(action_type="code.run", params={"code": code})
    res = provider.execute(action, CTX)
    assert res.success
    assert "standard output" in res.data["stdout"]
    assert "Test error output" in res.data["stderr"]


def test_execute_nonzero_exit_code(provider):
    code = "import sys\nsys.stderr.write('Fatal error\\n')\nsys.exit(3)"
    action = Action(action_type="code.run", params={"code": code})
    res = provider.execute(action, CTX)
    assert not res.success
    assert res.data["exit_code"] == 3
    assert "Fatal error" in res.data["stderr"]
    assert "failed" in res.summary.lower()


def test_execute_with_arguments(provider):
    code = "import sys\nprint(f'Arg1: {sys.argv[1]}, Arg2: {sys.argv[2]}')"
    action = Action(action_type="code.run", params={"code": code, "args": ["hello", "world"]})
    res = provider.execute(action, CTX)
    assert res.success
    assert "Arg1: hello, Arg2: world" in res.data["stdout"]


# -- Timeout ---------------------------------------------------------------------

def test_execute_timeout(provider):
    code = "import time\ntime.sleep(2.0)"
    action = Action(action_type="code.run", params={"code": code, "timeout_seconds": 0.5})
    with pytest.raises(ToolError) as exc_info:
        provider.execute(action, CTX)
    assert exc_info.value.code == ProviderErrorCode.TIMEOUT
    assert "timed out" in str(exc_info.value).lower()


# -- Sandbox Security: Environment Scrubbing ------------------------------------

def test_environment_secrets_scrubbed(provider, monkeypatch):
    """Host secrets must never be visible inside the executed Python sandbox."""
    monkeypatch.setenv("ERA_VAULT_MASTER_KEY", "super_secret_master_key_123456")
    monkeypatch.setenv("ERA_AGENT_LLM_API_KEY", "sk-proj-super-secret-api-key")
    monkeypatch.setenv("DATABASE_URL", "postgresql://admin:secret@db/prod")
    monkeypatch.setenv("CUSTOM_API_TOKEN", "token_9999999")

    code = """
import os
import json

keys = [
    "ERA_VAULT_MASTER_KEY",
    "ERA_AGENT_LLM_API_KEY",
    "DATABASE_URL",
    "CUSTOM_API_TOKEN",
]
found = {k: os.environ.get(k) for k in keys if os.environ.get(k) is not None}
print(json.dumps(found))
"""
    action = Action(action_type="code.run", params={"code": code})
    res = provider.execute(action, CTX)
    assert res.success
    import json
    found = json.loads(res.data["stdout"].strip())
    assert found == {}, f"Secrets leaked to child environment: {found}"


# -- Sandbox Security: Workspace Confinement ------------------------------------

def test_workspace_confinement(provider, tmp_path):
    """Child process runs within the sandboxed workspace directory."""
    code = """
import os
with open('output.txt', 'w') as f:
    f.write('sandbox file created')
print(os.getcwd())
"""
    action = Action(action_type="code.run", params={"code": code})
    res = provider.execute(action, CTX)
    assert res.success

    ws_root = provider.workspace.root
    assert str(ws_root) in res.data["stdout"]
    created_file = ws_root / "output.txt"
    assert created_file.is_file()
    assert created_file.read_text() == "sandbox file created"


# -- Output Truncation ----------------------------------------------------------

def test_output_truncation(provider):
    """Large output streams must be capped to prevent memory exhaustion."""
    code = "print('A' * 5000)"
    action = Action(action_type="code.run", params={"code": code})
    res = provider.execute(action, CTX)
    assert res.success
    stdout = res.data["stdout"]
    assert len(stdout) <= provider.max_output_bytes
    assert "output truncated" in stdout
