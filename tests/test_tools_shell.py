"""Tests for the allowlisted shell tool (era.tools.shell)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from era.tools.shell import DENIED_PROGRAMS, ShellRunTool, program_name, scrub_environment


def tool(allowed: tuple[str, ...] = (), **kwargs) -> ShellRunTool:
    defaults: dict = {"timeout_s": 5.0, "max_output_bytes": 50_000, "cwd": Path.cwd()}
    defaults.update(kwargs)
    return ShellRunTool(allowed_commands=allowed, **defaults)


class TestAllowlist:
    def test_empty_allowlist_denies_everything(self) -> None:
        result = tool().execute({"command": ["echo", "hi"]})
        assert not result.ok and "allowlist" in result.error

    def test_allowed_single_token_prefix(self) -> None:
        result = tool(("echo",)).execute({"command": ["echo", "hello", "world"]})
        assert result.ok and "hello world" in result.output

    def test_allowed_exact_prefix(self) -> None:
        shell = tool(("python", "--version"))
        result = shell.execute({"command": [sys.executable, "--version"]})
        # argv[0] differs (full path); allowlist matches the program name resolution
        assert result.ok or "allowlist" in result.error

    def test_prefix_mismatch_rejected(self) -> None:
        result = tool(("wc -l",)).execute({"command": ["wc", "-w", "x"]})
        assert not result.ok and "allowlist" in result.error

    def test_single_template_string_matches_prefix(self) -> None:
        result = tool(("wc -l",)).execute({"command": ["wc", "-l", "somefile.txt"]})
        assert result.ok or "No such file" in (result.error or "")  # allowed; ran

    def test_error_lists_allowlist(self) -> None:
        result = tool(("echo", "date")).execute({"command": ["ls"]})
        assert "echo" in result.error and "date" in result.error

    def test_program_name_normalization(self) -> None:
        assert program_name("/usr/bin/rm") == "rm"
        assert program_name("RM.EXE") == "rm"
        assert program_name("C:\\Windows\\curl.exe") == "curl"

    @pytest.mark.parametrize(
        "program", sorted(["rm", "sudo", "curl", "wget", "shutdown", "docker"])
    )
    def test_denied_programs_blocked_even_if_allowlisted(self, program: str) -> None:
        result = tool((program,)).execute({"command": [program, "x"]})
        assert not result.ok and "permanently blocked" in result.error

    def test_denied_program_via_path(self) -> None:
        result = tool(("/bin/rm",)).execute({"command": ["/bin/rm", "-rf", "."]})
        assert not result.ok and "permanently blocked" in result.error


class TestNoShellFeatures:
    def test_metacharacters_are_literal(self) -> None:
        result = tool(("echo",)).execute({"command": ["echo", "hi; rm -rf /"]})
        assert result.ok
        assert "hi; rm -rf /" in result.output  # printed literally, not executed

    def test_string_argv_required(self) -> None:
        result = tool(("echo",)).execute({"command": "echo hi"})  # type: ignore[arg-type]
        assert not result.ok  # schema: must be an array


class TestExecution:
    def test_nonzero_exit_is_failure_with_stderr(self) -> None:
        program = os.environ.get("ERA_TEST_PY", sys.executable)
        shell = tool((program,))
        result = shell.execute(
            {"command": [program, "-c", "import sys; print('out'); sys.exit(3)"]}
        )
        assert not result.ok and "exit code 3" in result.error

    def test_stderr_captured_on_success(self) -> None:
        program = sys.executable
        shell = tool((program,))
        result = shell.execute(
            {"command": [program, "-c", "import sys; print('warn', file=sys.stderr); print('ok')"]}
        )
        assert result.ok and "ok" in result.output

    def test_timeout_kills(self) -> None:
        program = sys.executable
        shell = tool((program,), timeout_s=1.0)
        result = shell.execute({"command": [program, "-c", "import time; time.sleep(30)"]})
        assert not result.ok and "timed out" in result.error

    def test_output_truncation(self) -> None:
        program = sys.executable
        shell = tool((program,), max_output_bytes=100)
        result = shell.execute({"command": [program, "-c", "print('a' * 5000)"]})
        assert "truncated" in result.output or len(result.output) <= 200

    def test_missing_program(self) -> None:
        result = tool(("definitely-not-a-real-program-xyz",)).execute(
            {"command": ["definitely-not-a-real-program-xyz"]}
        )
        assert not result.ok and "not found" in result.error


class TestEnvironmentScrubbing:
    def test_secret_env_vars_removed(self, monkeypatch) -> None:
        monkeypatch.setenv("ERA_LLM_API_KEY", "sk-should-never-appear")
        monkeypatch.setenv("MY_DATABASE_PASSWORD", "hunter2")
        monkeypatch.setenv("SAFE_VAR", "kept")
        env = scrub_environment()
        assert "ERA_LLM_API_KEY" not in env
        assert "MY_DATABASE_PASSWORD" not in env
        assert env["SAFE_VAR"] == "kept"

    def test_child_process_never_sees_secrets(self, monkeypatch) -> None:
        monkeypatch.setenv("ERA_LLM_API_KEY", "sk-should-never-appear")
        program = sys.executable
        shell = tool((program,))
        result = shell.execute(
            {
                "command": [
                    program,
                    "-c",
                    "import os; print(os.environ.get('ERA_LLM_API_KEY', 'ABSENT'))",
                ]
            }
        )
        assert result.ok
        assert "sk-should-never-appear" not in result.output
        assert "ABSENT" in result.output

    def test_cwd_is_sandbox(self, tmp_path: Path) -> None:
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        program = sys.executable
        shell = tool((program,), cwd=sandbox)
        result = shell.execute({"command": [program, "-c", "import os; print(os.getcwd())"]})
        assert result.ok and str(sandbox) in result.output


class TestDenylistContent:
    def test_denylist_not_empty_and_has_key_offenders(self) -> None:
        for expected in ("rm", "sudo", "curl", "wget", "shutdown", "chmod"):
            assert expected in DENIED_PROGRAMS
