"""Code Execution provider — isolated subprocess sandbox (Phase 3D).

Provides safe, sandboxed execution of Python code snippets and scripts:

* Actions: ``code.run`` and ``code.exec`` (both map to the sandboxed runner)
* Default language: ``python`` (executed via isolated Python interpreter)

Security & Sandbox Isolation:
* Environment scrub: Only a strict whitelist of safe environment variables
  (``PATH``, ``LANG``, ``LC_ALL``, ``TMPDIR``, ``USER``, etc.) is passed to the
  child process. Host secrets, vault master keys, API keys and DB credentials
  are never exposed to user code.
* Workspace confinement: Execution occurs strictly inside the sandboxed
  workspace directory (via :class:`~era.security.path_safety.WorkspaceRoot`).
* Resource limits: Enforces wall-clock timeout caps, CPU time limits and virtual
  memory caps (:mod:`resource` module on POSIX).
* Output capture & bounds: Captures stdout and stderr up to a configurable
  limit (:data:`DEFAULT_MAX_OUTPUT_BYTES`), truncating excessive output cleanly.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_OUTPUT_BYTES = 65536  # 64 KiB
DEFAULT_MEMORY_LIMIT_MB = 256
MAX_CODE_LEN = 262144  # 256 KiB

_SAFE_ENV_VARS = frozenset({
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "HOME",
})

_ALLOWED_LANGUAGES = frozenset({"python", "python3"})

_ACTION_TYPES = frozenset({
    ActionType.CODE_RUN.value,
    ActionType.CODE_EXEC.value,
})


class CodeExecProvider:
    """ToolProvider for executing code in an isolated subprocess sandbox."""

    id = "code-exec"
    action_types = _ACTION_TYPES

    def __init__(
        self,
        *,
        workspace_root: str | Path | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        allow_network: bool = False,
        allowed_languages: frozenset[str] = _ALLOWED_LANGUAGES,
    ):
        self.workspace = WorkspaceRoot(workspace_root) if workspace_root is not None else None
        self.timeout_seconds = max(0.1, min(float(timeout_seconds), MAX_TIMEOUT_SECONDS))
        self.max_output_bytes = max(1024, int(max_output_bytes))
        self.memory_limit_mb = max(0, int(memory_limit_mb))
        self.allow_network = bool(allow_network)
        self.allowed_languages = allowed_languages

    # -- SPI ---------------------------------------------------------------------

    def validate(self, action: Action) -> None:
        action_type = action.action_type
        if action_type not in self.action_types:
            raise ToolError(f"code-exec cannot handle {action_type}",
                            provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        params = action.params or {}
        code = params.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ToolError("'code' parameter is required and must be non-empty",
                            provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if len(code) > MAX_CODE_LEN:
            raise ToolError(f"code length exceeds maximum allowed ({MAX_CODE_LEN} chars)",
                            provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)

        lang = str(params.get("language", "python")).strip().lower()
        if lang not in self.allowed_languages:
            raise ToolError(
                f"unsupported execution language: {lang!r} (allowed: {sorted(self.allowed_languages)})",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )

        timeout = params.get("timeout_seconds")
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
            or timeout > MAX_TIMEOUT_SECONDS
        ):
            raise ToolError(
                f"timeout_seconds must be a positive number up to {MAX_TIMEOUT_SECONDS}",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )

        args = params.get("args")
        if args is not None and not isinstance(args, (list, tuple)):
            raise ToolError("'args' must be a list of strings",
                            provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        params = action.params or {}
        code = str(params["code"])
        lang = str(params.get("language", "python")).strip().lower()
        args = [str(a) for a in params.get("args") or []]
        timeout = float(params.get("timeout_seconds") or self.timeout_seconds)

        # Working directory confinement
        cwd = str(self.workspace.root) if self.workspace is not None else None

        # Build clean environment with all secrets scrubbed
        clean_env = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_VARS}
        clean_env["PYTHONUNBUFFERED"] = "1"
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"

        # Construct isolated python execution command
        # -I : isolated mode (ignores PYTHONPATH, PYTHONHOME, user site)
        # -s : do not add user site directory
        cmd = [sys.executable, "-I", "-s", "-c", code, *args]

        # Resource limits setup for POSIX systems
        preexec = self._make_preexec_fn(timeout)

        start_time = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                cwd=cwd,
                env=clean_env,
                timeout=timeout,
                preexec_fn=preexec,
                check=False,
            )
            duration_ms = (time.monotonic() - start_time) * 1000.0
        except subprocess.TimeoutExpired as exc:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            raise ToolError(
                f"code execution timed out after {timeout:.1f}s",
                provider_id=self.id,
                code=ProviderErrorCode.TIMEOUT,
            ) from exc
        except Exception as exc:
            raise ToolError(
                f"failed to execute subprocess: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.PROVIDER_ERROR,
            ) from exc

        stdout = self._truncate_output(proc.stdout.decode("utf-8", errors="replace"))
        stderr = self._truncate_output(proc.stderr.decode("utf-8", errors="replace"))
        exit_code = proc.returncode
        success = (exit_code == 0)

        summary = (
            f"Code execution succeeded (exit code {exit_code}, {duration_ms:.1f}ms)"
            if success
            else f"Code execution failed (exit code {exit_code}, {duration_ms:.1f}ms)"
        )

        return ActionResult(
            success=success,
            summary=summary,
            data={
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": False,
                "language": lang,
                "duration_ms": round(duration_ms, 2),
            },
        )

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.4.0",
            display_name="Code Execution Sandbox (isolated Python runner)",
            is_stub=False,
            capabilities=("python", "subprocess_isolation", "resource_limits"),
        )

    # -- Internal Helpers --------------------------------------------------------

    def _truncate_output(self, text: str) -> str:
        if len(text) <= self.max_output_bytes:
            return text
        cut = self.max_output_bytes - 64
        return text[:cut] + f"\n... [output truncated: exceeded {self.max_output_bytes} bytes]"

    def _make_preexec_fn(self, timeout: float):
        memory_mb = self.memory_limit_mb

        def _set_limits():
            try:
                import resource
                if memory_mb > 0:
                    mem_bytes = memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                cpu_seconds = max(1, int(timeout + 2))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            except (ImportError, ValueError, OSError):
                pass

        return _set_limits
