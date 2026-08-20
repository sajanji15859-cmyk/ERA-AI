"""Allowlisted shell execution: ``shell.run``.

Security model (hard boundaries):

* **No shell interpreter is ever invoked** — commands run via ``subprocess``
  with an argv list, so metacharacters are literal data, never syntax.
* The allowlist (``[tools.shell] allowed_commands`` / ``ERA_SHELL_ALLOWED``)
  holds argv-*prefix templates*: ``"python --version"`` only matches commands
  starting with ``["python", "--version"]``; ``"echo"`` matches any ``echo``.
  The default allowlist is **empty** — the tool refuses everything until
  explicitly configured.
* A hard denylist blocks dangerous programs even if allowlisted
  (``rm``, ``sudo``, ``curl``, package managers, ...).
* The child runs with cwd pinned to the sandbox, stdin closed, a timeout with
  process-group kill, output caps, and an environment scrubbed of
  secret-looking variables (``*KEY*``/``*TOKEN*``/``*SECRET*``/``*PASSWORD*``),
  including ``ERA_LLM_API_KEY``.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from era.tools.base import RiskLevel, Tool, ToolExecutionError, ToolResult, ToolValidationError

#: Programs that are always blocked, even if the user allowlists them.
DENIED_PROGRAMS: frozenset[str] = frozenset(
    {
        "rm",
        "rmdir",
        "unlink",
        "shred",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
        "lsattr",
        "setfacl",
        "passwd",
        "visudo",
        "dd",
        "mkfs",
        "mkfs.ext4",
        "mkfs.vfat",
        "mkfs.btrfs",
        "mkfs.xfs",
        "fdisk",
        "sfdisk",
        "parted",
        "mount",
        "umount",
        "swapoff",
        "swapon",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "systemctl",
        "service",
        "init",
        "kill",
        "pkill",
        "killall",
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "ssh",
        "scp",
        "sftp",
        "ftp",
        "telnet",
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "pacman",
        "zypper",
        "brew",
        "snap",
        "flatpak",
        "pip",
        "pip3",
        "uv",
        "npm",
        "yarn",
        "pnpm",
        "gem",
        "cargo",
        "go",
        "docker",
        "podman",
        "kubectl",
        "helm",
        "crontab",
        "at",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
    }
)

_SECRET_ENV_RE = re.compile(
    r"api[_-]?key|secret|token|password|passphrase|credential", re.IGNORECASE
)


def scrub_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a child-safe environment: drop secret-looking variable names."""
    source = dict(os.environ if env is None else env)
    return {name: value for name, value in source.items() if not _SECRET_ENV_RE.search(name)}


def program_name(argv0: str) -> str:
    """Normalize an argv[0] to a comparable program name."""
    normalized = argv0.replace("\\", "/").rsplit("/", 1)[-1]
    if normalized.lower().endswith(".exe"):
        normalized = normalized[: -len(".exe")]
    return normalized.lower()


class ShellRunTool(Tool):
    name = "shell.run"
    description = (
        "Run a command from the configured allowlist (no shell features; argv only). "
        "Input: {command: array of strings}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "command": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
        },
        "required": ["command"],
        "additionalProperties": False,
    }
    risk_level = RiskLevel.LOW_RISK_WRITE

    def __init__(
        self,
        *,
        allowed_commands: tuple[str, ...] = (),
        timeout_s: float = 10.0,
        max_output_bytes: int = 50_000,
        cwd: Path,
    ) -> None:
        self._templates = sorted(
            {tuple(entry.split()) for entry in allowed_commands if entry.strip()}
        )
        self._timeout_s = timeout_s
        self._max_output_bytes = max_output_bytes
        self._cwd = cwd

    @property
    def allowed_prefixes(self) -> list[list[str]]:
        """Configured argv-prefix templates (for diagnostics)."""
        return [list(t) for t in self._templates]

    def _check_allowed(self, argv: list[str]) -> None:
        if not argv:
            msg = "command must be a non-empty array of strings"
            raise ToolValidationError(msg)
        program = program_name(argv[0])
        if program in DENIED_PROGRAMS:
            msg = f"program {program!r} is permanently blocked"
            raise ToolExecutionError(msg)
        if not any(tuple(argv[: len(template)]) == template for template in self._templates):
            allowed = ", ".join(" ".join(t) for t in self._templates) or "<allowlist empty>"
            msg = f"command not in the allowlist (allowed prefixes: {allowed})"
            raise ToolExecutionError(msg)

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        argv = [str(item) for item in args["command"]]
        try:
            self._check_allowed(argv)
        except (ToolValidationError, ToolExecutionError) as exc:
            return ToolResult.failure(str(exc), tool=self.name)

        try:
            self._cwd.mkdir(parents=True, exist_ok=True)
            process = subprocess.Popen(
                argv,
                cwd=self._cwd,
                env=scrub_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # own process group, so we can kill the tree
            )
        except FileNotFoundError:
            return ToolResult.failure(f"program not found: {argv[0]!r}", tool=self.name)
        except PermissionError:
            return ToolResult.failure(f"program not executable: {argv[0]!r}", tool=self.name)
        except OSError as exc:
            return ToolResult.failure(f"cannot start {argv[0]!r}: {exc}", tool=self.name)

        try:
            stdout, stderr = process.communicate(timeout=self._timeout_s)
        except subprocess.TimeoutExpired:
            self._kill_group(process)
            stdout, stderr = process.communicate()
            return ToolResult.failure(
                f"command timed out after {self._timeout_s:.0f}s and was killed",
                tool=self.name,
            )

        truncated = len(stdout) + len(stderr) > self._max_output_bytes
        stdout = stdout[: self._max_output_bytes]
        stderr = stderr[: max(0, self._max_output_bytes - len(stdout))]
        exit_code = process.returncode
        output = stdout.decode("utf-8", errors="replace")
        error_text = stderr.decode("utf-8", errors="replace")
        ok = exit_code == 0
        note = " [...output truncated]" if truncated else ""
        if not ok:
            detail = f"exit code {exit_code}"
            if error_text.strip():
                detail += f": {error_text.strip()[:500]}"
            return ToolResult.failure(
                f"{detail}{note}",
                output=output + note,
                tool=self.name,
            )
        return ToolResult.success(
            output + note,
            data={"argv": argv, "exit_code": exit_code},
            tool=self.name,
        )

    @staticmethod
    def _kill_group(process: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()  # fallback: at least kill the direct child
