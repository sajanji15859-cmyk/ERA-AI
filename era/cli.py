"""Command-line interface for ERA-AI (Phase 0: foundation).

Commands:
    era                 status overview (default command)
    era status          same as above
    era doctor          environment health checks
    era config show     print the effective configuration and its sources
    era config path     print the config file path
    era chat            the legacy keyword chat (placeholder until Phase 1 LLM core)

No autonomous actions are performed anywhere in this phase.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NamedTuple

from era import __author__, __version__
from era.config import (
    APP_NAME,
    Config,
    ConfigError,
    config_path,
    era_home,
    load_config,
)
from era.logging import get_logger, setup_logging

_PHASE = "Phase 0 (foundation)"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="era",
        description=f"{APP_NAME} — personal autonomous computer-use agent ({_PHASE})",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--debug", action="store_true", help="force debug logging for this run")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.add_parser("status", help="show a short status overview (default)")
    sub.add_parser("doctor", help="run environment health checks")
    config_parser = sub.add_parser("config", help="inspect configuration")
    config_sub = config_parser.add_subparsers(dest="config_command", metavar="ACTION")
    config_sub.add_parser("show", help="print effective configuration and sources (default)")
    config_sub.add_parser("path", help="print the config file path")
    sub.add_parser("chat", help="start the legacy keyword chat (pre-LLM placeholder)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"{APP_NAME} {__version__}")
        return 0

    # `era` and `era config` without a subcommand fall back to sensible defaults.
    command = args.command or "status"

    try:
        config = load_config()
    except ConfigError as exc:
        if command == "doctor":
            # doctor itself will report the failure; run the rest with defaults.
            config = Config()
            config = _patched_config(config, args, str(exc))
            _dispatch(parser, command, args, config, config_error=str(exc))
            return _doctor_exit_hint()
        print(f"error: {exc}", file=sys.stderr)
        print("Run `era doctor` for details.", file=sys.stderr)
        return 2

    if args.debug:
        from era.config import with_debug

        config = with_debug(config, True)

    setup_logging(config)
    get_logger("cli").debug("era CLI started (command=%s, debug=%s)", command, config.debug)

    return _dispatch(parser, command, args, config)


def _patched_config(config: Config, args: argparse.Namespace, error: str) -> Config:
    """Apply CLI debug flag onto a fallback config (doctor path only)."""
    if args.debug:
        from era.config import with_debug

        return with_debug(config, True)
    return config


def _doctor_exit_hint() -> int:
    # The doctor command re-reports the config error; mirror its failure code.
    return 1


def _dispatch(
    parser: argparse.ArgumentParser,
    command: str,
    args: argparse.Namespace,
    config: Config,
    config_error: str | None = None,
) -> int:
    """Route to a command handler."""
    if command == "status":
        return _cmd_status(config, config_error)
    if command == "doctor":
        return _cmd_doctor(config, config_error)
    if command == "config":
        action = args.config_command or "show"
        if action == "path":
            return _cmd_config_path(config)
        return _cmd_config_show(config, config_error)
    if command == "chat":
        return _cmd_chat()
    parser.error(f"unknown command {command!r}")
    return 2  # unreachable; parser.error exits


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def _cmd_status(config: Config, config_error: str | None = None) -> int:
    path = config_path()
    file_state = f"{path}" + ("" if path.exists() else "  (not created — defaults in use)")
    print(f"{APP_NAME} v{__version__} — {_PHASE}")
    print(f"author: {__author__}")
    print(f"python: {sys.version.split()[0]}")
    print(f"config: {file_state}")
    print(f"data home: {era_home()}")
    if config_error:
        print(f"config warning: {config_error}")
    print()
    print("Commands: era doctor · era config show · era config path · era chat · era --help")
    print("Roadmap: docs/ARCHITECTURE_AND_ROADMAP.md")
    return 0


class _CheckResult(NamedTuple):
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


def _cmd_doctor(config: Config, config_error: str | None = None) -> int:
    """Run environment health checks; return 0 if nothing failed."""
    results: list[_CheckResult] = []

    py = sys.version_info
    results.append(
        _CheckResult(
            "python",
            "ok" if py >= (3, 11) else "fail",
            f"{sys.version.split()[0]} (requires >= 3.11)",
        )
    )
    results.append(_CheckResult("package", "ok", f"era {__version__} importable"))

    if config_error:
        results.append(_CheckResult("config file", "fail", config_error))
    else:
        path = config_path()
        if path.exists():
            results.append(_CheckResult("config file", "ok", f"{path} (parsed cleanly)"))
        else:
            results.append(
                _CheckResult("config file", "ok", "not created — built-in defaults in use")
            )
        for warning in config.warnings:
            results.append(_CheckResult("config content", "warn", warning))

    home = era_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
        probe = home / ".doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        results.append(_CheckResult("data home", "ok", f"{home} is writable"))
    except OSError as exc:
        results.append(_CheckResult("data home", "fail", f"{home} not writable: {exc}"))

    if config.logging.to_file:
        log_file = setup_logging(config)
        if log_file is not None and log_file.parent.is_dir():
            results.append(_CheckResult("log file", "ok", f"{log_file}"))
        else:
            results.append(_CheckResult("log file", "warn", "file logging unavailable"))
    else:
        results.append(_CheckResult("log file", "ok", "file logging disabled by config"))

    legacy_ok, legacy_detail = _check_legacy()
    results.append(_CheckResult("legacy modules", "ok" if legacy_ok else "fail", legacy_detail))

    width = max(len(r.name) for r in results) + 2
    failed = False
    for result in results:
        mark = {"ok": "[ok]  ", "warn": "[warn]", "fail": "[FAIL]"}[result.status]
        print(f"{mark} {result.name.ljust(width)} {result.detail}")
        failed = failed or result.status == "fail"
    print()
    if failed:
        print("Some checks failed.")
        return 1
    print("All checks passed.")
    return 0


def _check_legacy() -> tuple[bool, str]:
    """Verify the legacy placeholder modules still import."""
    try:
        from era.legacy import ERAAI, Brain, Chat, Memory, Research  # noqa: F401
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"import error: {exc}"
    return True, "brain, memory, research, chat, agent (placeholder until Phase 1)"


def _cmd_config_show(config: Config, config_error: str | None = None) -> int:
    """Print each setting, its value and which layer supplied it."""
    print(f"config file: {config_path()}")
    print(f"data home:   {era_home()}")
    if config_error:
        print(f"config error: {config_error} — showing defaults")
    print()
    rows = [
        ("debug", str(config.debug)),
        ("logging.level", config.logging.level),
        ("logging.to_file", str(config.logging.to_file)),
    ]
    for key, value in rows:
        source = config.sources.get(key, "default")
        print(f"{key:<18} {value:<8} ({source})")
    print()
    print("Layers: default < config file < environment (ERA_* variables).")
    print("Secrets: environment variables only — never the config file.")
    return 0


def _cmd_config_path(config: Config) -> int:
    print(config_path())
    return 0


def _cmd_chat() -> int:
    """Start the legacy keyword chat placeholder."""
    from era.legacy import ERAAI

    print("Legacy keyword chat — a placeholder that will be replaced by the Phase 1 LLM core.")
    try:
        ERAAI().start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
