"""Layered configuration for ERA-AI.

Resolution order (later layers win):

1. Built-in defaults (defined below)
2. TOML config file — default ``$ERA_HOME/config.toml`` (usually ``~/.era/config.toml``),
   or the path in ``$ERA_CONFIG``
3. Environment variables prefixed with ``ERA_``

Security rule: **secrets never go in the config file.** Any secret-like key found in
the file is flagged by :func:`load_config` (and by ``era doctor`` / ``era config show``);
supply secrets via environment variables instead (e.g. ``ERA_LLM_API_KEY``). Keys under
reserved future-phase sections are parsed but ignored until those phases are implemented.
Unknown keys inside active sections (e.g. ``[tools.*]``) fail closed with a ConfigError,
because silent typos in security-relevant tool settings are worse than loud errors.

Example ``~/.era/config.toml``::

    [general]
    debug = false

    [logging]
    level = "info"      # debug | info | warning | error
    to_file = true

    [llm]               # Phase 1A: LLM adapter layer
    provider = "none"   # none | mock | openai
    model = ""          # required when provider = "openai"
    base_url = ""       # optional; any OpenAI-compatible endpoint
    timeout_s = 60.0

    [tools.files]       # Phase 1B: sandboxed file tools
    # sandbox_root = ""           # default: $ERA_HOME/sandbox
    # max_read_bytes = 100000
    # max_write_bytes = 100000

    [tools.web]         # Phase 1B: read-only web tools
    timeout_s = 15.0
    # max_bytes = 200000
    # output_char_limit = 8000
    # search = "duckduckgo"       # duckduckgo | searxng
    # searxng_url = ""            # required when search = "searxng"
    # allow_private_networks = false

    [tools.shell]       # Phase 1B: allowlisted shell execution
    allowed_commands = []          # argv-prefix templates; empty = tool disabled
    # timeout_s = 10.0
    # max_output_bytes = 50000

Environment overrides: ``ERA_HOME``, ``ERA_CONFIG``, ``ERA_DEBUG``, ``ERA_LOG_LEVEL``,
``ERA_LOG_FILE``, ``ERA_LLM_PROVIDER``, ``ERA_LLM_MODEL``, ``ERA_LLM_BASE_URL``,
``ERA_LLM_TIMEOUT``, ``ERA_SANDBOX_ROOT``, ``ERA_SHELL_ALLOWED`` — plus
``ERA_LLM_API_KEY`` (environment only; never a config key).
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

APP_NAME = "ERA AI"

ENV_PREFIX = "ERA_"
VALID_LOG_LEVELS = ("debug", "info", "warning", "error")
#: LLM providers recognised by ``era.llm.factory.create_client``.
VALID_LLM_PROVIDERS = frozenset({"none", "mock", "openai"})
#: Web search providers recognised by ``era.tools.web``.
VALID_WEB_SEARCH_PROVIDERS = frozenset({"duckduckgo", "searxng"})
#: Sections parsed but not yet honoured by an implemented phase.
RESERVED_SECTIONS = ("agent", "memory", "safety")

_SECRET_KEY_RE = re.compile(
    r"api[_-]?key|secret|token|password|passphrase|credential", re.IGNORECASE
)

_KNOWN_TOP_LEVEL_SECTIONS = frozenset({"general", "logging", "llm", "tools", *RESERVED_SECTIONS})
_KNOWN_TOOLS_SUBSECTIONS = frozenset({"files", "web", "shell"})


class ConfigError(ValueError):
    """Raised when configuration sources are invalid (bad TOML, bad values)."""


@dataclass(frozen=True, slots=True)
class LoggingSettings:
    """Logging-related settings."""

    level: str = "info"
    to_file: bool = True


@dataclass(frozen=True, slots=True)
class LLMSettings:
    """LLM provider settings (Phase 1A).

    The API key is intentionally NOT part of this dataclass: it is read from
    the ``ERA_LLM_API_KEY`` environment variable only, so it can never leak
    through the Config object (config show, equality, logs).
    """

    provider: str = "none"  # none | mock | openai
    model: str = ""
    base_url: str = ""  # empty -> provider default (OpenAI)
    timeout_s: float = 60.0


@dataclass(frozen=True, slots=True)
class FilesToolSettings:
    """Sandboxed file tools (Phase 1B). Empty ``sandbox_root`` means ``$ERA_HOME/sandbox``."""

    sandbox_root: str = ""
    max_read_bytes: int = 100_000
    max_write_bytes: int = 100_000


@dataclass(frozen=True, slots=True)
class WebToolSettings:
    """Read-only web tools (Phase 1B)."""

    timeout_s: float = 15.0
    max_bytes: int = 200_000
    output_char_limit: int = 8_000
    user_agent: str = "ERA-AI/0.1 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
    search: str = "duckduckgo"  # duckduckgo | searxng
    searxng_url: str = ""
    allow_private_networks: bool = False


@dataclass(frozen=True, slots=True)
class ShellToolSettings:
    """Allowlisted shell execution (Phase 1B).

    ``allowed_commands`` holds argv-prefix templates (e.g. ``"python --version"``).
    The default is empty: the shell tool refuses everything until explicitly
    configured — by design.
    """

    allowed_commands: tuple[str, ...] = ()
    timeout_s: float = 10.0
    max_output_bytes: int = 50_000


@dataclass(frozen=True, slots=True)
class ToolsSettings:
    """All tool-family settings (Phase 1B)."""

    files: FilesToolSettings = FilesToolSettings()
    web: WebToolSettings = WebToolSettings()
    shell: ShellToolSettings = ShellToolSettings()


@dataclass(frozen=True, slots=True)
class Config:
    """Effective ERA-AI configuration.

    ``sources`` maps each setting key (e.g. ``"logging.level"``) to the layer that
    supplied it (``"default"``, ``"file"`` or ``"env"``). ``warnings`` collects
    non-fatal issues such as secret-like keys in the config file. Both fields are
    excluded from equality so configurations remain easy to compare in tests.
    """

    debug: bool = False
    logging: LoggingSettings = LoggingSettings()
    llm: LLMSettings = LLMSettings()
    tools: ToolsSettings = ToolsSettings()
    sources: dict[str, str] = field(default_factory=dict, compare=False, repr=False)
    warnings: tuple[str, ...] = field(default=(), compare=False, repr=False)


def era_home(env: Mapping[str, str] | None = None) -> Path:
    """Return the ERA-AI data directory (``$ERA_HOME``, default ``~/.era``)."""
    env = os.environ if env is None else env
    return Path(env.get("ERA_HOME", str(Path.home() / ".era")))


def config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return the config file path (``$ERA_CONFIG``, default ``$ERA_HOME/config.toml``)."""
    env = os.environ if env is None else env
    if "ERA_CONFIG" in env:
        return Path(env["ERA_CONFIG"])
    return era_home(env) / "config.toml"


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Load and validate the effective configuration.

    Raises:
        ConfigError: if the TOML file cannot be parsed or a value is invalid.
    """
    env = os.environ if env is None else env
    path = config_path(env)
    file_data, warnings = _read_file(path)

    sources = {
        "debug": "default",
        "logging.level": "default",
        "logging.to_file": "default",
        "llm.provider": "default",
        "llm.model": "default",
        "llm.base_url": "default",
        "llm.timeout_s": "default",
        "tools.files.sandbox_root": "default",
        "tools.files.max_read_bytes": "default",
        "tools.files.max_write_bytes": "default",
        "tools.web.timeout_s": "default",
        "tools.web.max_bytes": "default",
        "tools.web.output_char_limit": "default",
        "tools.web.user_agent": "default",
        "tools.web.search": "default",
        "tools.web.searxng_url": "default",
        "tools.web.allow_private_networks": "default",
        "tools.shell.allowed_commands": "default",
        "tools.shell.timeout_s": "default",
        "tools.shell.max_output_bytes": "default",
    }
    debug = False
    level = "info"
    to_file = True
    llm_provider = "none"
    llm_model = ""
    llm_base_url = ""
    llm_timeout = 60.0
    files_settings: dict[str, Any] = {}
    web_settings: dict[str, Any] = {}
    shell_settings: dict[str, Any] = {}

    # Layer 2: config file. -------------------------------------------------
    general = file_data.get("general", {})
    if not isinstance(general, dict):
        msg = f"[general] must be a table, got {type(general).__name__}"
        raise ConfigError(msg)
    if "debug" in general:
        debug = _as_bool(general["debug"], "general.debug")
        sources["debug"] = "file"

    log_section = file_data.get("logging", {})
    if not isinstance(log_section, dict):
        msg = f"[logging] must be a table, got {type(log_section).__name__}"
        raise ConfigError(msg)
    if "level" in log_section:
        level = str(log_section["level"]).strip().lower()
        sources["logging.level"] = "file"
    if "to_file" in log_section:
        to_file = _as_bool(log_section["to_file"], "logging.to_file")
        sources["logging.to_file"] = "file"

    llm_section = file_data.get("llm", {})
    if not isinstance(llm_section, dict):
        msg = f"[llm] must be a table, got {type(llm_section).__name__}"
        raise ConfigError(msg)
    if "provider" in llm_section:
        raw_provider = str(llm_section["provider"]).strip().lower()
        if raw_provider not in VALID_LLM_PROVIDERS:
            msg = (
                f"invalid llm provider {raw_provider!r} in [llm] "
                f"(valid: {', '.join(sorted(VALID_LLM_PROVIDERS))})"
            )
            raise ConfigError(msg)
        llm_provider = raw_provider
        sources["llm.provider"] = "file"
    if "model" in llm_section:
        llm_model = str(llm_section["model"]).strip()
        sources["llm.model"] = "file"
    if "base_url" in llm_section:
        llm_base_url = str(llm_section["base_url"]).strip().rstrip("/")
        sources["llm.base_url"] = "file"
    if "timeout_s" in llm_section:
        llm_timeout = _as_positive_float(llm_section["timeout_s"], "llm.timeout_s")
        sources["llm.timeout_s"] = "file"

    tools_section = file_data.get("tools", {})
    if not isinstance(tools_section, dict):
        msg = f"[tools] must be a table, got {type(tools_section).__name__}"
        raise ConfigError(msg)
    for sub in sorted(set(tools_section) - _KNOWN_TOOLS_SUBSECTIONS):
        if not isinstance(tools_section[sub], dict):
            continue  # scalar under [tools]; reported below by key checks
        known = ", ".join(sorted(_KNOWN_TOOLS_SUBSECTIONS))
        msg = f"unknown config section [tools.{sub}] (known: {known})"
        raise ConfigError(msg)

    files_data = tools_section.get("files", {})
    if not isinstance(files_data, dict):
        msg = f"[tools.files] must be a table, got {type(files_data).__name__}"
        raise ConfigError(msg)
    _reject_unknown_keys(
        files_data, "tools.files", {"sandbox_root", "max_read_bytes", "max_write_bytes"}
    )
    if "sandbox_root" in files_data:
        files_settings["sandbox_root"] = _as_str(
            files_data["sandbox_root"], "tools.files.sandbox_root"
        )
        sources["tools.files.sandbox_root"] = "file"
    if "max_read_bytes" in files_data:
        files_settings["max_read_bytes"] = _as_positive_int(
            files_data["max_read_bytes"], "tools.files.max_read_bytes"
        )
        sources["tools.files.max_read_bytes"] = "file"
    if "max_write_bytes" in files_data:
        files_settings["max_write_bytes"] = _as_positive_int(
            files_data["max_write_bytes"], "tools.files.max_write_bytes"
        )
        sources["tools.files.max_write_bytes"] = "file"

    web_data = tools_section.get("web", {})
    if not isinstance(web_data, dict):
        msg = f"[tools.web] must be a table, got {type(web_data).__name__}"
        raise ConfigError(msg)
    _reject_unknown_keys(
        web_data,
        "tools.web",
        {
            "timeout_s",
            "max_bytes",
            "output_char_limit",
            "user_agent",
            "search",
            "searxng_url",
            "allow_private_networks",
        },
    )
    if "timeout_s" in web_data:
        web_settings["timeout_s"] = _as_positive_float(web_data["timeout_s"], "tools.web.timeout_s")
        sources["tools.web.timeout_s"] = "file"
    if "max_bytes" in web_data:
        web_settings["max_bytes"] = _as_positive_int(web_data["max_bytes"], "tools.web.max_bytes")
        sources["tools.web.max_bytes"] = "file"
    if "output_char_limit" in web_data:
        web_settings["output_char_limit"] = _as_positive_int(
            web_data["output_char_limit"], "tools.web.output_char_limit"
        )
        sources["tools.web.output_char_limit"] = "file"
    if "user_agent" in web_data:
        agent = _as_str(web_data["user_agent"], "tools.web.user_agent")
        if not agent:
            msg = "tools.web.user_agent must be a non-empty string"
            raise ConfigError(msg)
        web_settings["user_agent"] = agent
        sources["tools.web.user_agent"] = "file"
    if "search" in web_data:
        raw_search = _as_str(web_data["search"], "tools.web.search").lower()
        if raw_search not in VALID_WEB_SEARCH_PROVIDERS:
            msg = (
                f"invalid tools.web.search {raw_search!r} "
                f"(valid: {', '.join(sorted(VALID_WEB_SEARCH_PROVIDERS))})"
            )
            raise ConfigError(msg)
        web_settings["search"] = raw_search
        sources["tools.web.search"] = "file"
    if "searxng_url" in web_data:
        web_settings["searxng_url"] = _as_str(
            web_data["searxng_url"], "tools.web.searxng_url"
        ).rstrip("/")
        sources["tools.web.searxng_url"] = "file"
    if "allow_private_networks" in web_data:
        web_settings["allow_private_networks"] = _as_bool(
            web_data["allow_private_networks"], "tools.web.allow_private_networks"
        )
        sources["tools.web.allow_private_networks"] = "file"

    shell_data = tools_section.get("shell", {})
    if not isinstance(shell_data, dict):
        msg = f"[tools.shell] must be a table, got {type(shell_data).__name__}"
        raise ConfigError(msg)
    _reject_unknown_keys(
        shell_data, "tools.shell", {"allowed_commands", "timeout_s", "max_output_bytes"}
    )
    if "allowed_commands" in shell_data:
        shell_settings["allowed_commands"] = _as_command_list(
            shell_data["allowed_commands"], "tools.shell.allowed_commands"
        )
        sources["tools.shell.allowed_commands"] = "file"
    if "timeout_s" in shell_data:
        shell_settings["timeout_s"] = _as_positive_float(
            shell_data["timeout_s"], "tools.shell.timeout_s"
        )
        sources["tools.shell.timeout_s"] = "file"
    if "max_output_bytes" in shell_data:
        shell_settings["max_output_bytes"] = _as_positive_int(
            shell_data["max_output_bytes"], "tools.shell.max_output_bytes"
        )
        sources["tools.shell.max_output_bytes"] = "file"

    # Layer 3: environment. -------------------------------------------------
    if "ERA_DEBUG" in env:
        debug = _coerce_bool(env["ERA_DEBUG"], "ERA_DEBUG")
        sources["debug"] = "env"
    if "ERA_LOG_LEVEL" in env:
        level = env["ERA_LOG_LEVEL"].strip().lower()
        sources["logging.level"] = "env"
    if "ERA_LOG_FILE" in env:
        to_file = _coerce_bool(env["ERA_LOG_FILE"], "ERA_LOG_FILE")
        sources["logging.to_file"] = "env"
    if "ERA_LLM_PROVIDER" in env:
        raw_provider = env["ERA_LLM_PROVIDER"].strip().lower()
        if raw_provider not in VALID_LLM_PROVIDERS:
            msg = (
                f"invalid llm provider {raw_provider!r} in ERA_LLM_PROVIDER "
                f"(valid: {', '.join(sorted(VALID_LLM_PROVIDERS))})"
            )
            raise ConfigError(msg)
        llm_provider = raw_provider
        sources["llm.provider"] = "env"
    if "ERA_LLM_MODEL" in env:
        llm_model = env["ERA_LLM_MODEL"].strip()
        sources["llm.model"] = "env"
    if "ERA_LLM_BASE_URL" in env:
        llm_base_url = env["ERA_LLM_BASE_URL"].strip().rstrip("/")
        sources["llm.base_url"] = "env"
    if "ERA_LLM_TIMEOUT" in env:
        llm_timeout = _coerce_positive_float(env["ERA_LLM_TIMEOUT"], "ERA_LLM_TIMEOUT")
        sources["llm.timeout_s"] = "env"
    if "ERA_SANDBOX_ROOT" in env:
        files_settings["sandbox_root"] = env["ERA_SANDBOX_ROOT"].strip()
        sources["tools.files.sandbox_root"] = "env"
    if "ERA_SHELL_ALLOWED" in env:
        raw_commands = env["ERA_SHELL_ALLOWED"]
        shell_settings["allowed_commands"] = tuple(
            entry.strip() for entry in raw_commands.split(",") if entry.strip()
        )
        sources["tools.shell.allowed_commands"] = "env"

    if level not in VALID_LOG_LEVELS:
        msg = f"invalid log level {level!r} (valid: {', '.join(VALID_LOG_LEVELS)})"
        raise ConfigError(msg)

    if web_settings.get("search", "duckduckgo") == "searxng" and not web_settings.get(
        "searxng_url", ""
    ):
        msg = "tools.web.search = 'searxng' requires tools.web.searxng_url to be set"
        raise ConfigError(msg)

    return Config(
        debug=debug,
        logging=LoggingSettings(level=level, to_file=to_file),
        llm=LLMSettings(
            provider=llm_provider,
            model=llm_model,
            base_url=llm_base_url,
            timeout_s=llm_timeout,
        ),
        tools=ToolsSettings(
            files=FilesToolSettings(
                sandbox_root=files_settings.get("sandbox_root", ""),
                max_read_bytes=files_settings.get("max_read_bytes", 100_000),
                max_write_bytes=files_settings.get("max_write_bytes", 100_000),
            ),
            web=WebToolSettings(
                timeout_s=web_settings.get("timeout_s", 15.0),
                max_bytes=web_settings.get("max_bytes", 200_000),
                output_char_limit=web_settings.get("output_char_limit", 8_000),
                user_agent=web_settings.get(
                    "user_agent", "ERA-AI/0.1 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
                ),
                search=web_settings.get("search", "duckduckgo"),
                searxng_url=web_settings.get("searxng_url", ""),
                allow_private_networks=web_settings.get("allow_private_networks", False),
            ),
            shell=ShellToolSettings(
                allowed_commands=shell_settings.get("allowed_commands", ()),
                timeout_s=shell_settings.get("timeout_s", 10.0),
                max_output_bytes=shell_settings.get("max_output_bytes", 50_000),
            ),
        ),
        sources=sources,
        warnings=tuple(warnings),
    )


def with_debug(config: Config, debug: bool) -> Config:
    """Return a copy of ``config`` with debug forced on/off (used by ``era --debug``)."""
    return replace(config, debug=debug, sources={**config.sources, "debug": "cli"})


def _read_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Read the TOML file; return its data plus non-fatal warnings."""
    if not path.exists():
        return {}, []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        msg = f"could not read config file {path}: {exc}"
        raise ConfigError(msg) from exc

    warnings: list[str] = []
    for secret_key in _find_secret_keys(data):
        warnings.append(
            f"secret-like key '{secret_key}' found in {path} — secrets must be supplied "
            "via environment variables, never the config file"
        )
    for section in sorted(set(data) - _KNOWN_TOP_LEVEL_SECTIONS):
        warnings.append(f"unknown config section [{section}] in {path} — ignored")
    for section in sorted(set(data) & set(RESERVED_SECTIONS)):
        warnings.append(f"config section [{section}] is reserved for a future phase — ignored")
    return data, warnings


def _find_secret_keys(data: Mapping[str, Any], prefix: str = "") -> list[str]:
    """Return dotted paths of any secret-like keys in a nested mapping."""
    found: list[str] = []
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if _SECRET_KEY_RE.search(str(key)):
            found.append(dotted)
        elif isinstance(value, Mapping):
            found.extend(_find_secret_keys(value, prefix=f"{dotted}."))
    return found


def _reject_unknown_keys(section: Mapping[str, Any], where: str, known: set[str]) -> None:
    for key in sorted(set(section) - known):
        msg = f"unknown config key {where}.{key}"
        raise ConfigError(msg)


def _as_bool(value: Any, where: str) -> bool:
    """Coerce a config-file value to bool; raise ConfigError for anything ambiguous."""
    if isinstance(value, bool):
        return value
    msg = f"{where} must be a boolean, got {value!r}"
    raise ConfigError(msg)


def _as_str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        msg = f"{where} must be a string, got {value!r}"
        raise ConfigError(msg)
    return value.strip()


def _as_command_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        msg = f"{where} must be an array of strings"
        raise ConfigError(msg)
    commands = tuple(entry.strip() for entry in value if entry.strip())
    if len(commands) != len(value):
        msg = f"{where} contains empty entries"
        raise ConfigError(msg)
    return commands


def _coerce_bool(raw: str, where: str) -> bool:
    """Coerce an environment-variable string to bool."""
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    msg = f"{where} must be a boolean-like value, got {raw!r}"
    raise ConfigError(msg)


def _as_positive_float(value: object, where: str) -> float:
    """Coerce a config-file value to a positive float."""
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        msg = f"{where} must be a number, got {value!r}"
        raise ConfigError(msg) from exc
    if result <= 0 or result != result:  # rejects <= 0 and NaN
        msg = f"{where} must be a positive number, got {value!r}"
        raise ConfigError(msg)
    return result


def _coerce_positive_float(raw: str, where: str) -> float:
    """Coerce an environment-variable string to a positive float."""
    return _as_positive_float(raw.strip(), where)


def _as_positive_int(value: object, where: str) -> int:
    """Coerce a config-file value to a positive integer (bools rejected)."""
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{where} must be an integer, got {value!r}"
        raise ConfigError(msg)
    if value <= 0:
        msg = f"{where} must be a positive integer, got {value!r}"
        raise ConfigError(msg)
    return value
