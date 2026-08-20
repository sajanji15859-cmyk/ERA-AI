"""Layered configuration for ERA-AI.

Resolution order (later layers win):

1. Built-in defaults (defined below)
2. TOML config file — default ``$ERA_HOME/config.toml`` (usually ``~/.era/config.toml``),
   or the path in ``$ERA_CONFIG``
3. Environment variables prefixed with ``ERA_``

Security rule: **secrets never go in the config file.** Any secret-like key found in
the file is flagged by :func:`load_config` (and by ``era doctor`` / ``era config show``);
supply secrets via environment variables instead (e.g. ``ERA_LLM_API_KEY``). Keys under
reserved future-phase sections (e.g. ``[tools]``) are parsed but ignored until those
phases are implemented.

Example ``~/.era/config.toml``::

    [general]
    debug = false

    [logging]
    level = "info"      # debug | info | warning | error
    to_file = true

    [llm]              # Phase 1A: LLM adapter layer
    provider = "none"  # none | mock | openai
    model = ""         # required when provider = "openai"
    base_url = ""      # optional; any OpenAI-compatible endpoint
    timeout_s = 60.0

Environment overrides: ``ERA_HOME``, ``ERA_CONFIG``, ``ERA_DEBUG``, ``ERA_LOG_LEVEL``,
``ERA_LOG_FILE``, ``ERA_LLM_PROVIDER``, ``ERA_LLM_MODEL``, ``ERA_LLM_BASE_URL``,
``ERA_LLM_TIMEOUT`` — plus ``ERA_LLM_API_KEY`` (environment only; never a config key).
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
#: Sections parsed but not yet honoured by an implemented phase.
RESERVED_SECTIONS = ("agent", "memory", "safety", "tools")

_SECRET_KEY_RE = re.compile(
    r"api[_-]?key|secret|token|password|passphrase|credential", re.IGNORECASE
)

_KNOWN_TOP_LEVEL_SECTIONS = frozenset({"general", "logging", "llm", *RESERVED_SECTIONS})


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
    }
    debug = False
    level = "info"
    to_file = True
    llm_provider = "none"
    llm_model = ""
    llm_base_url = ""
    llm_timeout = 60.0

    # Layer 2: config file.
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

    # Layer 3: environment.
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

    if level not in VALID_LOG_LEVELS:
        msg = f"invalid log level {level!r} (valid: {', '.join(VALID_LOG_LEVELS)})"
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


def _as_bool(value: Any, where: str) -> bool:
    """Coerce a config-file value to bool; raise ConfigError for anything ambiguous."""
    if isinstance(value, bool):
        return value
    msg = f"{where} must be a boolean, got {value!r}"
    raise ConfigError(msg)


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
