"""Tests for the layered configuration system (era.config)."""

from __future__ import annotations

from pathlib import Path

import pytest
from era.config import (
    Config,
    ConfigError,
    config_path,
    era_home,
    load_config,
    with_debug,
)


def write_config(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestPaths:
    def test_default_home_is_dot_era(self, tmp_path: Path) -> None:
        home = era_home(env={"ERA_HOME": str(tmp_path / "h")})
        assert home == tmp_path / "h"

    def test_era_config_overrides_config_path(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom.toml"
        assert config_path(env={"ERA_CONFIG": str(custom)}) == custom

    def test_config_defaults_to_home_config_toml(self) -> None:
        env = {"ERA_HOME": "/tmp/fake-home"}
        assert config_path(env=env) == Path("/tmp/fake-home/config.toml")


class TestLayering:
    def test_defaults_when_no_file_or_env(self) -> None:
        config = load_config(env={"ERA_HOME": "/tmp/nonexistent"})
        assert config.debug is False
        assert config.logging.level == "info"
        assert config.logging.to_file is True
        assert set(config.sources.values()) == {"default"}

    def test_file_overrides_defaults(self, tmp_path: Path) -> None:
        write_config(
            tmp_path / "era-home" / "config.toml",
            "[general]\ndebug = true\n\n[logging]\nlevel = 'warning'\nto_file = false\n",
        )
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert config.debug is True
        assert config.logging.level == "warning"
        assert config.logging.to_file is False
        assert config.sources["debug"] == "file"
        assert config.sources["logging.level"] == "file"
        assert config.sources["logging.to_file"] == "file"

    def test_env_overrides_file(self, tmp_path: Path) -> None:
        write_config(
            tmp_path / "era-home" / "config.toml",
            "[logging]\nlevel = 'info'\n",
        )
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home"), "ERA_LOG_LEVEL": "error"})
        assert config.logging.level == "error"
        assert config.sources["logging.level"] == "env"

    def test_debug_env_coercion_variants(self) -> None:
        for raw, expected in [
            ("1", True),
            ("true", True),
            ("YES", True),
            ("0", False),
            ("no", False),
        ]:
            config = load_config(env={"ERA_HOME": "/tmp/x", "ERA_DEBUG": raw})
            assert config.debug is expected, raw

    def test_with_debug_sets_cli_source(self) -> None:
        config = with_debug(load_config(env={"ERA_HOME": "/tmp/x"}), True)
        assert config.debug is True
        assert config.sources["debug"] == "cli"


class TestValidation:
    def test_invalid_level_raises(self) -> None:
        with pytest.raises(ConfigError, match="invalid log level"):
            load_config(env={"ERA_HOME": "/tmp/x", "ERA_LOG_LEVEL": "verbose"})

    def test_invalid_bool_raises(self) -> None:
        with pytest.raises(ConfigError, match="ERA_DEBUG"):
            load_config(env={"ERA_HOME": "/tmp/x", "ERA_DEBUG": "maybe"})

    def test_broken_toml_raises(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[general\nbroken = ")
        with pytest.raises(ConfigError, match="could not read config file"):
            load_config(env={"ERA_HOME": str(tmp_path / "era-home")})

    def test_non_bool_file_value_raises(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[general]\ndebug = 'yes please'\n")
        with pytest.raises(ConfigError, match=r"general\.debug"):
            load_config(env={"ERA_HOME": str(tmp_path / "era-home")})


class TestSecretsAndWarnings:
    def test_secret_like_key_in_file_is_flagged(self, tmp_path: Path) -> None:
        write_config(
            tmp_path / "era-home" / "config.toml",
            "[llm]\napi_key = 'super-secret'\nprovider = 'x'\n",
        )
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert any("api_key" in w and "secret" in w.lower() for w in config.warnings)

    def test_reserved_section_is_ignored_with_warning(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[llm]\nprovider = 'anthropic'\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert any("[llm]" in w and "reserved" in w for w in config.warnings)
        assert config.debug is False  # value untouched

    def test_unknown_section_warns(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[teleport]\nenabled = true\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert any("[teleport]" in w and "unknown" in w for w in config.warnings)

    def test_clean_config_has_no_warnings(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[general]\ndebug = true\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert config.warnings == ()


class TestEquality:
    def test_config_equality_ignores_metadata(self) -> None:
        a = Config(debug=True)
        b = Config(debug=True, sources={"debug": "env"}, warnings=("w",))
        assert a == b
