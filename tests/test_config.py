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
        write_config(tmp_path / "era-home" / "config.toml", "[llm]\napi_key = 'super-secret'\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert any("api_key" in w and "secret" in w.lower() for w in config.warnings)

    def test_reserved_section_is_ignored_with_warning(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[tools]\nprovider = 'anthropic'\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert any("[tools]" in w and "reserved" in w for w in config.warnings)
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


class TestLLMSection:
    """Phase 1A: the [llm] section is now honoured (previously reserved)."""

    def test_defaults(self) -> None:
        config = load_config(env={"ERA_HOME": "/tmp/x"})
        assert config.llm.provider == "none"
        assert config.llm.model == ""
        assert config.llm.base_url == ""
        assert config.llm.timeout_s == 60.0

    def test_file_overrides(self, tmp_path: Path) -> None:
        write_config(
            tmp_path / "era-home" / "config.toml",
            "[llm]\nprovider = 'openai'\nmodel = 'm-1'\n"
            "base_url = 'http://localhost:11434/v1/'\ntimeout_s = 12.5\n",
        )
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert config.llm.provider == "openai"
        assert config.llm.model == "m-1"
        assert config.llm.base_url == "http://localhost:11434/v1"  # trailing / stripped
        assert config.llm.timeout_s == 12.5
        assert config.sources["llm.provider"] == "file"

    def test_env_overrides(self) -> None:
        config = load_config(
            env={
                "ERA_HOME": "/tmp/x",
                "ERA_LLM_PROVIDER": "mock",
                "ERA_LLM_MODEL": "env-model",
                "ERA_LLM_BASE_URL": "http://env-host/v1",
                "ERA_LLM_TIMEOUT": "5",
            }
        )
        assert config.llm.provider == "mock"
        assert config.llm.model == "env-model"
        assert config.llm.base_url == "http://env-host/v1"
        assert config.llm.timeout_s == 5.0
        assert config.sources["llm.provider"] == "env"

    def test_invalid_provider_in_file_raises(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[llm]\nprovider = 'skynet'\n")
        with pytest.raises(ConfigError, match="invalid llm provider"):
            load_config(env={"ERA_HOME": str(tmp_path / "era-home")})

    def test_invalid_provider_in_env_raises(self) -> None:
        with pytest.raises(ConfigError, match="ERA_LLM_PROVIDER"):
            load_config(env={"ERA_HOME": "/tmp/x", "ERA_LLM_PROVIDER": "hal9000"})

    @pytest.mark.parametrize("bad", ["0", "-3", "abc", "nan"])
    def test_invalid_timeout_raises(self, bad: str) -> None:
        with pytest.raises(ConfigError, match="ERA_LLM_TIMEOUT"):
            load_config(env={"ERA_HOME": "/tmp/x", "ERA_LLM_TIMEOUT": bad})

    def test_bad_timeout_in_file_raises(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[llm]\ntimeout_s = -1\n")
        with pytest.raises(ConfigError, match=r"llm\.timeout_s"):
            load_config(env={"ERA_HOME": str(tmp_path / "era-home")})

    def test_llm_is_no_longer_reserved(self, tmp_path: Path) -> None:
        write_config(tmp_path / "era-home" / "config.toml", "[llm]\nmodel = 'm'\n")
        config = load_config(env={"ERA_HOME": str(tmp_path / "era-home")})
        assert not any("reserved" in w for w in config.warnings)
