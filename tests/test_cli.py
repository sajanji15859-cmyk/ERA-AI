"""Tests for the CLI (era.cli.main)."""

from __future__ import annotations

from pathlib import Path

import pytest
from era import __version__
from era.cli import main


class TestBasics:
    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--version"]) == 0
        assert __version__ in capsys.readouterr().out

    def test_status_is_default_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([]) == 0
        out = capsys.readouterr().out
        assert "ERA AI" in out
        assert __version__ in out

    def test_explicit_status_matches_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        main([])
        default_out = capsys.readouterr().out
        main(["status"])
        assert capsys.readouterr().out == default_out

    def test_debug_flag_accepted(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--debug", "status"]) == 0


class TestDoctor:
    def test_doctor_passes_on_clean_environment(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["doctor"]) == 0
        out = capsys.readouterr().out
        assert "All checks passed." in out

    def test_doctor_fails_on_broken_config(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "era-home"
        home.mkdir()
        (home / "config.toml").write_text("[general\nbroken", encoding="utf-8")
        assert main(["doctor"]) == 1
        out = capsys.readouterr().out
        assert "[FAIL]" in out
        assert "Some checks failed." in out

    def test_doctor_warns_on_secret_in_config(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "era-home"
        home.mkdir()
        (home / "config.toml").write_text("[llm]\napi_key = 'x'\n", encoding="utf-8")
        assert main(["doctor"]) == 0  # warning, not failure
        out = capsys.readouterr().out
        assert "[warn]" in out
        assert "api_key" in out


class TestConfigCommands:
    def test_config_show(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["config", "show"]) == 0
        out = capsys.readouterr().out
        for key in (
            "debug",
            "logging.level",
            "logging.to_file",
            "llm.provider",
            "llm.model",
            "llm.base_url",
            "llm.timeout_s",
        ):
            assert key in out

    def test_config_show_defaults_without_action(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["config"]) == 0
        assert "logging.level" in capsys.readouterr().out

    def test_config_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["config", "path"]) == 0
        assert "config.toml" in capsys.readouterr().out

    def test_status_reports_invalid_config(
        self, tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "era-home"
        home.mkdir()
        (home / "config.toml").write_text("[general\nbroken", encoding="utf-8")
        assert main(["status"]) == 2
        assert "could not read config file" in capsys.readouterr().err


class TestChat:
    def test_chat_repl_roundtrip(self, monkeypatch, capsys: pytest.CaptureFixture[str]) -> None:
        inputs = iter(["tell me about ai", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        assert main(["chat"]) == 0
        out = capsys.readouterr().out
        assert "Artificial Intelligence" in out
        assert "Goodbye" in out

    def test_chat_eof_exits_cleanly(self, monkeypatch, capsys: pytest.CaptureFixture[str]) -> None:
        def eof(_: str) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", eof)
        assert main(["chat"]) == 0
        assert "Goodbye" in capsys.readouterr().out
