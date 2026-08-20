"""Tests for the legacy placeholder modules and their root facades."""

from __future__ import annotations

import importlib
import sys
import warnings

import pytest
from era.legacy import ERAAI, Brain, Chat, Memory, Research


class TestLegacyBehaviour:
    def test_brain_status(self, capsys: pytest.CaptureFixture[str]) -> None:
        Brain().status()
        out = capsys.readouterr().out
        assert "ERA AI Brain" in out
        assert "Research" in out

    def test_memory_remember_and_show(self, capsys: pytest.CaptureFixture[str]) -> None:
        memory = Memory()
        memory.show()
        assert "Memory Empty" in capsys.readouterr().out
        memory.remember("note one")
        memory.show()
        out = capsys.readouterr().out
        assert "- note one" in out

    def test_research_known_and_unknown(self) -> None:
        research = Research()
        assert "Tesla" in research.search("tesla")
        assert research.search("tesla") == research.search("TESLA")
        assert research.search("quantum foam") == "Information not found."

    def test_agent_has_single_erai_class(self) -> None:
        # Regression: the original agent.py defined ERAAI twice (second shadowed first).
        import era.legacy.agent as agent_module

        classes = [v for k, v in vars(agent_module).items() if isinstance(v, type) and k == "ERAAI"]
        assert len(classes) == 1
        agent = ERAAI()
        assert isinstance(agent.brain, Brain)
        assert isinstance(agent.memory, Memory)
        assert isinstance(agent.research, Research)
        assert isinstance(agent.chat, Chat)

    def test_agent_repl_roundtrip(self, monkeypatch, capsys: pytest.CaptureFixture[str]) -> None:
        inputs = iter(["what is history", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        ERAAI().start()
        out = capsys.readouterr().out
        assert "इतिहास" in out
        assert "Goodbye" in out


class TestChatWordBoundaryFix:
    """Regression tests: substring matching made 'email', 'wait', 'gmail' trigger the AI reply."""

    @pytest.mark.parametrize("message", ["email", "wait", "gmail", "trains are great"])
    def test_substring_words_do_not_trigger_ai(self, message: str) -> None:
        assert Chat().reply(message) == "❌ अभी मैं इस विषय को नहीं जानता।"

    @pytest.mark.parametrize(
        ("message", "marker"),
        [
            ("tell me about AI", "Artificial Intelligence"),
            ("Who was Tesla?", "Tesla"),
            ("i visited the Taj Mahal today", "ताजमहल"),
            ("SCIENCE is fun", "विज्ञान"),
        ],
    )
    def test_keywords_still_match(self, message: str, marker: str) -> None:
        assert marker in Chat().reply(message)


class TestRootFacades:
    @pytest.mark.parametrize(
        ("facade", "legacy_name"),
        [
            ("brain", "Brain"),
            ("memory", "Memory"),
            ("research", "Research"),
            ("chat", "Chat"),
            ("agent", "ERAAI"),
        ],
    )
    def test_facades_reexport_legacy_classes_with_warning(
        self, facade: str, legacy_name: str
    ) -> None:
        sys.modules.pop(facade, None)  # force a fresh import
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            module = importlib.import_module(facade)
        assert len(caught) == 1
        assert caught[0].category is DeprecationWarning
        assert getattr(module, legacy_name) is getattr(
            importlib.import_module("era.legacy"), legacy_name
        )

    def test_config_facade_exports_constants(self) -> None:
        sys.modules.pop("config", None)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            module = importlib.import_module("config")
        assert module.APP_NAME == "ERA AI"
        assert module.AUTHOR == "Sarafraj"
        assert module.DEBUG is False

    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_main_facade_is_import_safe(self) -> None:
        # Regression: the old main.py started a blocking REPL at import time.
        import main  # noqa: F401  (must not block or start any loop)
