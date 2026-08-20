"""Tests for logging setup (era.logging)."""

from __future__ import annotations

import logging

from era.config import Config, LoggingSettings
from era.logging import get_logger, setup_logging


def make_config(level: str = "info", to_file: bool = True, debug: bool = False) -> Config:
    return Config(debug=debug, logging=LoggingSettings(level=level, to_file=to_file))


class TestSetupLogging:
    def test_handlers_configured(self) -> None:
        setup_logging(make_config())
        root = logging.getLogger("era")
        assert not root.propagate
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)

    def test_file_logging_creates_log_file(self) -> None:
        log_file = setup_logging(make_config())
        assert log_file is not None and log_file.name.endswith("era.log")
        logger = get_logger("test")
        logger.warning("hello from test")
        for handler in logging.getLogger("era").handlers:
            handler.flush()
        assert "hello from test" in log_file.read_text(encoding="utf-8")

    def test_file_logging_disabled(self) -> None:
        assert setup_logging(make_config(to_file=False)) is None

    def test_idempotent_no_duplicate_handlers(self) -> None:
        setup_logging(make_config())
        setup_logging(make_config())
        root = logging.getLogger("era")
        # Note: RotatingFileHandler subclasses StreamHandler — filter by exact type.
        console = [h for h in root.handlers if type(h) is logging.StreamHandler]
        assert len(console) == 1

    def test_debug_flag_sets_debug_level(self) -> None:
        setup_logging(make_config(debug=True))
        console = logging.getLogger("era").handlers[0]
        assert console.level == logging.DEBUG

    def test_unwritable_home_does_not_raise(self, monkeypatch) -> None:
        monkeypatch.setenv("ERA_HOME", "/proc/definitely-not-writable")
        log_file = setup_logging(make_config())
        assert log_file is None


class TestGetLogger:
    def test_child_names_are_namespaced(self) -> None:
        assert get_logger("cli").name == "era.cli"
        assert get_logger("era.cli").name == "era.cli"
