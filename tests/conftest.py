"""Shared pytest fixtures: every test gets an isolated ERA home."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_era_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point ERA_HOME at a temp dir and clear ERA_* overrides for every test."""
    monkeypatch.setenv("ERA_HOME", str(tmp_path / "era-home"))
    for var in (
        "ERA_CONFIG",
        "ERA_DEBUG",
        "ERA_LOG_LEVEL",
        "ERA_LOG_FILE",
        "ERA_LLM_PROVIDER",
        "ERA_LLM_MODEL",
        "ERA_LLM_BASE_URL",
        "ERA_LLM_TIMEOUT",
        "ERA_LLM_API_KEY",
        "ERA_SANDBOX_ROOT",
        "ERA_SHELL_ALLOWED",
    ):
        monkeypatch.delenv(var, raising=False)
