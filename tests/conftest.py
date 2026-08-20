"""Shared fixtures."""

from __future__ import annotations

import pytest

from era.config import Settings
from era.container import Container, build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.tool_provider import ToolProvider


@pytest.fixture
def container(tmp_path) -> Container:
    settings = Settings(database_url=f"sqlite:///{tmp_path}/era_test.db")
    c = build_container(settings)
    yield c
    c.engine.dispose()


def make_container(tmp_path, providers: list[ToolProvider] | None = None) -> Container:
    settings = Settings(database_url=f"sqlite:///{tmp_path}/era_test.db")
    return build_container(settings, providers=providers)


@pytest.fixture
def ctx() -> ExecutionContext:
    return ExecutionContext(actor_id="test-actor")


def action(action_type: str, **params) -> Action:
    return Action(action_type=action_type, params=params)
