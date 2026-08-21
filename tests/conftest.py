"""Shared fixtures."""

from __future__ import annotations

import pytest

from era.config import Settings
from era.container import Container, build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.tool_provider import ToolProvider


def create_principal(container: Container, *, username: str, role: str = "user") -> dict:
    """Create a user + API key; return the raw key to authenticate with.

    Returns ``{"user": ..., "api_key": ..., "raw_key": ...}``.
    """
    user = container.auth_service.create_user(username=username, role=role)
    key, raw = container.auth_service.create_api_key(user.id, f"{username}-test")
    return {"user": user, "api_key": key, "raw_key": raw}


def make_authed_app(tmp_path, *, admin_username: str = "tadmin",
                    user_username: str = "tuser"):
    """Build an app + a principal factory for authenticated TestClient tests."""
    settings = Settings(database_url=f"sqlite:///{tmp_path}/authed.db")
    from era.main import create_app
    app = create_app(settings)
    container = app.state.container
    admin = create_principal(container, username=admin_username, role="admin")
    user = create_principal(container, username=user_username, role="user")
    return app, {"admin": admin, "user": user, "container": container}


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
