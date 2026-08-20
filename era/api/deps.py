"""FastAPI dependencies: expose the application container."""

from __future__ import annotations

from fastapi import Request

from era.container import Container


def get_container(request: Request) -> Container:
    return request.app.state.container
