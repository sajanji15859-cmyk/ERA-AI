"""Application settings.

Secrets must never be placed here or in ``.env`` as credentials: providers own
their own credential access (see the secret/credential boundary). These settings
are operational knobs only.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ERA_", extra="ignore")

    database_url: str = "sqlite:///era.db"

    # Confirmation TTLs (seconds).
    confirmation_ttl_seconds: int = 300       # normal CONFIRM
    confirmation_ttl_strong_seconds: int = 120  # CONFIRM_STRONG (financial/booking/destructive)

    # Append-only hash chain.
    audit_genesis_hash: str = "0" * 64

    app_version: str = "0.1.0"

    # Note: a missing/malformed policy is always DENY-all (hard fail-closed).
    # This is intentionally not configurable — weakening it is a footgun.
