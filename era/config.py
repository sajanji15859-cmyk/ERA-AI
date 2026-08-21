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

    # Hard wall-clock budget (seconds) for a single provider validate/execute
    # call during the dispatch phase (Phase 1E). Overrun -> ToolError(TIMEOUT),
    # recorded as FAILED. 0 disables the hard timeout (used only by tests/stub).
    provider_timeout_seconds: float = 30.0

    # Reliability knobs (Phase 1F). All have safe bounded defaults; the retry
    # policy additionally hard-caps max attempts so no configuration can create
    # an unbounded retry loop.
    #: Max provider-execute attempts per dispatch (1 = no retry; capped at 10).
    provider_retry_max_attempts: int = 3
    #: Exponential backoff start (seconds) before the second attempt.
    provider_retry_base_backoff_seconds: float = 0.1
    #: Upper cap on a single backoff sleep (seconds).
    provider_retry_max_backoff_seconds: float = 2.0
    #: Backoff growth factor between attempts.
    provider_retry_backoff_factor: float = 2.0
    #: Consecutive eligible provider failures that open the circuit.
    circuit_breaker_failure_threshold: int = 5
    #: How long an OPEN circuit blocks dispatch before a HALF_OPEN probe.
    circuit_breaker_cooldown_seconds: float = 30.0

    #: Max accepted HTTP request body (bytes) for hardening (Phase 2A).
    max_request_body_bytes: int = 262144

    # --- Phase 3A: agent (MVEA) settings -------------------------------------
    #: Build the agent-enabled container (real providers + agent routes).
    agent_enabled: bool = False
    #: Sandbox root for all agent file operations (relative to the CWD).
    agent_workspace_root: str = "workspace"
    #: Agent loop caps (all enforced in code — an endless loop is impossible).
    agent_max_iterations: int = 25
    agent_max_tool_calls: int = 40
    agent_run_timeout_seconds: float = 900.0
    agent_max_retries_per_task: int = 2
    agent_max_llm_calls: int = 20
    agent_cost_cap_usd: float = 0.10
    #: LLM wiring. Empty/"none"/"off" = offline deterministic mode (free).
    #: "openai" = any OpenAI-compatible chat/completions endpoint.
    agent_llm_provider: str = ""
    agent_llm_base_url: str = "https://api.openai.com/v1"
    agent_llm_model: str = "gpt-4o-mini"
    #: Env-only. Never commit a real key; with no key the agent runs offline.
    agent_llm_api_key: str = ""
    agent_llm_max_tokens: int = 2048
    #: Provider caps.
    workspace_max_file_bytes: int = 1_048_576
    web_max_fetch_bytes: int = 2_097_152
    web_timeout_seconds: float = 15.0
    web_user_agent: str = "ERA-Agent/0.3"

    app_version: str = "0.3.0"

    # Note: a missing/malformed policy is always DENY-all (hard fail-closed).
    # This is intentionally not configurable — weakening it is a footgun.
