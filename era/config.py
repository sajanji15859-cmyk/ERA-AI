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

    # Append-only hash chain + optional keyed authentication (Phase 3F).
    audit_genesis_hash: str = "0" * 64
    #: Explicit legacy mode is ``none``. Production should use hmac-sha256 or
    #: ed25519 and inject key material through environment/secret management.
    audit_signing_algorithm: str = "none"
    audit_signing_key: str = ""
    audit_signing_public_key: str = ""
    audit_signing_key_id: str = "default"

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
    #: Maximum JSON-encoded provider result returned/persisted after centralized
    #: secret redaction and structural validation.
    provider_result_max_bytes: int = 524288
    #: Consecutive eligible provider failures that open the circuit.
    circuit_breaker_failure_threshold: int = 5
    #: How long an OPEN circuit blocks dispatch before a HALF_OPEN probe.
    circuit_breaker_cooldown_seconds: float = 30.0
    #: Persist state so OPEN circuits survive process restarts and are shared.
    circuit_breaker_persistent: bool = True

    #: Max accepted HTTP request body (bytes) for hardening (Phase 2A).
    max_request_body_bytes: int = 262144

    # Fixed-window API limiting (Phase 3F). Authenticated requests are checked
    # against both an API-key bucket and a source-IP bucket.
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 120
    rate_limit_ip_requests: int = 300
    rate_limit_window_seconds: float = 60.0

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
    web_user_agent: str = "ERA-Agent/0.4"

    # --- Phase 4A: self-hosted browser automation ----------------------------
    browser_headless: bool = True
    browser_timeout_seconds: float = 30.0
    browser_viewport_width: int = 1280
    browser_viewport_height: int = 800
    browser_user_agent: str = (
        "ERA-Agent/0.8.1 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
    )
    browser_max_contexts: int = 32
    browser_context_idle_seconds: float = 300.0
    browser_command_queue_size: int = 128
    #: Optional explicit Chromium executable path. Empty = use the Playwright-
    #: managed browser (normal case). Some environments provide a system or
    #: bundled Chromium and need Playwright pointed at it.
    browser_executable_path: str = ""
    #: Optional extra Chromium launch args (JSON array in env). Kept empty in
    #: production; used e.g. for a sandbox-proxied TLS/CAC environment.
    browser_extra_args: list[str] = []
    #: Optional mandatory-egress proxy for production browser workers. Keep
    #: credentials outside this URL and configure them at the proxy boundary.
    browser_proxy_server: str = ""

    # --- Phase 4B: reliable browser workflows --------------------------------
    #: Lifetime of a browser.inspect element reference (seconds). After this a
    #: ref fails closed with CONFLICT; the agent must re-inspect.
    browser_element_ref_ttl_seconds: float = 120.0
    #: Default max elements returned by one browser.inspect snapshot.
    browser_max_inspect_elements: int = 200
    #: Hard bound on a single browser.download artifact (bytes).
    browser_max_download_bytes: int = 209715200  # 200 MiB
    #: Hard bound on a single browser.upload source file (bytes).
    browser_max_upload_bytes: int = 104857600   # 100 MiB

    # --- Phase 4C: durable, resumable browser workflows -----------------------
    #: Hard cap on the number of steps in one workflow definition.
    workflow_max_steps: int = 50
    #: Hard wall-clock budget for one workflow run (seconds). Overrun -> FAILED.
    workflow_max_wallclock_seconds: float = 600.0
    #: Max pending confirmations a workflow may hold at once (sequential engine
    #: means 1; kept configurable for future parallel steps).
    workflow_max_pending_confirmations: int = 1
    #: Max total rendered-param characters across a workflow definition.
    workflow_max_param_chars: int = 16384

    # --- Phase 4D: workflow operations & governance --------------------------
    #: Max concurrent runs a single actor may have at once.
    workflow_max_concurrent_per_actor: int = 2
    #: Max concurrent runs of one workflow (any actor) at once.
    workflow_max_concurrent_per_workflow: int = 2
    #: Max runs of one workflow per rolling window.
    workflow_max_runs_per_window: int = 10
    #: Governance rate-limit window (seconds).
    workflow_rate_window_seconds: int = 3600
    #: Max step dispatches in a single run (step budget).
    workflow_max_steps_per_run: int = 120
    #: Cost/quota budget in arbitrary units per run (1 unit per dispatched step).
    workflow_max_cost_units: int = 1000

    # --- Phase 3C: credential vault + provider secrets -----------------------
    #: Master key for the credential vault: 32 bytes as 64 hex chars or 44
    #: base64 chars. Env-only — never commit a real key. Empty = the vault is
    #: DISABLED (fail-closed: nothing stored, nothing resolved).
    vault_master_key: str = ""

    # --- Phase 3C: SMTP email provider (opt-in) ------------------------------
    #: Empty host = provider not built (StubProvider keeps handling email.send).
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    #: Plain env value OR ``vault:<domain>/<name>`` reference.
    email_smtp_user: str = ""
    email_smtp_password: str = ""
    email_smtp_from: str = ""
    email_smtp_starttls: bool = False
    email_smtp_ssl: bool = False
    email_smtp_timeout_seconds: float = 10.0

    # --- Phase 3D: GitHub provider -------------------------------------------
    github_api_base_url: str = "https://api.github.com"
    github_token: str = ""  # env-only or vault:github/token
    github_timeout_seconds: float = 15.0
    github_user_agent: str = "ERA-Agent/0.4.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
    github_max_response_bytes: int = 1_048_576

    # --- Phase 3D: Code execution provider ----------------------------------
    code_exec_timeout_seconds: float = 10.0
    code_exec_max_output_bytes: int = 65536
    code_exec_memory_limit_mb: int = 256
    code_exec_allow_network: bool = False

    # --- Phase 3G: replay safety + background jobs ---------------------------
    #: How long a completed idempotency record is honoured before a replayed
    #: execute (same key) is treated as a fresh request.
    idempotency_ttl_seconds: int = 86400
    #: How long an in-flight (processing) idempotency record may remain before
    #: it is considered abandoned (e.g. after a crash) and can be re-attempted.
    idempotency_processing_ttl_seconds: int = 300
    #: In-process background worker pool size for async execution jobs.
    job_worker_threads: int = 2
    #: How long completed/failed job rows are retained for inspection.
    job_ttl_seconds: int = 86400

    # --- Phase 3H: scheduled jobs + providers (WhatsApp, Image, Booking) ----
    scheduler_enabled: bool = False
    scheduler_interval_seconds: float = 1.0
    #: Phase 4E: heartbeat timeout for scheduler leader election (seconds).
    scheduler_heartbeat_timeout_seconds: float = 30.0
    #: Phase 4E: how often the confirmation expiry sweeper runs (seconds). 0 disables.
    confirmation_sweeper_interval_seconds: float = 60.0

    #: WhatsApp Provider (Meta Cloud API / Twilio)
    whatsapp_api_url: str = "https://graph.facebook.com/v20.0"
    whatsapp_phone_number_id: str = ""
    whatsapp_access_token: str = ""  # env or vault:whatsapp/token
    whatsapp_timeout_seconds: float = 15.0

    #: Image Generation Provider (OpenAI / Stability / Compatible)
    image_gen_api_key: str = ""  # env or vault:image/token
    image_gen_base_url: str = "https://api.openai.com/v1"
    image_gen_model: str = "dall-e-3"
    image_gen_timeout_seconds: float = 30.0

    #: Travel Booking Provider (Partner API)
    booking_partner_api_key: str = ""  # env or vault:booking/api_key
    booking_partner_url: str = ""
    booking_timeout_seconds: float = 15.0

    app_version: str = "0.8.1"

    # Note: a missing/malformed policy is always DENY-all (hard fail-closed).
    # This is intentionally not configurable — weakening it is a footgun.
