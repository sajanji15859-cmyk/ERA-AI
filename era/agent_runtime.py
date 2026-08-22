"""Agent runtime wiring (Phase 3A).

Builds the agent-enabled container: real Workspace, Web and Browser providers
take over their catalogued action types from the StubProvider, an OpenAI-compatible
LLM is wired when a key is configured (otherwise the agent runs in offline
deterministic mode), and the AgentService is attached to the container.

The default (non-agent) container from ``era/container.py`` is unchanged —
this runtime is opt-in via ``ERA_AGENT_ENABLED=true``.
"""

from __future__ import annotations

from pathlib import Path

from era.agents.brain import OfflineBrain
from era.agents.memory import LongTermMemoryService
from era.agents.planner import LLMPlanner, RulePlanner
from era.agents.verifier import Verifier
from era.config import Settings
from era.container import Container, build_container
from era.providers import StubProvider
from era.providers.booking import BookingProvider
from era.providers.browser import BrowserProvider, BrowserTransport
from era.providers.code_exec import CodeExecProvider
from era.providers.email_smtp import EmailSmtpProvider
from era.providers.github import GitHubProvider
from era.providers.image_gen import ImageGenProvider
from era.providers.llm_openai import OpenAICompatLLMProvider
from era.providers.web import WebProvider
from era.providers.whatsapp import WhatsAppProvider
from era.providers.workspace import WorkspaceProvider
from era.security.vault import VaultError, is_vault_ref
from era.services.agent_service import AgentService
from era.services.vault_service import VaultRefResolver


def build_llm_provider(settings: Settings, vault_service=None):
    """Build the real LLM provider, or ``None`` (offline mode).

    No key configured → ``None`` (deterministic offline brain; FREE
    LIMITATION — see AGENT_AUDIT_AND_PLAN.md §E). Unknown provider names also
    resolve to ``None``: never guess a provider configuration.

    Phase 3C: the key may be a vault reference (``vault:llm/<name>``). It is
    resolved exactly once, at build time, and fails closed — an unresolvable
    reference raises instead of silently degrading to offline mode, so a
    misconfigured secret can never masquerade as "no key".
    """
    provider = (settings.agent_llm_provider or "").strip().lower()
    if provider in ("", "none", "off", "offline"):
        return None
    if provider != "openai":
        return None
    api_key = (settings.agent_llm_api_key or "").strip()
    if not api_key:
        return None
    if is_vault_ref(api_key):
        if vault_service is None or not vault_service.enabled:
            raise VaultError(
                "LLM API key is a vault reference but the credential vault is "
                "disabled (set ERA_VAULT_MASTER_KEY)", code="disabled")
        try:
            api_key = vault_service.resolve_ref(api_key, actor_id="vault-system")
        except VaultError as exc:
            raise VaultError(
                f"LLM API key reference could not be resolved: {exc}",
                code=exc.code) from exc
        if not api_key:
            raise VaultError("vault reference resolved to an empty LLM API key",
                             code="validation")
    return OpenAICompatLLMProvider(
        base_url=settings.agent_llm_base_url,
        api_key=api_key,
        model=settings.agent_llm_model,
        timeout_seconds=float(settings.web_timeout_seconds),
    )


def build_browser_provider(settings: Settings, workspace_root: Path,
                           transport: BrowserTransport | None = None,
                           secret_resolver: VaultRefResolver | None = None) -> BrowserProvider:
    """Build the self-hosted Playwright browser provider (Phase 4A).

    The Playwright package/Chromium process is loaded lazily on first browser
    action.  Tests and offline deployments may inject a simulator transport.
    """

    return BrowserProvider(
        workspace_root=workspace_root,
        transport=transport,
        headless=bool(settings.browser_headless),
        timeout_seconds=float(settings.browser_timeout_seconds),
        viewport_width=int(settings.browser_viewport_width),
        viewport_height=int(settings.browser_viewport_height),
        user_agent=settings.browser_user_agent,
        max_contexts=int(settings.browser_max_contexts),
        context_idle_seconds=float(settings.browser_context_idle_seconds),
        command_queue_size=int(settings.browser_command_queue_size),
        proxy_server=settings.browser_proxy_server,
        secret_resolver=secret_resolver,
    )


def build_email_provider(settings: Settings, vault_resolver: VaultRefResolver):
    """Build the SMTP email provider, or ``None`` when not configured.

    Opt-in: only ``ERA_EMAIL_SMTP_HOST`` set. Credentials may be plain env
    values or ``vault:`` references (resolved at send time).
    """
    if not (settings.email_smtp_host or "").strip():
        return None
    return EmailSmtpProvider(
        host=settings.email_smtp_host.strip(),
        port=int(settings.email_smtp_port),
        username=settings.email_smtp_user,
        password=settings.email_smtp_password,
        from_address=settings.email_smtp_from,
        starttls=bool(settings.email_smtp_starttls),
        use_ssl=bool(settings.email_smtp_ssl),
        timeout_seconds=float(settings.email_smtp_timeout_seconds),
        secret_resolver=vault_resolver,
    )


def build_github_provider(settings: Settings, vault_resolver: VaultRefResolver):
    """Build the GitHub provider (Phase 3D).

    Token may be a plain env string or a vault reference (e.g. vault:github/token).
    """
    token = settings.github_token.strip() if settings.github_token else ""
    return GitHubProvider(
        token=token,
        api_base_url=settings.github_api_base_url,
        timeout_seconds=float(settings.github_timeout_seconds),
        user_agent=settings.github_user_agent,
        max_response_bytes=int(settings.github_max_response_bytes),
        secret_resolver=vault_resolver,
    )


def build_code_exec_provider(settings: Settings, workspace_root: Path):
    """Build the Code-Exec sandbox provider (Phase 3D)."""
    return CodeExecProvider(
        workspace_root=workspace_root,
        timeout_seconds=float(settings.code_exec_timeout_seconds),
        max_output_bytes=int(settings.code_exec_max_output_bytes),
        memory_limit_mb=int(settings.code_exec_memory_limit_mb),
        allow_network=bool(settings.code_exec_allow_network),
    )


def build_whatsapp_provider(settings: Settings, vault_resolver: VaultRefResolver):
    """Build the Meta Cloud API WhatsApp provider (Phase 3H)."""
    if not (settings.whatsapp_phone_number_id or settings.whatsapp_access_token):
        return None
    return WhatsAppProvider(
        phone_number_id=settings.whatsapp_phone_number_id,
        access_token=settings.whatsapp_access_token,
        api_url=settings.whatsapp_api_url,
        timeout_seconds=float(settings.whatsapp_timeout_seconds),
        secret_resolver=vault_resolver,
    )


def build_image_gen_provider(settings: Settings, workspace_root: Path, vault_resolver: VaultRefResolver):
    """Build the Image Generation provider (Phase 3H)."""
    if not settings.image_gen_api_key:
        return None
    return ImageGenProvider(
        api_key=settings.image_gen_api_key,
        base_url=settings.image_gen_base_url,
        model=settings.image_gen_model,
        workspace_root=workspace_root,
        timeout_seconds=float(settings.image_gen_timeout_seconds),
        secret_resolver=vault_resolver,
    )


def build_booking_provider(settings: Settings, vault_resolver: VaultRefResolver):
    """Build the Travel Booking provider (Phase 3H)."""
    if not (settings.booking_partner_api_key or settings.booking_partner_url):
        return None
    return BookingProvider(
        partner_api_key=settings.booking_partner_api_key,
        partner_url=settings.booking_partner_url,
        timeout_seconds=float(settings.booking_timeout_seconds),
        secret_resolver=vault_resolver,
    )


def build_agent_container(settings: Settings | None = None) -> Container:
    """Build a container wired for the ERA agent (real providers + AgentService)."""
    settings = settings or Settings()
    workspace_root = Path(settings.agent_workspace_root)

    workspace = WorkspaceProvider(root=workspace_root,
                                  max_file_bytes=int(settings.workspace_max_file_bytes))
    web = WebProvider(max_fetch_bytes=int(settings.web_max_fetch_bytes),
                      timeout_seconds=float(settings.web_timeout_seconds),
                      user_agent=settings.web_user_agent,
                      workspace_root=workspace_root)

    # Phase 3C, 3D, 3H & 4A: provider secrets and real providers.
    vault_resolver = VaultRefResolver()
    browser = build_browser_provider(
        settings, workspace_root, secret_resolver=vault_resolver,
    )
    email = build_email_provider(settings, vault_resolver)
    github = build_github_provider(settings, vault_resolver)
    code_exec = build_code_exec_provider(settings, workspace_root)
    whatsapp = build_whatsapp_provider(settings, vault_resolver)
    image_gen = build_image_gen_provider(settings, workspace_root, vault_resolver)
    booking = build_booking_provider(settings, vault_resolver)

    providers = [workspace, web, browser]
    claimed = workspace.action_types | web.action_types | browser.action_types
    if email is not None:
        providers.append(email)
        claimed |= email.action_types
    if github is not None:
        providers.append(github)
        claimed |= github.action_types
    if code_exec is not None:
        providers.append(code_exec)
        claimed |= code_exec.action_types
    if whatsapp is not None:
        providers.append(whatsapp)
        claimed |= whatsapp.action_types
    if image_gen is not None:
        providers.append(image_gen)
        claimed |= image_gen.action_types
    if booking is not None:
        providers.append(booking)
        claimed |= booking.action_types
    providers.append(StubProvider(exclude=claimed))

    container = build_container(settings, providers=providers)
    vault_resolver.attach(container.vault_service)

    llm = build_llm_provider(settings, container.vault_service)
    container.llm_provider = llm

    verifier = Verifier(workspace_root=workspace_root.resolve())
    long_term_memory = LongTermMemoryService(
        session_factory=container.session_factory,
        memory_repo=container.repositories.memory,
    )

    catalog_actions = sorted(s.action_type for s in container.catalog)

    def _domain_guard_for(role: str):
        from era.core.enums import RiskLevel
        from era.security.rbac import role_domain_allowed

        def guard(action_type: str) -> bool:
            spec = container.catalog.get(action_type)
            if spec is None or spec.risk_level is RiskLevel.FORBIDDEN:
                return False
            return role_domain_allowed(role, spec.capability_domain)
        return guard

    def make_planner(budget, role: str = "user"):
        if llm is not None:
            return LLMPlanner(llm, budget, fallback=RulePlanner(),
                              catalog_actions=catalog_actions)
        return RulePlanner()

    def make_brain(budget, role: str = "user"):
        if llm is not None:
            # Phase 3B: native function-calling tool selection with the RBAC
            # domain guard — the model only ever sees tools this role may use.
            from era.agents.tool_brain import ToolCallBrain
            return ToolCallBrain(
                llm, budget,
                catalog=container.catalog,
                registry=container.registry,
                allowed=_domain_guard_for(role),
                max_tokens=int(settings.agent_llm_max_tokens),
            )
        return OfflineBrain()

    container.agent_service = AgentService(
        session_factory=container.session_factory,
        execution_service=container.execution_service,
        confirmation_service=container.confirmation_service,
        audit_service=container.audit_service,
        agent_run_repo=container.repositories.agent_run,
        settings=settings,
        make_planner=make_planner,
        make_brain=make_brain,
        verifier=verifier,
        long_term_memory=long_term_memory,
    )
    return container
