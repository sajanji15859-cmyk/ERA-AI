"""ToolProviders and (mock) LLM providers.

Phase 1C ships only ``StubProvider`` (a no-op executor standing in for every
future capability) and ``MockLLMProvider`` (a fixed-response model for testing
the agent loop). Real Web/Email/WhatsApp/Booking/File-Photo/Android providers
arrive in later phases and register themselves with the ToolRegistry.
"""

from era.providers.code_exec import CodeExecProvider
from era.providers.email_smtp import EmailSmtpProvider
from era.providers.github import GitHubProvider
from era.providers.mock_llm import MockLLMProvider
from era.providers.stub import StubProvider

__all__ = [
    "CodeExecProvider",
    "EmailSmtpProvider",
    "GitHubProvider",
    "MockLLMProvider",
    "StubProvider",
]
