"""ERA tool and model providers.

The package exports production providers that are useful across runtime wiring
and tests. ``StubProvider`` and ``MockLLMProvider`` remain deterministic test
implementations; browser automation additionally exposes both its self-hosted
Playwright transport and a socket-free simulator.
"""

from era.providers.browser import (
    BrowserProvider,
    PlaywrightBrowserTransport,
    SimulatedBrowserTransport,
)
from era.providers.code_exec import CodeExecProvider
from era.providers.email_smtp import EmailSmtpProvider
from era.providers.github import GitHubProvider
from era.providers.mock_llm import MockLLMProvider
from era.providers.stub import StubProvider

__all__ = [
    "BrowserProvider",
    "CodeExecProvider",
    "EmailSmtpProvider",
    "GitHubProvider",
    "MockLLMProvider",
    "PlaywrightBrowserTransport",
    "SimulatedBrowserTransport",
    "StubProvider",
]
