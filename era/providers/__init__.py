"""ERA tool and model providers.

Exports include production integrations and deterministic offline test doubles.
Provider registration remains runtime-controlled; importing a class never opens
network/device connections or resolves credentials.
"""

from era.providers.android_device import AndroidDeviceProvider, SubprocessAdbTransport
from era.providers.browser import (
    BrowserProvider,
    PlaywrightBrowserTransport,
    SimulatedBrowserTransport,
)
from era.providers.code_exec import CodeExecProvider
from era.providers.email_imap import EmailImapProvider
from era.providers.email_smtp import EmailSmtpProvider
from era.providers.github import GitHubProvider
from era.providers.mock_llm import MockLLMProvider
from era.providers.stub import StubProvider

__all__ = [
    "AndroidDeviceProvider",
    "BrowserProvider",
    "CodeExecProvider",
    "EmailImapProvider",
    "EmailSmtpProvider",
    "GitHubProvider",
    "MockLLMProvider",
    "PlaywrightBrowserTransport",
    "SimulatedBrowserTransport",
    "StubProvider",
    "SubprocessAdbTransport",
]
