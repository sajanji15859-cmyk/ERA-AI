"""SMTP email provider + vault secret resolution tests (Phase 3C).

Uses a minimal in-process SMTP sink (loopback, ephemeral port) — fully
offline. Proves the secret boundary end to end: credentials live in the
vault, the provider resolves them at send time, and the plaintext appears
in NO audit row, response or error message.
"""

from __future__ import annotations

import socketserver
import threading

import pytest

from era.config import Settings
from era.container import build_container
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.db import transaction
from era.providers import EmailSmtpProvider, StubProvider
from era.security.vault import VaultError
from era.services.vault_service import VaultRefResolver
from tests.conftest import action


# -- minimal SMTP sink ----------------------------------------------------------
class _SMTPSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *, fail_auth: bool = False):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.fail_auth = fail_auth
        self.messages: list[dict] = []  # {"env":, "data": [lines]}
        self.auth_lines: list[str] = []
        self.connections = 0
        self._lock = threading.Lock()

    @property
    def port(self) -> int:
        return self.server_address[1]


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):  # tiny protocol, kept linear for clarity
        srv: _SMTPSink = self.server
        with srv._lock:
            srv.connections += 1
        self.wfile.write(b"220 era-test ESMTP\r\n")
        in_data = False
        buf: list[str] = []
        env: dict = {}
        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").strip()
            if in_data:
                if line == ".":
                    in_data = False
                    with srv._lock:
                        srv.messages.append({"env": env, "data": list(buf)})
                    env, buf = {}, []
                    self.wfile.write(b"250 OK queued\r\n")
                else:
                    buf.append(line)
                continue
            cmd = line.upper()
            if cmd.startswith("EHLO"):
                self.wfile.write(b"250-era-test\r\n250 AUTH PLAIN LOGIN\r\n")
            elif cmd.startswith("AUTH"):
                with srv._lock:
                    srv.auth_lines.append(line)
                if srv.fail_auth:
                    self.wfile.write(b"535 5.7.8 Authentication failed\r\n")
                else:
                    self.wfile.write(b"235 2.7.0 Authentication successful\r\n")
            elif cmd.startswith("MAIL FROM"):
                env["from"] = line
                self.wfile.write(b"250 OK\r\n")
            elif cmd.startswith("RCPT TO"):
                env["to"] = line
                self.wfile.write(b"250 OK\r\n")
            elif cmd.startswith("DATA"):
                in_data = True
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif cmd.startswith("QUIT"):
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")
            self.wfile.flush()


@pytest.fixture
def sink():
    srv = _SMTPSink()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _make_provider(sink, *, username="vault:email/smtp_user",
                   password="vault:email/smtp_password", resolver=None):
    return EmailSmtpProvider(
        host="127.0.0.1", port=sink.port, username=username, password=password,
        from_address="era@example.com", timeout_seconds=5.0,
        secret_resolver=resolver,
    )


def _make_container(tmp_path, provider, master_key="cd" * 32):
    kwargs: dict = {"database_url": f"sqlite:///{tmp_path}/email_test.db"}
    if master_key is not None:
        kwargs["vault_master_key"] = master_key
    return build_container(
        Settings(**kwargs),
        providers=[provider, StubProvider(exclude=provider.action_types)],
    )


# -- end to end: vault secret -> SMTP -------------------------------------------
def test_email_send_resolves_vault_secrets_end_to_end(tmp_path, sink):
    resolver = VaultRefResolver()
    provider = _make_provider(sink, resolver=resolver)
    c = _make_container(tmp_path, provider)
    resolver.attach(c.vault_service)  # container built -> vault attached

    c.vault_service.store_or_rotate_secret(domain="email", name="smtp_user",
                                           value="era-bot", actor_id="admin")
    password = "P@ssw0rd-Vault-Test"
    c.vault_service.store_or_rotate_secret(domain="email", name="smtp_password",
                                           value=password, actor_id="admin")

    a = action("email.send", to="site@example.com", subject="Hi",
               body="Hello from the vault")
    ctx = ExecutionContext(actor_id="actor-1")
    # COMMUNICATION -> CONFIRM under the default policy:
    pending = c.execution_service.request(a, ctx)
    assert pending.status == "confirmation_required", pending.model_dump()
    done = c.execution_service.approve(pending.confirmation_id, a, ctx)
    assert done.status == "executed", done.model_dump()

    # The sink really got the mail:
    assert len(sink.messages) == 1
    msg = sink.messages[0]
    assert "site@example.com" in msg["env"]["to"]
    assert "Hello from the vault" in "\r\n".join(msg["data"])

    # ...and authenticated once, with the vault-resolved credentials:
    assert len(sink.auth_lines) == 1

    # Secret boundary: the password appears in NO response or audit row:
    assert password not in done.model_dump_json()
    with transaction(c.session_factory) as session:
        entries = c.audit_service.list(session, limit=500)
    for e in entries:
        assert password not in str(e.action_params)
        assert password not in str(e.result)
    # the vault ops themselves were audited (store + resolve):
    ops = {e.action_type for e in entries}
    assert "vault.store" in ops and "vault.resolve" in ops
    assert "era-bot" not in str([e.action_params for e in entries])


# -- auth failure -> AUTH (never retried) ----------------------------------------
def test_email_auth_failure_maps_to_auth_and_never_retries(tmp_path):
    bad = _SMTPSink(fail_auth=True)
    threading.Thread(target=bad.serve_forever, daemon=True).start()
    try:
        provider = _make_provider(bad, resolver=VaultRefResolver())
        c = _make_container(tmp_path, provider)
        provider._resolver.attach(c.vault_service)
        c.vault_service.store_or_rotate_secret(domain="email", name="smtp_user",
                                               value="u", actor_id="a")
        c.vault_service.store_or_rotate_secret(domain="email", name="smtp_password",
                                               value="wrong", actor_id="a")
        a = action("email.send", to="x@example.com", body="hi")
        pending = c.execution_service.request(a, ExecutionContext(actor_id="a"))
        assert pending.status == "confirmation_required"
        resp = c.execution_service.approve(pending.confirmation_id, a,
                                           ExecutionContext(actor_id="a"))
        assert resp.status == "failed"

        # The audit log carries the stable code, and AUTH was NOT retried by
        # the ERA dispatch layer (exactly ONE connection = one execute; the
        # two AUTH lines are smtplib's own PLAIN->LOGIN fallback inside it):
        with transaction(c.session_factory) as session:
            entries = c.audit_service.list(session, action_type="email.send")
        assert [e.outcome for e in entries if e.outcome == "FAILED"] == ["FAILED"]
        assert entries[-1].error_code == ProviderErrorCode.AUTH
        assert bad.connections == 1
    finally:
        bad.shutdown()
        bad.server_close()


# -- unreachable server -> UNAVAILABLE ---------------------------------------------
def test_email_unreachable_maps_to_unavailable(tmp_path):
    provider = _make_provider(_SMTPSink(), username="plain-user",
                              password="plain-pass", resolver=None)
    # point at a closed port:
    provider._host, provider._port = "127.0.0.1", 1
    with pytest.raises(ToolError) as ei:
        provider.execute(action("email.send", to="x@example.com", body="hi"),
                         ExecutionContext(actor_id="a"))
    assert ei.value.code == ProviderErrorCode.UNAVAILABLE


# -- unresolved / disabled vault -> AUTH, fail closed ------------------------------
def test_email_unresolvable_ref_fails_closed(tmp_path, sink):
    provider = _make_provider(sink, resolver=VaultRefResolver())
    c = _make_container(tmp_path, provider)
    provider._resolver.attach(c.vault_service)
    c.vault_service.store_or_rotate_secret(domain="email", name="smtp_user",
                                           value="era-bot", actor_id="a")
    # no smtp_password stored:
    with pytest.raises(ToolError) as ei:
        provider.execute(action("email.send", to="x@example.com", body="hi"),
                         ExecutionContext(actor_id="a"))
    assert ei.value.code == ProviderErrorCode.AUTH
    assert "vault" in str(ei.value).lower()


def test_email_ref_without_vault_wired_fails_closed(tmp_path, sink):
    provider = _make_provider(sink, resolver=None)  # no resolver at all
    with pytest.raises(ToolError) as ei:
        provider.execute(action("email.send", to="x@example.com", body="hi"),
                         ExecutionContext(actor_id="a"))
    assert ei.value.code == ProviderErrorCode.AUTH


def test_email_disabled_vault_fails_closed(tmp_path, sink):
    provider = _make_provider(sink, resolver=VaultRefResolver())
    c = _make_container(tmp_path, provider, master_key=None)  # vault disabled
    provider._resolver.attach(c.vault_service)
    with pytest.raises(ToolError) as ei:
        provider.execute(action("email.send", to="x@example.com", body="hi"),
                         ExecutionContext(actor_id="a"))
    assert ei.value.code == ProviderErrorCode.AUTH


# -- validation --------------------------------------------------------------------
def test_email_validate_rejects_bad_params(tmp_path):
    provider = _make_provider(_SMTPSink())
    with pytest.raises(ToolError) as ei:
        provider.validate(action("email.send", body="hi"))
    assert ei.value.code == ProviderErrorCode.VALIDATION
    with pytest.raises(ToolError):
        provider.validate(action("email.send", to="x@example.com"))  # no body
    provider.validate(action("email.send", to="x@example.com", body="hi"))  # ok


# -- plain credentials still work (no vault needed) ----------------------------------
def test_email_plain_credentials(tmp_path, sink):
    provider = _make_provider(sink, username="plain-user", password="plain-pass",
                              resolver=None)
    resp = provider.execute(action("email.send", to="x@example.com",
                                   subject="s", body="b"),
                            ExecutionContext(actor_id="a"))
    assert resp.success
    assert len(sink.messages) == 1
    assert sink.auth_lines  # authenticated as plain-user


def test_unattached_resolver_fails_closed(tmp_path, sink):
    provider = _make_provider(sink, resolver=VaultRefResolver())
    # never attached to a vault service:
    with pytest.raises(ToolError) as ei:
        provider.execute(action("email.send", to="x@example.com", body="hi"),
                         ExecutionContext(actor_id="a"))
    assert ei.value.code == ProviderErrorCode.AUTH
    with pytest.raises(VaultError) as ei:
        VaultRefResolver().resolve_ref("vault:a/b")
    assert ei.value.code == "disabled"
