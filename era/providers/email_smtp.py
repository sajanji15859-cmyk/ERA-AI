"""Real SMTP email provider (Phase 3C).

The first production provider that resolves its credentials from the
**credential vault**:

* ``username`` / ``password`` are configured either as plain env values
  (like the LLM key — env-only) or as vault references
  (``vault:email/smtp_user`` / ``vault:email/smtp_password``).
* Vault references are resolved at send time through the
  :class:`~era.services.vault_service.VaultService` (or a
  :class:`~era.services.vault_service.VaultRefResolver` adapter). The
  resolved plaintext exists only for the duration of the SMTP session.
* The credential never appears in action params, results, error messages or
  the audit log — the execution gate redacts params and this provider simply
  never puts secrets in them.

Opt-in: the agent runtime builds this provider only when
``ERA_EMAIL_SMTP_HOST`` is set; otherwise ``StubProvider`` keeps handling
``email.send`` exactly as before. Transport: stdlib ``smtplib`` (plain
SMTP, optional STARTTLS or implicit TLS — whatever the operator's mailbox
supports). Error mapping onto the stable taxonomy: auth failure -> ``AUTH``
(never retried), timeout -> ``TIMEOUT``, connection/server problems ->
``UNAVAILABLE`` (retried boundedly), bad params -> ``VALIDATION``.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.vault import VaultError, is_vault_ref

_MAX_TO_LEN = 320
_MAX_SUBJECT_LEN = 998
_MAX_BODY_LEN = 1_000_000


class EmailSmtpProvider:
    """Sends ``email.send`` over SMTP with vault-resolvable credentials."""

    id = "email-smtp"
    action_types = frozenset({ActionType.EMAIL_SEND})

    def __init__(self, *, host: str, port: int, username: str = "",
                 password: str = "", from_address: str = "",
                 starttls: bool = False, use_ssl: bool = False,
                 timeout_seconds: float = 10.0,
                 secret_resolver=None):
        if not host:
            raise ValueError("EmailSmtpProvider requires an SMTP host")
        self._host = str(host)
        self._port = int(port)
        #: Plain env value OR ``vault:<domain>/<name>`` reference.
        self._username_ref = str(username or "")
        self._password_ref = str(password or "")
        self._from_address = str(from_address or "")
        self._starttls = bool(starttls)
        self._use_ssl = bool(use_ssl)
        self._timeout = float(timeout_seconds)
        self._resolver = secret_resolver  # object with resolve_ref(ref) -> str

    # -- SPI -------------------------------------------------------------------
    def validate(self, action) -> None:
        to = action.params.get("to")
        if not isinstance(to, str) or not to.strip():
            raise ToolError("email.send requires a non-empty 'to' address",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)
        if len(to) > _MAX_TO_LEN:
            raise ToolError("'to' address too long", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        body = action.params.get("body")
        if not isinstance(body, str) or not body.strip():
            raise ToolError("email.send requires a non-empty 'body'",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)
        if len(body) > _MAX_BODY_LEN:
            raise ToolError("'body' too long", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        subject = action.params.get("subject")
        if subject is not None and (not isinstance(subject, str)
                                    or len(subject) > _MAX_SUBJECT_LEN):
            raise ToolError("'subject' must be a string (<= 998 chars)",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)

    def execute(self, action, ctx) -> ActionResult:
        to = str(action.params["to"]).strip()
        subject = str(action.params.get("subject") or "")
        body = str(action.params["body"])

        username = self._resolve(self._username_ref, "SMTP username")
        password = self._resolve(self._password_ref, "SMTP password")
        if not password:
            raise ToolError("SMTP password not configured or not resolvable",
                            provider_id=self.id, code=ProviderErrorCode.AUTH)
        from_addr = self._from_address or username
        if not from_addr:
            raise ToolError("no sender address: set ERA_EMAIL_SMTP_FROM "
                            "or an SMTP username",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)

        message = EmailMessage()
        message["From"] = from_addr
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        raw = message.as_bytes()

        try:
            if self._use_ssl:
                server = smtplib.SMTP_SSL(self._host, self._port,
                                          timeout=self._timeout)
            else:
                server = smtplib.SMTP(self._host, self._port,
                                      timeout=self._timeout)
        except (OSError, TimeoutError, smtplib.SMTPException) as exc:
            raise ToolError(f"cannot connect to SMTP server {self._host}:{self._port}",
                            provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

        try:
            with server:
                if self._starttls and not self._use_ssl:
                    try:
                        server.starttls()
                    except (OSError, TimeoutError, smtplib.SMTPException) as exc:
                        raise ToolError("SMTP STARTTLS negotiation failed",
                                        provider_id=self.id,
                                        code=ProviderErrorCode.UNAVAILABLE) from exc
                if username:
                    try:
                        server.login(username, password)
                    except smtplib.SMTPAuthenticationError as exc:
                        raise ToolError("SMTP authentication failed",
                                        provider_id=self.id,
                                        code=ProviderErrorCode.AUTH) from exc
                try:
                    server.sendmail(from_addr, [to], raw)
                except smtplib.SMTPServerDisconnected as exc:
                    raise ToolError("SMTP server disconnected during send",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.UNAVAILABLE) from exc
                except (OSError, TimeoutError, smtplib.SMTPException) as exc:
                    raise ToolError("SMTP send failed", provider_id=self.id,
                                    code=ProviderErrorCode.UNAVAILABLE) from exc
        except TimeoutError as exc:
            raise ToolError("SMTP operation timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        return ActionResult(success=True, summary=f"email sent to {to}",
                            data={"to": to, "bytes": len(raw)})

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.4.0",
            display_name=f"SMTP email ({self._host}:{self._port})",
            is_stub=False,
            capabilities=("email.send", "vault-secrets"),
        )

    # -- internals -------------------------------------------------------------
    def _resolve(self, ref_or_plain: str, what: str) -> str:
        """Resolve a vault reference (or return a plain value) without leaking
        the plaintext into any error message."""
        if not ref_or_plain:
            return ""
        if not is_vault_ref(ref_or_plain):
            return ref_or_plain
        if self._resolver is None:
            raise ToolError(f"{what} is a vault reference but no vault is wired",
                            provider_id=self.id, code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref_or_plain)
        except VaultError as exc:
            raise ToolError(f"{what} could not be resolved from the vault",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc
