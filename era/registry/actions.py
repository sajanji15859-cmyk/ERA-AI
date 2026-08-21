"""The authoritative action catalog: action types, risk tiers, domains, schemas.

This file is the single source of truth for what the agent *may* do and how
risky each action is. Future ToolProviders (Web, Email, WhatsApp, Booking,
File/Photo, Android device) map to the action types declared here — in Phase 1C
only the ``StubProvider`` is wired, so none of these perform real work.

Notable security decisions encoded here:

* ``web.fetch`` is **SENSITIVE**, not ``SAFE``: a future WebProvider must apply
  URL/network restrictions (scheme allowlist, block private/link-local/loopback
  ranges, DNS-rebinding guards) to prevent SSRF / private-network access.
* Device automation lives in its own ``capability_domain`` (``"device"``) so it
  can be policy-scoped, audited and later served by a separate on-device agent.
* Secret-bearing parameters are declared via ``secret_fields`` so the redaction
  layer can mask them before they reach the audit log.
"""

from __future__ import annotations

from enum import StrEnum

from era.core.enums import RiskLevel
from era.core.tool_registry import ActionCatalog, ActionSpec


class ActionType(StrEnum):
    # --- demo / core (exercised end-to-end in 1C via the stub) ---------------
    STUB_NOOP = "stub.noop"

    # --- web -----------------------------------------------------------------
    WEB_SEARCH = "web.search"
    WEB_FETCH = "web.fetch"          # SENSITIVE: SSRF surface, see docstring
    WEB_DOWNLOAD = "web.download"

    # --- email ---------------------------------------------------------------
    EMAIL_READ = "email.read"
    EMAIL_SEARCH = "email.search"
    EMAIL_DRAFT = "email.draft"
    EMAIL_SEND = "email.send"

    # --- whatsapp ------------------------------------------------------------
    WHATSAPP_READ = "whatsapp.read"
    WHATSAPP_SEND = "whatsapp.send"
    WHATSAPP_REACT = "whatsapp.react"

    # --- booking -------------------------------------------------------------
    BOOKING_SEARCH = "booking.search"
    BOOKING_HOLD = "booking.hold"
    BOOKING_CONFIRM = "booking.confirm"
    BOOKING_CANCEL = "booking.cancel"

    # --- file / photo --------------------------------------------------------
    FS_LIST = "fs.list"
    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    FS_MOVE = "fs.move"
    FS_DELETE = "fs.delete"
    PHOTO_VIEW = "photo.view"
    PHOTO_EDIT = "photo.edit"
    PHOTO_UPLOAD = "photo.upload"
    PHOTO_DELETE = "photo.delete"

    # --- android device (separate capability boundary) -----------------------
    DEVICE_SHELL = "device.shell"
    DEVICE_APP_LAUNCH = "device.app_launch"
    DEVICE_UI_CLICK = "device.ui_click"
    DEVICE_SCREENSHOT = "device.screenshot"
    DEVICE_PHOTO_CAPTURE = "device.photo_capture"
    DEVICE_LOCATION = "device.location"
    DEVICE_NOTIFICATION = "device.notification"
    DEVICE_CONTACTS = "device.contacts"
    DEVICE_SMS_READ = "device.sms_read"
    DEVICE_SMS_SEND = "device.sms_send"
    DEVICE_INSTALL_APP = "device.install_app"
    DEVICE_UNINSTALL_APP = "device.uninstall_app"
    DEVICE_SETTINGS_CHANGE = "device.settings_change"
    DEVICE_PAYMENT = "device.payment"

    # --- github (Phase 3D) ---------------------------------------------------
    GITHUB_REPO_GET = "github.repo_get"
    GITHUB_ISSUE_LIST = "github.issue_list"
    GITHUB_ISSUE_GET = "github.issue_get"
    GITHUB_ISSUE_CREATE = "github.issue_create"
    GITHUB_ISSUE_COMMENT = "github.issue_comment"
    GITHUB_PR_LIST = "github.pr_list"
    GITHUB_PR_GET = "github.pr_get"
    GITHUB_PR_CREATE = "github.pr_create"
    GITHUB_FILE_GET = "github.file_get"
    GITHUB_FILE_COMMIT = "github.file_commit"

    # --- code execution (Phase 3D) --------------------------------------------
    CODE_RUN = "code.run"
    CODE_EXEC = "code.exec"

    # --- forbidden -----------------------------------------------------------
    SECRET_EXPORT = "secret.export"
    ACCOUNT_DELETE = "account.delete"


def _spec(action_type: ActionType, risk: RiskLevel, domain: str,
          secret_fields: tuple[str, ...] = ()) -> ActionSpec:
    return ActionSpec(
        action_type=action_type.value,
        risk_level=risk,
        capability_domain=domain,
        secret_fields=frozenset(secret_fields),
    )


_SPECS: list[ActionSpec] = [
    # demo / core
    _spec(ActionType.STUB_NOOP, RiskLevel.SAFE, "core"),

    # web
    _spec(ActionType.WEB_SEARCH, RiskLevel.SAFE, "web", ("api_key",)),
    # SENSITIVE, not SAFE: SSRF / private-network guard required by the provider.
    _spec(ActionType.WEB_FETCH, RiskLevel.SENSITIVE, "web", ("api_key",)),
    _spec(ActionType.WEB_DOWNLOAD, RiskLevel.MUTATING, "web", ("api_key",)),

    # email
    _spec(ActionType.EMAIL_READ, RiskLevel.SENSITIVE, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_SEARCH, RiskLevel.SENSITIVE, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_DRAFT, RiskLevel.MUTATING, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_SEND, RiskLevel.COMMUNICATION, "email", ("token", "refresh_token")),

    # whatsapp
    _spec(ActionType.WHATSAPP_READ, RiskLevel.SENSITIVE, "whatsapp", ("token",)),
    _spec(ActionType.WHATSAPP_SEND, RiskLevel.COMMUNICATION, "whatsapp", ("token",)),
    _spec(ActionType.WHATSAPP_REACT, RiskLevel.COMMUNICATION, "whatsapp", ("token",)),

    # booking
    _spec(ActionType.BOOKING_SEARCH, RiskLevel.SENSITIVE, "booking", ("token", "payment_token")),
    _spec(ActionType.BOOKING_HOLD, RiskLevel.MUTATING, "booking", ("token", "payment_token")),
    _spec(ActionType.BOOKING_CONFIRM, RiskLevel.BOOKING, "booking", ("token", "payment_token")),
    _spec(ActionType.BOOKING_CANCEL, RiskLevel.BOOKING, "booking", ("token", "payment_token")),

    # file / photo
    _spec(ActionType.FS_LIST, RiskLevel.SAFE, "file"),
    _spec(ActionType.FS_READ, RiskLevel.SENSITIVE, "file", ("token",)),
    _spec(ActionType.FS_WRITE, RiskLevel.MUTATING, "file", ("token",)),
    _spec(ActionType.FS_MOVE, RiskLevel.MUTATING, "file", ("token",)),
    _spec(ActionType.FS_DELETE, RiskLevel.DESTRUCTIVE, "file", ("token",)),
    _spec(ActionType.PHOTO_VIEW, RiskLevel.SENSITIVE, "file", ("token",)),
    _spec(ActionType.PHOTO_EDIT, RiskLevel.MUTATING, "file", ("token",)),
    _spec(ActionType.PHOTO_UPLOAD, RiskLevel.MUTATING, "file", ("token",)),
    _spec(ActionType.PHOTO_DELETE, RiskLevel.DESTRUCTIVE, "file", ("token",)),

    # android device (separate capability boundary: domain == "device")
    _spec(ActionType.DEVICE_SHELL, RiskLevel.DESTRUCTIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_APP_LAUNCH, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_UI_CLICK, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_SCREENSHOT, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_PHOTO_CAPTURE, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_LOCATION, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_NOTIFICATION, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_CONTACTS, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_SMS_READ, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_SMS_SEND, RiskLevel.COMMUNICATION, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_INSTALL_APP, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_UNINSTALL_APP, RiskLevel.DESTRUCTIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_SETTINGS_CHANGE, RiskLevel.DESTRUCTIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_PAYMENT, RiskLevel.FINANCIAL, "device", ("pairing_token",)),

    # github (Phase 3D)
    _spec(ActionType.GITHUB_REPO_GET, RiskLevel.SAFE, "github", ("token",)),
    _spec(ActionType.GITHUB_ISSUE_LIST, RiskLevel.SAFE, "github", ("token",)),
    _spec(ActionType.GITHUB_ISSUE_GET, RiskLevel.SAFE, "github", ("token",)),
    _spec(ActionType.GITHUB_ISSUE_CREATE, RiskLevel.MUTATING, "github", ("token",)),
    _spec(ActionType.GITHUB_ISSUE_COMMENT, RiskLevel.MUTATING, "github", ("token",)),
    _spec(ActionType.GITHUB_PR_LIST, RiskLevel.SAFE, "github", ("token",)),
    _spec(ActionType.GITHUB_PR_GET, RiskLevel.SAFE, "github", ("token",)),
    _spec(ActionType.GITHUB_PR_CREATE, RiskLevel.MUTATING, "github", ("token",)),
    _spec(ActionType.GITHUB_FILE_GET, RiskLevel.SENSITIVE, "github", ("token",)),
    _spec(ActionType.GITHUB_FILE_COMMIT, RiskLevel.MUTATING, "github", ("token",)),

    # code execution (Phase 3D)
    _spec(ActionType.CODE_RUN, RiskLevel.MUTATING, "code"),
    _spec(ActionType.CODE_EXEC, RiskLevel.MUTATING, "code"),

    # forbidden
    _spec(ActionType.SECRET_EXPORT, RiskLevel.FORBIDDEN, "core"),
    _spec(ActionType.ACCOUNT_DELETE, RiskLevel.FORBIDDEN, "core"),
]

ACTION_CATALOG = ActionCatalog(_SPECS)
