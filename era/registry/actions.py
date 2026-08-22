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
from typing import Any

from era.core.enums import RiskLevel
from era.core.tool_registry import ActionCatalog, ActionSpec


class ActionType(StrEnum):
    # --- demo / core (exercised end-to-end in 1C via the stub) ---------------
    STUB_NOOP = "stub.noop"

    # --- web -----------------------------------------------------------------
    WEB_SEARCH = "web.search"
    WEB_FETCH = "web.fetch"          # SENSITIVE: SSRF surface, see docstring
    WEB_DOWNLOAD = "web.download"

    # --- browser automation (Phase 4A) ---------------------------------------
    BROWSER_NAVIGATE = "browser.navigate"
    BROWSER_SCREENSHOT = "browser.screenshot"
    BROWSER_EXTRACT_DOM = "browser.extract_dom"
    BROWSER_CLICK = "browser.click"
    BROWSER_FILL = "browser.fill"
    BROWSER_SUBMIT = "browser.submit"

    # --- reliable browser workflows (Phase 4B) --------------------------------
    #: Bounded rendered-accessibility snapshot with context-bound element refs.
    BROWSER_INSPECT = "browser.inspect"
    #: List the run's tabs/popups with opaque, provider-issued tab identities.
    BROWSER_TABS = "browser.tabs"
    #: Activate an existing tab by its provider-issued tab id.
    BROWSER_ACTIVATE_TAB = "browser.activate_tab"
    #: Deterministic, workspace-confined download triggered by an element ref.
    BROWSER_DOWNLOAD = "browser.download"
    #: Workspace-confined file upload to a file input (set_input_files).
    BROWSER_UPLOAD = "browser.upload"
    #: Run a declarative, registered workflow (Phase 4C). Dispatch is a strict
    #: schema envelope; every inner step is still evaluated by the permission
    #: engine / confirmation / audit gates independently via ExecutionService.
    BROWSER_WORKFLOW_RUN = "browser.workflow_run"

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

    # --- image generation (Phase 3H) ------------------------------------------
    IMAGE_GENERATE = "image.generate"

    # --- forbidden -----------------------------------------------------------
    SECRET_EXPORT = "secret.export"
    ACCOUNT_DELETE = "account.delete"


#: Authoritative parameter schemas (Phase 3H: consolidated single source of truth).
ACTION_PARAM_SCHEMAS: dict[str, dict[str, Any]] = {
    # stub / core
    ActionType.STUB_NOOP.value: {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
    },
    # web
    ActionType.WEB_SEARCH.value: {
        "type": "object",
        "properties": {
            "q": {"type": "string", "description": "search query"},
            "query": {"type": "string"},
            "filters": {"type": "object"},
            "api_key": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": ["q"],
    },
    ActionType.WEB_FETCH.value: {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "public http(s) URL"},
            "api_key": {"type": "string"},
        },
        "required": ["url"],
    },
    ActionType.WEB_DOWNLOAD.value: {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "path": {"type": "string", "description": "workspace-relative file path"},
            "api_key": {"type": "string"},
        },
        "required": ["url", "path"],
    },
    # browser automation (Phase 4A) — deliberately strict, no undeclared args
    ActionType.BROWSER_NAVIGATE.value: {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "description": "public HTTP(S) URL",
            },
            "wait_until": {
                "type": "string",
                "enum": ["commit", "domcontentloaded", "load", "networkidle"],
            },
        },
        "required": ["url"],
        "additionalProperties": False,
    },
    ActionType.BROWSER_SCREENSHOT.value: {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "description": "workspace-relative .png/.jpg output path",
            },
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "full_page": {"type": "boolean"},
        },
        "required": ["path"],
        "additionalProperties": False,
    },
    ActionType.BROWSER_EXTRACT_DOM.value: {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "max_chars": {"type": "integer", "minimum": 1, "maximum": 100000},
            "save_html_path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "description": "optional workspace-relative HTML dump path",
            },
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.BROWSER_CLICK.value: {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "text": {"type": "string", "minLength": 1, "maxLength": 1000},
            "exact": {"type": "boolean"},
            # Phase 4B: provider-issued element reference from browser.inspect.
            # Prefer element_ref over fragile selectors/text; invented refs fail
            # closed at resolution time.
            "element_ref": {"type": "string", "minLength": 24, "maxLength": 128},
            "expect": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["navigation", "tab_opened", "element_detached"],
                    },
                    "url_contains": {"type": "string", "minLength": 1, "maxLength": 500},
                },
                "required": ["kind"],
                "additionalProperties": False,
            },
        },
        "required": [],
        "oneOf": [
            {"required": ["selector"], "not": {"required": ["text", "element_ref"]}},
            {"required": ["text"], "not": {"required": ["selector", "element_ref"]}},
            {"required": ["element_ref"], "not": {"required": ["selector", "text"]}},
        ],
        "additionalProperties": False,
    },
    ActionType.BROWSER_FILL.value: {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "element_ref": {"type": "string", "minLength": 24, "maxLength": 128},
            "text": {"type": "string", "maxLength": 2000},
            "value_ref": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "description": "vault:browser/<name> reference for secret input",
            },
        },
        "required": [],
        # Exactly one target (selector XOR element_ref) AND exactly one value
        # (text XOR value_ref). Two independent constraints -> allOf/oneOf.
        "allOf": [
            {
                "oneOf": [
                    {"required": ["selector"], "not": {"required": ["element_ref"]}},
                    {"required": ["element_ref"], "not": {"required": ["selector"]}},
                ],
            },
            {
                "oneOf": [
                    {"required": ["text"], "not": {"required": ["value_ref"]}},
                    {"required": ["value_ref"], "not": {"required": ["text"]}},
                ],
            },
        ],
        "additionalProperties": False,
    },
    ActionType.BROWSER_SUBMIT.value: {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "element_ref": {"type": "string", "minLength": 24, "maxLength": 128},
            "expect": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["navigation", "tab_opened", "element_detached"],
                    },
                    "url_contains": {"type": "string", "minLength": 1, "maxLength": 500},
                },
                "required": ["kind"],
                "additionalProperties": False,
            },
        },
        "required": [],
        "oneOf": [
            {"required": ["selector"], "not": {"required": ["element_ref"]}},
            {"required": ["element_ref"], "not": {"required": ["selector"]}},
            {
                "required": [],
                "not": {"anyOf": [
                    {"required": ["selector"]},
                    {"required": ["element_ref"]},
                ]},
            },
        ],
        "additionalProperties": False,
    },
    ActionType.BROWSER_INSPECT.value: {
        "type": "object",
        "properties": {
            "max_elements": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.BROWSER_TABS.value: {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
    ActionType.BROWSER_ACTIVATE_TAB.value: {
        "type": "object",
        "properties": {
            "tab_id": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "required": ["tab_id"],
        "additionalProperties": False,
    },
    ActionType.BROWSER_DOWNLOAD.value: {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "description": "workspace-relative destination file path",
            },
            "element_ref": {"type": "string", "minLength": 24, "maxLength": 128},
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
            "text": {"type": "string", "minLength": 1, "maxLength": 1000},
            "exact": {"type": "boolean"},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1073741824},
        },
        "required": ["path"],
        "oneOf": [
            {"required": ["element_ref"], "not": {"required": ["selector", "text"]}},
            {"required": ["selector"], "not": {"required": ["element_ref", "text"]}},
            {"required": ["text"], "not": {"required": ["element_ref", "selector"]}},
        ],
        "additionalProperties": False,
    },
    ActionType.BROWSER_UPLOAD.value: {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "description": "workspace-relative source file path (must exist)",
            },
            "element_ref": {"type": "string", "minLength": 24, "maxLength": 128},
            "selector": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
        "required": ["path"],
        "oneOf": [
            {"required": ["element_ref"], "not": {"required": ["selector"]}},
            {"required": ["selector"], "not": {"required": ["element_ref"]}},
        ],
        "additionalProperties": False,
    },
    # Phase 4C: run a declarative, registered workflow. The definition is a
    # bounded strict-schema envelope; params carry opaque run inputs only.
    ActionType.BROWSER_WORKFLOW_RUN.value: {
        "type": "object",
        "properties": {
            "workflow": {"type": "string", "minLength": 1, "maxLength": 64},
            "params": {"type": "object"},
            "run_token": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "required": ["workflow"],
        "additionalProperties": False,
    },
    # email
    ActionType.EMAIL_READ.value: {
        "type": "object",
        "properties": {
            "message_id": {"type": "string", "maxLength": 20},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "mailbox": {"type": "string", "maxLength": 128},
            "token": {"type": "string"},
            "refresh_token": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.EMAIL_SEARCH.value: {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 500},
            "q": {"type": "string", "minLength": 1, "maxLength": 500},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "mailbox": {"type": "string", "maxLength": 128},
            "token": {"type": "string"},
            "refresh_token": {"type": "string"},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
    ActionType.EMAIL_DRAFT.value: {
        "type": "object",
        "properties": {
            "to": {"type": ["string", "array"], "maxItems": 10},
            "subject": {"type": "string"},
            "body": {"type": "string"},
            "token": {"type": "string"},
            "refresh_token": {"type": "string"},
        },
        "required": ["to", "body"],
    },
    ActionType.EMAIL_SEND.value: {
        "type": "object",
        "properties": {
            "to": {"type": ["string", "array"], "maxItems": 10},
            "subject": {"type": "string", "maxLength": 998},
            "body": {"type": "string", "maxLength": 102400},
            "cc": {"type": ["string", "array"], "maxItems": 10},
            "bcc": {"type": ["string", "array"], "maxItems": 10},
            "attachments": {"type": "array", "maxItems": 5},
            "token": {"type": "string"},
            "refresh_token": {"type": "string"},
        },
        # The real SMTP provider requires body; keeping the catalog envelope
        # permissive preserves graceful StubProvider fallback for offline use.
        "required": ["to"],
        "additionalProperties": False,
    },
    # whatsapp
    ActionType.WHATSAPP_READ.value: {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 24},
            "sender": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.WHATSAPP_SEND.value: {
        "type": "object",
        "properties": {
            "to": {"type": ["string", "array"], "maxItems": 10,
                   "description": "recipient phone number(s), E.164"},
            "message": {"type": "string", "maxLength": 1000, "description": "text body"},
            "text": {"type": "string", "maxLength": 1000},
            "template": {"type": "string", "maxLength": 512, "description": "approved template name"},
            "template_params": {"type": ["object", "array"]},
            "language_code": {"type": "string", "maxLength": 32},
            "media": {"type": "array", "maxItems": 5},
            "token": {"type": "string"},
        },
        "required": ["to"],
        "additionalProperties": False,
    },
    ActionType.WHATSAPP_REACT.value: {
        "type": "object",
        "properties": {
            "message_id": {"type": "string", "maxLength": 512},
            "emoji": {"type": "string", "maxLength": 32},
            "to": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["message_id", "emoji", "to"],
        "additionalProperties": False,
    },
    # booking
    ActionType.BOOKING_SEARCH.value: {
        "type": "object",
        "properties": {
            "origin": {"type": "string"},
            "destination": {"type": "string"},
            "date": {"type": "string"},
            "departure_date": {"type": "string"},
            "mode": {"type": "string"},
            "token": {"type": "string"},
            "payment_token": {"type": "string"},
        },
        "required": ["origin", "destination"],
        "additionalProperties": False,
    },
    ActionType.BOOKING_HOLD.value: {
        "type": "object",
        "properties": {
            "booking_id": {"type": "string"},
            "offer_ref": {"type": "string"},
            "trip_id": {"type": "string"},
            "passenger_name": {"type": "string"},
            "passengers": {"type": "array", "maxItems": 10},
            "guests": {"type": "array", "maxItems": 10},
            "amount_minor": {"type": "integer", "minimum": 1},
            "currency": {"type": "string", "maxLength": 3},
            # Legacy simulator input; real provider requires amount_minor.
            "fare": {"type": "number"},
            "service_number": {"type": "string"},
            "idempotency_key": {"type": "string", "maxLength": 128},
            "token": {"type": "string"},
            "payment_token": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.BOOKING_CONFIRM.value: {
        "type": "object",
        "properties": {
            "booking_id": {"type": "string"},
            "booking_ref": {"type": "string"},
            "draft_id": {"type": "string"},
            "hold_ref": {"type": "string"},
            "payment_ref": {"type": "string"},
            "idempotency_key": {"type": "string", "maxLength": 128},
            "token": {"type": "string"},
            "payment_token": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    },
    ActionType.BOOKING_CANCEL.value: {
        "type": "object",
        "properties": {
            "booking_id": {"type": "string"},
            "booking_ref": {"type": "string"},
            "reason": {"type": "string", "maxLength": 1000},
            "idempotency_key": {"type": "string", "maxLength": 128},
            "token": {"type": "string"},
            "payment_token": {"type": "string"},
        },
        "required": [],
        "additionalProperties": False,
    },
    # fs / photo
    ActionType.FS_LIST.value: {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "workspace directory"}},
        "required": ["path"],
    },
    ActionType.FS_READ.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "workspace file"},
            "token": {"type": "string"},
        },
        "required": ["path"],
    },
    ActionType.FS_WRITE.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string", "description": "full file content"},
            "content_from": {"type": "string"},
            "repair": {"type": "boolean"},
            "token": {"type": "string"},
        },
        "required": ["path", "content"],
    },
    ActionType.FS_MOVE.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "dst": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["path", "dst"],
    },
    ActionType.FS_DELETE.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "file/empty dir"},
            "token": {"type": "string"},
        },
        "required": ["path"],
    },
    ActionType.PHOTO_VIEW.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["path"],
    },
    ActionType.PHOTO_EDIT.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["path", "content"],
    },
    ActionType.PHOTO_UPLOAD.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["path", "content"],
    },
    ActionType.PHOTO_DELETE.value: {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "token": {"type": "string"},
        },
        "required": ["path"],
    },
    # device
    ActionType.DEVICE_SHELL.value: {
        "type": "object",
        "properties": {"command": {"type": "string", "maxLength": 512}, "pairing_token": {"type": "string"}},
        "required": ["command"], "additionalProperties": False,
    },
    ActionType.DEVICE_APP_LAUNCH.value: {
        "type": "object",
        "properties": {"package": {"type": "string", "maxLength": 256}, "pairing_token": {"type": "string"}},
        "required": ["package"], "additionalProperties": False,
    },
    ActionType.DEVICE_UI_CLICK.value: {
        "type": "object",
        "properties": {"x": {"type": "integer", "minimum": 0, "maximum": 4096},
                       "y": {"type": "integer", "minimum": 0, "maximum": 4096},
                       "pairing_token": {"type": "string"}},
        "required": ["x", "y"], "additionalProperties": False,
    },
    ActionType.DEVICE_SCREENSHOT.value: {
        "type": "object", "properties": {"path": {"type": "string"}, "pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_PHOTO_CAPTURE.value: {
        "type": "object", "properties": {"path": {"type": "string"}, "pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_LOCATION.value: {
        "type": "object", "properties": {"pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_NOTIFICATION.value: {
        "type": "object",
        "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50},
                       "pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_CONTACTS.value: {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": 256},
                       "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                       "pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_SMS_READ.value: {
        "type": "object",
        "properties": {"sender": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                       "pairing_token": {"type": "string"}},
        "required": [], "additionalProperties": False,
    },
    ActionType.DEVICE_SMS_SEND.value: {
        "type": "object",
        "properties": {"to": {"type": "string"}, "message": {"type": "string", "maxLength": 1000},
                       "pairing_token": {"type": "string"}},
        "required": ["to", "message"], "additionalProperties": False,
    },
    ActionType.DEVICE_INSTALL_APP.value: {
        "type": "object",
        "properties": {"path": {"type": "string"}, "pairing_token": {"type": "string"}},
        "required": ["path"], "additionalProperties": False,
    },
    ActionType.DEVICE_UNINSTALL_APP.value: {
        "type": "object",
        "properties": {"package": {"type": "string"}, "pairing_token": {"type": "string"}},
        "required": ["package"], "additionalProperties": False,
    },
    ActionType.DEVICE_SETTINGS_CHANGE.value: {
        "type": "object",
        "properties": {"setting": {"type": "string", "enum": ["wifi", "brightness"]},
                       "value": {"type": ["string", "integer", "boolean"]},
                       "pairing_token": {"type": "string"}},
        "required": ["setting", "value"], "additionalProperties": False,
    },
    ActionType.DEVICE_PAYMENT.value: {
        "type": "object",
        "properties": {"amount_minor": {"type": "integer", "minimum": 1},
                       # Legacy spelling accepted only when it is an integer; providers normalize it.
                       "amount": {"type": "integer", "minimum": 1},
                       "recipient": {"type": "string", "maxLength": 256},
                       "currency": {"type": "string", "maxLength": 3},
                       "pairing_token": {"type": "string"}},
        "required": ["recipient"], "additionalProperties": False,
    },
    # github
    ActionType.GITHUB_REPO_GET.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "token": {"type": "string"},
        },
        "required": ["repo"],
    },
    ActionType.GITHUB_ISSUE_LIST.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "state": {"type": "string", "description": "open|closed|all"},
            "token": {"type": "string"},
        },
        "required": ["repo"],
    },
    ActionType.GITHUB_ISSUE_GET.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "issue_number": {"type": "integer", "description": "issue number"},
            "token": {"type": "string"},
        },
        "required": ["repo", "issue_number"],
    },
    ActionType.GITHUB_ISSUE_CREATE.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "title": {"type": "string", "description": "issue title"},
            "body": {"type": "string", "description": "issue body"},
            "token": {"type": "string"},
        },
        "required": ["repo", "title"],
    },
    ActionType.GITHUB_ISSUE_COMMENT.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "issue_number": {"type": "integer", "description": "issue number"},
            "body": {"type": "string", "description": "comment body"},
            "token": {"type": "string"},
        },
        "required": ["repo", "issue_number", "body"],
    },
    ActionType.GITHUB_PR_LIST.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "state": {"type": "string", "description": "open|closed|all"},
            "token": {"type": "string"},
        },
        "required": ["repo"],
    },
    ActionType.GITHUB_PR_GET.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "pull_number": {"type": "integer", "description": "PR number"},
            "token": {"type": "string"},
        },
        "required": ["repo", "pull_number"],
    },
    ActionType.GITHUB_PR_CREATE.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "title": {"type": "string", "description": "PR title"},
            "head": {"type": "string", "description": "head branch"},
            "base": {"type": "string", "description": "base branch"},
            "body": {"type": "string", "description": "PR description"},
            "token": {"type": "string"},
        },
        "required": ["repo", "title", "head", "base"],
    },
    ActionType.GITHUB_FILE_GET.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "path": {"type": "string", "description": "file path in repo"},
            "ref": {"type": "string", "description": "branch, tag or commit SHA"},
            "token": {"type": "string"},
        },
        "required": ["repo", "path"],
    },
    ActionType.GITHUB_FILE_COMMIT.value: {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "owner/repo"},
            "path": {"type": "string", "description": "file path in repo"},
            "message": {"type": "string", "description": "commit message"},
            "content": {"type": "string", "description": "file content to commit"},
            "branch": {"type": "string", "description": "target branch"},
            "token": {"type": "string"},
        },
        "required": ["repo", "path", "message", "content"],
    },
    # code execution
    ActionType.CODE_RUN.value: {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code snippet to execute"},
            "language": {"type": "string", "description": "python"},
        },
        "required": ["code"],
    },
    ActionType.CODE_EXEC.value: {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code snippet to execute"},
            "language": {"type": "string", "description": "python"},
        },
        "required": ["code"],
    },
    # image generation (Phase 3H)
    ActionType.IMAGE_GENERATE.value: {
        "type": "object",
        "properties": {
            "prompt": {"type": "string", "description": "image description prompt"},
            "size": {"type": "string", "description": "e.g. 1024x1024"},
            "output_path": {"type": "string", "description": "workspace output file path"},
            "model": {"type": "string", "description": "model identifier"},
            "api_key": {"type": "string"},
        },
        "required": ["prompt"],
    },
    # forbidden
    ActionType.SECRET_EXPORT.value: {
        "type": "object",
        "properties": {},
        "required": [],
    },
    ActionType.ACCOUNT_DELETE.value: {
        "type": "object",
        "properties": {},
        "required": [],
    },
}


def _spec(action_type: ActionType, risk: RiskLevel, domain: str,
          secret_fields: tuple[str, ...] = ()) -> ActionSpec:
    return ActionSpec(
        action_type=action_type.value,
        risk_level=risk,
        capability_domain=domain,
        secret_fields=frozenset(secret_fields),
        param_schema=ACTION_PARAM_SCHEMAS.get(action_type.value),
    )


_SPECS: list[ActionSpec] = [
    # demo / core
    _spec(ActionType.STUB_NOOP, RiskLevel.SAFE, "core"),

    # web
    _spec(ActionType.WEB_SEARCH, RiskLevel.SAFE, "web", ("api_key",)),
    # SENSITIVE, not SAFE: SSRF / private-network guard required by the provider.
    _spec(ActionType.WEB_FETCH, RiskLevel.SENSITIVE, "web", ("api_key",)),
    _spec(ActionType.WEB_DOWNLOAD, RiskLevel.MUTATING, "web", ("api_key",)),

    # browser automation (Phase 4A)
    _spec(ActionType.BROWSER_NAVIGATE, RiskLevel.SENSITIVE, "browser"),
    _spec(ActionType.BROWSER_SCREENSHOT, RiskLevel.SENSITIVE, "browser"),
    _spec(ActionType.BROWSER_EXTRACT_DOM, RiskLevel.SAFE, "browser"),
    _spec(ActionType.BROWSER_CLICK, RiskLevel.MUTATING, "browser"),
    _spec(ActionType.BROWSER_FILL, RiskLevel.MUTATING, "browser", ("text",)),
    _spec(ActionType.BROWSER_SUBMIT, RiskLevel.MUTATING, "browser"),

    # reliable browser workflows (Phase 4B)
    # inspect/tabs are SAFE reads of the run's own browser state; activate_tab
    # only switches which tab the run's later actions address (SENSITIVE, not
    # SAFE, so policy can gate it); download/upload mutate the workspace and
    # the page -> MUTATING (default CONFIRM) and non-retryable.
    _spec(ActionType.BROWSER_INSPECT, RiskLevel.SAFE, "browser"),
    _spec(ActionType.BROWSER_TABS, RiskLevel.SAFE, "browser"),
    _spec(ActionType.BROWSER_ACTIVATE_TAB, RiskLevel.SENSITIVE, "browser"),
    _spec(ActionType.BROWSER_DOWNLOAD, RiskLevel.MUTATING, "browser"),
    _spec(ActionType.BROWSER_UPLOAD, RiskLevel.MUTATING, "browser"),
    # Phase 4C: conservatively MUTATING by default (a workflow may contain
    # mutating steps). Every inner step is still gated independently by the
    # permission engine, confirmation and audit layers.
    _spec(ActionType.BROWSER_WORKFLOW_RUN, RiskLevel.MUTATING, "browser"),

    # email
    _spec(ActionType.EMAIL_READ, RiskLevel.SENSITIVE, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_SEARCH, RiskLevel.SENSITIVE, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_DRAFT, RiskLevel.MUTATING, "email", ("token", "refresh_token")),
    _spec(ActionType.EMAIL_SEND, RiskLevel.COMMUNICATION, "email", ("token", "refresh_token")),

    # Content/PII fields are redacted by the action-aware audit boundary; these
    # static secret fields remain credential-specific for catalog compatibility.
    _spec(ActionType.WHATSAPP_READ, RiskLevel.SENSITIVE, "whatsapp", ("token",)),
    _spec(ActionType.WHATSAPP_SEND, RiskLevel.COMMUNICATION, "whatsapp", ("token",)),
    _spec(ActionType.WHATSAPP_REACT, RiskLevel.COMMUNICATION, "whatsapp", ("token",)),

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
    _spec(ActionType.DEVICE_SHELL, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_APP_LAUNCH, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_UI_CLICK, RiskLevel.MUTATING, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_SCREENSHOT, RiskLevel.SENSITIVE, "device", ("pairing_token",)),
    _spec(ActionType.DEVICE_PHOTO_CAPTURE, RiskLevel.MUTATING, "device", ("pairing_token",)),
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

    # image generation (Phase 3H)
    _spec(ActionType.IMAGE_GENERATE, RiskLevel.MUTATING, "image", ("api_key",)),

    # forbidden
    _spec(ActionType.SECRET_EXPORT, RiskLevel.FORBIDDEN, "core"),
    _spec(ActionType.ACCOUNT_DELETE, RiskLevel.FORBIDDEN, "core"),
]

ACTION_CATALOG = ActionCatalog(_SPECS)
