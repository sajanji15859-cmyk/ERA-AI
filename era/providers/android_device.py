"""Secure Android Device Bridge (ADB) provider.

ADB is intentionally exposed through a small, allowlisted action surface rather
than a generic remote shell.  A device must be explicitly configured and paired
with a vault-resolvable token; network ADB is localhost-only unless an operator
marks a TLS-wrapped transport.  The provider does not grant permissions itself:
the catalog keeps the ``device`` domain admin-only and ExecutionService applies
confirmation/dual approval before this code runs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shlex
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Protocol

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.providers._rate_limit import ActorRateLimiter
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot
from era.security.result_safety import redact_sensitive_text
from era.security.vault import VaultError, is_vault_ref

_ACTION_TYPES = frozenset({
    ActionType.DEVICE_SHELL.value,
    ActionType.DEVICE_APP_LAUNCH.value,
    ActionType.DEVICE_UI_CLICK.value,
    ActionType.DEVICE_SCREENSHOT.value,
    ActionType.DEVICE_PHOTO_CAPTURE.value,
    ActionType.DEVICE_LOCATION.value,
    ActionType.DEVICE_NOTIFICATION.value,
    ActionType.DEVICE_CONTACTS.value,
    ActionType.DEVICE_SMS_READ.value,
    ActionType.DEVICE_SMS_SEND.value,
    ActionType.DEVICE_INSTALL_APP.value,
    ActionType.DEVICE_UNINSTALL_APP.value,
    ActionType.DEVICE_SETTINGS_CHANGE.value,
    ActionType.DEVICE_PAYMENT.value,
})
_SAFE_SHELL_COMMANDS = frozenset({"ls", "cat", "dumpsys", "getprop"})
_FORBIDDEN_SHELL_WORDS = frozenset({"su", "sudo", "mount", "umount", "dd", "rm", "reboot", "setenforce"})
_SAFE_SETTING_NAMES = frozenset({"wifi", "brightness"})
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_PHONE_RE = re.compile(r"^\+?[1-9]\d{6,15}$")
_COORD_MAX = 4096
MAX_SHELL_OUTPUT_BYTES = 65_536


class AdbCommandError(RuntimeError):
    """A non-zero ADB process result without exposing raw device output."""


class AdbTransport(Protocol):
    def run(self, command: list[str], *, timeout: float) -> bytes: ...


class SubprocessAdbTransport:
    """Minimal subprocess transport; injectable for offline/provider tests."""

    def run(self, command: list[str], *, timeout: float) -> bytes:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if completed.returncode != 0:
            raise AdbCommandError("ADB command failed")
        return bytes(completed.stdout)


class AndroidDeviceProvider:
    """ADB provider with paired-device, command, artifact, and amount bounds."""

    id = "android-device"
    action_types = _ACTION_TYPES
    non_retryable_action_types = frozenset({ActionType.DEVICE_PAYMENT.value})
    ambiguous_on_failure_action_types = non_retryable_action_types

    def __init__(
        self,
        *,
        device_id: str,
        pairing_token: str = "",
        workspace_root: str | Path,
        adb_path: str = "adb",
        adb_host: str = "",
        adb_port: int = 5555,
        tls_enabled: bool = False,
        timeout_seconds: float = 15.0,
        secret_resolver=None,
        transport: AdbTransport | None = None,
        max_shell_commands_per_minute: int = 10,
        max_screenshot_bytes: int = 10_485_760,
        max_contacts: int = 100,
        max_sms_messages: int = 50,
        max_notifications: int = 50,
        max_payment_amount_minor: int = 1_000_000,
        safe_app_packages: list[str] | tuple[str, ...] | None = None,
    ):
        if not str(device_id or "").strip():
            raise ValueError("AndroidDeviceProvider requires a device_id")
        self._device_id = str(device_id).strip()
        self._pairing_token_ref = str(pairing_token or "").strip()
        self._workspace = WorkspaceRoot(workspace_root)
        self._adb_path = str(adb_path or "adb")
        self._adb_host = str(adb_host or "").strip().lower()
        self._adb_port = int(adb_port)
        self._tls_enabled = bool(tls_enabled)
        self._timeout = max(0.1, float(timeout_seconds))
        self._resolver = secret_resolver
        self._transport = transport or SubprocessAdbTransport()
        self._shell_limiter = ActorRateLimiter(
            limit=max_shell_commands_per_minute,
            window_seconds=60.0,
        )
        self._max_screenshot_bytes = max(1, int(max_screenshot_bytes))
        self._max_contacts = max(1, min(100, int(max_contacts)))
        self._max_sms = max(1, min(50, int(max_sms_messages)))
        self._max_notifications = max(1, min(50, int(max_notifications)))
        self._max_payment_amount_minor = max(1, int(max_payment_amount_minor))
        packages = safe_app_packages or ()
        self._safe_packages = frozenset(str(item).strip() for item in packages if str(item).strip())
        self._connected = False
        self._connect_lock = threading.Lock()

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name="Android device (paired ADB)",
            is_stub=False,
            capabilities=("adb", "paired", "allowlisted-shell", "workspace-artifacts", "no-root"),
        )

    # -- SPI -----------------------------------------------------------------
    def validate(self, action: Action) -> None:
        if action.action_type not in self.action_types:
            raise ToolError(f"Android provider cannot handle {action.action_type}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        params = action.params or {}
        action_type = action.action_type
        if action_type == ActionType.DEVICE_SHELL.value:
            self._validate_shell(params.get("command"))
        elif action_type == ActionType.DEVICE_APP_LAUNCH.value:
            self._validate_package(params.get("package"), require_allowlist=True)
        elif action_type == ActionType.DEVICE_UI_CLICK.value:
            self._validate_coordinates(params)
        elif action_type in {ActionType.DEVICE_SCREENSHOT.value, ActionType.DEVICE_PHOTO_CAPTURE.value}:
            path = params.get("path")
            if path is not None:
                if not isinstance(path, str) or not path:
                    raise ToolError("artifact path must be a non-empty string", provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
                self._workspace.resolve(path)
        elif action_type == ActionType.DEVICE_CONTACTS.value:
            self._validate_limit(params.get("limit", self._max_contacts), self._max_contacts)
        elif action_type == ActionType.DEVICE_SMS_READ.value:
            self._validate_limit(params.get("limit", self._max_sms), self._max_sms)
        elif action_type == ActionType.DEVICE_NOTIFICATION.value:
            self._validate_limit(params.get("limit", self._max_notifications), self._max_notifications)
        elif action_type == ActionType.DEVICE_SMS_SEND.value:
            to = params.get("to")
            message = params.get("message")
            if not isinstance(to, str) or not _PHONE_RE.fullmatch(to.replace(" ", "")):
                raise ToolError("device.sms_send requires an E.164-like recipient", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not isinstance(message, str) or not message or len(message) > 1_000:
                raise ToolError("device.sms_send requires a message up to 1000 chars", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
        elif action_type == ActionType.DEVICE_INSTALL_APP.value:
            path = params.get("path")
            if not isinstance(path, str) or not path.lower().endswith(".apk"):
                raise ToolError("device.install_app requires a workspace .apk path", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            resolved = self._workspace.resolve(path)
            if not resolved.exists() or not resolved.is_file():
                raise ToolError("APK was not found in workspace", provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND)
        elif action_type == ActionType.DEVICE_UNINSTALL_APP.value:
            self._validate_package(params.get("package"), require_allowlist=False)
        elif action_type == ActionType.DEVICE_SETTINGS_CHANGE.value:
            setting = str(params.get("setting", "")).lower()
            if setting not in _SAFE_SETTING_NAMES:
                raise ToolError("only wifi and brightness settings may be changed", provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN)
            self._validate_setting(setting, params.get("value"))
        elif action_type == ActionType.DEVICE_PAYMENT.value:
            amount = params.get("amount_minor", params.get("amount"))
            if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount <= self._max_payment_amount_minor:
                raise ToolError("payment amount_minor must be a positive bounded integer", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            recipient = params.get("recipient")
            if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 256:
                raise ToolError("payment requires a bounded recipient", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        self._ensure_endpoint_safe()
        self._ensure_paired(action.params or {})
        self._ensure_connected()
        params = action.params or {}
        action_type = action.action_type
        try:
            if action_type == ActionType.DEVICE_SHELL.value:
                if not self._shell_limiter.allow(ctx.actor_id):
                    raise ToolError("device shell rate limit exceeded for actor", provider_id=self.id,
                                    code=ProviderErrorCode.FORBIDDEN)
                return self._shell(str(params["command"]))
            if action_type == ActionType.DEVICE_SCREENSHOT.value:
                return self._screenshot(params.get("path"), prefix="screenshot")
            if action_type == ActionType.DEVICE_PHOTO_CAPTURE.value:
                self._adb("shell", "input", "keyevent", "27")
                return self._screenshot(params.get("path"), prefix="photo")
            if action_type == ActionType.DEVICE_LOCATION.value:
                return self._location()
            if action_type == ActionType.DEVICE_CONTACTS.value:
                return self._contacts(int(params.get("limit", self._max_contacts)))
            if action_type == ActionType.DEVICE_SMS_READ.value:
                return self._sms_read(int(params.get("limit", self._max_sms)))
            if action_type == ActionType.DEVICE_NOTIFICATION.value:
                return self._notifications(int(params.get("limit", self._max_notifications)))
            if action_type == ActionType.DEVICE_APP_LAUNCH.value:
                package = str(params["package"])
                self._adb("shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
                return ActionResult(success=True, summary="Android app launched", data={"package": package})
            if action_type == ActionType.DEVICE_UI_CLICK.value:
                x, y = int(params["x"]), int(params["y"])
                self._adb("shell", "input", "tap", str(x), str(y))
                return ActionResult(success=True, summary="Android UI tap sent", data={"x": x, "y": y})
            if action_type == ActionType.DEVICE_SMS_SEND.value:
                return self._sms_send(str(params["to"]), str(params["message"]))
            if action_type == ActionType.DEVICE_INSTALL_APP.value:
                return self._install_app(str(params["path"]))
            if action_type == ActionType.DEVICE_UNINSTALL_APP.value:
                package = str(params["package"])
                self._adb("uninstall", package)
                return ActionResult(success=True, summary="Android app uninstalled", data={"package": package})
            if action_type == ActionType.DEVICE_SETTINGS_CHANGE.value:
                return self._settings_change(str(params["setting"]).lower(), params["value"])
            if action_type == ActionType.DEVICE_PAYMENT.value:
                return self._payment(params)
        except ToolError:
            raise
        except subprocess.TimeoutExpired as exc:
            raise ToolError("Android device is not responding", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (FileNotFoundError, OSError, AdbCommandError) as exc:
            raise ToolError("Android device is unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        raise ToolError(f"unsupported Android action {action_type!r}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- device operations ---------------------------------------------------
    def _shell(self, command: str) -> ActionResult:
        parts = self._validate_shell(command)
        output = self._adb("shell", *parts)
        safe = redact_sensitive_text(output.decode("utf-8", errors="replace")[:MAX_SHELL_OUTPUT_BYTES])
        return ActionResult(success=True, summary="Android shell command completed",
                            data={"command": parts[0], "output": safe, "truncated": len(output) > MAX_SHELL_OUTPUT_BYTES})

    def _screenshot(self, path_value: Any, *, prefix: str) -> ActionResult:
        path = str(path_value) if isinstance(path_value, str) and path_value else f"device/{prefix}-{os.urandom(6).hex()}.png"
        resolved = self._workspace.resolve(path)
        raw = self._adb("exec-out", "screencap", "-p")
        if len(raw) > self._max_screenshot_bytes:
            raise ToolError("device screenshot exceeds configured size cap", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        _atomic_write(resolved, raw, provider_id=self.id)
        return ActionResult(success=True, summary=f"Android {prefix} captured",
                            data={"path": self._workspace.path_of(resolved), "size": len(raw),
                                  "sha256": hashlib.sha256(raw).hexdigest()})

    def _location(self) -> ActionResult:
        text = self._adb("shell", "dumpsys", "location").decode("utf-8", errors="replace")
        match = re.search(r"(-?\d{1,2}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)", text)
        if not match:
            raise ToolError("device location is unavailable", provider_id=self.id,
                            code=ProviderErrorCode.NOT_FOUND)
        latitude, longitude = round(float(match.group(1)), 3), round(float(match.group(2)), 3)
        return ActionResult(success=True, summary="Android location read",
                            data={"latitude": latitude, "longitude": longitude, "precision": "0.001-degree"})

    def _contacts(self, limit: int) -> ActionResult:
        text = self._adb("shell", "content", "query", "--uri", "content://contacts/phones/").decode("utf-8", errors="replace")
        contacts: list[dict[str, str]] = []
        for line in text.splitlines():
            name = _field(line, "display_name") or _field(line, "name")
            number = _field(line, "data1") or _field(line, "number")
            if name or number:
                contacts.append({"name": str(name or "")[:200], "phone": str(number or "")[:64]})
            if len(contacts) >= limit:
                break
        return ActionResult(success=True, summary=f"Retrieved {len(contacts)} Android contacts",
                            data={"contacts": contacts, "count": len(contacts)})

    def _sms_read(self, limit: int) -> ActionResult:
        text = self._adb("shell", "content", "query", "--uri", "content://sms", "--projection", "address:body:date").decode("utf-8", errors="replace")
        messages: list[dict[str, str]] = []
        for line in text.splitlines():
            address = _field(line, "address")
            body = _field(line, "body")
            if address or body:
                messages.append({"from": str(address or "")[:64],
                                 "body_preview": redact_sensitive_text(str(body or ""))[:1_000]})
            if len(messages) >= limit:
                break
        return ActionResult(success=True, summary=f"Retrieved {len(messages)} Android SMS messages",
                            data={"messages": messages, "count": len(messages)})

    def _notifications(self, limit: int) -> ActionResult:
        text = self._adb("shell", "dumpsys", "notification", "--noredact").decode("utf-8", errors="replace")
        notifications: list[dict[str, str]] = []
        for line in text.splitlines():
            if "NotificationRecord" in line or "tickerText" in line or "android.title" in line:
                notifications.append({"preview": redact_sensitive_text(line.strip())[:1_000]})
            if len(notifications) >= limit:
                break
        return ActionResult(success=True, summary=f"Retrieved {len(notifications)} Android notifications",
                            data={"notifications": notifications, "count": len(notifications)})

    def _sms_send(self, recipient: str, message: str) -> ActionResult:
        # Modern Android versions deliberately restrict silent SMS dispatch.
        # Launching the platform composer is the portable ADB route; the action
        # is still confirmation-gated and explicitly reports that the device UI
        # owns final delivery rather than claiming an unverifiable send.
        self._adb("shell", "am", "start", "-a", "android.intent.action.SENDTO", "-d", f"sms:{recipient}",
                  "--es", "sms_body", message)
        return ActionResult(success=True, summary="Android SMS composer opened",
                            data={"to": recipient, "status": "pending_device_send"})

    def _install_app(self, rel_path: str) -> ActionResult:
        apk = self._workspace.resolve(rel_path)
        self._verify_signed_apk(apk)
        self._adb("install", "-r", str(apk))
        return ActionResult(success=True, summary="Signed Android APK installed",
                            data={"path": self._workspace.path_of(apk)})

    def _settings_change(self, setting: str, value: Any) -> ActionResult:
        if setting == "wifi":
            enabled = _bool_setting(value)
            self._adb("shell", "svc", "wifi", "enable" if enabled else "disable")
            safe_value: bool | int = enabled
        else:
            brightness = int(value)
            self._adb("shell", "settings", "put", "system", "screen_brightness", str(brightness))
            safe_value = brightness
        return ActionResult(success=True, summary="Android setting changed",
                            data={"setting": setting, "value": safe_value})

    def _payment(self, params: dict[str, Any]) -> ActionResult:
        amount = int(params.get("amount_minor", params.get("amount")))
        recipient = str(params["recipient"]).strip()
        currency = str(params.get("currency") or "INR").upper()
        # A signed companion app must implement this explicit broadcast.  There
        # is intentionally no generic shell/payment fallback and no retry.
        self._adb("shell", "am", "broadcast", "-a", "ai.era.device.PAYMENT", "--ei", "amount_minor", str(amount),
                  "--es", "currency", currency, "--es", "recipient", recipient)
        return ActionResult(success=True, summary="Android payment handed to paired companion",
                            data={"amount_minor": amount, "currency": currency, "status": "submitted"})

    # -- pairing, transport, validation -------------------------------------
    def _ensure_endpoint_safe(self) -> None:
        if not self._adb_host:
            return  # USB / local adb-server transport.
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if self._adb_host not in local_hosts and not self._tls_enabled:
            raise ToolError("network ADB must be localhost-only or TLS-wrapped", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)

    def _ensure_paired(self, params: dict[str, Any]) -> None:
        expected = self._resolve(self._pairing_token_ref, "Android pairing token")
        if not expected:
            raise ToolError("Android pairing token is missing", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        supplied = params.get("pairing_token")
        if supplied is not None and (not isinstance(supplied, str) or not hmac.compare_digest(expected, supplied)):
            raise ToolError("Android pairing token was rejected", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)

    def _ensure_connected(self) -> None:
        if not self._adb_host or self._connected:
            return
        with self._connect_lock:
            if not self._connected:
                self._raw_adb("connect", f"{self._adb_host}:{self._adb_port}")
                self._connected = True

    def _adb(self, *args: str) -> bytes:
        return self._raw_adb("-s", self._device_id, *args)

    def _raw_adb(self, *args: str) -> bytes:
        command = [self._adb_path, *args]
        return self._transport.run(command, timeout=self._timeout)

    def _verify_signed_apk(self, apk: Path) -> None:
        verifier = getattr(self._transport, "verify_apk", None)
        if callable(verifier):
            if not verifier(apk, timeout=self._timeout):
                raise ToolError("APK signature verification failed", provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN)
            return
        try:
            completed = subprocess.run(
                ["apksigner", "verify", "--verbose", str(apk)],
                capture_output=True,
                check=False,
                timeout=self._timeout,
            )
        except FileNotFoundError as exc:
            raise ToolError("apksigner is required to install APKs", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED) from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError("APK signature verification timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        if completed.returncode != 0:
            raise ToolError("APK signature verification failed", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)

    def _validate_shell(self, command: Any) -> list[str]:
        if not isinstance(command, str) or not command.strip() or len(command) > 512:
            raise ToolError("device.shell requires a bounded command", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if any(character in command for character in ";|&`$><\n\r"):
            raise ToolError("shell metacharacters are forbidden", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)
        try:
            parts = shlex.split(command, posix=True)
        except ValueError as exc:
            raise ToolError("invalid shell command", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION) from exc
        if not parts or parts[0] not in _SAFE_SHELL_COMMANDS or any(part in _FORBIDDEN_SHELL_WORDS for part in parts):
            raise ToolError("shell command is not in the safe allowlist", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)
        return parts

    def _validate_package(self, package: Any, *, require_allowlist: bool) -> None:
        if not isinstance(package, str) or not _PACKAGE_RE.fullmatch(package):
            raise ToolError("invalid Android package name", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if require_allowlist and package not in self._safe_packages:
            raise ToolError("Android package is not in the safe app allowlist", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)

    @staticmethod
    def _validate_coordinates(params: dict[str, Any]) -> None:
        x, y = params.get("x"), params.get("y")
        if not isinstance(x, int) or isinstance(x, bool) or not isinstance(y, int) or isinstance(y, bool):
            raise ToolError("device.ui_click requires integer x and y coordinates", provider_id="android-device",
                            code=ProviderErrorCode.VALIDATION)
        if not 0 <= x <= _COORD_MAX or not 0 <= y <= _COORD_MAX:
            raise ToolError("device.ui_click coordinates exceed safe bounds", provider_id="android-device",
                            code=ProviderErrorCode.VALIDATION)

    @staticmethod
    def _validate_limit(value: Any, maximum: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            raise ToolError(f"limit must be an integer between 1 and {maximum}", provider_id="android-device",
                            code=ProviderErrorCode.VALIDATION)

    @staticmethod
    def _validate_setting(setting: str, value: Any) -> None:
        if setting == "wifi":
            _bool_setting(value)
        elif not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
            raise ToolError("brightness must be an integer between 0 and 255", provider_id="android-device",
                            code=ProviderErrorCode.VALIDATION)

    def _resolve(self, ref_or_plain: str, label: str) -> str:
        if not ref_or_plain:
            return ""
        if not is_vault_ref(ref_or_plain):
            return ref_or_plain
        if self._resolver is None:
            raise ToolError(f"{label} is a vault reference but no resolver is attached", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref_or_plain, actor_id="android-device-provider")
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"{label} could not be resolved from vault", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc


def _field(line: str, key: str) -> str | None:
    match = re.search(rf"(?:^|[,\s]){re.escape(key)}=([^,\s]+)", line)
    return match.group(1) if match else None


def _bool_setting(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"on", "true", "1", "enable", "enabled"}:
        return True
    if isinstance(value, str) and value.lower() in {"off", "false", "0", "disable", "disabled"}:
        return False
    raise ToolError("wifi value must be a boolean/on/off", provider_id="android-device",
                    code=ProviderErrorCode.VALIDATION)


def _atomic_write(path: Path, content: bytes, *, provider_id: str) -> None:
    temporary: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".era-device-", dir=path.parent)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise ToolError("device artifact write failed", provider_id=provider_id,
                        code=ProviderErrorCode.PROVIDER_ERROR) from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
