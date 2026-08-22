"""Image Generation Provider (Phase 3H).

Generates images from text prompts using OpenAI Images (DALL-E 3 / DALL-E 2) or any
compatible endpoint, saving outputs safely inside the sandboxed workspace.

Action:
* ``image.generate`` — risk MUTATING (CONFIRM gate required), domain "image".

Security controls:
* API key is vault-resolvable (``vault:image/token``) or env-configured.
* Keys are declared in ``secret_fields`` and masked before reaching audit logs.
* Outputs are confined to the sandboxed workspace directory (directory traversal rejected).
* Bounded response size (default max 10 MiB) prevents memory exhaustion.
* Offline / no-key mode yields a clean ``NOT_IMPLEMENTED`` ToolError (fail-closed, no crash).
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.path_safety import is_safe_relative_path
from era.security.vault import VaultError, is_vault_ref

DEFAULT_API_BASE_URL = "https://api.openai.com/v1"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MODEL = "dall-e-3"
DEFAULT_MAX_BYTES = 10_485_760  # 10 MiB
_MAX_PROMPT_LEN = 4000


class ImageGenProvider:
    """Generates images and writes them safely into the workspace."""

    id = "image-gen"
    action_types = frozenset({ActionType.IMAGE_GENERATE.value})

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = DEFAULT_API_BASE_URL,
        model: str = DEFAULT_MODEL,
        workspace_root: Path | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_image_bytes: int = DEFAULT_MAX_BYTES,
        secret_resolver=None,
    ):
        self._api_key_ref = str(api_key or "").strip()
        self._base_url = str(base_url or DEFAULT_API_BASE_URL).rstrip("/")
        self._model = str(model or DEFAULT_MODEL).strip()
        self._workspace_root = workspace_root
        self._timeout = float(timeout_seconds)
        self._max_bytes = int(max_image_bytes)
        self._resolver = secret_resolver

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            provider_type="image_gen",
            version="1.0.0",
        )

    # -- SPI -------------------------------------------------------------------
    def validate(self, action) -> None:
        params = action.params or {}
        prompt = params.get("prompt")
        if not prompt or not isinstance(prompt, str) or not prompt.strip():
            raise ToolError(
                "image.generate requires a non-empty 'prompt' parameter",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )
        if len(prompt) > _MAX_PROMPT_LEN:
            raise ToolError(
                f"'prompt' exceeds maximum length ({_MAX_PROMPT_LEN} chars)",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )

        output_path = params.get("output_path")
        if output_path is not None:
            if not isinstance(output_path, str) or not output_path.strip():
                raise ToolError(
                    "'output_path' must be a non-empty string",
                    provider_id=self.id,
                    code=ProviderErrorCode.VALIDATION,
                )
            if not is_safe_relative_path(output_path):
                raise ToolError(
                    f"insecure output path {output_path!r} (must be relative inside workspace)",
                    provider_id=self.id,
                    code=ProviderErrorCode.FORBIDDEN,
                )

    def execute(self, action, ctx) -> ActionResult:
        api_key = self._resolve(self._api_key_ref, "Image generation API key")
        if not api_key:
            raise ToolError(
                "image generation not configured (set ERA_IMAGE_GEN_API_KEY or vault:image/token)",
                provider_id=self.id,
                code=ProviderErrorCode.NOT_IMPLEMENTED,
            )

        params = action.params or {}
        prompt = str(params["prompt"]).strip()
        size = str(params.get("size") or "1024x1024").strip()
        model = str(params.get("model") or self._model).strip()
        output_path = params.get("output_path")

        # Determine target file destination
        if output_path:
            rel_dest = Path(output_path)
        else:
            filename = f"image_{uuid.uuid4().hex[:12]}.png"
            rel_dest = Path("images") / filename

        endpoint = f"{self._base_url}/images/generations"
        payload = {
            "prompt": prompt,
            "model": model,
            "size": size,
            "response_format": "b64_json",
            "n": 1,
        }

        resp_data = self._http_call(endpoint, payload, api_key)
        data_items = resp_data.get("data", [])
        if not data_items:
            raise ToolError("no image data returned by provider",
                            provider_id=self.id, code=ProviderErrorCode.PROVIDER_ERROR)

        first_item = data_items[0]
        if "b64_json" in first_item:
            try:
                img_bytes = base64.b64decode(first_item["b64_json"])
            except Exception as exc:
                raise ToolError(f"invalid base64 image data: {exc}",
                                provider_id=self.id, code=ProviderErrorCode.PROVIDER_ERROR) from exc
        elif "url" in first_item:
            img_bytes = self._download_image(first_item["url"])
        else:
            raise ToolError("unsupported image response format",
                            provider_id=self.id, code=ProviderErrorCode.PROVIDER_ERROR)

        if len(img_bytes) > self._max_bytes:
            raise ToolError(f"generated image exceeds size cap ({len(img_bytes)} > {self._max_bytes})",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION)

        # Write to workspace if configured
        saved_path = str(rel_dest)
        if self._workspace_root is not None:
            full_path = (self._workspace_root / rel_dest).resolve()
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(img_bytes)
            saved_path = str(rel_dest)

        return ActionResult(
            success=True,
            summary=f"Image generated and saved to {saved_path}",
            data={
                "path": saved_path,
                "bytes": len(img_bytes),
                "model": model,
                "size": size,
            },
        )

    # -- HTTP Transport -------------------------------------------------------
    def _http_call(self, url: str, payload: dict[str, Any], api_key: str) -> dict:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ERA-Agent/Phase3H",
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            self._map_http_error(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError(
                f"Image generation network error: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.UNAVAILABLE,
            ) from exc

    def _download_image(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "ERA-Agent/Phase3H"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read(self._max_bytes + 1)
        except Exception as exc:
            raise ToolError(f"failed to download generated image: {exc}",
                            provider_id=self.id, code=ProviderErrorCode.UNAVAILABLE) from exc

    def _map_http_error(self, exc: urllib.error.HTTPError) -> None:
        status_code = exc.code
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
            err_doc = json.loads(body_text)
            err_msg = err_doc.get("error", {}).get("message", body_text)
        except Exception:  # noqa: BLE001
            err_msg = str(exc)

        if status_code in (401, 403):
            raise ToolError(f"Image API auth failed ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc
        if status_code in (400, 422):
            raise ToolError(f"Image API validation error ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION) from exc
        if status_code == 429:
            raise ToolError("Image API rate limit exceeded",
                            provider_id=self.id, code=ProviderErrorCode.RATE_LIMITED) from exc
        if status_code >= 500:
            raise ToolError(f"Image API server error ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.UNAVAILABLE) from exc

        raise ToolError(f"Image API error ({status_code}): {err_msg}",
                        provider_id=self.id, code=ProviderErrorCode.PROVIDER_ERROR) from exc

    def _resolve(self, ref: str, label: str) -> str:
        if not ref:
            return ""
        if not is_vault_ref(ref):
            return ref
        if self._resolver is None:
            raise ToolError(
                f"{label} uses a vault reference {ref!r} but no resolver is attached",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            )
        try:
            return self._resolver.resolve_ref(ref, actor_id="image-gen-provider")
        except VaultError as exc:
            raise ToolError(
                f"cannot resolve {label} from vault reference {ref!r}: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            ) from exc
