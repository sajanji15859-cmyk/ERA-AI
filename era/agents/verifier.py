"""Task verification (Phase 3A).

The agent must not blindly believe a tool succeeded — "क्या requested task
वास्तव में पूरा हुआ?" Verification specs live on each task (``task.verify``)
and are checked after the tool observation:

* ``action_success`` — the execution service reported ``executed``;
* ``file_exists`` — file present with a minimum size;
* ``text_contains`` — file contains required phrases;
* ``html_valid`` — file parses as HTML, contains required elements and keywords;
* ``links_resolve`` — every local link across the listed pages points at a real
  workspace file.

A failed verdict produces a reason that becomes the task's correction note for
the retry (bounded by the task/budget retry caps).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from era.agents.models import Observation, Task


class Verdict(BaseModel):
    ok: bool
    reason: str = ""
    details: dict[str, Any] = {}


class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.text: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attrs = dict(attrs)
        href = attrs.get("href")
        if href:
            self.links.append(href)

    def handle_data(self, data):
        self.text.append(data)


def _parse_html(content: str) -> tuple[set[str], str, list[str]]:
    collector = _TagCollector()
    collector.feed(content)
    return set(collector.tags), " ".join(collector.text), collector.links


class Verifier:
    """Checks task outcomes against their verification specs."""

    def __init__(self, workspace_root: Path | None = None):
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None

    def verify(self, task: Task, observation: Observation | None) -> Verdict:
        spec = task.verify or {}
        kind = spec.get("kind") or "action_success"

        if observation is None:
            return Verdict(ok=False, reason="no observation recorded")

        if kind == "action_success":
            if observation.status == "executed":
                return Verdict(ok=True, reason="action executed")
            detail = observation.error or observation.summary or observation.status
            return Verdict(ok=False, reason=f"action did not execute: {detail}")

        if kind == "file_exists":
            return self._check_file_exists(spec)

        if kind == "text_contains":
            return self._check_text_contains(spec)

        if kind == "html_valid":
            return self._check_html_valid(spec)

        if kind == "links_resolve":
            return self._check_links_resolve(spec)

        return Verdict(ok=False, reason=f"unknown verification kind: {kind!r}")

    # -- internal checkers ----------------------------------------------------
    def _workspace_file(self, rel_path: str) -> Path:
        if self.workspace_root is None:
            raise RuntimeError("verifier has no workspace root")
        resolved = (self.workspace_root / rel_path).resolve()
        if resolved != self.workspace_root and self.workspace_root not in resolved.parents:
            return Path("/nonexistent-escape-guard")  # containment, fail closed
        return resolved

    def _check_file_exists(self, spec: dict[str, Any]) -> Verdict:
        path = self._workspace_file(str(spec.get("path", "")))
        min_bytes = int(spec.get("min_bytes", 1))
        if not path.is_file():
            return Verdict(ok=False, reason=f"file does not exist: {spec.get('path')}")
        size = path.stat().st_size
        if size < min_bytes:
            return Verdict(ok=False, reason=f"file too small: {size} bytes < {min_bytes}")
        return Verdict(ok=True, reason="file exists", details={"path": spec.get("path"), "bytes": size})

    def _check_text_contains(self, spec: dict[str, Any]) -> Verdict:
        path = self._workspace_file(str(spec.get("path", "")))
        required = [str(r) for r in spec.get("required", [])]
        if not path.is_file():
            return Verdict(ok=False, reason=f"file does not exist: {spec.get('path')}")
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError as exc:
            return Verdict(ok=False, reason=f"cannot read file: {exc}")
        missing = [r for r in required if str(r).lower() not in text]
        if missing:
            return Verdict(ok=False, reason=f"missing required text: {missing[:5]}")
        return Verdict(ok=True, reason="required text present", details={"path": spec.get("path")})

    def _check_html_valid(self, spec: dict[str, Any]) -> Verdict:
        path = self._workspace_file(str(spec.get("path", "")))
        required_elements = {str(e).lower() for e in spec.get("required_elements", [])}
        keywords = [str(k).lower() for k in spec.get("keywords", [])]
        if not path.is_file():
            return Verdict(ok=False, reason=f"file does not exist: {spec.get('path')}")
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return Verdict(ok=False, reason=f"cannot read file: {exc}")
        tags, text, _ = _parse_html(content)
        missing = [e for e in required_elements if e not in tags]
        if missing:
            return Verdict(ok=False, reason=f"missing HTML elements: {missing}")
        text_lower = text.lower()
        missing_kw = [k for k in keywords if k not in text_lower]
        if missing_kw:
            return Verdict(ok=False, reason=f"missing keywords: {missing_kw[:5]}")
        return Verdict(ok=True, reason="HTML structure verified",
                       details={"path": spec.get("path"), "elements_checked": sorted(required_elements)})

    def _check_links_resolve(self, spec: dict[str, Any]) -> Verdict:
        pages = [str(p) for p in spec.get("pages", [])]
        if not pages:
            return Verdict(ok=False, reason="links_resolve requires a page list")
        broken: list[str] = []
        checked = 0
        for page in pages:
            path = self._workspace_file(page)
            if not path.is_file():
                broken.append(f"{page} (page missing)")
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return Verdict(ok=False, reason=f"cannot read page {page}: {exc}")
            _, _, links = _parse_html(content)
            for href in links:
                href = href.strip()
                if not href or href.startswith(("#", "http://", "https://", "mailto:", "tel:")):
                    continue
                target = (path.parent / href.split("#", 1)[0]).resolve()
                if self.workspace_root is None or self.workspace_root not in target.parents \
                        or not target.is_file():
                    broken.append(f"{page} -> {href}")
                checked += 1
        if broken:
            return Verdict(ok=False, reason=f"broken links: {broken[:10]}", details={"broken": broken})
        return Verdict(ok=True, reason="all local links resolve", details={"links_checked": checked})


# Cache-buster helper for tests that want to verify a link checker runs.
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
