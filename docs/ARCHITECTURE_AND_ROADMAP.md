# ERA-AI: Computer-Use Agent — Architecture & Phased Roadmap

> Status: **Planning document** · Date: 2026-08-20 · **Phase 0 (foundation) implemented — see README.md**
> Scope: Full audit of the existing repository, target architecture for a personal autonomous computer-use agent (Android + laptop), platform feasibility, permissions/API requirements, and a phased development plan.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Part I — Current repository audit](#2-part-i--current-repository-audit)
3. [Part II — Platform feasibility: Android vs laptop](#3-part-ii--platform-feasibility-android-vs-laptop)
4. [Part III — Target architecture](#4-part-iii--target-architecture)
5. [Part IV — Phased development plan](#5-part-iv--phased-development-plan)
6. [Part V — Safety, permissions & confirmation design](#6-part-v--safety-permissions--confirmation-design)
7. [Part VI — Risks & mitigations](#7-part-vi--risks--mitigations)
8. [Appendix A — Dependency shortlist (future phases)](#appendix-a--dependency-shortlist-future-phases)
9. [Appendix B — Open-source projects worth studying](#appendix-b--open-source-projects-worth-studying)

---

## 1. Executive summary

ERA-AI today is a **~180-line pure-Python scaffold**: a hardcoded keyword chatbot, an in-RAM
note list, a 5-entry fake "research" database, and a duplicated agent class. **None of the
README's vision is implemented** — no LLM, no tools, no planning, no persistence, no device
control of any kind. This is not a criticism; it is a clean greenfield starting point whose
module taxonomy (brain / memory / research / chat / agent / config) happens to map neatly
onto the target architecture.

**Feasibility verdict (as of Aug 2026):**

| Goal | Verdict | Why |
|---|---|---|
| Operate the laptop (apps, files, browser, email) | ✅ Fully feasible | Three mature control ladders: structured APIs → OS accessibility trees → screenshot+VLM. All permissions grantable by the local user. |
| Operate the Android phone (apps, screen, UI) | ✅ Feasible for personal use, with real constraints | Works via (a) ADB from the laptop — most powerful & reliable, or (b) an on-device companion app with an Accessibility Service — needs sideloading + manual grants. Secure screens (banking, lock screen) are hard limits. |
| Publish an autonomous Android agent on Google Play | ❌ Effectively blocked | Play policy **explicitly prohibits** autonomous agent use of the AccessibilityService API. Personal sideloaded use is fine. |
| Fully hands-off autonomy (no confirmations ever) | ⚠️ Not advisable | Irreversible actions (send, pay, delete) need a confirmation layer; VLM grounding reliability compounds errors over long tasks. |

The recommended strategy: **laptop is the "brain", phone is a remote-controlled endpoint.**
Build the agent core + tool system + safety layer first (platform-independent), then laptop
control (browser → desktop), then Android via ADB, then an on-device companion app.

---

## 2. Part I — Current repository audit

### 2.1 Repository facts

| Item | Value |
|---|---|
| Files | 8 (7 Python + README.md), **179 lines total** |
| Commit history | Single commit `7ec8a98` — "Updated agent module" (2026-07-28) |
| Dependencies | **None.** No `requirements.txt`, no `pyproject.toml`, no lockfile — pure stdlib |
| Missing hygiene | No `.gitignore`, no tests, no CI, no linting config, no license file |
| Runtime | Verified: runs on Python 3.11.2 as an interactive echo-bot REPL |
| Packaging | None — flat script layout, entry point is `python main.py` |

### 2.2 Module-by-module inventory

| Module | LOC | What it actually does | Unused / broken |
|---|---|---|---|
| `main.py` | 36 | Prints a startup banner; `main()` instantiates `Brain` + `Memory`, stores 2 demo notes (one in Hindi), prints them | **Bug:** after the `if __name__ == "__main__": main()` guard, module-level code unconditionally runs `from agent import ERAAI; app = ERAAI(); app.start()` — the REPL launches **even if main.py is merely imported**. Hidden side effect; importing `main` anywhere starts a blocking `input()` loop. |
| `agent.py` | 39 | Defines class `ERAAI` **twice**. The second definition (REPL: `input()` → `Chat.reply()` → print) shadows the first (Brain/Memory/Research composition) | **Bug:** duplicate class name — the first class (the "real" agent composition) is dead code and is never instantiated. |
| `brain.py` | 22 | Holds a static list of skill names; `status()` prints them with emoji | No logic whatsoever. Never used by the live code path (only by the dead first `ERAAI`). |
| `memory.py` | 16 | `notes` Python list; `remember()` appends; `show()` prints | **Not persistent** (lost on exit), no query/retrieval API, no dedup, unbounded growth, no embeddings. |
| `research.py` | 19 | Hardcoded dict of 5 facts ("tesla", "history", "science", "ai", "taj mahal"); exact lowercase-string match | No network, no search, no ranking. Only referenced by the dead first `ERAAI` class. |
| `chat.py` | 24 | Substring keyword matching → hardcoded bilingual (Hindi/English) canned replies | **Bug:** `"ai" in message` matches any message containing those letters — e.g. "email", "wait", "gmail" all return the AI canned response. No conversation state, no fallback intelligence. |
| `config.py` | 7 | 4 constants (APP_NAME, VERSION, AUTHOR, DEBUG) | **Never imported by anything.** |
| `README.md` | 24 | Vision statement: research, PDF understanding, email, memory, planning, automation, multi-AI support | Aspirational only — 0% implemented. |

### 2.3 What exists vs what the goal needs

| Capability needed for computer-use agent | Present in repo? |
|---|---|
| LLM integration (any model) | ❌ none |
| Tool / action system | ❌ none |
| Planner (multi-step task decomposition) | ❌ none |
| Execution loop (act → observe → replan) | ❌ only a blocking echo REPL |
| Memory (persistent, queryable, semantic) | ❌ in-RAM list, no persistence |
| Permissions / safety layer | ❌ none |
| Confirmation system | ❌ none |
| Device control (laptop OS) | ❌ none |
| Device control (Android) | ❌ none |
| Browser automation | ❌ none |
| Email integration | ❌ none |
| Observability (logs, traces, replay) | ❌ "Logger Loaded" is a print statement with no logger |

**Reuse assessment:** nothing here needs preserving *as code* — the value is the taxonomy.
The plan below keeps the names as the skeleton of the new architecture:
`brain` → planner/LLM layer · `memory` → memory subsystem · `research` → tool layer (web) ·
`chat` → interface layer · `agent` → execution loop · `config` → settings/policy.
Everything gets rebuilt with real implementations; the audit found no behavioral surface
worth maintaining backward compatibility with.

---

## 3. Part II — Platform feasibility: Android vs laptop

The single most important design principle: **always prefer the most structured control plane
available, and only fall back to pixel-level vision when nothing better exists.**
Reliability ranking for any action: structured API > accessibility/DOM tree > screenshot + VLM.

### 3.1 Laptop (Windows / macOS / Linux)

The laptop is the easy platform: the OS user can grant everything locally, and there are
mature libraries for every control plane.

#### Control plane 1 — Structured APIs (best; use wherever possible)

| Domain | Mechanism | Notes / permissions |
|---|---|---|
| **Websites & Chrome** | Chrome DevTools Protocol (CDP) via **Playwright**/Selenium/Puppeteer | DOM-level control of pages: navigate, click by selector, fill forms, extract data, manage tabs, downloads. Can attach to the user's *real* Chrome instance launched with `--remote-debugging-port` (persisted logins/cookies), or drive an isolated automation profile. By far the most reliable web path. |
| Real browser session | Chrome/Edge **extension + Native Messaging host** | Extension uses `chrome.debugger` (CDP in-browser), `scripting`, `tabs`, `sidePanel`; talks to ERA-AI core over a native-messaging pipe. Requires one-time extension install; the `debugger` permission shows a scary-but-expected warning. |
| **Files** | Direct filesystem APIs (Python `pathlib`, `shutil`) | No permission needed beyond OS user rights. Sandboxing to allowed roots is *our* job. |
| **Email** | IMAP/SMTP (app passwords), **Gmail API** (OAuth), **Microsoft Graph** (OAuth) | Gmail API scopes: `gmail.readonly`, `gmail.send`, `gmail.compose`… — these are *restricted scopes* requiring Google's verification for public apps; for personal/"testing" OAuth the app stays unverified with a user cap (~100), which is fine for a personal agent. Graph needs an Azure app registration with delegated `Mail.ReadWrite`/`Mail.Send`. App passwords work but are being phased out across providers. |
| Shell / CLI tools | Subprocess execution | Any CLI tool becomes an agent tool for free. Must sandbox: allowlists, timeouts, resource limits. |

#### Control plane 2 — OS accessibility trees (semantic UI control of native apps)

| OS | Mechanism | Permissions required |
|---|---|---|
| Windows | **UI Automation (UIA)** via `pywinauto` / FlaUI / WinAppDriver | None beyond normal user rights; UAC elevation only for privileged apps. Win32 apps also reachable via win32 API; older apps via MSAA. |
| macOS | **AXUIElement** accessibility API (e.g. via `pyobjc` + AX APIs, or `osascript`/AppleScript + System Events) | User must grant per-app in **System Settings → Privacy & Security**: **Accessibility** (UI reading + synthetic input via CGEvent), **Automation** (Apple Events, per target app), **Screen Recording** (macOS 10.15+, for screenshots), optionally Full Disk Access. Re-grant after significant app re-signing. |
| Linux | **AT-SPI2** accessibility tree (`pyatspi` / `at-spi2`) | X11: works freely. Wayland/GNOME: enable the accessibility bus. |

Gives you: enumerate windows/elements, read text & roles, click named buttons, set values —
semantic and reliable for well-built native apps.

#### Control plane 3 — Pixel-level (screenshot + VLM grounding) — the universal fallback

Screenshot (`mss`/PIL/`screencapture`) + synthetic mouse/keyboard (`pynput`/`pyautogui` /
CGEvent / SendInput) + a **vision-language model** to locate elements from the image.
Works on *anything* visible on screen — including canvas apps, games, remote viewers —
but is slow (1–3 s/action), costs inference, and mis-clicks. Anthropic's computer-use
reference implementation (2024) proved the pattern; production systems keep it as the
fallback, not the primary.

**Laptop permission summary:** everything is grantable locally by the user:
macOS TCC grants (Accessibility / Screen Recording / Automation), Windows UAC where needed,
Linux X11 = unrestricted / Wayland = portal prompts (see below). Browser path needs either a
debug port or a one-time extension install. Email needs OAuth consent (or app passwords).

#### Linux Wayland caveat (important if the laptop runs Wayland)

Wayland deliberately has no global input-injection protocol like X11's XTEST. The sanctioned
paths (as of 2025–26):

- **libei + XDG RemoteDesktop portal** (`org.freedesktop.portal.RemoteDesktop` → `ConnectToEIS`) —
  the intended mechanism for emulated input on GNOME/KDE; shows a permission prompt per session.
- **wlroots protocols** (`wlr-virtual-keyboard/pointer`) on Sway/Hyprland/river/Wayfire.
- **KWin scripting** on KDE (window management over D-Bus).
- **`/dev/uinput`** fallback — compositor-agnostic, but no focus awareness; needs a udev rule.

New tools (e.g. `wdotool`, an xdotool-compatible layer over these backends) exist. Practical
consequence: on a Wayland laptop, input injection may trigger portal permission prompts, and
global hotkeys are harder than on X11. Design the input layer as pluggable.

### 3.2 Android — the constrained platform

Android is a hardened sandbox. Three viable control planes exist for a **personal** agent,
plus hard limits that no plane crosses.

#### Control plane A — ADB-driven from the laptop (recommended first)

The phone is driven over USB (or Wi-Fi debugging, Android 11+) using ADB-level APIs:

| Ability | Mechanism | Quality |
|---|---|---|
| Semantic screen state | `uiautomator2` (Python) / `uiautomator dump` — full UI tree: text, resource-ids, content-desc, bounds, clickability | ★★★ the workhorse — coordinates + semantics in one |
| Screenshots | `adb exec-out screencap -p` | ★★★ no on-device consent needed (unlike MediaProjection) |
| Input injection | `adb shell input tap/swipe/text/keyevent`, plus uiautomator2's element actions | ★★★ works in any app (coordinates only via `input`; element-based via u2) |
| Launch apps / deep links | `am start -a android.intent.action.VIEW -d <uri>`, package launch intents | ★★★ |
| App inventory | `pm list packages`, `dumpsys activity`, etc. | ★★★ |
| Read notifications | `dumpsys notification` (limited) | ★★ |
| Files | `adb pull/push` | ★★★ |

**Setup/permissions:** enable Developer Options + USB debugging; accept the RSA
authorization prompt once per host; for wireless use, pairing code once. No app install on
the phone needed at all — this is why it's the right pilot path.

**Limits:** ADB authorization must be re-accepted after revoke/reboot of debug on some
devices; `input text` can't type into some secure fields; secure screens black out
(see hard limits); wireless debugging port rotates (needs discovery).

#### Control plane B — On-device companion app with an Accessibility Service

An ERA-AI Android app (Kotlin) runs on the phone and exposes a control channel to the
laptop brain (local Wi-Fi WebSocket/HTTP, or `adb reverse` tunnel). Its superpowers:

- **AccessibilityService API**: receives `AccessibilityNodeInfo` trees and window-change
  events in real time (richer and event-driven vs polling ADB), performs gestures
  (`dispatchGesture`), `GLOBAL_ACTION` back/home/recents, reads text content.
- **NotificationListenerService**: read notifications (messages, OTPs — sensitive).
- **Foreground service**: keeps the agent alive (required for long-running use);
  battery-optimization exemption needed; OEM task-killer whitelisting (Xiaomi/Samsung/etc.).
- **MediaProjection** for on-device screenshots/VLM — but Android 14+ requires
  **per-session user consent** and a `mediaProjection` foreground-service type; consent
  cannot be cached. (On-device screenshotting is therefore consent-gated each session —
  a UX cost; ADB screencap avoids it.)

**Required user steps (one-time, manual — this is the "price" of Android):**
1. Sideload the APK.
2. On Android 13+, sideloaded accessibility services are blocked by **restricted settings**:
   the user must go to App info → ⋮ → *Allow restricted settings* (with PIN/biometric),
   then enable the service in Accessibility settings. Documented flow, works on
   Pixel/Samsung/OnePlus/Xiaomi with OEM menu differences.
3. Grant notification access, disable battery optimization for the app, optionally
   "Ignore Play Protect" warnings for the sideload.

**Policy reality (why this app must stay personal/sideloaded):**
- Google Play policy states that **any use of the Accessibility API that enables an app to
  autonomously initiate, plan, and execute actions or decisions is strictly prohibited** —
  exactly what an agent is. (Deterministic rule-based automation is allowed; autonomous
  agents are not.) So: distribute to yourself via sideload/GitHub releases, never Play.
- Google's **Advanced Protection Mode** (rolling out through 2026) automatically identifies
  non-accessibility-tool apps via the `isAccessibilityTool` flag and **revokes their
  accessibility permission** when enabled. Don't enable APM on the phone ERA-AI controls.
- **App Functions API (Android 16 / API 36)** — Google's MCP-like registry letting agents
  invoke app functions directly — is real but **`EXECUTE_APP_FUNCTIONS` is restricted to
  system-privileged callers (currently only Gemini)**; third-party agents like ERA-AI
  cannot call other apps' functions yet. Track it; don't depend on it.

#### Control plane C — Hybrid helpers

- **Shizuku**: grants an ordinary app ADB-level shell powers via wireless debugging
  (re-auth after each reboot) — lets the companion app do `input`/`screencap` without
  its own accessibility service. Good fallback if accessibility gets revoked.
- **Termux + termux-api**: on-device Python + SMS/notifications/clipboard APIs (with
  grants). Handy for a fully on-device "lite" agent later; battery/background limits apply.
- **Tasker as a bridge**: ERA-AI sends Tasker intents; Tasker executes proven macros.
  Deterministic, policy-safe, good for "phrases that always do X".
- **Root/Magisk**: full power but **explicitly out of scope** — breaks banking apps,
  Play Integrity, and the daily-driver security model.

#### Android hard limits (no control plane crosses these)

| Limit | Consequence |
|---|---|
| **`FLAG_SECURE` screens** (banking, some payment/OTP screens) | Render **black** in screenshots; often blank in uiautomator dumps. Agent goes blind on exactly the most dangerous screens — arguably a feature. Accessibility can sometimes still read some nodes; policies should treat secure screens as "stop and hand back to human". |
| **Lock screen / biometric auth** | Agent cannot fingerprint-auth for you. Device must be unlocked for UI control (wake + PIN via ADB is possible but means storing the PIN — should be opt-in, encrypted, or never). |
| **Play Integrity / anti-instrumentation** | Some banking/DRM apps detect uiautomator, accessibility services, or debugging and refuse to run. Per-app problem; keep a blocklist. |
| **OTP/2FA flows** | Reading SMS OTPs needs SMS permission (sensitive) — better pattern: agent pauses and asks the human for the code, or uses notification-listener only with explicit grants. |
| **Chrome on Android has no CDP automation surface** | Options: drive Chrome via accessibility/uiautomator (works, semantic-ish since Chrome exposes view nodes), or use `chrome://inspect` over USB (experimental, version-dependent, pages must be open), or run web tasks in an in-app WebView/Custom Tab where CDP-ish control exists. Pragmatic answer: for heavy web work, do it on the **laptop** browser; use phone web only for quick lookups. |
| **Background execution limits / Doze / OEM killers** | Long-running on-device autonomy needs a foreground service + battery exemptions + OEM-specific whitelisting; expect to fight this. |

### 3.3 Capability matrix (summary)

| Capability | Laptop | Android (ADB) | Android (on-device app) |
|---|---|---|---|
| Open apps | ★★★ (a11y/API) | ★★★ (`am start`) | ★★★ (intents) |
| Read screen (semantic) | ★★★ UIA/AX/AT-SPI + DOM | ★★★ uiautomator2 | ★★★ a11y tree (live events) |
| Read screen (visual/VLM) | ★★★ screenshots | ★★★ `screencap` | ★★ consent per session (Android 14+) |
| Tap/click/type | ★★★ | ★★★ `input`/u2 | ★★★ `dispatchGesture` |
| Browser automation | ★★★ CDP/Playwright | ★★ (uiautomator on Chrome UI) | ★★ same |
| Files | ★★★ | ★★★ `pull/push` | ★★ app-scoped by default; SAF/MANAGE_EXTERNAL_STORAGE |
| Email | ★★★ IMAP/APIs | via laptop | ★ possible (Gmail API) |
| Notifications | ★★ per-OS | ★★ `dumpsys` | ★★★ NotificationListener |
| Secure screens | n/a | ❌ blacked out | ❌ mostly blacked out |
| One-time setup cost | Low (local grants) | Low (USB debugging) | **High** (sideload + restricted-settings + grants) |
| Policy risk | None | None | **Play policy blocks distribution; APM revokes** — personal sideload only |

---

## 4. Part III — Target architecture

### 4.1 Principle: brain on the laptop, phone as endpoint

The laptop has the compute, the network freedom, the secrets vault, and the easiest
permissions. The phone is a *controlled device* reached over ADB or the companion app.
Later, an on-device model can take over subset tasks offline.

### 4.2 Layer diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  INTERFACES      CLI (first) · Desktop tray app · Android app UI ·        │
│                  remote approve-from-phone · (later) voice                │
├──────────────────────────────────────────────────────────────────────────┤
│  ORCHESTRATOR    Execution loop (plan→act→observe→replan) · task queue ·  │
│                  session manager · step budget / loop & stuck detection · │
│                  cost caps · background scheduler & triggers              │
├──────────────────────────────────────────────────────────────────────────┤
│  PLANNER (brain) LLM router: fast model for steps, strong model for plans │
│                  · multi-provider adapters (README "Multi-AI") · optional │
│                  local model (llama.cpp) for privacy                      │
├──────────────────────────────────────────────────────────────────────────┤
│  TOOL SYSTEM     Registry · JSON-schema tools · MCP client (reuse the     │
│                  ecosystem) · dry-run · per-tool policy metadata          │
│    Tool families: system │ browser │ files │ comms(email/chat) │          │
│                   android │ knowledge/memory │ shell(sandboxed)           │
├──────────────────────────────────────────────────────────────────────────┤
│  DEVICE ABSTRACTION LAYER — one normalized action vocabulary             │
│    open_app · read_screen(state) · tap(selector|x,y) · type · key ·       │
│    scroll · open_url · launch_intent · get_notifications …                │
│  Adapters: WindowsUIA · macOSAX/AppleScript · Linux(X11/Wayland/AT-SPI) · │
│            BrowserCDP(Playwright) · AndroidADB · AndroidCompanion(a11y)   │
├──────────────────────────────────────────────────────────────────────────┤
│  PERCEPTION      ScreenState fusion: a11y/UIA/DOM tree (preferred) +      │
│                  screenshot+VLM/OCR (fallback) → normalized element list  │
├──────────────────────────────────────────────────────────────────────────┤
│  MEMORY          Episodic (session/step traces) · Semantic (vector store) │
│                  · Procedural (learned, replayable workflows) · Profile   │
│                  (preferences, contacts, rules) · SQLite + sqlite-vec     │
├──────────────────────────────────────────────────────────────────────────┤
│  SAFETY/PERMS    Policy engine (risk tiers, scopes, quotas) · secrets     │
│                  vault · audit log (append-only) · prompt-injection       │
│                  defenses · CONFIRMATION BROKER (CLI/desktop/phone) ·     │
│                  kill switch · sandboxed execution                        │
├──────────────────────────────────────────────────────────────────────────┤
│  OBSERVABILITY   Structured logs · step traces w/ screenshots · replay ·  │
│                  eval harness & task benchmarks                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Core data flow (one task)

```
User goal
  → Planner decomposes → TaskGraph (steps with expected effects)
  → Execution loop picks next step → resolves tools + target device
  → Policy engine classifies action (risk tier T0–T3) & checks scopes
      → T2/T3: Confirmation broker pauses & asks the human (CLI/desktop/phone)
  → Device adapter executes (normalized action → platform API)
  → Perception reads new screen/document state (untrusted-content tagged)
  → Memory writes episode; loop observes vs expectation; replan on mismatch
  → Report + audit entry; optional "learn this as a workflow?" (procedural memory)
```

### 4.4 Key design decisions

1. **Model-agnostic LLM layer.** A thin provider adapter (OpenAI/Anthropic/Google/local
   via llama.cpp or similar). Cheap-fast model for per-step acting; strong model for
   planning and recovery. Matches the README's "Multi-AI support" promise.
2. **Normalized action vocabulary.** The planner reasons over *one* set of actions;
   adapters translate per platform. This is what makes the same brain run a phone and
   three desktop OSes.
3. **Tools carry policy metadata.** Every tool declares risk tier, scope type
   (path prefixes, domains, app packages, contacts), reversibility, and cost. The policy
   engine — not the LLM — decides what needs confirmation. The LLM can *propose*; only the
   policy engine *disposes*.
4. **MCP client early.** Adopting the Model Context Protocol client gives ERA-AI an
   off-the-shelf tool ecosystem (files, search, etc.) and a clean extension story.
5. **Untrusted-content boundary (prompt-injection defense).** Everything read from the
   web, email, or screens is tagged untrusted; the planner is instructed that untrusted
   content is *data, never instructions*; no T2/T3 action derived primarily from untrusted
   content executes without human confirmation. This is the #1 security concern for
   computer-use agents.
6. **Memory: SQLite-first.** One embedded store (episodes, tasks, audit) + a vector index
   (sqlite-vec → upgradeable to Qdrant/FAISS) + plain-files knowledge dir. No server
   dependencies; easy backup; local embeddings option for privacy.
7. **Confirmation UX is a product surface.** Approve from the CLI at first, then a desktop
   dialog, then **approve laptop actions from your phone** (and vice versa) via push.
   Time-limited approvals, per-scope "always allow", full audit of what was approved.
8. **Everything replayable.** Every step stores inputs, screenshots, and outputs so any
   failure can be debugged offline — and later turned into an eval case.

---

## 5. Part IV — Phased development plan

Estimates assume a focused solo developer; part-time roughly doubles them. Each phase ends
with something demoable. **No phase requires the next one to be useful.**

### Phase 0 — Foundation & hygiene (1–2 weeks)
**Goal: make the repo a real project.**
- Restructure into a package (`era/`), fix the audit bugs (duplicate `ERAAI` class,
  module-level REPL launch in `main.py`), add `.gitignore`, `pyproject.toml`, ruff +
  pytest + GitHub Actions, pre-commit.
- Config system: layered settings (defaults < config file < env), secrets kept out of git
  (keyring/env), real logger replacing the print banners.
- Keep the historical modules as thin facades initially, delete once superseded.
**Exit criteria:** `pip install -e .`, `era` CLI starts, tests+lint green in CI.

### Phase 1 — Agent core: LLM, tools, loop, memory, permissions (3–6 weeks)
**Goal: a chat agent that can *act* on the laptop in safe ways.**
- LLM adapter layer + conversation/session management (replaces `chat.py`/`brain.py`).
- Tool system v1: registry, JSON-schema definitions, validation, structured error returns,
  tool-choice policy metadata.
- Memory v1: SQLite persistence, episodic logging, embeddings + retrieval (replaces `memory.py`).
- Permission layer v1: config-defined allow/deny lists, CLI confirmation prompts,
  append-only audit log, kill switch (Ctrl+C-safe interrupt), step/cost budgets.
- First tools: `web.fetch`/`web.search` (honest replacement of `research.py`), `fs.read/
  write/list` (scoped to a sandbox dir), `shell.run` (allowlisted commands), `sys.open_app/
  open_url`.
- Execution loop v1: ReAct-style plan→act→observe, max-steps, loop detection, final report.
**Exit criteria:** "Search X, save a summary to notes.md" runs end-to-end with audit trail.

### Phase 2 — Browser operator (laptop) (4–8 weeks, overlaps Phase 1 tail)
- Playwright/CDP tool suite: navigate, click, fill, extract, tabs, downloads, waits;
  session profiles (persistent logins); screenshot evidence.
- Page-state summarizer: DOM → compact element list for the planner.
- Web task policies: domain allowlists, form-submit & purchase confirmations,
  credential autofill only from the vault with explicit confirmation.
- Optional later: Chrome extension + native messaging to operate the *user's real* browser
  with its logins.
**Exit criteria:** "Log into site X, fill form Y, draft (not send) the submission" works.

### Phase 3 — Desktop operator (laptop) (6–10 weeks)
- Device abstraction layer formalized; input+screen backends per OS:
  Windows (UIA/pywinauto + SendInput + mss), macOS (AX + AppleScript + CGEvent + TCC
  permission wizard), Linux (X11/xdotool + AT-SPI; Wayland via libei/portal + wlr/uinput).
- VLM grounding fallback: screenshot → element detection → coordinate actions, with
  confidence thresholds and human-check on low confidence.
- Window management, multi-app flows, "permission wizard" that checks/guides OS grants.
- Desktop confirmation dialog + tray app.
**Exit criteria:** "Open LibreOffice, summarize this file, save as PDF in Documents" on all
three OSes (start with the user's own OS).

### Phase 4 — Communications: email, files, documents (4–8 weeks, can parallel Phase 3)
- Email: IMAP/SMTP baseline; Gmail API/Graph OAuth with vaulted tokens; read/search/
  summarize/draft/send (send = always-confirmed T2); attachments; anti-injection rules
  for email content.
- File organizer: rule + LLM classification over directories (trash-first, never delete).
- PDF/document understanding (README promise): extraction + summarization + Q&A.
- Calendar/notes integrations as plugins.
**Exit criteria:** "Summarize today's important mail, draft replies for my approval."

### Phase 5 — Android pilot (8–12 weeks)
**Track A — ADB-driven (start here, ~first half):**
- Device manager: USB/wireless pairing, trusted-host keys, connection health.
- AndroidADB adapter: uiautomator2 screen state, `input` taps/swipes/typing, `am start`/
  deep links, `pm` inventory, `screencap`, `pull/push`.
- Phone policies as **strictest tier**: messaging/purchases always confirmed; per-app
  blocklists (banking apps = never touch); secure-screen detection → graceful stop.
**Exit criteria:** "On my phone, open WhatsApp, send <draft> to <contact>" — with the send
confirmed from the laptop/CLI — and "read my notifications and summarize."

**Track B — On-device companion app (second half):**
- Kotlin app: foreground service + WebSocket/HTTP control channel (Wi-Fi LAN and
  `adb reverse`); AccessibilityService for live node trees + gestures;
  NotificationListenerService; optional MediaProjection (per-session consent) for VLM.
- Sideload + "Allow restricted settings" + grants onboarding wizard; battery-optimization
  exemption guide per OEM; Shizuku fallback mode.
- **Never Play-distributed** (policy: autonomous a11y use is prohibited) — personal
  builds only. Keep APM off the phone.
**Exit criteria:** phone tasks run with the on-device agent while the laptop is on the
same LAN; approve-from-phone for laptop actions.

### Phase 6 — Autonomy & memory maturity (ongoing)
- Background/scheduled tasks & triggers (new-mail → triage → notify; morning brief).
- Procedural memory: record successful task traces → replayable parameterized workflows
  (deterministic replay, no LLM in the loop for repeats = fast, cheap, safe).
- Cross-device orchestration (phone screenshots feeding laptop VLM, etc.).
- Self-eval harness, regression benchmarks, failure replay debugger.
- Optional on-device small model (llama.cpp/mediapipe-class) for offline/low-latency
  assists; optional voice interface.
- Hardening: sandboxed execution containers, network egress rules, tamper-evident audit.

### Suggested milestone demos (motivation anchors)
1. M1 (end P1): "Research X and write notes.md" — autonomous, audited.
2. M2 (end P2): fills a real web form with confirmation.
3. M3 (end P3): native-app document workflow.
4. M4 (end P4): morning email brief with drafted replies.
5. M5 (end P5A): sends a WhatsApp message from your laptop via your phone (confirmed).
6. M6 (end P5B): same, with the on-device app over Wi-Fi; approve desktop actions from phone.

**Realistic total:** ~6–9 months focused part-time work to reach M5; the core (P0–P2)
is achievable in the first 2–3 months.

---

## 6. Part V — Safety, permissions & confirmation design

### 6.1 Action risk tiers (enforced by the policy engine, not the LLM)

| Tier | Definition | Examples | Default behavior |
|---|---|---|---|
| T0 | Read-only, no side effects | screenshot, read screen, list files, fetch page, search | auto-allowed (logged) |
| T1 | Reversible/low-stakes writes | create file in sandbox, open app/URL, draft email, download | auto-allowed with quotas |
| T2 | External side effects | send email/message/post, form submit, install, delete-to-trash, purchase under cap | **confirmation required** (rememberable per-scope) |
| T3 | Irreversible / high-stakes | permanent delete, payments/money transfers, permission changes, mass ops, disclosing secrets, any banking-app interaction | **always confirm**, never rememberable, two-step describe-back |

### 6.2 Grant model
- Scopes: tool × target (path prefixes, domains, Android package names, email contacts).
- Grant lifetime: once / session / always-this-scope. T3 never gets "always".
- Quotas: actions/hour, spend/day, steps/task — hard caps independent of the LLM.

### 6.3 Confirmation broker
One subsystem, many fronts: CLI prompt → desktop dialog → phone push-approve.
Confirmation messages show: intended action, target, the *evidence* (screenshot/excerpt),
and a plain-language consequence line. Time-limited; auto-deny on timeout.

### 6.4 Audit & kill switch
- Append-only JSONL: every action, inputs, policy decision, human approvals, outputs,
  screenshot refs. Replayable.
- Global kill switch: hotkey + phone action; loop halts at next step boundary; in-flight
  T2/T3 aborted.

### 6.5 Prompt-injection defense (the agent-specific threat)
Web pages/emails/screens can contain "ignore your instructions and…" text. Countermeasures:
content provenance tagging; system-prompt separation of instructions vs observations;
policy engine independent of the LLM; T2/T3 actions triggered *primarily by untrusted
content* always escalate to human confirmation; egress & scope limits cap blast radius.

### 6.6 Secrets
OS keyring-backed vault; OAuth tokens stored encrypted; the LLM never receives raw
credentials — tools reference them by name and inject at the API layer only.

---

## 7. Part VI — Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| VLM/pixel grounding errors compound over long tasks | High | Prefer trees/DOM; step budgets; verification checks; confirm-before-irreversible; procedural replay for repeats |
| Android accessibility policy tightening (APM revocations, Android 17 changes) | Medium–High | ADB + Shizuku + Tasker fallbacks; sideload-only distribution; watch App Functions API maturing into third-party access |
| Prompt injection via web/email | High | §6.5 controls; assume compromise of observed content |
| OAuth verification friction (Gmail restricted scopes) | Medium | Personal/unverified OAuth caps (~100 users) are fine; IMAP fallback |
| Cost runaway (LLM/VLM per-step) | Medium | Model routing, caching, budgets, deterministic replays |
| Privacy: screens/email to cloud models | Medium | Local-model option for perception/planning; redaction before VLM; on-device path |
| OS updates breaking input/capture (macOS TCC re-prompts, Wayland portals, Android 14+ MediaProjection consent) | Medium | Permission wizard health-checks; per-OS integration tests |
| Banking/secure apps & Play Integrity | Certain (by design) | Per-app blocklists; "hand back to human" UX for secure screens |
| Solo-dev scope creep | High | Phase gates with demo milestones; MCP reuse; resist rebuilding what libraries provide |

---

## Appendix A — Dependency shortlist (future phases, not yet added)

| Layer | Candidates |
|---|---|
| LLM access | provider SDKs or a router (e.g. litellm); llama.cpp bindings for local |
| CLI/UI | typer, rich; later textual/tauri or Electron tray; Android: Jetpack Compose |
| Tools/schema | pydantic; MCP client SDK |
| Browser | playwright (+ CDP attach), selenium fallback |
| Desktop control | pyautogui/pynput/mss (cross), pywinauto (Win), pyobjc+osascript (mac), pyatspi + ydotool/wdotool/uinput (Linux) |
| Android | adbutils, uiautomator2 (laptop-driven); Kotlin app: AccessibilityService, Shizuku API |
| Email | imap-tools, google-api-python-client (Gmail), msal/requests (Graph) |
| Memory | sqlite + sqlite-vec (→ FAISS/Qdrant later); sentence-transformers (local embeddings) |
| Safety/infra | keyring, structlog, pytest, ruff, docker (sandboxed exec) |

## Appendix B — Open-source projects worth studying (references, not dependencies)

- **Anthropic computer-use demo** — canonical VLM screenshot→action loop pattern.
- **browser-use / Skyvern** — LLM browser operation, DOM state summarization.
- **Open Interpreter / OS-Copilots** — local tool-execution agent UX and permission models.
- **AutoDroid / MobileAgent research lines** — phone UI agents over a11y trees.
- **DroidRun** — Android a11y-driven agent app (closest to Track B).
- **Tasker + AutoInput, Shizuku** — study their grant flows and gesture APIs.
- **MCP ecosystem** — tool schemas to reuse rather than reinvent.

---

*This document is a plan only. No source code has been added, modified, or removed as part
of this analysis. Implementation begins with Phase 0 upon approval.*
