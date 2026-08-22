# ERA-AI — Architecture Audit & Development Roadmap (V1 → Final Personal AI Agent)

*Status: audit + **Phase 2A delivered**. Test baseline: `259 passed` on `main` (Phase 2A landed).
**Phase 3A (MVEA — Minimum Viable ERA Agent) delivered** on top of 2A: agent loop, planner,
task manager, real Workspace/Web providers, verification, memory, approval-gated execution and
budget controls — `359 passed`. **Phases 3B (streaming chat + LLM hardening), 3C (credential
vault + SMTP), 3D (GitHub + code-exec sandbox), 3E (web chat dashboard), **3F
(PostgreSQL scale, Alembic, signed audit, rate limits, durable circuit state)**,
and **3G (replay-safe idempotent execution + durable background job queue + legacy cleanup)** are
delivered on top. See [AGENT_AUDIT_AND_PLAN.md](AGENT_AUDIT_AND_PLAN.md) for the
full agent-transformation audit and roadmap (supersedes §D–§E for agent work).*

---

## A) CURRENT V1 CAPABILITIES (what is fully implemented and working)

The Phase 1C–1F work built a **provider-agnostic security and execution foundation** — it is not yet a functional agent, but it is a genuinely solid, well-tested platform layer.

### Fully implemented (all under `era/`)

| Area | What works | Files |
|---|---|---|
| **Permission engine** | Pure, side-effect-free `(action, policy) -> Decision`; fail-closed on unknown action / missing / malformed policy; `FORBIDDEN` is override-proof | `era/services/permission_engine.py` |
| **Action catalog** | ~35 catalogued action types across `core`, `web`, `email`, `whatsapp`, `booking`, `file`, `device` domains, each with a risk tier and declared `secret_fields` | `era/registry/actions.py` |
| **Policy versioning** | Versioned, audited policy store; seeded with a safe fail-closed default (`SAFE/SENSITIVE=ALLOW`, `COMMUNICATION/MUTATING=CONFIRM`, `FINANCIAL/BOOKING/DESTRUCTIVE=CONFIRM_STRONG`, `FORBIDDEN=DENY`) | `era/services/policy.py`, `era/models/policy.py` |
| **Fail-closed execution** | Two-phase model: authorization durably committed **before** provider dispatch; result recorded after; providers never hold a DB transaction; engine/service is the *only* route to execution | `era/services/execution_service.py` |
| **Confirmation flow** | Single-use, TTL-bound, action-hash-bound approvals; `CONFIRM_STRONG` requires a challenge phrase; approve/deny/expire lifecycle | `era/services/confirmation_service.py` |
| **Append-only audit log** | SHA-256 hash-chained + optional HMAC/Ed25519 signatures; DB-level `BEFORE UPDATE/DELETE` triggers; `verify` checks links and signatures | `era/security/signing.py`, `era/repositories/{sqlite,postgres}.py`, `era/api/routes/audit.py` |
| **Secret redaction** | Deep redaction of `secret_fields` + conservative key-name hints before audit/persistence | `era/security/redaction.py` |
| **Provider SPI** | `ToolProvider` (sync) + `AsyncToolProvider` (async) protocols, bidirectional adapters, `ToolRegistry` with duplicate rejection and auto-adaptation | `era/core/tool_provider.py`, `era/core/async_provider.py`, `era/core/tool_registry.py` |
| **Provider reliability** | Error taxonomy (`ProviderErrorCode`), bounded deadline-aware retry, per-provider circuit breaker, hard wall-clock timeouts (sync + async) | `era/core/result.py`, `era/core/retry.py`, `era/core/circuit_breaker.py`, `era/core/timeout.py` |
| **Provider introspection** | Non-secret `ProviderInfo` metadata, registry listing, `/v1/providers` endpoints | `era/core/provider_info.py` |
| **LLM interface (abstract)** | `LLMProvider`, `AgentInterface`, `ToolCall` structural contracts; enforced boundary that agents receive *only* the ExecutionService | `era/core/llm.py`, `tests/test_agent_interface.py` |
| **REST API** | FastAPI app factory; evaluate/execute actions, confirmations, audit read+verify, policy read/update, provider listing | `era/api/*`, `era/main.py` |
| **Storage abstraction** | Complete repository protocols with URL-selected SQLite/PostgreSQL implementations and Alembic migrations | `era/repositories/*`, `era/migrations/*` |
| **Config** | Pydantic-settings `Settings`, env-prefixed (`ERA_`), bounded safe defaults | `era/config.py`, `.env.example` |
| **Tests** | **225 tests, all passing** (permission matrix, security regression, confirmation, dispatch boundary, fail-closed, provider contract, retry, circuit breaker, async, reliability integration, API) | `tests/` |

---

## B) MISSING CAPABILITIES

### B1. Only stubs / placeholders (present but no-op)
- **`StubProvider`** — registers for *every* catalogued action type and returns a canned success. Every "real" capability (web, email, whatsapp, booking, file, device) is currently this no-op.
- **`MockLLMProvider`** — fixed canned response; no real model.
- **`AgentInterface`** — a `Protocol` only; **no concrete orchestrator/agent loop exists.**
- **Container `llm_provider`** — hardcoded `None`.
- **Legacy top-level prototype** (`agent.py`, `brain.py`, `chat.py`, `config.py`, `main.py`, `memory.py`, `research.py`) — dead/duplicated prototype (e.g. `chat.py` and `agent.py` both define `ERAAI`; `main.py` runs a blocking `input()` loop). Excluded from ruff; not part of `era/`.

### B2. Completely missing
- **Real LLM integration** (OpenAI / Anthropic / local) and a **real multi-turn tool-calling agent loop** (model → tool-call → execution → feed results back → stop).
- **Real credential store / vault** — the opaque-ref credential *contract* is excellent, but nothing actually stores or resolves secrets.
- **Real providers:** Web (search/fetch/download), Email, WhatsApp, Booking, File/Photo (filesystem), Android/Device.
- **User authentication & authorization (RBAC)** on the API — **there is none**.
- **UI** (web chat / dashboard) in the new architecture.
- **Memory / long-term knowledge store** — new architecture has none (legacy `memory.py` is just an in-memory list).
- **Task planning, background workers / job queue**, streaming responses.
- ~~**PostgreSQL implementation + DB migrations**~~ — delivered in Phase 3F.
- **Input/schema validation** for action params (declared `param_schema` is unused).
- ~~**Rate limiting / abuse protection**~~ — delivered in Phase 3F (content-size guards landed in 2A).
- ~~**Cryptographic signing of audit entries**~~ — HMAC-SHA-256 + Ed25519 delivered in Phase 3F.

---

## C) ARCHITECTURAL PROBLEMS (friction for future tools/integrations)

1. **No authentication / authorization / identity on the API (critical).** `era/api/deps.py` returns the container directly; `actor_id` is client-supplied and spoofable. Anyone who can reach the endpoint can execute actions, approve confirmations, read the audit log, or **rewrite policy**. This must be fixed before any real-world capability ships.
2. **No credential store.** The secure boundary (opaque `credential_ref`s, providers own secrets) is designed well, but with no vault there is nowhere for a real provider's API keys/OAuth tokens to live or be resolved.
3. **`StubProvider` claims every action type.** Because `ToolRegistry.register` rejects duplicate `action_type`s, a real provider cannot take over an action type until `StubProvider` is withdrawn from it. Worse, today a real-ish action *silently* returns stub success. Registration needs an allowlist/ownership policy.
4. **No real agent loop.** Only a structural interface + one 2-line test agent. No multi-turn orchestration, tool-result feedback, loop termination, or model wiring.
5. ~~**`param_schema` declared but unused**~~ — resolved in Phase 3H (consolidated authoritative `ACTION_PARAM_SCHEMAS`, fail-closed validation enforced before provider dispatch in ExecutionService).
6. **`web.fetch`/`web.download` have a recognized SSRF surface with no guard implemented** (no URL scheme/private-range/DNS-rebinding protection).
7. **File/photo & device paths are arbitrary** — no path sandboxing / traversal guard for `fs.*` / `photo.*`.
8. **Confirmation approval is not bound to the requesting actor/session** — anyone knowing a confirmation id can approve it.
9. ~~**No idempotency keys** on execute~~ — resolved in Phase 3G (idempotency keys on execute: replay returns the recorded result, never re-dispatches).
10. ~~**Audit chain is not cryptographically signed**~~ — resolved in Phase 3F (HMAC/Ed25519).
11. ~~**No migration framework**~~ — resolved in Phase 3F (Alembic upgrade/downgrade).
12. ~~**Reliability state is in-memory only**~~ — resolved in Phase 3F (SQL-backed circuit state).
13. ~~**Dead legacy prototype files**~~ — resolved in Phase 3G (removed from the repo root; the ruff exclude that was also shadowing real `era/` modules by basename is gone).
14. ~~**No background workers / async job queue**~~ — resolved in Phase 3G (`POST /v1/actions/execute` with `async=true` + durable `GET /v1/jobs`).

---

## D) PROPOSED PHASES (foundation first, integrations after)

Priority rule: **secure, identity-gated core first; external integrations only after the foundation is complete.** Each phase is independently shippable and tested.

| # | Phase | Goal | Likely files/modules | Depends on | Security considerations | Tests required | User capability gained |
|---|---|---|---|---|---|---|---|
| **2A** | **Foundation security: AuthN + AuthZ + identity + input hardening** | Make the API safe to expose: real actor identity, API auth (tokens/sessions), RBAC (who may do what), actor-bound confirmations, schema/size validation. **✅ DELIVERED (see §Phase 2A deliverable).** | `era/api/deps.py`, `era/api/routes/*`, `era/services/auth_service.py`, `era/security/rbac.py`, `era/security/validation.py`, `era/api/middleware.py`, `era/models/user.py`, `era/repositories/*`, `era/schemas/*`, `era/cli.py` | 1C–1F | API keys stored as SHA-256 hashes (raw shown once); confirmations bound to requester; param/size caps; body-size limit; no actor spoofing; RBAC outer gate over the permission engine | AuthN tests, RBAC matrix, actor-bound confirmation tests, schema/unknown-field/oversize tests, security regressions | A usable, authenticated personal-agent API surface |
| **2B** | **Credential vault + provider secrets** | Real secure secret store; per-actor/provider credential refs; provider config | new `era/security/vault.py`, `era/models/credential.py`, new credential repo/schema, `era/services/credential_service.py`, provider config loading | 2A | Secrets at-rest encrypted; never logged/redacted; refs never resolved in core; rotation | Vault tests, at-rest encryption tests, ref-boundary tests, rotation tests | Providers can finally resolve real credentials safely |
| **2C** | **Real LLM + agent orchestrator** | Implement `AgentInterface`: multi-turn tool-call loop with a real `LLMProvider` (OpenAI/Anthropic/local); conversation state; loop termination | `era/agents/` (new orchestrator), `era/providers/llm_*`, `era/core/llm.py` (extend), `era/schemas/agent.py`, new chat/conversation repo | 2A, 2B | LLM carries no secrets; every tool call routed through ExecutionService; prompt-injection / tool-arg validation; output redaction | Orchestrator unit tests, tool-loop tests, injection-resistance tests, boundary tests | A real conversational agent that plans and calls tools |
| **2D** | **Web provider (search/fetch/download) + File/Photo provider** | First real tools: SSRF-safe web + sandboxed filesystem | `era/providers/web.py`, `era/providers/filephoto.py`, `era/security/url_safety.py`, `era/security/path_safety.py`; **withdraw web/fs/photo actions from StubProvider** | 2A, 2B | SSRF guards (scheme allowlist, private-range block, DNS-rebinding), path sandboxing, size limits, `web.download`/`fs.write` need confirmation | SSRF tests, traversal tests, provider-contract tests (reuse `tests/provider_contract.py`) | Agent can search the web and read/write sandboxed files |
| **2E** | **Email + WhatsApp providers** | Real communication; OAuth/token flows using vault; confirmation-gated sends | `era/providers/email.py`, `era/providers/whatsapp.py`; withdraw from stub; maybe `era/services/oauth.py` | 2A–2D | OAuth token handling, scoped delegation, all `email.send`/`whatsapp.send` CONFIRM-gated (already in catalog), PII redaction | Provider-contract tests, OAuth tests, send-confirmation tests | Agent can draft/send email and messages with user approval |
| **2F** | **Booking provider** | Real booking search/hold/confirm/cancel with strong confirmation | `era/providers/booking.py`; withdraw from stub | 2A–2E | `CONFIRM_STRONG` enforced, payment-token redaction, cancellation safety | Booking flow tests, strong-confirmation tests | Agent can help search/hold/book travel |
| **2G** | **Device (Android) provider** | On-device automation: shell/app/UI/notification/location/contacts (separate capability boundary) | `era/providers/device.py` (or separate on-device agent); withdraw from stub | 2A–2F | High-risk domain: strong confirmation for shell/delete/payment; pairing-token security; location/contacts privacy | Device action tests, pairing tests, privacy tests | Agent acts on the user's device with strong gating |
| **2H** | **Memory + task planning + background workers** | Long-term knowledge store, task/job queue, scheduled work | new `era/memory/`, `era/tasks/`, worker entrypoint; new repos/models | 2A–2D | Memory encrypted/redacted, retention policy, task permissions | Memory tests, task/queue tests, worker tests | Agent remembers across sessions and runs background work |
| **2I** | **UI + streaming** | Web chat/dashboard frontend; streaming responses | new `era/web/` or `web/` frontend, streaming endpoints, SSE/WebSocket | 2A–2H | Same auth as API; no secret leakage to UI; CSP | UI E2E tests, streaming tests | A real personal-assistant interface |
| **2J** | **Scale: PostgreSQL + migrations + signing — ✅ DELIVERED as Phase 3F** | Postgres backend, Alembic migrations, keyed audit signing, rate limits, persistent circuit state | `era/repositories/postgres.py`, Alembic setup, `era/security/signing.py` | all | Signed audit chain, migration safety, key management | Postgres integration tests, migration tests, signing tests | Production-grade durability and scale |

### Sequencing rationale
- **2A first** — nothing real-world should be reachable without identity/auth; it also removes the dead prototype.
- **2B before any real provider** — providers can't exist without a place to keep credentials.
- **2C before/with 2D** — the agent loop is the "brain" that makes tools useful; start wiring real tools (web/file) once the loop exists.
- **2E–2G after** — external communication/booking/device integrations only on the hardened foundation.
- **2H–2J** — value-add (memory/UI) and scale after core capability is real.

---

## E) RECOMMENDED NEXT PHASE

**→ Phase 2B — Credential vault + provider secrets.**

Phase 2A is delivered. The recommended next phase is the secure credential vault so real providers can resolve credentials safely.

## § Phase 2A deliverable (implemented)

Shipped as a single branch; **`259 passed`**, ruff clean. No Phase 2B+ work included.

- **Authentication** — `Authorization: Bearer <api-key>`; API keys stored as SHA-256 hashes, raw key shown exactly once (CLI/API). `era/services/auth_service.py`, `era/models/user.py`, `era/security/validation.py`, `era/cli.py`.
- **Server-side identity** — actor/session derived from the authenticated principal (`era/api/deps.py`); client-supplied `actor_id`/`session_id`/`credential_refs` removed from request schemas and rejected (`extra='forbid'`).
- **Authorization (RBAC)** — roles `admin`/`user`; permission matrix + capability-domain allowlist (`era/security/rbac.py`). Audit/policy-write/user&key management are admin-only; `device.*` is admin-only.
- **Protected endpoints** — execute/evaluate, confirmations (actor-bound), audit, policy, providers, and new admin user/key endpoints all require auth + permission (401/403).
- **Actor-bound confirmations** — `PendingConfirmation.actor_id`; only the initiating actor can approve/deny.
- **Input hardening** — strict schemas (`extra='forbid'`), action-type + param budget validation, body-size limit middleware (413).
- **CLI** — `python -m era.cli create-admin|create-user|add-key|list-users|disable-user|revoke-key`.
- **Tests** — new `tests/test_auth.py`, `test_authorization.py`, `test_input_hardening.py`, `test_confirmation_actor_bound.py`; updated `test_api.py` to be authenticated; original security suites unchanged and passing.

### Remaining (future phases)
Credential vault (2B), real LLM/agent loop (2C), real providers (2D–2G), memory/workers (2H), UI (2I), scale/Postgres/signing (2J). Rate limiting / abuse throttling and the legacy prototype archive remain TODO in a later hardening pass (2A focused on identity + input hardening as scoped).

---

## § Phase 3H deliverable (implemented)

Delivered:
- **`param_schema` enforcement & single source of truth**: Consolidated authoritative `ACTION_PARAM_SCHEMAS`, fail-closed validation before provider dispatch in `ExecutionService`.
- **Scheduled and recurring jobs**: `Schedule` model with Alembic migration `0004_phase_3h_schedules`, lightweight 5-field cron parser / interval evaluator, in-process scheduler worker, and actor-scoped `/v1/schedules` REST API.
- **Website Builder capability**: Natural language goal parsing (Hinglish/Hindi/English), multi-page mobile-first static generator, SVG favicon, SEO meta tags, contact forms, 0 broken internal links link-verifier, and zip packaging export.
- **Official Meta Cloud API / Twilio WhatsApp provider**: Text/template messaging, reaction, read, vault-resolved tokens (`vault:whatsapp/token`), and standardized error taxonomy mapping.
- **Image Generation provider (`image.generate`)**: OpenAI Images / Stability / compatible endpoint support, safe workspace confinement, and graceful offline fallback.
- **IRCTC / Travel Booking safe draft model**: Safe search + draft hold + `CONFIRM_STRONG` approval challenge for booking and cancellations; connects through official B2B partner APIs.

---

## § Phase 4A — Self-Hosted Browser Automation (implemented)

Phase 4A delivers secure dynamic-site automation through self-hosted Playwright
Chromium without creating a second execution path.

### Delivered actions and policy

| Action | Risk | Default gate | Purpose |
|---|---|---|---|
| `browser.navigate` | `SENSITIVE` | `ALLOW` | Open a public HTTP(S) URL after SSRF validation |
| `browser.screenshot` | `SENSITIVE` | `ALLOW` | Save a page/element PNG or JPEG in the workspace |
| `browser.extract_dom` | `SAFE` | `ALLOW` | Return rendered text, Markdown and resolved links; optional HTML dump |
| `browser.click` | `MUTATING` | `CONFIRM` | Click by CSS selector or visible text |
| `browser.fill` | `MUTATING` | `CONFIRM` | Fill an input in the current context |
| `browser.submit` | `MUTATING` | `CONFIRM` | Submit the selected/current form |

All six actions have strict `ACTION_PARAM_SCHEMAS` with
`additionalProperties: false`, belong to the `browser` capability domain and
are available to both `Role.USER` and `Role.ADMIN`. Every call flows through
the existing permission → confirmation → append-only audit → reliability gate.

### Provider and sandbox

- `BrowserProvider` uses a modular `BrowserTransport`; production defaults to
  `PlaywrightBrowserTransport`, while `SimulatedBrowserTransport` provides a
  deterministic, socket-free CI path.
- Playwright runs on a dedicated owner thread so Chromium contexts remain safe
  under ERA's hard-timeout worker-thread boundary.
- Non-persistent contexts are keyed by actor/session, isolating cookies, cache,
  local storage and page state. Shutdown discards all contexts.
- `validate_public_url` runs during validation and immediately before every
  top-level navigation. Chromium request routing rechecks redirects and
  subresources; private/loopback/link-local/metadata addresses, disallowed
  ports/schemes and WebSockets are blocked.
- Screenshots and optional HTML dumps are resolved through `WorkspaceRoot`;
  traversal, absolute paths and symlink escapes are rejected.
- Browser timeout and viewport defaults are bounded at 30 seconds and
  1280×800. DOM output, HTML source, link count and screenshot bytes are capped.

### Agent integration

The offline rule planner recognizes explicit URL screenshot and dynamic/live
extraction requests before the static website-builder rule. New verifier kinds
`screenshot_exists` and `dom_extracted` validate artifacts and structured DOM
results instead of blindly trusting tool success. `build_browser_provider` is
wired into `build_agent_container`.

### Configuration

- `ERA_BROWSER_HEADLESS=true`
- `ERA_BROWSER_TIMEOUT_SECONDS=30.0`
- `ERA_BROWSER_VIEWPORT_WIDTH=1280`
- `ERA_BROWSER_VIEWPORT_HEIGHT=800`
- `ERA_BROWSER_USER_AGENT=ERA-Agent/0.8.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)`

### Validation

The repository baseline collected 600 tests (599 passed + one optional live
PostgreSQL skip). Phase 4A adds **52 tests**; current result is **651 passed, 1
skipped (652 collected)**, with `ruff check .` clean.

---

## § Phase 4A.1 — Browser Security & Reliability Hardening (implemented)

Before moving to wider browser workflows, ERA closes the state and side-effect
ambiguities identified after Phase 4A:

1. **True run isolation:** `ExecutionContext.execution_scope` is derived by the
   server from `run_id`; confirmation revision `0005` preserves it across
   approval requests; terminal runs clean up their ephemeral contexts.
2. **No duplicate interactions:** click/fill/submit opt out of provider retries
   and agent verification retries. Timeout after dispatch is classified as
   `SIDE_EFFECT_UNKNOWN` and quarantines the context.
3. **Cancellable bounded worker:** absolute command deadlines, pre-dispatch
   cancellation, bounded queue, active-context cap and idle reaping.
4. **Secret-safe input:** agent fills use owner-bound
   `vault:browser/<name>` references. Direct plaintext fill is redacted, while
   raw agent-plan fill values are erased and denied before persistence.
5. **Safe result boundary:** all providers now receive centralized JSON/type,
   size and recursive token/key redaction before results can reach responses,
   observations, jobs or idempotency storage.
6. **Egress controls:** optional operator-controlled browser proxy plus Chromium
   QUIC/non-proxied-WebRTC restrictions; application SSRF routing remains
   defense-in-depth, not a replacement for production network namespaces.
7. **Real-browser CI hook:** an opt-in `browser` pytest marker exercises actual
   Playwright navigation, rendered DOM and screenshots when Chromium/network
   are available; default CI remains binary-free.

Version: **0.8.1**. Validation: **683 passed, 2 optional skips, 685 collected**;
`ruff check .` clean. The suite grew by **33 collected cases** over Phase 4A.

---

## § Phase 4B — Reliable Browser Workflows (implemented)

Phase 4B turns browser automation into a stable, inspectable,
drift-resistant, verifiable and fail-closed workflow engine:

1. **`browser.inspect`** (`SAFE`/`ALLOW`): bounded rendered-accessibility
   snapshot (role, accessible name, tag, input type, tab/frame/origin,
   snapshot generation) returning opaque, provider-issued `element_ref`
   tokens.  No CSS selectors or visible-text matching are needed or
   inventable.
2. **Element-reference security**: refs are actor/run-, tab-, frame- and
   snapshot-generation-scoped and TTL-bound; resolution requires exactly one
   fingerprint match or a deterministic `NOT_FOUND`/`CONFLICT` error.
   Navigation, tab close, frame replacement, context close, new snapshots and
   drift invalidate refs; there is never a selector fallback.
3. **Confirmation continuity**: contexts are preserved while waiting; after
   approval the provider revalidates actor/run, tab, frame, origin, page
   state, reference and fingerprint before executing exactly once.  Drift
   during review fails closed.
4. **Non-retryable side effects preserved**: click/fill/submit/download/upload
   are non-retryable; ambiguous timeouts return `SIDE_EFFECT_UNKNOWN` and
   quarantine the context.
5. **Tabs/popups**: opaque tab ids, `browser.tabs`/`browser.activate_tab`,
   bounded popup detection, tab-scoped refs.
6. **Frames**: explicit frame identity, frame-scoped refs, stale-frame
   invalidation, cross-origin frames expose metadata only.
7. **Shadow DOM**: open (incl. nested) shadow roots are inspected and usable,
   with no security relaxation.
8. **Secure downloads/uploads**: workspace confinement, no traversal, size
   bounds, atomic writes, verified artifacts, sanitized receipts.
9. **Prompt-injection defenses**: page content is data, never policy
   (`content_untrusted` flag, planner/brain rules, gate enforcement).
10. **Deterministic post-conditions** (`expect: navigation | tab_opened |
    element_detached`) and sanitized interaction receipts.
11. **Planner integration**: LLM planner and ToolCallBrain prompts encode the
    inspect-first / never-invent-refs / no-retry-of-ambiguous-mutations rules.

No schema migration was required (references are runtime state; the 4A.1
confirmation schema already preserves execution scope).

Version: **0.8.1**. Validation: **732 passed, 3 optional skips, 735 collected**
(50 new Phase 4B cases); `ruff check .` clean; `git diff --check` clean.  The
opt-in real-Chromium E2E (`ERA_TEST_BROWSER=1`) additionally exercises the
inspect → element_ref → click → stale-ref workflow; without Chromium it is
skipped with an explicit reason and never counted as passed.

### Recommended next phase

**Phase 4C — Workflow Automation**: reusable multi-step browser workflows
(login helpers, form pipelines) with persisted step receipts, plus idempotency
for irreversible transactions once a dedicated strong-confirmation design is
delivered.  Payments and irreversible transactions remain outside autonomous
operation.

## § Phase 4C — Durable, Resumable, Exactly-Once Browser Workflows (implemented)

Phase 4C makes the Phase 4B primitives composable into **declarative,
durable, resumable multi-step browser workflows**:

1. **Workflow definition layer** (`era/workflows/`): bounded, strict-schema
   definitions validated at registration time. Steps reference exactly one
   catalogued browser action (an explicit allowlist), with `expect`
   post-conditions (reused from 4B), target-acquisition descriptors resolved
   to *fresh* `element_ref`s by re-inspection, opaque `vault:browser/<name>`
   fills (plaintext password/unknown-sensitivity fills are rejected), and
   `on_denied: stop|skip`.
2. **Catalog / registry integration**: `browser.workflow_run` is catalogued as
   `MUTATING`/`CONFIRM` in `era/registry/actions.py` and appears in the
   permission-matrix, RBAC domain allowlist and default-policy tests. Every
   inner step is still gated independently.
3. **Engine** (`era/services/workflow_service.py`): dispatches every inner step
   **exclusively through `ExecutionService`**; records per-step results; stops
   deterministically on failure/drift/budget; maps `SIDE_EFFECT_UNKNOWN` to an
   `ambiguous` state requiring explicit operator resolution.
4. **Durable run state**: migration `0006` adds `workflow_run` and
   `workflow_step_run` (never raw refs, plaintext values, cookies or page
   content — only redacted intent/params). Fresh DBs reach head; legacy DBs
   upgrade cleanly; downgrade drops only the new tables.
5. **Resumability**: confirmation-pause → approve (existing flow) → resume from
   the durable checkpoint; actor-bound; preserves `execution_scope`; re-inspects
   on resume and never trusts persisted browser state; audit-outcome + post-condition
   revalidation after approval.
6. **Exactly-once**: `run_token` unique per actor; completed/confirmed steps
   never re-run; ambiguous outcomes never auto-continue/retry.
7. **Secrets & injection defenses**: vault-only secret fills; redacted stored
   state (opaque refs preserved); sanitized receipts; page text can never
   define/modify/start a workflow.
8. **Bounded execution**: max steps, max param chars, max wall-clock; cycles /
   unbounded recursion rejected.
9. **Reference workflows**: `login` (tested offline), plus `search_and_extract`
   and `download_report` documentation examples.

New action: `browser.workflow_run` (`MUTATING`/`CONFIRM`).

Version: **0.8.1**. Validation: **765 passed, 3 optional skips, 768 collected**
(33 new Phase 4C cases, including migration tests for `0006`); `ruff check .`
clean; `git diff --check` clean.  The opt-in real-Chromium E2E now also runs a
workflow through the engine on a public page; without `ERA_TEST_BROWSER=1` it
is skipped with an explicit reason and never counted as passed.

## Phase 4D — Workflow Operations & Governance (delivered)

Phase 4D adds the operations layer around the Phase 4C engine:

1. **Scheduling** — `workflow_schedule` reuses Phase 3H cron/interval
   machinery; due runs are started through the same WorkflowService gates with a
   deterministic run token (crash/double-due exactly-once), so a schedule is
   never a confirmation bypass.
2. **Parallel & conditional steps (bounded DAG)** — `depends_on`, `parallel`
   blocks with `max_concurrency`, and pure schema-constrained `condition`
   predicates over prior step receipts. Validation rejects cycles, unknown deps,
   parallel-sibling conditional deps, unbounded fan-out and non-allowed
   predicates. Each step is individually gated.
3. **Governance** — DB-backed concurrency caps, per-window rate limits and
   step/cost budgets; a cap breach starts the run as `FAILED` with a
   machine-readable `governance_code`.
4. **Templates & versioning** — immutable published template versions with
   `params_schema`; a run pins template+version+checksum and fails closed on
   drift.
5. **Operator review** — admin-only awaiting-run listing, run timelines,
   cross-actor resolve/cancel/approve with audit trail and sanitized output.
6. **Observability** — bounded, actor-scoped filtering and aggregation.
7. **Migration** `0007_phase_4d_operations` (additive, backward compatible).

Validation: full offline suite green; `ruff check era tests` clean;
`git diff --check` clean. Real-Chromium E2E remains opt-in
(`ERA_TEST_BROWSER=1 pytest -m browser`); without it the E2E tests are skipped
with an explicit reason and not counted as passed.

### Recommended next phase

**Phase 4E — Strong confirmation & production hardening (delivered)**: see §Phase 4E below.

## Phase 4E — Strong Confirmation & Production Hardening (delivered)

Phase 4E adds the production-hardening layer on top of the Phase 4A–4D browser
and workflow engine:

1. **Dual-approval for FINANCIAL / BOOKING actions** — `CONFIRM_STRONG`
   confirmations on FINANCIAL and BOOKING risk-level actions now require two
   distinct approvals (primary + secondary) before dispatch. The
   `ConfirmationApproval` model tracks each approval with sequence number and
   context hash (IP + UA fingerprint) for non-repudiation. Any single denial
   immediately blocks dispatch. Non-FINANCIAL/BOOKING confirmations retain the
   existing single-approval flow.
2. **DB-backed scheduler leader election** — `SchedulerLeaderService` uses a
   singleton row with optimistic concurrency so exactly one ERA process runs
   scheduler ticks in a multi-worker deployment. Stale-heartbeat takeover,
   graceful release on shutdown, and a `/v1/health` endpoint for monitoring.
3. **Confirmation expiry sweeper** — `ConfirmationSweeper` periodically marks
   overdue PENDING confirmations as EXPIRED (batch-bounded, idempotent).
4. **Health endpoint** — `GET /v1/health` (public, no auth) returns database
   status, scheduler leader info, circuit breaker aggregate and app version.
5. **Operator review UI** — full operator dashboard in the web UI:
   * Tab navigation (Chat / Operator / Workflows)
   * Pending confirmations panel with approve/deny actions
   * Health status display (DB, scheduler leader, version)
   * Workflow runs panel (awaiting attention + recent runs)
6. **Operator review API** — admin-only endpoints for listing pending
   confirmations, viewing approval records, and granting/denying approvals
   with context-hash tracking (`/v1/operator/*`).
7. **New RBAC permission** — `operator.review` (admin-only) gates the operator
   review endpoints.
8. **Migration** `0008_phase_4e_production` — adds `confirmation_approval`
   and `scheduler_leader` tables (additive, backward compatible).
9. **Graceful shutdown** — scheduler leadership is released on SIGTERM.

Validation: full offline suite green (812 passed, 4 optional skips); `ruff check
era tests` clean; `git diff --check` clean. 24 new Phase 4E tests cover
dual-approval, leader election, sweeper, health endpoint, operator API and
migration. Real-Chromium E2E remains opt-in (`ERA_TEST_BROWSER=1 pytest -m
browser`); without it the E2E tests are skipped with an explicit reason and not
counted as passed.

### Recommended next phase

**Phase 5A — Real provider integration**: plug in real Web, Email (SMTP),
WhatsApp (Meta Cloud API), Booking (partner API) and Android device providers,
each under the existing ToolProvider SPI + ExecutionService gate, with the
Phase 4E dual-approval and governance guards applied to their
FINANCIAL/BOOKING/DESTRUCTIVE actions. Cross-process persistent cookies/session
store remains out of scope (browser state stays ephemeral per run with
confirmation-pause continuity).

## Phase 5A — Real Provider Integration (delivered)

Phase 5A upgrades ERA to **0.9.0** and replaces opt-in stub action ownership in
the agent runtime with real provider boundaries:

1. **Web** — DuckDuckGo Instant Answer search, pinned public-HTTPS fetch,
   redirect revalidation, DNS-rebinding/private-address blocking, bounded text
   extraction, and atomic workspace downloads with SHA-256 receipts.
2. **Email** — bounded SMTP delivery plus a separate TLS/read-only IMAP
   provider. SMTP/IMAP credentials resolve from direct env values or opaque
   vault references; body and PII content are redacted before audit persistence.
3. **WhatsApp** — Meta Cloud API text/template/media routing, actor quotas,
   bounded webhook-backed reads, delivery state, challenge-token verification,
   and signed webhook POST validation.
4. **Booking** — official partner API adapter with integer minor units,
   idempotency keys, hold TTLs, no automatic confirm/cancel retry, and
   `SIDE_EFFECT_UNKNOWN` quarantine. The execution path now consumes
   FINANCIAL/BOOKING confirmations only after two distinct approvals.
5. **Android** — paired ADB provider with localhost-or-TLS network constraints,
   no-root shell allowlist, workspace-only artifacts/APKs, caps, and a
   confirmation/dual-approval protected payment companion handoff.
6. **Graceful degradation** — incomplete provider configuration leaves the
   corresponding action types with `StubProvider`; `/v1/providers` identifies
   active real versus stub providers.
7. **Validation** — 928 offline tests collected/passing (4 opt-in skips),
   including a 100+-case provider safety matrix; `ruff check era tests` and
   `git diff --check` clean. No schema migration is required for runtime
   provider configuration.
