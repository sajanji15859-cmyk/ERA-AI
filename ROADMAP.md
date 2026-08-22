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

## § Browser Automation Architecture (Future Design Scope)

### Objective
Enable ERA to navigate, interact with, and extract content from arbitrary modern web applications (SPAs, dynamic dashboards, login-protected portals) through a secure, self-hosted headless browser environment.

### Design Principles
1. **Sandboxed Headless Chromium (Playwright)**
   - Run self-hosted Chromium inside isolated process containers with restricted network namespaces and strict CPU/memory limits.
   - Separate browser sessions per actor with ephemeral browser contexts that are discarded after task completion to prevent cross-session cookie/credential leakage.

2. **Actions & Risk Tiers**
   - `browser.navigate` — `RiskLevel.SENSITIVE`: Navigate to allowed HTTP/HTTPS URLs with SSRF protections (blocking loopback/link-local/private RFC1918 ranges).
   - `browser.screenshot` — `RiskLevel.SENSITIVE`: Capture page viewport screenshots into workspace sandbox.
   - `browser.extract_dom` — `RiskLevel.SAFE`: Extract structured accessibility tree / text content.
   - `browser.click` / `browser.fill` — `RiskLevel.MUTATING`: Interactive page inputs (approval-gated when on external origin).
   - `browser.submit_form` — `RiskLevel.MUTATING`: Submit actions (approval-gated).

3. **Security Invariants**
   - Headless browser never accesses master credential vault directly — session credentials/cookies are injected through ephemeral context handles.
   - Path containment for downloaded assets and screenshots via `WorkspaceRoot`.
   - Timeout and resource caps: strict per-navigation wall-clock budget (30s default).
