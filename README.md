# ERA AI

## Vision

ERA AI is a personal artificial intelligence assistant designed to help with knowledge, research, productivity, reasoning, automation and daily digital work.

Its goal is not to be just another chatbot, but to become a long-term intelligent assistant that can grow over time.

## Core Capabilities

- Research from reliable sources
- Philosophy, science, history and technology analysis
- PDF and document understanding
- Email assistance
- Writing and summarization
- Memory and knowledge management
- Task planning
- Automation
- Multi-AI support

## Long-Term Goal

ERA AI will evolve into a complete digital assistant capable of helping with learning, thinking, organizing information and assisting in everyday work.

---

## Phase 1C — Permission Engine + Append-Only Audit Log

Phase 1C builds the **security and action-execution foundation** for a
general-purpose, provider-agnostic personal AI agent (web search, LLM inference,
email, messaging/WhatsApp, ticket/booking, file/photo operations, and eventually
Android/device automation). It is the stable boundary every future capability
plugs into — **not** the capabilities themselves.

### What it provides

- **Permission engine** — a pure, side-effect-free evaluator
  `(action, policy) -> Decision` with risk tiers (`SAFE`, `SENSITIVE`,
  `COMMUNICATION`, `MUTATING`, `FINANCIAL`, `BOOKING`, `DESTRUCTIVE`,
  `FORBIDDEN`) and policy outcomes (`ALLOW`, `CONFIRM`, `CONFIRM_STRONG`,
  `DENY`). Defaults are **fail-closed**: unknown actions, missing/malformed
  policy, and any ambiguity are `DENY`.
- **Append-only, tamper-evident audit log** — every decision and outcome is
  recorded, hash-chained (SHA-256), and protected at the DB level by
  `BEFORE UPDATE/DELETE` triggers. A `verify` endpoint recomputes the chain.
- **Confirmation flow** — single-use, TTL-bound, action-hash-bound approvals,
  with a challenge phrase for `CONFIRM_STRONG` (financial/booking/destructive).
- **Provider SPI (`ToolProvider`)** + **ToolRegistry** — the extension point for
  Web, Email, WhatsApp, Booking, File/Photo, and Android device providers. Only
  a `StubProvider` is wired in 1C.
- **Abstract `AgentInterface` / `LLMProvider`** — the future model → tool-call
  loop (only a `MockLLMProvider` in 1C). Every model-proposed tool call must
  route through the ExecutionService gate.
- **Strict secret/credential boundary** — the agent/LLM layer and the
  permission/audit core never touch raw API keys, OAuth tokens, or passwords.
  Providers own credential access; the core sees only opaque references.

### Two-phase execution model

External provider work never holds a database transaction open:

1. **Authorize** — evaluate, then durably persist the authorization state to the
   audit log **and commit** (one transaction). If this write fails, the action
   is *not* executed (fail closed).
2. **Dispatch** — invoke the provider *outside* any DB transaction.
3. **Record** — append the resulting `EXECUTED` / `FAILED` / `REJECTED` event in
   a fresh transaction.

The invariant: **an action executes iff it was positively authorized *and* that
authorization was immutably recorded.**

### Layout

```
era/
├── core/          # provider-agnostic platform layer (Action, ToolProvider SPI,
│                  #   ToolRegistry, AgentInterface/LLMProvider, enums)
├── registry/      # the authoritative action catalog (types, risk tiers, domains)
├── providers/     # StubProvider + MockLLMProvider (real providers arrive later)
├── models/        # SQLAlchemy ORM models (audit, confirmation, policy)
├── schemas/       # Pydantic request/response models
├── services/      # permission engine, execution, confirmation, audit, policy
├── repositories/  # storage protocols + SQLite implementation (Postgres later)
├── security/      # canonical hashing, redaction, append-only triggers
└── api/           # FastAPI routes
```

### Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn era.main:create_app --factory
```

### Test

```bash
pytest
```

### API (summary)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/actions/evaluate` | dry-run decision (no side effects) |
| POST | `/v1/actions/execute` | evaluate → allow / deny / confirm |
| GET | `/v1/confirmations/{id}` | confirmation status |
| POST | `/v1/confirmations/{id}/approve` | approve (+ challenge if strong) |
| POST | `/v1/confirmations/{id}/deny` | deny |
| GET | `/v1/audit` | list / filter (read-only) |
| GET | `/v1/audit/{id}` | single entry |
| GET | `/v1/audit/verify` | hash-chain integrity check |
| GET | `/v1/policy` | current policy |
| PUT | `/v1/policy` | new version (audited) |
| GET | `/v1/providers` | list registered providers (metadata only) |
| GET | `/v1/providers/{id}` | single provider metadata |

### Explicitly NOT in Phase 1C

Real provider implementations (no network/messaging/booking/cloud/device
transport), a real LLM/tool-calling loop, human auth/RBAC, a UI, multi-user/
multi-tenant support, PostgreSQL (protocol only), cryptographic signing of audit
entries, and background workers. Only gating + confirmation for
financial/booking/communication/device actions is built — their providers come
later.

---

## Phase 1D — Permission-matrix hardening + provider contracts

Phase 1D does **not** add capabilities. It locks the Phase 1C security boundary
with exhaustive tests and a reusable ToolProvider contract so later providers
cannot silently weaken the gate.

### What it adds

- **Exhaustive permission matrix** — every catalogued action’s risk tier,
  default decision (`ALLOW` / `CONFIRM` / `CONFIRM_STRONG` / `DENY`),
  `capability_domain`, and `secret_fields` is asserted. Unknown actions, missing
  policy, malformed policy objects, empty/unmapped tier tables, and broken
  override predicates are **always DENY**.
- **FORBIDDEN is override-proof** — catalogued `FORBIDDEN` actions (`secret.export`,
  `account.delete`) are always `DENY`, even if a policy override, broad allow-all
  tier table, malformed policy, or a planted confirmation would otherwise
  authorize them. Execution never dispatches them.
- **CONFIRM vs CONFIRM_STRONG** — COMMUNICATION/MUTATING stay `CONFIRM`;
  FINANCIAL/BOOKING/DESTRUCTIVE stay `CONFIRM_STRONG`; FORBIDDEN stays `DENY`.
- **Provider contract suite** (`tests/provider_contract.py`) — SPI checks
  (identity, catalogued action types, validate/execute shape, no secret
  fragments in results, `ToolError` as a valid failure). `StubProvider` is the
  first implementation under the contract. The same helper is intended for
  WebProvider, EmailProvider, WhatsAppProvider, BookingProvider,
  FilePhotoProvider, and AndroidProvider when those land.
- **Security regression lock** — fail-closed evaluation, confirmation
  single-use, TTL expiry, action-hash binding, `CONFIRM_STRONG` challenge,
  audit-write failure blocking dispatch, secret redaction, append-only audit
  integrity.

### Explicitly NOT in Phase 1D

**Real providers remain out of scope.** No network calls, no API keys / OAuth /
passwords, no real email / WhatsApp / booking / payment / device / filesystem
mutations. Stub-only execution continues.

---

## Phase 1E — Provider integration foundation

Phase 1E does **not** add a real provider. It hardens the *boundary* that every
future real provider (Web, Email, WhatsApp, Booking, File/Photo, Android) will
plug into, so a flaky, slow or buggy downstream cannot weaken the security gate.

### What it adds

- **`ProviderErrorCode` + error semantics** — a stable, provider-agnostic error
  taxonomy (`VALIDATION`, `AUTH`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`,
  `TIMEOUT`, `UNAVAILABLE`, `NOT_IMPLEMENTED`, `PROVIDER_ERROR`, `INTERNAL`).
  `ToolError` carries a `code` (default `PROVIDER_ERROR` for backward
  compatibility). Free-text messages are for humans; codes are for the gate,
  audit log and callers to react to deterministically.
- **Provider timeout / deadline** — every provider `validate`/`execute` call
  during dispatch is bounded by a hard wall-clock timeout
  (`ERA_PROVIDER_TIMEOUT_SECONDS`, default 30s). Overrun becomes
  `ToolError(TIMEOUT)` recorded as `FAILED`; the abandoned (daemon) worker never
  blocks the caller. An absolute `time.monotonic()` deadline is advertised on
  `ExecutionContext.deadline` so cooperative providers can observe remaining
  budget. Dispatch remains *outside* any DB transaction.
- **`ProviderInfo` / `describe_provider()`** — static, non-secret provider
  metadata (`id`, `action_types`, `version`, `display_name`, `is_stub`,
  `capabilities`). `describe()` is optional on a provider; the helper
  synthesises a safe default (and survives a buggy `describe()`) so
  introspection never breaks a legacy provider.
- **`ToolRegistry` registration/lookup** — providers are now indexed by both
  `action_type` and provider `id`, with duplicate-provider/duplicate-action
  rejection, `get_provider(id)`, `provider_ids`, `list_providers()`,
  `describe(action_type)` and `describe_all()`.
- **Structured `error_code` in the audit log** — `FAILED`/`REJECTED` outcomes
  carry the `ProviderErrorCode` in a new indexed column (and hash-chain field),
  so failures are queryable without string-matching messages.
- **Read-only `/v1/providers` endpoints** — list / inspect registered providers.
  No provider is invoked, no network opened, no credentials exposed.
- **Dispatch-boundary and fail-closed tests** — authorization is durably
  committed *before* dispatch (audit-before-execute) on both the direct and
  confirmed paths; `FORBIDDEN` actions never dispatch even with a provider
  registered and an engine override; missing provider maps to
  `NOT_IMPLEMENTED`; a provider raising a non-`ToolError` is mapped to
  `INTERNAL`.

### Explicitly NOT in Phase 1E

**Still no real provider.** No network/HTTP calls, no API keys / OAuth /
passwords, no real email / WhatsApp / booking / payment / device / filesystem
mutations. `StubProvider` and `MockLLMProvider` remain the only wired
implementations. No retries/circuit-breakers, no async provider interface, no
background workers, and no credential *storage* — providers continue to own
credential resolution against their own secure stores in later phases.

---

## Phase 1F — Provider Execution Reliability Foundation

Phase 1F adds the next *additive* reliability layer on top of Phase 1E — still
**no real provider, no network calls, no credentials**. It makes the dispatch
boundary resilient to transient provider failures without weakening any Phase
1C/1D/1E security guarantee.

### Retry foundation (`era/core/retry.py`)

A provider-agnostic `RetryPolicy` + `with_retry()` loop applied to
provider `execute` only:

- **Only explicitly retryable failures are retried** — by default
  `UNAVAILABLE` and `PROVIDER_ERROR`. `VALIDATION`, `AUTH`, `FORBIDDEN`,
  `NOT_FOUND`, `CONFLICT`, `TIMEOUT`, `NOT_IMPLEMENTED`, `INTERNAL` and
  `UNKNOWN` (an out-of-taxonomy code string, classified by `ToolError`) are
  never retried (a hard carve-out that configuration cannot override).
- **Bounded** — `max_attempts` (default 3) is hard-capped at 10; the loop is a
  plain `for`, so it can never run unboundedly.
- **Configurable, deterministic backoff** — exponential (`base × factor^n`),
  capped at `max_backoff`, no jitter, fully testable via injected clock/sleep.
- **Deadline-aware** — respects `ExecutionContext.deadline`: a backoff that
  would exceed the dispatch budget is not taken; the loop terminates with
  `TIMEOUT` instead, so retrying can never bypass the Phase 1E deadline, and
  the hard wall-clock timeout still bounds the whole loop (a `TIMEOUT` is
  never retried).
- **Quiet** — `with_retry` performs no logging; retry exhaustion re-raises the
  original `ToolError` object with its original code, so no secrets can leak
  through retry activity.

### Circuit breaker (`era/core/circuit_breaker.py`)

A small, deterministic per-provider breaker with `CLOSED` / `OPEN` /
`HALF_OPEN` states:

- Consecutive **eligible** failures (`UNAVAILABLE` / `PROVIDER_ERROR`,
  default threshold 5) open the circuit.
- `OPEN` blocks dispatch for `cooldown_seconds` (default 30s); then a
  controlled `HALF_OPEN` probe is admitted. A successful probe closes the
  circuit; a failed probe reopens it.
- `AUTH`, `FORBIDDEN`, `VALIDATION`, `NOT_FOUND`, `CONFLICT`, `TIMEOUT`,
  `NOT_IMPLEMENTED`, `INTERNAL` and `UNKNOWN` failures **never** affect
  breaker state — authorization/policy failures can never be converted into
  circuit-breaker behavior, and an unrecognized failure is never mistaken for
  a transient outage.
- Breakers are isolated per provider id (`CircuitBreakerRegistry`), so one
  provider's outage never blocks another.
- The breaker is consulted only by the execution service **after** the
  authorization record is durably committed and **outside** any DB
  transaction; it can only block dispatch, never perform it.

### Async provider foundation (`era/core/async_provider.py`)

An additive extension point for asynchronous providers:

- `AsyncToolProvider` protocol (`async validate` / `async execute`) mirroring
  the synchronous `ToolProvider` SPI.
- `to_async()` / `to_sync()` adapters: existing synchronous providers
  (`StubProvider`) work from async code unchanged, and async providers can be
  driven through the existing synchronous dispatch boundary. `ExecutionContext`
  — including the Phase 1E deadline — is forwarded untouched. The registry
  adapts async providers automatically at registration
  (`ToolRegistry.register`), so an `AsyncToolProvider` can be wired straight
  into `build_container`; both adapters forward `describe()` so provider
  introspection metadata survives adaptation, and awaitable-returning /
  mixed sync-async providers are handled without leaking coroutine objects.
- `run_async_with_timeout()` — the async counterpart of `run_with_timeout()`
  (overrun → `ToolError(TIMEOUT)`, never retried; any other unexpected
  exception → `ToolError(INTERNAL)`, mirroring the sync boundary).
- No real async provider ships; nothing here opens a socket or stores
  credentials.

### Execution integration (`era/services/execution_service.py`)

Retry + circuit breaker live **only** at the provider dispatch boundary, in an
order that preserves the security model:

```
AUTHORIZATION -> AUDIT AUTHORIZATION COMMITTED -> RELIABILITY / DISPATCH LAYER
-> PROVIDER EXECUTE -> RECORD EXECUTED / FAILED / REJECTED
```

- The breaker gate and `with_retry` run strictly after the authorization record
  is committed, outside any DB transaction.
- `validate` remains single-attempt (a validation rejection is `REJECTED`, not
  a retryable/health failure).
- Error semantics stay on the existing `ProviderErrorCode` / `ToolError`
  system: retry exhaustion → `FAILED` with the original code; circuit open →
  deterministic `UNAVAILABLE`; unexpected exception → `INTERNAL`; `FORBIDDEN`
  remains `DENY` and never dispatches (the breaker is never even consulted on
  that path).

### Configuration

| Setting | Default | Meaning |
|---|---|---|
| `ERA_PROVIDER_RETRY_MAX_ATTEMPTS` | `3` | max execute attempts per dispatch (cap 10) |
| `ERA_PROVIDER_RETRY_BASE_BACKOFF_SECONDS` | `0.1` | backoff before the 2nd attempt |
| `ERA_PROVIDER_RETRY_MAX_BACKOFF_SECONDS` | `2.0` | cap on a single backoff sleep |
| `ERA_PROVIDER_RETRY_BACKOFF_FACTOR` | `2.0` | backoff growth between attempts |
| `ERA_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `5` | consecutive eligible failures that open the circuit |
| `ERA_CIRCUIT_BREAKER_COOLDOWN_SECONDS` | `30` | how long OPEN blocks dispatch |

All defaults are safe and bounded; the retry cap is enforced in code, so a
misconfiguration can never create an unbounded loop.

### Security invariants (unchanged from Phase 1C/1D/1E)

Fail-closed permission evaluation; `FORBIDDEN` is permanently `DENY`;
authorization is durably recorded before provider dispatch (also under retry
and circuit-open); confirmation cannot bypass policy; the audit log stays
append-only with an intact hash chain; secrets remain redacted (including in
the Phase 1F-generated messages); providers receive no raw credentials; no real
network calls, API keys, OAuth, passwords or credential storage.

### Explicitly NOT in Phase 1F

**Still no real provider.** No Web, Email, WhatsApp, Booking, File/Photo or
Android providers; no network/HTTP calls; no API keys / OAuth / passwords; no
credential storage; no background workers; no persistent circuit state; no
distributed/coordinated retry. `StubProvider` and `MockLLMProvider` remain the
only wired implementations. Real providers (sync or async) land in later
phases.

---

## Phase 3A — MVEA (Minimum Viable ERA Agent)

Phase 3A turns the Phase 1C–2A execution foundation into a **real, safe,
autonomous agent** — planning, task management, tool use, verification,
bounded retry/replan and memory — without weakening any existing security
invariant. Full audit + roadmap: [`AGENT_AUDIT_AND_PLAN.md`](AGENT_AUDIT_AND_PLAN.md).

### What it provides

- **Agent loop** — `PLAN → EXECUTE → OBSERVE → VERIFY → SUCCESS`, with
  bounded retry (`fix → retry → verify`), one replan with repair tasks, and
  hard budget caps (iterations, tool calls, LLM calls, tokens, wall-clock
  timeout, USD cost cap). An endless loop is structurally impossible.
- **Planner** — `RulePlanner` (offline, free, deterministic) + `LLMPlanner`
  (model-generated JSON plan, strictly validated, offline fallback).
- **Task manager** — `pending / running / completed / failed / retrying /
  waiting_for_user / skipped`, dependency ordering, deadlock fail-closed.
- **Real tools (ToolProviders)** — sandboxed `WorkspaceProvider` (`fs.*`,
  `photo.*`: traversal/symlink guards, size caps) and `WebProvider`
  (keyless DuckDuckGo search + `web.fetch`/`web.download` with SSRF guards:
  scheme allowlist, private/loopback/link-local/reserved IP blocking,
  redirect re-validation).
- **Human approval** — MUTATING → CONFIRM, DESTRUCTIVE → CONFIRM_STRONG (all
  unchanged defaults). The loop pauses (`waiting_for_user`) and resumes only
  from audit-log-proven resolutions — the agent can never assume an approval.
- **Verification** — action success, file existence/size, HTML structure +
  keywords, internal link integrity; failures produce correction notes that
  drive retries.
- **Memory** — short-term per-run + long-term per-actor SQLite store.
- **LLM (optional, free-tier ready)** — `OpenAICompatLLMProvider` works with
  any OpenAI-compatible endpoint (OpenAI free tier / Groq / OpenRouter /
  Ollama). No key → **offline deterministic mode**: the whole loop still runs
  for real (FREE LIMITATION: open-ended content then comes from built-in
  knowledge packs, not a model).
- **API** — authenticated `POST /v1/agent/runs`, `GET /v1/agent/runs[/{id}]`,
  `POST /v1/agent/runs/{id}/continue` (permission `agent.run`), enabled with
  `ERA_AGENT_ENABLED=true`.

### First real goal — works end-to-end

```
python -m era.agent demo --auto-approve
```

«मेरे लिए एक welding training website बनाओ» → plan (research → structure →
6 pages → CSS/JS → verification) → tool execution through the permission/
confirmation/audit gate → HTML + link verification → retry/replan → final
site in `workspace/welding_training_site/`. Offline: **$0.00**, no API keys,
no network required.

### Test

```bash
pytest          # 259 (Phase 1C–2A) + 100 (Phase 3A) = 359 tests
```

### Explicitly NOT in Phase 3A

Free-form model-driven tool selection beyond the planned action (planned for
3B+), SSE streaming chat, a web UI, the credential vault, GitHub/code-exec
providers, browser automation (FREE LIMITATION — needs a real browser),
multi-agent orchestration, Postgres/migrations and keyed audit signing —
these stay on the roadmap in `AGENT_AUDIT_AND_PLAN.md`.
