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



---

## Phase 3B — Real LLM hardening + streaming chat API

Phase 3B makes the agent *live*: SSE streaming, a chat endpoint, native
function-calling tool selection, prompt-injection defense and cost accounting
— on top of the untouched 3A loop.

### What it provides

- **SSE chat API** — `POST /v1/agent/chat` (`{"message", "run_id"?}`) starts a
  run or continues a paused one, streaming typed events
  (`run_started`, `plan_created`, `task_started`, `tool_call`, `observation`,
  `verdict`, `task_retrying`, `task_completed/failed/skipped`,
  `confirmation_required`, `run_finished`) as `text/event-stream`. Events are
  secret-free: params are redacted and long values (file content) are length
  markers. `GET /v1/agent/runs/{id}/events` replays a run's history.
- **Chat flow** — user message → streamed events → pause at the approval gate
  (`run_finished` with `status=waiting_for_user` + pending confirmation ids)
  → approve/deny via the existing `/v1/confirmations/{id}` endpoints → next
  chat message with `run_id` continues. Resolutions are proven from the
  append-only audit log; the **first terminal outcome wins**, so a duplicate
  approve/deny can never overwrite the real result.
- **ToolCallBrain** — native function calling: the model sees only
  catalogued + registered + role-allowed tools (JSON schemas from the action
  catalog; FORBIDDEN types are never offered). Proposals are re-validated
  (catalog, registry, RBAC domain guard, param bounds) and fall back to the
  planned action on any rejection.
- **RBAC domain guard inside the loop** — the API-level capability-domain
  allowlist now also applies to every model-proposed tool call, closing the
  gap between route-level RBAC and in-loop execution (`device.*` stays
  admin-only even if the model asks for it).
- **Prompt-injection defense** — hardened system prompt, tool output wrapped
  as UNTRUSTED data, plus real enforcement: injected `fs.delete` needs
  CONFIRM_STRONG, FORBIDDEN types can never dispatch, secrets in
  model-generated content are redacted before audit, and audit rows are
  size-capped (long strings stored as length markers).
- **Cost accounting** — pricing table for common cheap models; every LLM call
  records tokens + estimated USD against the run budget cap.
- **Real SSE LLM streaming** — `OpenAICompatLLMProvider.stream()` parses
  `text/event-stream` token deltas with final usage capture.

### Bugs fixed in 3B (found by audit + tests)

- `AgentLoop._settle_failure` was called but never defined (latent
  `AttributeError` on LLM/budget failures).
- Duplicate approve/deny of an already-resolved confirmation overwrote the
  confirmation state and poisoned resolution (task flipped to failed).
- Resumed runs lost artifact tracking (empty artifact list in final reports).
- Approving content-bearing writes (>2000 chars) through the API was
  rejected by the 2A input caps — action-aware param limits now allow full
  file content for `fs.write`/`photo.edit`/`photo.upload` only.
- Tool-selection validation accepted FORBIDDEN catalogued actions.

### Try it

```bash
ERA_AGENT_ENABLED=true uvicorn era.main:create_app --factory
# POST /v1/agent/chat  {"message": "मेरे लिए एक welding training website बनाओ"}
python -m era.agent demo --auto-approve --stream   # CLI live stream
```

### Test

```bash
pytest          # 259 (1C–2A) + 100 (3A) + 39 (3B) = 398 tests
```

### Explicitly NOT in Phase 3B

SSE streaming of LLM *tokens* inside the run loop (provider-level streaming
exists; the loop consumes complete responses), a web chat UI, the credential
vault, GitHub/code-exec providers, browser automation, multi-agent
orchestration — these stay on the roadmap in `AGENT_AUDIT_AND_PLAN.md`.

### Explicitly NOT in Phase 3A

Free-form model-driven tool selection beyond the planned action (planned for
3B+), SSE streaming chat, a web UI, the credential vault, GitHub/code-exec
providers, browser automation (FREE LIMITATION — needs a real browser),
multi-agent orchestration, Postgres/migrations and keyed audit signing —
these stay on the roadmap in `AGENT_AUDIT_AND_PLAN.md`.

## Phase 3C — Credential Vault + Provider Secrets

Phase 3C adds the **credential vault**: the first place provider secrets are
stored securely, and the first production provider (SMTP email) that consumes
them. The secret boundary from the audit is preserved exactly — the core
(agent / LLM / permission / audit layers) only ever sees opaque references
like `vault:email/smtp_password`; providers resolve them at execution time.

### What it provides

- **Vault core** (`era/security/vault.py`) — secrets encrypted at rest with
  **AES-256-GCM** (authenticated encryption, `cryptography` lib) under a
  32-byte env-only master key (`ERA_VAULT_MASTER_KEY`). Fresh random nonce per
  value; ciphertext bound to `(domain, name)` via AAD so rows can't be
  swapped. No valid master key → vault **disabled, fail-closed** (nothing
  stored, nothing resolved); malformed keys are treated as absent.
- **Vault service** (`era/services/vault_service.py`) — store / rotate (with
  `revision` bumping) / soft-revoke / metadata list / **resolve**. Every op
  — including every resolution failure — is appended to the tamper-evident
  audit log with metadata only (domain/name; never the value).
- **Vault API** (admin-only, `vault.manage`) —
  `POST /v1/vault/secrets` (create-or-rotate; value accepted once, never
  returned), `GET /v1/vault/secrets[?domain=]`,
  `POST /v1/vault/secrets/{domain}/{name}/revoke`. `user` role gets 403;
  disabled vault returns 503 on mutations.
- **SMTP email provider** (`era/providers/email_smtp.py`) — real
  `email.send` (stdlib `smtplib`, opt-in via `ERA_EMAIL_SMTP_HOST`).
  Username/password are plain env values **or vault references**, resolved at
  send time. The credential never appears in params, results, errors or audit
  rows. Stable error mapping: auth → `AUTH` (never retried), timeout →
  `TIMEOUT`, connection/server → `UNAVAILABLE`.
- **LLM key from the vault** — `ERA_AGENT_LLM_API_KEY=vault:llm/openai` is
  resolved once at build time and fails closed (a misconfigured secret can
  never masquerade as "no key → offline").
- **RBAC** — new `vault.manage` permission, **admin-only** (day-to-day `user`
  roles never touch the vault).

### Try it

```bash
# 1. generate a master key and enable the vault
export ERA_VAULT_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 2. store provider secrets (admin API key)
curl -s -X POST localhost:8000/v1/vault/secrets -H "Authorization: Bearer $ERA_ADMIN_KEY" \
  -d '{"domain": "email", "name": "smtp_password", "value": "..." }'
curl -s -X POST localhost:8000/v1/vault/secrets -H "Authorization: Bearer $ERA_ADMIN_KEY" \
  -d '{"domain": "llm", "name": "openai", "value": "sk-..."}'

# 3. point providers at the vault (references, not secrets)
export ERA_AGENT_LLM_API_KEY=vault:llm/openai
export ERA_EMAIL_SMTP_HOST=smtp.example.com ERA_EMAIL_SMTP_PORT=587
export ERA_EMAIL_SMTP_STARTTLS=true
export ERA_EMAIL_SMTP_USER=vault:email/smtp_user ERA_EMAIL_SMTP_PASSWORD=vault:email/smtp_password
ERA_AGENT_ENABLED=true uvicorn era.main:create_app --factory
```

### Test

```bash
pytest          # 259 (1C–2A) + 100 (3A) + 39 (3B) + 46 (3C) = 444 tests
```

Regression locks: disabled vault fails closed everywhere; malformed master
keys stay disabled; the plaintext is unfindable in the database file, audit
log, API responses and error messages; `user` role is denied; revoked secrets
can no longer resolve.

---

## Phase 3D: GitHub + Code-Exec Sandbox Providers (delivered)

Phase 3D adds native **GitHub operations** and a **sandboxed Python code execution runner** to ERA-AI:

### What it provides

- **GitHub Provider** (`era/providers/github.py`):
  - **Repositories & Issues**: `github.repo_get`, `github.issue_list`, `github.issue_get`, `github.issue_create`, `github.issue_comment`
  - **Pull Requests**: `github.pr_list`, `github.pr_get`, `github.pr_create`
  - **Files / Contents**: `github.file_get` (base64 decode), `github.file_commit` (base64 encode)
  - **Vault-backed PAT**: Supports Personal Access Token from environment (`ERA_GITHUB_TOKEN`) or credential vault reference (`vault:github/token`).
  - **Security & Redaction**: `token` is declared in `secret_fields` and never logged or leaked in results/errors/audit; input parameters and repository paths are strictly bounded against traversal.
  - **Error taxonomy mapping**: 401/403 → `AUTH`, 404 → `NOT_FOUND`, 422 → `VALIDATION`, 429/secondary rate limit → `UNAVAILABLE`, 5xx/network → `UNAVAILABLE`, timeout → `TIMEOUT`.

- **Code Execution Sandbox Provider** (`era/providers/code_exec.py`):
  - **Actions**: `code.run` and `code.exec` (isolated Python runner).
  - **Environment isolation**: Scrubs all host secrets (`ERA_*`, API keys, database URLs, master vault keys); only passes a strict whitelist of safe environment variables (`PATH`, `LANG`, `TMPDIR`, `USER`, etc.).
  - **Workspace confinement**: Subprocess execution is confined to the agent workspace root.
  - **Resource limits**: Wall-clock timeout (default 10s), CPU time caps, and virtual memory caps (via `resource` module on POSIX).
  - **Output size truncation**: Captures and truncates stdout and stderr safely (default 64 KiB cap).

### Test

```bash
pytest          # 522 passed across all suites (444 pre-existing + 78 Phase 3D)
ruff check .    # clean
```

## Phase 3E: Web UI / Chat Dashboard (delivered)

Phase 3E adds a **mobile-first web chat dashboard** over the same authenticated
API — no build step, no npm, no new backend capability. It is served by the
FastAPI app itself at `/`, same-origin, so the Phase 2A auth model (Bearer API
key → server-derived identity) applies unchanged and no CORS is needed.

### What it provides

- **Static dashboard** (`era/web/static/{index.html,app.js,styles.css}`) served
  by the app at `/` (never cached) and `/static/*` (asset files). Dependency-free
  vanilla HTML/CSS/JS, mobile-first responsive layout (sidebar drawer on small
  screens).
- **Login screen** — the operator pastes their API key once; it is kept in
  `localStorage` and sent only as an `Authorization: Bearer` header, never in
  the URL or the DOM. `GET /v1/me` verifies the key and returns the
  server-derived identity (`username`, `role`) plus `agent_enabled` so the UI
  can explain a 503 instead of failing silently. Invalid/revoked keys fall back
  to the login screen.
- **Streaming chat** — `POST /v1/agent/chat` is consumed with `fetch` +
  `ReadableStream` (native `EventSource` cannot send auth headers). Every typed
  event (`run_started`, `plan_created`, `task_started`, `tool_call`,
  `observation`, `verdict`, `task_retrying`, `task_completed/failed/skipped`,
  `confirmation_required`, `run_finished`) is rendered as a timeline; tool-call
  params and file content are shown as the server already redacts/summarises
  them.
- **Approval gate in the UI** — `confirmation_required` renders an interactive
  approve/deny card. Approve re-fetches the confirmation (`GET
  /v1/confirmations/{id}`) for the exact hash-bound params and posts to the
  existing approve endpoint; `CONFIRM_STRONG` shows the challenge phrase and
  requires it typed back. A paused run shows a "Continue run" button, enabled
  only once every pending confirmation is resolved. Replayed history renders
  confirmations read-only (the server is the source of truth).
- **Runs dashboard** — sidebar lists recent runs (`GET /v1/agent/runs`); opening
  one replays its event history (`GET /v1/agent/runs/{id}/events`) and summary,
  and lets a still-paused run be resumed.
- **Response hardening** — every response (API, static, SSE, errors) gets
  `Content-Security-Policy` (same-origin only, `frame-ancestors 'none'`),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`, via
  `SecurityHeadersMiddleware` (`era/api/middleware.py`). The UI inserts all
  dynamic content with `textContent` only — no `innerHTML`, so event data can
  never inject markup.

### Try it

```bash
ERA_AGENT_ENABLED=true uvicorn era.main:create_app --factory
# open http://localhost:8000  →  paste an API key (python -m era.cli create-admin)
```

### Test

```bash
pytest          # 522 (1C–3D) + 15 (Phase 3E) = 537 passed
ruff check .    # clean
```

### Explicitly NOT in Phase 3E

No new backend capability (the agent/LLM/tools/approval gate are unchanged);
no WebSocket (SSE already suffices); no multi-user realtime/push. PostgreSQL,
rate limiting, audit signing, migrations, and durable circuit state are delivered
in Phase 3F below.

---

## Phase 3F: Production Scale & Integrity (delivered)

Phase 3F replaces single-node persistence assumptions with a PostgreSQL-ready,
migration-managed backend while preserving SQLite for local/offline operation.

### What it provides

- **PostgreSQL repositories** — `era/repositories/postgres.py` implements every
  repository protocol (audit, confirmations, policy, users/API keys, vault,
  agent runs, memory, and circuit state). `ERA_DATABASE_URL` selects SQLite or
  PostgreSQL automatically. Concurrent PostgreSQL audit appends are serialized
  with a transaction-scoped advisory lock so `seq` and `prev_hash` cannot fork.
- **Alembic schema lifecycle** — startup upgrades to Alembic `head`; ORM
  `create_all()` is no longer used. Fresh databases migrate from zero, while a
  pre-Alembic ERA database is baseline-stamped and upgraded without deleting
  data. Operators can run `alembic upgrade head` / `alembic downgrade <rev>`.
- **Keyed audit authentication** — `era/security/signing.py` supports
  HMAC-SHA-256 and Ed25519. Every signed row binds its chain head, algorithm,
  and key id; `/v1/audit/verify` checks both the SHA-256 links and signatures.
  Key material stays outside the DB. `none` is explicit legacy mode.
- **API abuse throttling** — versioned API routes use fixed-window limits.
  Authenticated calls consume independent API-key and source-IP buckets;
  unauthenticated calls are constrained by IP. HTTP 429 includes `Retry-After`
  and rate-limit headers, and still receives all security headers.
- **Persistent circuit breakers** — provider state, failure streak, and
  wall-clock open time are stored in the selected database, so OPEN/HALF_OPEN
  survives process restart and is visible to fresh workers.

### Configure and migrate

```bash
# PostgreSQL (bare postgresql:// URLs are normalized to psycopg 3)
export ERA_DATABASE_URL='postgresql://era:password@localhost:5432/era'

# Recommended production audit signing (use a secret manager in practice)
export ERA_AUDIT_SIGNING_ALGORITHM=hmac-sha256
export ERA_AUDIT_SIGNING_KEY='replace-with-at-least-32-random-bytes'
export ERA_AUDIT_SIGNING_KEY_ID='audit-2026-01'

alembic upgrade head
uvicorn era.main:create_app --factory
```

Ed25519 accepts a PEM private key (literal newlines or escaped `\\n`) or a raw
32-byte private seed encoded as hex/base64. A public-only
`Ed25519AuditSigner` can verify exported audit records independently.

For the optional live integration suite, point
`ERA_TEST_POSTGRES_URL` at a PostgreSQL database; tests create and drop an
isolated schema and do not alter existing schemas.

### Test

```bash
pytest  # 562 passed, 1 live-Postgres test skipped unless URL is configured
ERA_TEST_POSTGRES_URL='postgresql://...' pytest -m postgres
ruff check .
```

---

## Phase 3G: Replay Safety & Background Execution (delivered)

Phase 3G closes the last two production gaps from the audit: **replay safety**
(idempotency keys) and **background workers** (an async job queue). It also
removes the dead legacy prototype files from the repository root.

### What it provides

- **Idempotent execution** — `POST /v1/actions/execute` accepts an optional
  `idempotency_key`. Replaying the same key with the same request returns the
  originally recorded result **without** re-dispatching the provider, creating
  a second confirmation, or appending audit rows. The same key with a
  *different* request is a `409`; a key still in flight is a `409` so a
  concurrent duplicate cannot race the first dispatch. Keys are SHA-256-hashed
  and scoped to the actor, records expire after `ERA_IDEMPOTENCY_TTL_SECONDS`,
  and an abandoned in-flight record (e.g. after a crash) is re-attempted after
  `ERA_IDEMPOTENCY_PROCESSING_TTL_SECONDS`. The CONFIRM_STRONG challenge phrase
  is never persisted — a replay returns the same `confirmation_id` without
  re-issuing the one-time phrase.

- **Background job queue** — the same endpoint with `"async": true` returns
  `202` with a `job_id` immediately and executes the action on a bounded
  in-process worker pool, through the **same** permission → confirmation →
  audit → reliability gate. Poll `GET /v1/jobs/{job_id}` (or list with
  `GET /v1/jobs`; both require the `jobs.read` permission and are actor-scoped).
  Job rows store only *redacted* params; the raw action lives in memory, so a
  crash never persists secret material. Jobs left `queued`/`running` by a
  crashed process are failed on the next startup (never silently resumed), and
  an async re-submission with the same `idempotency_key` returns the same job.

- **Legacy prototype cleanup** — the dead top-level prototypes (`agent.py`,
  `brain.py`, `chat.py`, `config.py`, `main.py`, `memory.py`, `research.py`)
  are removed, and the ruff `exclude` list (which was accidentally matching
  real `era/` modules by basename) is gone — surfacing and fixing six hidden
  lint issues in the real modules.

### Try it

```bash
python -m era.cli create-admin   # then create a user + key
uvicorn era.main:create_app --factory

# Replay-safe execute (same key -> same result, no double side effect)
curl -X POST localhost:8000/v1/actions/execute -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"web.search","params":{"q":"era"},"idempotency_key":"op-1"}'

# Background execution
curl -X POST localhost:8000/v1/actions/execute -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"web.search","params":{"q":"era"},"async":true}'
curl localhost:8000/v1/jobs/<job_id> -H "Authorization: Bearer $KEY"
```

### Test

```bash
pytest          # 562 passed (546 Phase 1C–3F + 16 Phase 3G), 1 live-Postgres skipped
ruff check .    # clean
```

---

## Phase 3H: Parameter Schema Enforcement, Recurring Schedules, Website Builder & Extended Providers (delivered)

Phase 3H resolves the last architectural debt item, adds recurring scheduled jobs, elevates Website Builder into a first-class capability, and introduces official WhatsApp, Image Generation, and Safe Travel Booking providers.

### What it provides

1. **`param_schema` Enforcement & Single Source of Truth (ROADMAP §C #5)**
   - Single authoritative parameter schema definition in `era/registry/actions.py` (`ACTION_PARAM_SCHEMAS`), aliased to `TOOL_PARAM_SCHEMAS`.
   - Action-aware schema validation runs *before* provider dispatch in `ExecutionService`.
   - **Fail-closed**: missing required fields, unexpected extra fields (when strict properties defined), or invalid parameter types are rejected immediately with `Outcome.REJECTED` and `ProviderErrorCode.VALIDATION`.
   - Composes seamlessly with generic payload caps (`MAX_PARAMS`, `MAX_CONTENT_LEN`).

2. **Scheduled & Recurring Jobs (Cron / Interval)**
   - `Schedule` persistence model + Alembic migration `0004_phase_3h_schedules`.
   - Pure-Python, lightweight 5-field cron parser and interval evaluator (`era/core/cron.py`).
   - In-process background scheduler worker thread (`ScheduleService`) that evaluates due schedules and submits runs via `JobService.submit()` with idempotent keys (`sched:<schedule_id>:<due_next_run_at>`).
   - Full REST API: `POST /v1/schedules`, `GET /v1/schedules`, `GET /v1/schedules/{id}`, `PATCH /v1/schedules/{id}`, `DELETE /v1/schedules/{id}`, `POST /v1/schedules/{id}/enable`, `POST /v1/schedules/{id}/disable`.
   - Actor-scoped access protected by `schedules.manage` and `schedules.read` permissions.

3. **First-Class Website Builder**
   - Natural language intent extraction across Hinglish, Hindi, and English goals (`meri [X] ki website banao`, `make me a website about X`).
   - Complete multi-page mobile-first static website generation (`index.html`, `about.html`, `services.html` / `courses.html`, `contact.html`, `assets/style.css`, `assets/app.js`, `assets/favicon.svg`, `README.md`).
   - SEO meta tags, OpenGraph tags, accessible client-side validated contact forms, and SVG vector favicons.
   - Built-in verifier checks (`html_valid`, `links_resolve`) ensuring **0 broken internal links**.
   - Zip archive export for immediate distribution and deployment.

4. **Official Meta Cloud API / Twilio WhatsApp Provider**
   - Implements `whatsapp.send` (text/template), `whatsapp.read` (message history/status), `whatsapp.react` (emoji reactions).
   - Vault-resolvable access tokens (`vault:whatsapp/token`) and strict secret redaction.
   - Deterministic error taxonomy mapping (401/403 -> `AUTH`, 404 -> `NOT_FOUND`, 400/422 -> `VALIDATION`, 429 -> `RATE_LIMITED`, 5xx -> `UNAVAILABLE`).

5. **Image Generation Provider (`image.generate`)**
   - OpenAI Images / Stability / OpenAI-compatible endpoint support.
   - Domain `image`, risk `MUTATING` (gated by user confirmation).
   - Safe workspace file confinement (path traversal prevented).
   - Clean offline / no-key handling via `NOT_IMPLEMENTED` ToolError without crashing.

6. **IRCTC / Travel Booking — Safe Draft & Approval Model**
   - Strict safe workflow: search is `SAFE`/`SENSITIVE`, temporary reservations (`booking.hold`) are `MUTATING` draft holds.
   - Confirmation (`booking.confirm`) and cancellation (`booking.cancel`) require `CONFIRM_STRONG` user approval challenge.
   - Avoids unsafe web scraping / CAPTCHA bypass to eliminate ToS and account ban risks; connects through official B2B partner APIs.

### Test

```bash
pytest          # 600+ tests passed
ruff check .    # clean
```

---

## Phase 4A: Self-Hosted Browser Automation (Playwright) (delivered)

ERA AI `0.8.0` can now open and interact with modern dynamic/SPA pages in a
self-hosted headless Chromium browser. Browser work is not a privileged side
channel: every action uses the same permission engine, confirmation flow,
append-only audit log, timeout/retry policy and circuit breaker as every other
provider.

### Browser action catalog

| Action | Risk / default decision | Parameters |
|---|---|---|
| `browser.navigate` | `SENSITIVE` / `ALLOW` | `url`, optional `wait_until` |
| `browser.screenshot` | `SENSITIVE` / `ALLOW` | workspace `path`, optional `selector` / `full_page` |
| `browser.extract_dom` | `SAFE` / `ALLOW` | optional `selector`, `max_chars`, `save_html_path` |
| `browser.click` | `MUTATING` / **`CONFIRM`** | exactly one of CSS `selector` or visible `text` |
| `browser.fill` | `MUTATING` / **`CONFIRM`** | `selector`, `text` |
| `browser.submit` | `MUTATING` / **`CONFIRM`** | optional form/element `selector` |

Every schema is strict (`additionalProperties: false`). The `browser`
capability domain is allowed for `user` and `admin` roles; RBAC is still only
the outer gate and never bypasses policy/confirmation.

### Security and isolation

- **SSRF defense:** public HTTP(S) only; private RFC1918, loopback, link-local,
  reserved/multicast, cloud metadata addresses, credentials-in-URL and ports
  other than 80/443 are denied. Validation runs before dispatch and Playwright
  routing checks redirects/subresources. Service workers and WebSockets are
  blocked to prevent alternate private-network paths.
- **Workspace confinement:** screenshots and optional HTML dumps are resolved
  through `WorkspaceRoot`; absolute paths, `..` traversal and symlink escapes
  fail closed.
- **Ephemeral contexts:** each actor/session receives a separate non-persistent
  Chromium context, so cookies/local storage/cache never cross actors or runs.
  Application shutdown closes Chromium and discards all contexts.
- **Resource bounds:** internal operation/navigation timeout defaults to 30s;
  viewport defaults to 1280×800; DOM source/output, links and screenshot size
  are capped. ERA's provider-level hard timeout remains independently active.
- **Offline CI:** `SimulatedBrowserTransport` exercises navigation, screenshots,
  dynamic DOM extraction and isolated interaction state without sockets or a
  browser binary. Playwright is lazy-loaded only on the first production action.

### Install Chromium on a browser worker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,browser]'
playwright install --with-deps chromium
```

No browser binary is needed to run the unit suite.

### Configuration

```dotenv
ERA_BROWSER_HEADLESS=true
ERA_BROWSER_TIMEOUT_SECONDS=30.0
ERA_BROWSER_VIEWPORT_WIDTH=1280
ERA_BROWSER_VIEWPORT_HEIGHT=800
ERA_BROWSER_USER_AGENT=ERA-Agent/0.8.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)
```

The rule planner recognizes goals such as:

- `https://example.com website ka screenshot lo`
- `example.org website se live data nikaalo`

It emits `browser.navigate` followed by `browser.screenshot` or
`browser.extract_dom`. Verifier kinds `screenshot_exists` and `dom_extracted`
validate the resulting image/structured DOM, and screenshot/HTML paths are
reported as run artifacts.

### Validation

```bash
pytest          # 651 passed, 1 optional live-PostgreSQL test skipped
ruff check .    # clean
```

Phase 4A adds **52 tests** (provider contract, SSRF/private DNS, workspace and
symlink escapes, DOM/Markdown/links, interaction validation, actor/session
isolation, confirmation+audit flow, planner, verifier, settings and runtime
wiring). Total: **652 collected**.

---

## Phase 4A.1: Browser Security & Reliability Hardening (delivered)

ERA AI `0.8.1` hardens stateful browser workflows before the next major
capability phase.

### Run-scoped lifecycle and approval continuity

- `AgentService` derives an internal `agent:<run_id>` execution scope. Browser
  contexts no longer share state merely because two runs used the same API key.
- The scope is persisted on `PendingConfirmation` by Alembic revision
  `0005_phase_4a1_browser_hardening`. An approval arriving through a later HTTP
  request resumes the exact browser context that requested it.
- Waiting runs retain their context; completed, failed and budget-exhausted runs
  discard it. Exceptions also trigger best-effort fail-closed cleanup.
- Chromium enforces a maximum active-context count and reaps idle contexts.

### Side-effect and timeout safety

- `browser.click`, `browser.fill` and `browser.submit` declare themselves
  non-retryable. `ExecutionService` forces one transport attempt even when a
  transient provider code would normally be retried.
- Agent post-condition failures cannot automatically repeat these actions.
- Playwright commands carry absolute deadlines and cancellation flags. Expired
  queued commands are rejected before dispatch, and the command queue is
  bounded.
- A mutating operation that times out after dispatch returns
  `SIDE_EFFECT_UNKNOWN`, is never retried and quarantines its browser context.
- Browser's internal timeout reserves margin inside ERA's outer provider
  deadline, preventing abandoned timeout threads from routinely outliving the
  dispatch budget.

### Vault-backed browser input

Agents must use `value_ref: "vault:browser/<name>"` for `browser.fill`.
Plaintext `text` remains available to direct API callers but is treated as a
secret field and redacted from confirmation/audit/event surfaces. Raw fill text
proposed inside an agent plan is erased and rejected before dispatch or
persistence. Browser vault resolution is owner-bound, so one actor cannot use
another actor's stored browser credential. Vault admins can set
`owner_user_id` when storing the secret for its intended existing user.

```json
{
  "action_type": "browser.fill",
  "params": {
    "selector": "#password",
    "value_ref": "vault:browser/login_password"
  }
}
```

### Central provider-result boundary

Every provider result now passes through one runtime boundary before it reaches
an API response, agent observation, idempotency row or job row:

- recursive secret-key and unmistakable token-pattern redaction;
- JSON-compatible type, finite-number, depth, key and collection validation;
- a configurable encoded size cap (`ERA_PROVIDER_RESULT_MAX_BYTES`);
- unsafe output fails once after invocation and is never placed in a retry loop.

### Additional browser worker controls

```dotenv
ERA_BROWSER_MAX_CONTEXTS=32
ERA_BROWSER_CONTEXT_IDLE_SECONDS=300.0
ERA_BROWSER_COMMAND_QUEUE_SIZE=128
ERA_BROWSER_EXECUTABLE_PATH=
ERA_BROWSER_EXTRA_ARGS=[]
ERA_BROWSER_PROXY_SERVER=
ERA_PROVIDER_RESULT_MAX_BYTES=524288
```

`ERA_BROWSER_EXECUTABLE_PATH` (optional) points Playwright at an explicit
Chromium binary (e.g. a bundled/system build) instead of the Playwright-managed
one — useful on restricted networks where the Playwright CDN is unreachable.
`ERA_BROWSER_EXTRA_ARGS` (optional) is a JSON array of extra Chromium launch
args (empty by default, so production defaults are unchanged).

Production deployments should set `ERA_BROWSER_PROXY_SERVER` to a
credential-free, default-deny egress proxy and enforce private/metadata network
drops at the container/network-namespace layer. Chromium also disables QUIC,
non-proxied WebRTC UDP, service workers and page WebSockets.

### Tests

```bash
pytest          # 683 passed, 2 skipped, 685 collected
ruff check .    # clean
```

Phase 4A.1 contributes **33 additional collected cases** (30 in dedicated new
test files plus expanded error-taxonomy and vault-owner API coverage). The two
skips are the existing opt-in live PostgreSQL test and the new opt-in real Chromium smoke
test. Run the latter after installing Chromium:

```bash
ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py
```

---

## Phase 4B: Reliable Browser Workflows (delivered)

Phase 4B makes ERA's browser automation **stable, inspectable, drift-resistant,
verifiable and safely resumable** on modern dynamic websites.  The centerpiece
is `browser.inspect` — a bounded snapshot of the rendered accessibility state
that returns opaque, provider-issued element references (`element_ref`).  The
agent never invents CSS selectors or visible-text matchers; it inspects, picks a
reference, confirms, and the provider revalidates everything before executing.

### New actions

| Action | Risk / default decision | Purpose |
|---|---|---|
| `browser.inspect` | `SAFE` / `ALLOW` | Bounded accessibility snapshot (role, accessible name, tag, input type, tab/frame/origin, snapshot generation) with `element_ref` tokens |
| `browser.tabs` | `SAFE` / `ALLOW` | List the run's tabs/popups with opaque tab ids |
| `browser.activate_tab` | `SENSITIVE` / `ALLOW` | Switch the run's active tab by tab id |
| `browser.download` | `MUTATING` / `CONFIRM` | Trigger a download via element ref and save it workspace-confined, size-bound and atomically |
| `browser.upload` | `MUTATING` / `CONFIRM` | Upload an existing workspace file to a file input (`set_input_files`) |

`browser.click`, `browser.fill` and `browser.submit` additionally accept an
`element_ref` target (exactly one of `selector` / `text` / `element_ref`) and an
optional deterministic `expect` post-condition.

### element_ref lifecycle

- Refs are **provider-generated** (`er_<random>`), opaque and unpredictable;
  users/LLMs can never craft a resolvable reference.
- Refs are scoped to one actor/run, tab, frame and **snapshot generation**, and
  are TTL-bound (`ERA_BROWSER_ELEMENT_REF_TTL_SECONDS`, default 120 s).
- Refs become invalid after: navigation, tab close/switch-away, frame
  replacement, context close, a newer `browser.inspect` snapshot, page drift or
  TTL expiry.
- Resolution is fail-closed and requires **exactly one** fingerprint match
  (tag + role + accessible name + input type + structural path + origin):
  - zero matches → `NOT_FOUND` (`no element matches the reference`);
  - multiple matches → `CONFLICT` (`re-inspect`);
  - moved element → `CONFLICT` (`fingerprint mismatch / page drift`);
  - wrong tab / stale snapshot / expired / frame gone / origin changed →
    `CONFLICT` with a specific message;
  - cross-actor / cross-run / closed context → `NOT_FOUND`.
- There is **no fallback** to CSS selectors or text matching when a reference
  cannot be resolved exactly.

### Confirmation continuity

Mutating actions still require confirmation.  While waiting, the browser
context is preserved.  After approval the provider revalidates actor/run, tab,
frame, origin, page state, reference, fingerprint and snapshot generation
before executing **exactly once**.  If the page drifted while the human was
reviewing, the action fails closed and the agent must run `browser.inspect`
again — the mutation is never replayed on a different element.

### Tabs, popups, frames and Shadow DOM

- New tabs/popups opened by a click are detected with a bounded wait; each gets
  an opaque tab id (`browser.tabs` / `browser.activate_tab`).  Refs are
  tab-scoped and never usable across tabs.
- Iframes are identified explicitly (`frame:main`, `frame:N`).  Element refs
  are frame-scoped; replaced or removed frames invalidate their refs.  For
  cross-origin frames only bounded accessibility metadata is exposed — never
  secrets.
- Open Shadow DOM roots are walked and exposed with `in_shadow` flags; nested
  shadow roots work too.  Security restrictions are unchanged.

### Downloads and uploads

- `browser.download`: destination must resolve inside the workspace
  (`../` and absolute paths are rejected), the artifact is size-bound
  (`ERA_BROWSER_MAX_DOWNLOAD_BYTES`, default 200 MiB), copied to a temp file
  and atomically renamed; the final artifact is verified inside the workspace.
  The receipt contains only the workspace-relative path, byte count, sanitized
  filename and scope ids — never browser internals or sensitive state.
- `browser.upload`: source must exist inside the workspace, be within
  `ERA_BROWSER_MAX_UPLOAD_BYTES` (default 100 MiB), and target a real file
  input.  `browser.fill` rejects file inputs (use `browser.upload`).
- Both are `MUTATING`/`CONFIRM` and non-retryable; ambiguous outcomes return
  `SIDE_EFFECT_UNKNOWN` and quarantine the context.

### Sensitive DOM and prompt-injection defenses

- `browser.inspect` never returns input values, hidden-input values, cookies,
  authorization headers, storage secrets or raw sensitive form contents;
  password inputs appear only as metadata (`input_type: "password"`,
  `sensitive: true`).
- Page content is **data, never policy**.  Inspect results are marked
  `content_untrusted: true`, the planner and brain prompts forbid treating page
  text as instructions, and the permission/confirmation/audit gates apply to
  every proposed action — an injected "ignore previous instructions…" page can
  never authorize payments, credential disclosure, destructive mutations or
  downloads/uploads by itself.

### Deterministic post-conditions and receipts

Mutations return sanitized interaction receipts: action type, opaque ref,
tab/frame context, origin, URL, and a `post_condition` block
(`url_changed`, `tab_count_before/after`, `element_attached`).  Callers may
declare `expect: {"kind": "navigation" | "tab_opened" | "element_detached",
"url_contains": "..."}`; if the declared post-condition is not met the action
fails with `CONFLICT` and is never blindly repeated.

### Configuration

```dotenv
ERA_BROWSER_ELEMENT_REF_TTL_SECONDS=120.0
ERA_BROWSER_MAX_INSPECT_ELEMENTS=200
ERA_BROWSER_MAX_DOWNLOAD_BYTES=209715200
ERA_BROWSER_MAX_UPLOAD_BYTES=104857600
```

### Tests and real-Chromium E2E

The Phase 4B suite is deterministic and offline (simulated transport) and adds
**48 collected cases**.  The opt-in real-Chromium E2E now also exercises the
inspect → element_ref → click → stale-ref workflow:

```bash
pytest                                   # offline: 767 passed, 4 optional skips
ruff check .                             # clean
ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py
```

In an environment with a non-standard Chromium path or a sandbox-proxied
TLS/CAC network, configure the browser explicitly (see the browser config
section above):

```bash
ERA_BROWSER_EXECUTABLE_PATH=/path/to/chromium \
ERA_BROWSER_EXTRA_ARGS='["--no-sandbox","--disable-dev-shm-usage","--ignore-certificate-errors"]' \
LD_LIBRARY_PATH=/path/to/browser-libs \
ERA_TEST_BROWSER=1 \
ERA_TEST_BROWSER_URL=https://<reachable-public-host> \
pytest -m browser tests/test_browser_playwright_e2e.py
```

With Chromium installed and network available the 3 opt-in real-Chromium E2E
tests run and pass; without it they are skipped with the exact reason
(`set ERA_TEST_BROWSER=1 for real Chromium E2E`) — never counted as passed.

Skipped E2E tests are reported as skipped with the exact reason
(`set ERA_TEST_BROWSER=1 for real Chromium E2E`) — never as passes.

### Remaining limitations

- Element references live in the browser worker's memory; a process restart
  invalidates them (fail-closed `NOT_FOUND`, re-inspect required).  Approval
  pauses keep the context alive only for the life of the worker process.
- Roles/names are derived from the rendered DOM with an ARIA-mapped walk, not
  Chromium's computed accessibility-tree roles; visually rich widgets may
  expose fewer usable elements than a native a11y tree would.
- Elements with identical fingerprints (e.g. two identical buttons) resolve to
  a deterministic `CONFLICT` until re-inspected with more context.
- The simulator walker covers declarative shadow DOM; dynamically attached
  shadow roots are exercised only by the real-Chromium E2E.
- No database migration was required for Phase 4B (references are runtime
  state; the confirmation schema from 4A.1 already carries execution scope).

## Phase 4C: Durable, Resumable, Exactly-Once Browser Workflows (delivered)

Phase 4C builds on the Phase 4B primitives to run **declarative multi-step
browser workflows** that are durable, resumable, exactly-once,
gate-preserving and fail-closed. A workflow is a bounded, strict-schema list of
steps; each step references exactly one catalogued browser action
(`navigate`, `inspect`, `click`, `fill`, `submit`, `download`, `upload`,
`tabs`, `activate_tab`, `extract_dom`, `screenshot`) with a params template.
The engine never adds browser actions or reliability primitives — it makes
Phase 4B primitives *composable*.

### New action

| Action | Risk / default decision | Purpose |
|---|---|---|
| `browser.workflow_run` | `MUTATING` / `CONFIRM` | Run a registered/strictly-validated workflow; every inner step is still gated independently by the permission engine, confirmation, audit and reliability layers |

### Workflow definitions

A definition is validated at registration time (`era/workflows/definition.py`)
and **fails closed** if any step is unknown, malformed, references an
uncatalogued/out-of-domain action, violates the security constraints, exceeds
the step/param budget, or contains cycles/unbounded recursion (a workflow can
only reference the closed browser-action allowlist — never `browser.workflow_run`).

Steps may declare:

- `expect` post-conditions — reused directly from Phase 4B (`navigation` /
  `tab_opened` / `element_detached`, with `url_contains`).
- A **target acquisition descriptor** (`role`/`name`/`tag`/`input_type`/
  `frame_id`/`index`) that the runtime resolves to a **fresh** `element_ref`
  by re-inspecting the current page at execution time. Workflows never carry a
  persisted `element_ref`, never invent references, and fail closed on
  zero-match / multi-match / drift.
- Opaque `vault:browser/<name>` `value_ref`s for secret fills. A fill targeting
  a password field (or with no declared target, i.e. unknown sensitivity)
  **must** use a vault reference — plaintext secret steps are rejected at
  definition time. Non-secret text fills are allowed only on explicitly
  non-password inputs.
- `on_denied: "stop" | "skip"` for what happens when a required confirmation is
  denied.

`{{name}}` placeholders in params (and in `expect.url_contains`) are rendered
from caller-supplied workflow params at run time.

### Reference workflows

`era/workflows/reference.py` ships three validated workflows:

- **`login`** — the primary tested reference: navigate to the login URL, fill
  the username from `vault:browser/<user>`, fill the password from
  `vault:browser/<pass>`, submit with `expect: navigation`, verify a
  deterministic post-condition on the landing page, emit a sanitized receipt.
- **`search_and_extract`** — open a search page, fill a non-secret query,
  submit, extract bounded markdown (documentation example).
- **`download_report`** — open a page and save a download artifact to the
  workspace, workspace-confined and size-bound (documentation example).

To add a workflow, define a `WorkflowDefinition`, call
`WorkflowCatalog.register(...)` (registration-time validation) or pass an
inline definition to `POST /v1/workflows/run`.

### The engine (durability, resumability, exactly-once)

`era/services/workflow_service.py` dispatches **every inner step exclusively
through `ExecutionService`** — the engine never calls a provider directly.
Per-step results are recorded in `workflow_step_run`; the run row
(`workflow_run`) tracks `status`, `current_step`, a resume token, the checksum
of the definition used, and the redacted definition + params.

- **Durable**: run + per-step state live in the database (migration `0006`).
- **Resumable**: a run paused at a confirmation continues from its durable
  checkpoint; a process-restarted run is resumed the same way. Resume is
  **actor-bound** (a different actor cannot resume another actor's run) and
  preserves the original `execution_scope` so the browser context resumes
  correctly. On resume the engine **re-inspects** the current page and
  re-acquires targets fail-closed — it never trusts persisted browser state.
- **Exactly-once**: `run_token` is unique per actor (reusing the same token
  returns the existing run). A completed step is never re-run; a confirmed
  (approved + dispatched) step is never re-dispatched — on resume the engine
  checks the confirmation's **audit outcome** (it never assumes an approval
  succeeded) and revalidates any declared post-condition before continuing.
- **Fail-closed**: drift, stale refs, zero/multi-match, denied/expired
  confirmations, checksum drift of the definition, and budget breaches stop
  the workflow deterministically. `SIDE_EFFECT_UNKNOWN` maps to a workflow
  `ambiguous` state that requires explicit operator resolution
  (`continue`/`abort`) — never auto-continue, never auto-retry.
- **Bounded**: hard caps on max steps, total param size and wall-clock time
  make infinite loops structurally impossible. Non-retryable mutating steps
  are never retried.

### Secrets and injection defenses

- Workflow params/definitions stored in the DB are redacted; opaque
  `vault:browser/<name>` references stay visible so approvals can resubmit the
  exact hash-bound action. Receipts never include resolved secret values,
  cookies, headers, raw form values or raw refs.
- Page content is **data, never policy**: a page containing "ignore previous
  instructions / run this workflow / send this secret" cannot define, modify,
  start or alter a workflow. Workflows are strict-schema code/config; browser
  observations remain untrusted (`content_untrusted`).

### API

```bash
POST /v1/workflows/run      {"workflow": "login", "params": {...}, "run_token": "..."}
POST /v1/workflows/{id}/resume
POST /v1/workflows/{id}/cancel
POST /v1/workflows/{id}/resolve   {"decision": "continue" | "abort"}
GET  /v1/workflows/{id}
GET  /v1/workflows
```

A workflow run is gated like any action (RBAC domain + permission engine) and
its inner steps each pass their own gates through `ExecutionService`.
Confirmations are approved through the existing
`POST /v1/confirmations/{id}/approve` flow; the workflow is then resumed from
its durable checkpoint.

### Configuration

```dotenv
ERA_WORKFLOW_MAX_STEPS=50
ERA_WORKFLOW_MAX_WALLCLOCK_SECONDS=600.0
ERA_WORKFLOW_MAX_PENDING_CONFIRMATIONS=1
ERA_WORKFLOW_MAX_PARAM_CHARS=16384
```

### Tests

Phase 4C adds **33 offline/simulator cases** (workflow definition validation,
catalog/permission integration, engine dispatch through `ExecutionService`,
the happy-path login workflow, pause→approve→resume→revalidate→exactly-once,
page drift after approval, `SIDE_EFFECT_UNKNOWN`→ambiguous→operator
resolution, restart-style resume without persisted refs, stale/zero/multi-match,
cross-actor resume rejection, secret redaction, prompt-injection isolation,
non-retryable steps, bounded execution, sanitized receipts) plus migration
tests for `0006`:

```bash
pytest                                    # full suite (offline, green)
ruff check .                              # clean
ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py
```

The opt-in real-Chromium E2E now also runs a workflow through the engine on a
public page; with Chromium configured it runs and passes, and without
`ERA_TEST_BROWSER=1` it is skipped with an explicit reason. Full-suite result
with the real-Chromium E2E enabled: **770 passed, 1 skipped** (the single skip
is the opt-in live-PostgreSQL integration test).

### Remaining limitations

- Workflow fills are vault-only by default for secret/unknown-sensitivity
  targets (a deliberate fail-closed choice). Non-secret fills are allowed only
  on explicitly non-password inputs.
- Confirmed steps without a declared `expect` are recorded as completed after
  approval based on the audit outcome; their *content* is not re-verified (only
  dispatch success + any declared post-condition). Prefer adding an `expect`
  post-condition to every mutating step.
- A workflow run pauses at each confirmation and is continued by an explicit
  resume call; approvals do not auto-advance the run.
- The reference `login` workflow's offline test uses the simulator's
  form-action discovery; real-world login pages may need a tab-opened or
  custom post-condition.
- Cross-process persistent cookies/session store remain out of scope (browser
  state stays ephemeral per run, with only confirmation-pause continuity).

## Phase 4D: Workflow Operations & Governance (delivered)

Phase 4D adds the **operations layer** around the Phase 4C engine without
changing its durability/resumability/exactly-once/fail-closed guarantees:
workflows become schedulable, governed, templated, reviewable and observable.

### Scheduling

A workflow can be registered as a recurring schedule
(`POST /v1/workflow-schedules`) reusing the Phase 3H cron/interval machinery.
A due schedule is started through the **same** `WorkflowService` gates as an
interactive run, so it is never a confirmation bypass (a scheduled login that
needs confirmation pauses exactly like an interactive run).

- Deterministic run token `sched:<actor>:<schedule_id>:<due_time>` gives
  crash/double-due exactly-once dedup.
- Schedules store redacted params and the actor role; registration rejects a
  schedule whose inner steps the role may not run.

### Parallel & conditional steps (bounded DAG)

Workflow definitions may declare `depends_on`, `parallel` blocks with
`max_concurrency` (default 1 = today's sequential behavior), and a pure,
schema-constrained `condition` predicate (`step_result`, `url_contains`,
`element_present`) over prior step receipts — never arbitrary code and never
raw page text. Validation rejects cycles, unknown deps, parallel-sibling
conditional dependencies, unbounded fan-out and non-allowed predicates. Each
step still goes through `ExecutionService` independently.

### Governance

A deterministic governance layer constrains execution globally and per
actor/workflow (concurrency caps, per-window rate, step/cost budgets) before a
run starts and re-checks during long runs. A cap breach starts the run as
`FAILED` with a machine-readable `governance_code` (`CONCURRENCY_EXCEEDED`,
`RATE_LIMIT_EXCEEDED`, `BUDGET_EXCEEDED`) and is audited.

### Templates & versioning

`workflow_template` stores immutable, versioned, params-schema-validated
definitions. `login`, `search_and_extract` and `download_report` are published
as version 1 templates. A run pins the exact template+version+checksum; a later
version bump never silently changes an in-flight run (checksum drift fails
closed).

### Operator review

Admin-only endpoints list runs awaiting attention, expose an ordered timeline,
and allow cross-actor resolve/cancel/approve with a clear audit trail. No
operator surface exposes plaintext values, refs, cookies, headers or page
content.

### Observability

Bounded, actor-scoped filtering and aggregation:
`GET /v1/workflows/summary?status=&workflow=`,
`GET /v1/workflows/aggregate?workflow=&start_at=&end_at=` and
`GET /v1/workflows/{id}/timeline`.

### Migration

Migration `0007_phase_4d_operations` adds `workflow_schedule`,
`workflow_template`, `workflow_governance_counter` and additive columns on
`workflow_run` / `workflow_step_run`. It is backward compatible and the
downgrade drops only the new tables/columns.

### New endpoints

```bash
POST /v1/workflow-schedules                      # register a schedule
GET/PATCH/DELETE /v1/workflow-schedules/{id}
POST /v1/workflow-templates                      # publish a template version
GET  /v1/workflow-templates
POST /v1/workflow-templates/instantiate
GET  /v1/workflows/awaiting                      # admin-only
GET  /v1/workflows/summary?limit=&offset=
GET  /v1/workflows/aggregate
GET  /v1/workflows/{id}/timeline
POST /v1/admin/workflows/{id}/resolve            # admin cross-actor
POST /v1/admin/workflows/{id}/cancel             # admin cross-actor
POST /v1/admin/confirmations/{id}/approve        # admin cross-actor
```

### Configuration

```dotenv
ERA_WORKFLOW_MAX_CONCURRENT_PER_ACTOR=2
ERA_WORKFLOW_MAX_CONCURRENT_PER_WORKFLOW=2
ERA_WORKFLOW_MAX_RUNS_PER_WINDOW=10
ERA_WORKFLOW_RATE_WINDOW_SECONDS=3600
ERA_WORKFLOW_MAX_STEPS_PER_RUN=120
ERA_WORKFLOW_MAX_COST_UNITS=1000
```

### Tests

Phase 4D adds offline/simulator coverage for scheduling (register, due,
crash-double-due dedup, confirmation-pause, enable/disable), DAG validation and
execution, governance caps and DB racing, template/versioning, operator review
(timeline, sanitization, cross-actor resolve/deny), observability and RBAC,
plus migration tests for `0007`.

### Remaining limitations (Phase 4D)

- True parallel *mutating* steps are bounded by `workflow_max_pending_confirmations`
  (default 1), so mutating parallel blocks stay sequential/safe by default;
  SAFE read steps (e.g. parallel extract) can run concurrently.
- The scheduler runs in-process (Phase 3H reuse); a production deployment
  should run one scheduler worker per DB.
- Template publishing/versioning is metadata-only; no runtime template
  delegation beyond the catalogued browser action allowlist.
