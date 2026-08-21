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
pytest  # 546 passed, 1 live-Postgres test skipped unless URL is configured
ERA_TEST_POSTGRES_URL='postgresql://...' pytest -m postgres
ruff check .
```
