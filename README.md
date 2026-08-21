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
