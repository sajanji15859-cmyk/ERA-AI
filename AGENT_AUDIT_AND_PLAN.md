# ERA-AI → Autonomous AI Agent: Full Audit & Transformation Roadmap

*Status: audit complete + **Phase 3A (MVEA)**, **Phase 3B (LLM hardening + streaming chat API)** and **Phase 3C (Credential Vault + Provider Secrets)** implemented. Baseline before changes: `259 passed` on `main` (Phase 1C–1F + 2A). All existing tests still pass — current total: **444 passed** (259 pre-existing + 185 new).*

---

## सारांश (Executive Summary)

**ERA-AI आज एक chatbot नहीं है — यह एक बहुत solid, well-tested "security + execution foundation" है, जिसमें agent अभी सिर्फ़ एक abstract interface है।** Phase 1C–1F + 2A ने निम्न चीज़ें पहले ही बना दी हैं: permission engine (fail-closed), ~37 action types का catalog (web/email/whatsapp/booking/file/device), versioned policy, two-phase fail-closed execution, single-use actor-bound confirmations, tamper-evident append-only audit log, secret redaction, provider SPI + registry, retry/circuit-breaker/timeouts, और API authentication + RBAC। **259 tests green हैं।**

जो missing है: **real agent loop, real LLM, real tools (सिर्फ़ StubProvider है), memory, planner, verification।** असली काम अब "foundation को agent में बदलना" है — foundation दोबारा बनाने की ज़रूरत नहीं है। इस session में **Phase 3A (MVEA — Minimum Viable ERA Agent)** ने यह कर दिया:

- Full agent loop: PLAN → EXECUTE → OBSERVE → VERIFY → SUCCESS / (FAIL → ANALYZE → RETRY → VERIFY)
- Planner + Task Manager (pending/running/completed/failed/retrying/waiting_for_user)
- Real tools: sandboxed Workspace filesystem (fs.*, photo.*) + SSRF-safe Web provider (web.search/fetch/download)
- Memory (short-term + long-term) + Verification (HTML/link/file checks) + retry/replan
- Cost controls (iterations, tool calls, LLM calls, tokens, timeout, USD cap)
- Human approval: हर risky action मौजूदा confirmation gate से गुज़रती है
- Real LLM: OpenAI-compatible provider (free tiers जैसे OpenRouter/Groq/OpenAI free) — बिना key के **offline deterministic mode** में भी पूरा loop चलता है (FREE LIMITATION देखें)
- पहला real goal पूरा: **"welding training website बनाओ"** → plan → files → verify → fix → final site

**कोई existing behavior नहीं बदला।** Default container वही रहता है; agent opt-in है (`ERA_AGENT_ENABLED=true`), सारे 259 पुराने tests unchanged pass करते हैं।

---

## A) CURRENT ARCHITECTURE (audit result)

### Layer diagram (as built)

```
                ┌──────────────────────────────────────────────┐
                │  FastAPI (era/api/*)                          │
                │  AuthN (Bearer API key → User) + RBAC outer   │
                │  gate (role → permission → capability domain) │
                └──────────────────────┬───────────────────────┘
                                       │ (server-derived identity)
                ┌──────────────────────▼───────────────────────┐
                │  ExecutionService  (era/services/)            │
                │  1. PermissionEngine  (action, policy)→Decision│
                │     fail-closed; FORBIDDEN override-proof     │
                │  2. AUTHORIZED durably committed to AUDIT LOG │
                │  3. Reliability layer: circuit breaker +      │
                │     deadline-aware retry + hard timeout       │
                │  4. ToolProvider.validate → execute           │
                │  5. EXECUTED/FAILED/REJECTED appended         │
                └───────┬───────────────────────────┬───────────┘
                        │                           │
             ┌──────────▼─────────┐      ┌──────────▼──────────┐
             │ ActionCatalog      │      │ ToolRegistry        │
             │ (37 action types,  │      │ (action_type →      │
             │  risk tiers,       │      │  ToolProvider)      │
             │  domains,          │      │  StubProvider only  │
             │  secret_fields)    │      │  (1C–1F)            │
             └────────────────────┘      └─────────────────────┘
             ┌──────────────────────────────────────────────────┐
             │ SQLite repos + append-only audit (hash-chained,  │
             │ DB triggers), policy versions, confirmations,     │
             │ users/API-keys (SHA-256 hashed)                   │
             └──────────────────────────────────────────────────┘

   (Abstract only, pre-3A) LLMProvider / AgentInterface protocols
   (Dead code) agent.py, brain.py, chat.py, config.py, main.py,
   memory.py, research.py at repo root — legacy prototype.
```

### Component inventory (the 14 audit questions, answered)

| # | Audit question | Status in codebase |
|---|---|---|
| 1 | Current architecture | Layered FastAPI + service/repository + provider SPI. Security-first two-phase fail-closed execution. SQLite backend (Postgres-ready protocols). |
| 2 | Existing AI/model integration | **Abstract only**: `LLMProvider` / `AgentInterface` protocols + `MockLLMProvider` (fixed canned response). `Container.llm_provider = None`. No real model. |
| 3 | Existing tools | **SPI + registry complete, no real tools.** `ToolProvider`/`AsyncToolProvider` protocols, `ToolRegistry`, `ToolError`/`ProviderErrorCode`, retry/circuit-breaker/timeout, introspection. Only `StubProvider` (no-op for ALL 37 action types) is wired. |
| 4 | Existing memory/state | None in `era/` (legacy root `memory.py` is an in-memory list). State = DB tables (audit, confirmations, policy, users). No short/long-term agent memory. |
| 5 | Existing file handling | Catalogued `fs.*` + `photo.*` actions (risk tiers declared) but **no provider** — no path sandbox, no size caps implemented. |
| 6 | Existing web/search capability | Catalogued `web.search/fetch/download` (with SSRF warning in comments) but **no provider**, no network code. |
| 7 | Existing GitHub/code capability | None (no action types, no provider). |
| 8 | Existing authentication/security | **Strong**: API-key auth (SHA-256 hashed, shown once), RBAC roles+permissions+domain allowlist, actor-bound confirmations, input hardening (schema strict, param budget, body-size limit), append-only audit + verify endpoint, secret redaction. No credential vault yet. |
| 9 | Existing testing infrastructure | Excellent: pytest, 259 tests, contract suites (`tests/provider_contract.py` reusable for every new provider), fail-closed/security regression locks, ruff-clean. |
| 10 | Existing Phase 1F functionality | Delivered: retry policy (bounded, deadline-aware, only retryable codes), per-provider circuit breakers, async provider foundation, all integrated at the dispatch boundary *after* authorization commit. |
| 11 | क्या पहले से मौजूद है | Security gate, audit, confirmations, policy, SPI/registry, reliability layer, authN/Z, input validation, config, CLI, tests — i.e. **the entire "safe execution" half of an agent**. |
| 12 | क्या missing है | Real LLM, agent loop/orchestrator, planner, task manager, memory, verification, real providers (web/file/…), credential vault, UI, rate limiting, migrations, Postgres, signing. |
| 13 | क्या बदलना ज़रूरी है | (a) `StubProvider` claims every action type → needs withdraw/exclude so real providers can take over (`fs.*`, `web.*`). (b) Add `agent.run` permission for the agent API. (c) `LLMResponse` needs optional usage metadata for cost control. (d) Audit repo list needs a `confirmation_id` filter so the loop can resolve approvals. All additive. |
| 14 | क्या बिल्कुल नहीं बदलना चाहिए | Permission engine semantics, fail-closed defaults, policy defaults, audit-before-execute order, confirmation single-use/actor-binding/TTL, secret boundary (providers own credentials; core sees only refs), error taxonomy, existing public API behavior, and all 259 existing tests. Phase 3A respected all of this. |

### B) The 8 key questions — direct answers

1. **Current architecture?** See §A diagram. A security/execution platform, not yet an agent.
2. **Components already present?** Permission engine, action catalog, policy, execution gate, confirmations, audit, SPI/registry, retry/breaker/timeout, authN/Z, input hardening, CLI, tests.
3. **Phase 1F complete?** Yes — retry + circuit breaker + async foundation, at the dispatch boundary, without weakening 1C/1D/1E invariants.
4. **Missing for the agent?** Brain (LLM), planner, task manager, execution loop, real tools, memory, verification/retry logic, approval→loop integration.
5. **Minimal-change integration?** Implement `AgentInterface` as a new `era/agents/` subsystem that talks ONLY to the existing `ExecutionService` (as 1C designed). No new execution path, no bypass. New providers plug into the existing registry; `StubProvider` withdraws claimed action types. Agent API = new router + one new permission. Everything else is additive.
6. **Reusable?** ExecutionService (authorization+confirmation+audit+reliability), ToolRegistry/SPI/error taxonomy, action catalog (`fs.*`, `web.*` already catalogued with correct risk tiers), policy/confirmation machinery, authN/Z + `build_ctx`, repos, config, provider contract test suite.
7. **Refactor required?** Almost none. `StubProvider` gains an optional `exclude` (default = current behavior); `LLMResponse` gains optional `usage`; `AuditRepo.list` gains optional `confirmation_id` filter. No renames, no rewrites.
8. **Practical free/mobile-first architecture?** SQLite + FastAPI + httpx/urllib only, zero paid services required. LLM = OpenAI-compatible free tiers when the user adds a key; otherwise a deterministic offline brain. Web search = DuckDuckGo (no key). Files = local workspace sandbox. This is exactly what Phase 3A ships.

---

## C) ERA AGENT ARCHITECTURE (proposed & implemented core)

```
User Goal
  ↓  AgentService (start/continue runs, persisted state)
  ↓  AgentLoop ── budget gate (iterations, tool calls, LLM calls, tokens,
  │               wall-clock timeout, USD cap)
  ↓
Planner (LLMPlanner → falls back to RulePlanner)  →  Plan{Task[]}
  ↓
Task Manager (pending → running → completed / failed / retrying /
              waiting_for_user; dependency order; per-task max attempts)
  ↓
Brain (LLMBrain or OfflineBrain) → tool selection + params/content
  ↓
Tool execution → ExecutionService.request()  ← THE EXISTING GATE
  │   (permission engine → allow / CONFIRM → confirmation / deny →
  │    audit-commit → breaker+retry+timeout → provider execute)
  ↓
Observation (executed / failed / rejected / confirmation_required)
  ↓
Verification (action success, file existence/size, HTML structure+keywords,
              link integrity)  →  verdict
  ↓
  ok → memory update, next task
  fail → correction note → retry (bounded) → re-verify → or mark failed →
         optional one replan with repair tasks
  ↓
Final Result (status, summary, artifacts, counts, cost, audit trail)
```

Design decisions (documented, deliberate):

- **The agent loop calls the existing ExecutionService for every tool call.** The model/agent never touches providers directly (structurally impossible — providers aren't exposed to it). Prompt injection, malicious tool args, etc. still hit the same permission gate, audit log and redaction as any API caller.
- **Tool selection is planner/brain-driven, not free-form model-driven (MVEA scope).** The planner assigns each task an action; the brain refines params/content and may propose alternative registered actions (validated against the registry; unknown → fall back to planned). A fully free-form model tool-selection loop is a later phase (Phase I) — this keeps MVEA deterministic, cheap and safe.
- **Approval integration:** when execution returns `confirmation_required`, the loop pauses (task → `waiting_for_user`, run → `waiting_for_user`) and records the confirmation id. The human approves/denies through the existing `/v1/confirmations/{id}` endpoints (unchanged). On continue, the loop resolves each pending confirmation **from the append-only audit log** (EXECUTED → completed; FAILED/REJECTED/DENIED/EXPIRED → failed) — the audit log is the single source of truth, so the agent cannot "believe" an approval that never happened.
- **Safety rails (anti-infinite-loop), enforced in code:** `max_iterations` (25), `max_tool_calls` (40), per-task `max_attempts` (3), run wall-clock timeout (900 s), `max_llm_calls` (20), `max_tokens` per call, USD cost cap (0.10 default). Any breach → run ends `budget_exceeded`/`aborted`, never an endless loop.
- **Risk tiers unchanged:** `fs.write/move`, `web.download` are MUTATING → CONFIRM; `fs.delete/photo.delete` are DESTRUCTIVE → CONFIRM_STRONG; `web.fetch` stays SENSITIVE (SSRF-guarded). Default policy untouched.

### Core components (file map)

| Component | Where |
|---|---|
| Agent Brain | `era/agents/brain.py` (+ `era/providers/llm_openai.py` for real LLM) |
| Planner | `era/agents/planner.py` (RulePlanner offline + LLMPlanner) |
| Task Manager | `era/agents/task_manager.py` |
| Tool System | existing `era/core/tool_registry.py` + new `era/providers/workspace.py`, `era/providers/web.py` |
| Memory | `era/agents/memory.py` (short-term per-run + long-term SQLite per-actor) |
| Verification | `era/agents/verifier.py` (action/file/HTML/link checks) |
| Human Approval | existing confirmation flow + `era/services/agent_service.py` resolution |
| Execution Loop | `era/agents/loop.py` + `era/services/agent_service.py` |
| Budget/Cost | `era/agents/budget.py` |
| API | `era/api/routes/agent.py` (POST `/v1/agent/runs`, GET run, POST continue) |

---

## D) MVEA SPEC — first real goal: "मेरे लिए एक welding training website बनाओ"

End-to-end trace (this is what `python -m era.agent demo` actually does):

1. **Goal समझना** — planner detects "website" intent, extracts subject (`welding training`).
2. **Plan** — decomposes into ~12 tasks: research (best-effort) → site structure → 6 content pages → CSS → JS → verification tasks (HTML, links, structure) → final report.
3. **Tasks** — each task = one catalogued action (`web.search`, `fs.write`, `fs.read`, …) + verification spec + dependencies + max attempts.
4. **Information collection** — `web.search` runs (free, keyless DuckDuckGo). In an offline environment it fails cleanly (`UNAVAILABLE`) and the loop records the observation, marks the best-effort task failed **without failing the run**, and uses the built-in offline knowledge pack — this is exactly the error-recovery path working.
5. **Website structure + code** — `fs.write` creates `index.html`, `safety.html`, `processes.html`, `courses.html`, `career.html`, `contact.html`, `assets/style.css`, `assets/app.js` (content generated by the LLM when configured; otherwise from the offline content pack).
6. **Files create** — WorkspaceProvider, sandboxed to `./workspace`, path-traversal guarded, size-capped.
7. **Test** — verification tasks `fs.read` each page and check: HTML parses, required elements present (`<title>`, `<h1>`, `<nav>`, sections), keywords present, all internal links resolve to real files.
8. **Errors identify + सुधार** — any failing check produces a correction note; the task retries (bounded) with corrected content; after retries, one replan with repair tasks.
9. **Final result** — run report: status, pages built, verification results, artifact list, tool-call count, estimated cost (₹0 in offline mode), full audit trail.

Approval behavior in the demo: `fs.write` is MUTATING → CONFIRM under the default policy. The demo operator auto-approves **workspace-scoped, non-destructive** writes (and prints each approval); destructive actions would still require CONFIRM_STRONG with a challenge. In API mode, nothing is auto-approved — the run pauses and waits for the user.

---

## E) FREE / MOBILE-FIRST ANALYSIS

| Concern | Choice | Cost |
|---|---|---|
| LLM | OpenAI-compatible endpoint (`base_url` configurable) → works with OpenAI free tier, Groq free tier, OpenRouter free models, Together, Ollama (local), etc. | ₹0 (user's own free key) or ₹0 (offline mode) |
| Web search | DuckDuckGo HTML endpoint, no API key | ₹0 |
| Web fetch | Direct HTTP(S) with SSRF guards | ₹0 |
| Files | Local workspace directory (SQLite DB included) | ₹0 |
| Vector DB / embeddings | Not needed for MVEA (exact-key long-term memory) | ₹0 |
| Hosting | Runs on a laptop / GitHub Codespaces free tier / any $0 VPS | ₹0 |

**FREE LIMITATION notes (honest):**
1. **No API key = no real LLM.** The full agent architecture runs offline with a deterministic brain (plans, builds, verifies real artifacts), but *open-ended* reasoning, natural-language content generation and free-form tool selection need a model. Alternative: any OpenAI-compatible free tier, or a local model (Ollama/LlamaFile) pointed at via `ERA_AGENT_LLM_BASE_URL`.
2. **Browser automation (click/navigate)** is not realistically free/reliable via pure HTTP. Phase G will ship HTTP fetch/parse first; real browser automation is marked "FREE LIMITATION — use Playwright on your own machine or a paid browser API later".
3. **Image generation** is a paid API in practice. MVEA excludes it; the tool framework is ready to add an `image.generate` provider later.
4. **Email/WhatsApp sending** needs the user's own account credentials (provider-owned, never stored in core). Phase roadmap, not MVEA.
5. **Sandbox environment network note:** this dev sandbox's egress allowlist blocks most sites (GitHub + PyPI reachable). The web provider degrades gracefully to `UNAVAILABLE`, which the agent handles as an observation — it never crashes the run.

## F) COST CONTROLS (in the architecture from day one)

| Control | Setting (env) | Default |
|---|---|---|
| Max loop iterations | `ERA_AGENT_MAX_ITERATIONS` | 25 |
| Max tool calls per run | `ERA_AGENT_MAX_TOOL_CALLS` | 40 |
| Per-task max attempts | `ERA_AGENT_MAX_RETRIES_PER_TASK` | 2 (i.e. 3 tries) |
| Run wall-clock timeout | `ERA_AGENT_RUN_TIMEOUT_SECONDS` | 900 s |
| Max LLM calls per run | `ERA_AGENT_MAX_LLM_CALLS` | 20 |
| Max tokens per LLM call | `ERA_AGENT_LLM_MAX_TOKENS` | 2048 |
| USD cost cap per run | `ERA_AGENT_COST_CAP_USD` | 0.10 |
| Model choice | `ERA_AGENT_LLM_MODEL` | `gpt-4o-mini` (or any cheap model) |
| Caching | Plan/verification results reused within a run; long-term memory avoids re-research | — |

Token usage from provider `usage` payloads (estimated by length when absent). A run that exceeds any cap terminates cleanly with `budget_exceeded` and a full audit trail — the agent can never silently burn money or loop forever.

## G) SECURITY (reused, not rebuilt)

The agent adds **no new privilege surface** — every tool call flows through the existing gate:

- **Tool permissions:** the existing permission engine + policy + RBAC domain allowlist gate every call. The agent cannot call anything the policy denies.
- **Sandboxed execution:** filesystem confined to `workspace_root` (resolved-path containment + traversal rejection → `FORBIDDEN`); web fetch confined by scheme allowlist + private/loopback/link-local/reserved IP blocking (pre-connect DNS check).
- **Secret/API-key protection:** LLM provider holds its key in env/config only; the agent layer sees `model_ref`s; provider results are redaction-aware (no key fragments), errors never include Authorization headers.
- **Input validation:** reused strict schemas + param budget for every tool call; file writes capped at `workspace_max_file_bytes`.
- **Output validation:** verification layer checks produced artifacts before the run claims success.
- **Command restrictions:** no shell/code-exec tool in MVEA (deliberate — `device.shell` remains admin-only, code execution arrives later inside an explicit sandbox phase).
- **Rate limits:** per-provider circuit breakers + retry policy already gate dispatch; the loop's tool-call cap bounds total volume.
- **Approval gates:** MUTATING → CONFIRM, DESTRUCTIVE/FINANCIAL/BOOKING → CONFIRM_STRONG with challenge, FORBIDDEN → DENY (override-proof). Unchanged defaults.

## H) DEVELOPMENT PHASES (roadmap — as adapted to this codebase)

| Phase | Content | Status |
|---|---|---|
| **Phase A — Audit** | Full audit of 1C–1F+2A, gap analysis, roadmap | ✅ this document |
| **Phase B — Agent core + planner** | `era/agents/` models, budget, RulePlanner + LLMPlanner, brain interface | ✅ delivered (3A) |
| **Phase C — Task manager + execution loop** | TaskManager states, AgentLoop (plan→execute→observe→verify→retry), pause/resume on approval | ✅ delivered (3A) |
| **Phase D — Tool framework** | SPI/registry already existed; added real Workspace + Web providers with StubProvider withdraw | ✅ delivered (3A) |
| **Phase E — Memory/state** | Short-term run memory + long-term per-actor SQLite memory | ✅ delivered (3A) |
| **Phase F — Verification + retry** | Verifier (action/file/HTML/link), correction notes, bounded retry, one replan | ✅ delivered (3A) |
| **Phase G — Web/browser** | Real web.search/fetch/download shipped; browser automation = FREE LIMITATION (later, Playwright/self-hosted) | ⬜ partial (next) |
| **Phase 3B — LLM hardening + streaming chat** | SSE chat API + typed events, ToolCallBrain (native function calling, catalog/registry/RBAC-validated), prompt-injection defense + tests, in-loop RBAC domain guard, pricing/cost accounting, real SSE LLM streaming, 5 product bugs fixed (incl. duplicate-approval poisoning, missing `_settle_failure`, artifact loss on resume, 2A param caps blocking API approvals) | ✅ delivered (3B) |
| **Phase H — Coding/file agent** | The welding-site goal works end-to-end; deeper code-exec sandbox + git integration next | ⬜ next |
| **Phase 3C — Credential vault + provider secrets (2B)** | AES-256-GCM vault (env-only master key, fail-closed), admin vault API, vault-backed secret resolution for providers, real SMTP email provider, LLM key via vault, `vault.manage` RBAC | ✅ delivered (3C) |
| **Phase I — Multi-agent, streaming UI, Postgres, signing** | Multiple agents, SSE streaming chat, migrations, keyed audit signing, rate limiting (vault done in 3C) | ⬜ future |

### Next recommended phases (in order)
1. ~~Phase 3C — Credential vault (2B)~~ — ✅ delivered.
3. **Phase 3D — GitHub + code-exec sandbox provider** (user's "GitHub/code capability" ask) — `github.*` action types, PAT in vault, repo/file operations; subprocess code runner with allowlist, time/memory caps, no network by default.
4. **Phase 3E — Web UI** (mobile-first chat dashboard over the same authenticated API).
5. **Phase 3F — Scale:** Postgres, Alembic, keyed audit signing, rate limiting.

### Testing strategy per phase (uniform)
- New behavior: unit tests per component (planner, task manager, budget, verifier, memory).
- Providers: reuse `tests/provider_contract.py` + security-specific tests (path traversal, SSRF, size caps).
- Loop: end-to-end runs against in-memory fakes (success, failure→retry→recover, confirmation pause→approve→resume, budget abort).
- Security: regression locks — every new gate must fail closed.
- **Completion criteria:** all old tests + new tests green, ruff clean, demo run produces the welding site and verifies it.

---

## I) PHASE 3A DELIVERED (this session) — file inventory

New modules:

```
era/agents/            models, budget, planner, brain, task_manager,
                       verifier, loop, memory, content (offline knowledge pack)
era/providers/llm_openai.py    OpenAI-compatible LLM provider (free-tier ready)
era/providers/workspace.py     sandboxed fs.* + photo.* provider
era/providers/web.py           keyless web.search + SSRF-safe fetch/download
era/security/path_safety.py    workspace path containment helper
era/security/url_safety.py     SSRF URL/DNS guards
era/models/agent.py            AgentRun + MemoryEntry ORM
era/services/agent_service.py  run lifecycle + approval resolution from audit log
era/agent_runtime.py           agent container wiring (providers + llm + service)
era/agent.py                   CLI: `python -m era.agent demo|run`
era/api/routes/agent.py        POST /v1/agent/runs, GET run/list, POST continue
era/schemas/agent.py           request/response models
tests/test_agent_*.py          planner, tasks, budget, loop, workspace, web,
                               verifier, memory, llm_openai, api, demo
```

Modified (additive only): `era/config.py` (agent settings), `era/security/rbac.py` (`agent.run` permission), `era/providers/stub.py` (optional `exclude`), `era/core/llm.py` (`LLMResponse.usage`), `era/repositories/sqlite.py` (agent-run + memory repos, audit `confirmation_id` filter), `era/models/__init__.py`, `era/main.py` (agent router when enabled), `.env.example`, `.gitignore` (`workspace/`), README (Phase 3A section).

**Run it:** `python -m era.agent demo` → builds `workspace/welding_training_site/` and prints the run report. **API:** enable `ERA_AGENT_ENABLED=true`, start `uvicorn era.main:create_app --factory`, then `POST /v1/agent/runs {"goal": "मेरे लिए एक welding training website बनाओ"}`.

## J) PHASE 3C DELIVERED — file inventory

New modules:

```
era/security/vault.py          AES-256-GCM core: master-key parsing (hex/b64,
                               malformed -> absent), vault:<domain>/<name> ref
                               parsing, AAD-bound encrypt/decrypt, VaultError
era/models/vault.py            VaultSecret ORM (ciphertext + nonce + metadata
                               only; unique (domain,name); soft revocation)
era/services/vault_service.py  VaultService (store/rotate/revoke/list/resolve,
                               every op + every failure audited, fail-closed)
                               + VaultRefResolver adapter for providers
era/schemas/vault.py           strict request/response schemas (value never
                               returned)
era/api/routes/vault.py        POST /v1/vault/secrets (create-or-rotate),
                               GET /v1/vault/secrets, POST .../revoke
                               (admin-only: vault.manage; 503 when disabled)
era/providers/email_smtp.py    real email.send via smtplib; credentials plain
                               env or vault refs resolved at send time
tests/test_vault.py            crypto (roundtrip, tamper, AAD, nonce), master
                               key parsing, ref parsing, service, at-rest
                               ciphertext check on the DB file
tests/test_vault_api.py        RBAC (401/403/200), no value leakage, 422
                               validation, 503 disabled
tests/test_email_smtp.py       in-process SMTP sink: end-to-end send through
                               the approval gate with vault-resolved creds,
                               AUTH/TIMEOUT/UNAVAILABLE mapping, AUTH never
                               retried, fail-closed paths, redaction locks
tests/test_agent_llm_vault.py  LLM key via vault (build-time resolution,
                               fail-closed on disabled/unknown ref, plain env
                               key unchanged)
tests/test_security_regression.py  +5 vault regression locks
```

Modified (additive only): `pyproject.toml` (`cryptography>=42`, v0.4.0),
`era/config.py` (`vault_master_key` + `email_smtp_*`),
`era/security/rbac.py` (`vault.manage`, admin-only),
`era/models/__init__.py` (`VaultSecret`), `era/repositories/base.py` +
`era/repositories/sqlite.py` (`VaultSecretRepo`), `era/container.py`
(`vault_service` always built, disabled by default), `era/main.py` (vault
router), `era/agent_runtime.py` (vault-aware LLM build + opt-in SMTP
provider via `VaultRefResolver`), `era/providers/__init__.py`,
`.env.example`, `README.md` (Phase 3C section).

**Design invariants kept:** the secret boundary (core sees only `vault:`
refs; providers own credential access), fail-closed defaults,
audit-before-everything (vault ops + resolutions are audit rows), the
default container is unchanged when no vault key / SMTP host is configured,
and all 398 pre-existing tests pass unmodified (total now 444).
