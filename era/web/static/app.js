/* ERA AI — chat dashboard client (Phase 3E).
 *
 * A dependency-free client over the authenticated ERA API. Design rules:
 *  - Same-origin only: every request is a relative fetch, no CORS.
 *  - The API key lives in localStorage and is sent only as an
 *    `Authorization: Bearer` header — never in a URL or the DOM.
 *  - All dynamic content is inserted with `textContent` (never innerHTML)
 *    so server/event data can never inject markup.
 *  - The client performs no authorization of its own: approve/deny/continue
 *    all go through the server's permission + confirmation gate.
 */

"use strict";

const KEY_STORAGE = "era_api_key";

const state = {
  key: localStorage.getItem(KEY_STORAGE) || "",
  me: null,
  activeRunId: null,
  activeRunStatus: null,
  streaming: false,
  taskTitles: new Map(),
  approvalCards: new Map(), // confirmation_id -> { resolved: boolean, element: HTMLElement }
  pendingIds: [],
};

/* ------------------------------------------------------------------ *
 * Tiny DOM helpers
 * ------------------------------------------------------------------ */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function badge(text, kind) {
  return el("span", "badge" + (kind ? " badge-" + kind : ""), text);
}

/* ------------------------------------------------------------------ *
 * API client
 * ------------------------------------------------------------------ */

function authHeaders() {
  return { Authorization: "Bearer " + state.key };
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function readError(res) {
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("json")) {
    try {
      const data = await res.json();
      return typeof data.detail === "string" ? data.detail : JSON.stringify(data);
    } catch (_) { /* fall through */ }
  }
  try {
    const text = await res.text();
    return text.slice(0, 300) || res.statusText;
  } catch (_) {
    return res.statusText;
  }
}

async function api(path, options) {
  const opts = Object.assign({}, options);
  opts.headers = Object.assign({}, options && options.headers, authHeaders());
  const res = await fetch(path, opts);
  if (res.status === 401) {
    handleUnauthorized();
    throw new ApiError(401, "authentication required");
  }
  if (!res.ok) {
    throw new ApiError(res.status, await readError(res));
  }
  if (res.status === 204) return null;
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

/* ------------------------------------------------------------------ *
 * SSE streaming (fetch-based — EventSource cannot send auth headers)
 * ------------------------------------------------------------------ */

async function streamChat(payload, onEvent) {
  const res = await fetch("/v1/agent/chat", {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
    body: JSON.stringify(payload),
  });
  if (res.status === 401) {
    handleUnauthorized();
    throw new ApiError(401, "authentication required");
  }
  if (!res.ok) {
    throw new ApiError(res.status, await readError(res));
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    buffer += decoder.decode(chunk.value, { stream: true });

    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const lines = frame.split("\n");
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          let ev;
          try {
            ev = JSON.parse(line.slice("data: ".length));
          } catch (_) {
            continue; // ignore a malformed frame rather than crash the stream
          }
          onEvent(ev);
        }
      }
    }
  }
}

/* ------------------------------------------------------------------ *
 * Auth / login
 * ------------------------------------------------------------------ */

function show(elNode, visible) {
  elNode.hidden = !visible;
}

function handleUnauthorized() {
  state.key = "";
  localStorage.removeItem(KEY_STORAGE);
  state.me = null;
  renderAppShell();
}

function renderAppShell() {
  const loggedIn = Boolean(state.key && state.me);
  show(document.getElementById("login-screen"), !loggedIn);
  show(document.getElementById("app"), loggedIn);
  if (loggedIn) {
    const name = state.me.display_name || state.me.username;
    document.getElementById("me-name").textContent = name;
    document.getElementById("me-role").textContent = state.me.role;
    document.getElementById("me-avatar").textContent = name.charAt(0).toUpperCase();
    show(document.getElementById("agent-banner"), !state.me.agent_enabled);
  }
}

async function tryLogin(key) {
  const previous = state.key;
  state.key = key.trim();
  try {
    const me = await api("/v1/me");
    state.me = me;
    localStorage.setItem(KEY_STORAGE, state.key);
    renderAppShell();
    resetChat();
    await loadRuns();
    return true;
  } catch (err) {
    state.key = previous;
    state.me = null;
    const errorBox = document.getElementById("login-error");
    errorBox.textContent = err.status === 401
      ? "Invalid API key — check it and try again."
      : "Could not connect: " + err.message;
    show(errorBox, true);
    return false;
  }
}

async function bootstrap() {
  const key = state.key;
  if (!key) {
    renderAppShell();
    return;
  }
  try {
    state.me = await api("/v1/me");
    renderAppShell();
    resetChat();
    await loadRuns();
  } catch (_) {
    // invalid/revoked key — fall back to the login screen
    state.key = "";
    localStorage.removeItem(KEY_STORAGE);
    renderAppShell();
  }
}

/* ------------------------------------------------------------------ *
 * Runs sidebar
 * ------------------------------------------------------------------ */

async function loadRuns() {
  let data;
  try {
    data = await api("/v1/agent/runs");
  } catch (err) {
    if (err.status === 503) return; // agent disabled — banner already shown
    throw err;
  }
  const list = document.getElementById("runs-list");
  list.textContent = "";
  const runs = (data.runs || []).slice(0, 50);
  if (runs.length === 0) {
    list.appendChild(el("li", "run-item", "No runs yet — start a chat."));
    return;
  }
  for (const run of runs) {
    const item = el("button", "run-item");
    item.type = "button";
    item.dataset.runId = run.run_id;
    if (run.run_id === state.activeRunId) item.classList.add("active");
    const goal = el("span", "run-item-goal", run.goal);
    const meta = el("span", "run-item-meta", run.status);
    item.appendChild(goal);
    item.appendChild(meta);
    item.addEventListener("click", () => openRun(run.run_id));
    list.appendChild(item);
  }
}

function refreshRunListActive() {
  const list = document.getElementById("runs-list");
  Array.from(list.querySelectorAll(".run-item")).forEach((node) => {
    node.classList.toggle("active", node.dataset.runId === state.activeRunId);
  });
}

/* ------------------------------------------------------------------ *
 * Chat / timeline
 * ------------------------------------------------------------------ */

const timeline = () => document.getElementById("timeline");

function resetChat() {
  state.activeRunId = null;
  state.activeRunStatus = null;
  state.streaming = false;
  state.taskTitles.clear();
  state.approvalCards.clear();
  state.pendingIds = [];
  timeline().textContent = "";
  document.getElementById("chat-title").textContent = "New chat";
  document.getElementById("run-status").textContent = "";
  setComposerEnabled(true);
}

function appendCard(className) {
  const card = el("div", "card" + (className ? " " + className : ""));
  timeline().appendChild(card);
  scrollToBottom();
  return card;
}

function appendMetaCard(label, text, kind) {
  const card = appendCard();
  card.appendChild(el("p", "card-label", label));
  card.appendChild(badge(text, kind));
  return card;
}

function scrollToBottom() {
  const t = timeline();
  t.scrollTop = t.scrollHeight;
}

function setStreaming(on) {
  state.streaming = on;
  setComposerEnabled(!on);
  document.getElementById("run-status").textContent = on ? "Working…" : "";
  if (!on) refreshContinueBars();
}

function setComposerEnabled(enabled) {
  const input = document.getElementById("message-input");
  document.getElementById("send-button").disabled = !enabled || input.value.trim() === "";
}

function setRunTitle(goal) {
  const MAX = 48;
  const title = goal.length > MAX ? goal.slice(0, MAX) + "…" : goal;
  document.getElementById("chat-title").textContent = title;
}

/* ---------- Event rendering ---------- */

function renderEvent(ev, live) {
  const type = ev.type;
  const data = ev.data || {};

  if (type === "run_started") {
    state.activeRunId = ev.run_id;
    setRunTitle(data.goal || "Run");
    if (data.resumed) {
      appendMetaCard("Resumed run", "continuing", "info");
    } else {
      const card = appendCard("card-goal");
      card.appendChild(el("p", "card-label", "Goal"));
      const title = el("h3", "card-title", data.goal || "");
      title.style.wordBreak = "break-word";
      card.appendChild(title);
    }
    return;
  }

  if (type === "plan_created") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Plan"));
    card.appendChild(badge((data.task_count || 0) + " tasks", "info"));
    if (data.summary) card.appendChild(el("p", "card-text", data.summary));
    return;
  }

  if (type === "task_started") {
    state.taskTitles.set(data.task_id, data.title || data.task_id);
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Task"));
    card.appendChild(badge("running", "info"));
    card.appendChild(el("h4", "card-title", data.title || data.task_id));
    if (data.action_type) card.appendChild(actionChip(data.action_type));
    return;
  }

  if (type === "tool_call") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Tool call"));
    card.appendChild(actionChip(data.action_type));
    const title = state.taskTitles.get(data.task_id);
    if (title) card.appendChild(el("p", "card-text", title));
    if (data.params && Object.keys(data.params).length) {
      card.appendChild(preJson(data.params));
    }
    return;
  }

  if (type === "observation") {
    const kind = data.status === "executed" ? "ok"
      : data.status === "denied" || data.status === "rejected" ? "err"
      : "info";
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Observation"));
    card.appendChild(badge(data.status, kind));
    if (data.action_type) card.appendChild(actionChip(data.action_type));
    if (data.summary) card.appendChild(el("p", "card-text", data.summary));
    if (data.error) card.appendChild(el("p", "card-text", "Error: " + data.error));
    return;
  }

  if (type === "verdict") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Verification"));
    card.appendChild(badge(data.ok ? "passed" : "failed", data.ok ? "ok" : "err"));
    if (data.reason) card.appendChild(el("p", "card-text", data.reason));
    return;
  }

  if (type === "task_retrying") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Task"));
    card.appendChild(badge("retrying", "warn"));
    const title = state.taskTitles.get(data.task_id);
    card.appendChild(el("h4", "card-title", title || data.task_id));
    if (data.reason) card.appendChild(el("p", "card-text", data.reason));
    return;
  }

  if (type === "task_completed") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Task"));
    card.appendChild(badge("completed", "ok"));
    const title = state.taskTitles.get(data.task_id);
    card.appendChild(el("h4", "card-title", title || data.task_id));
    if (data.note) card.appendChild(el("p", "card-text", data.note));
    return;
  }

  if (type === "task_failed") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Task"));
    card.appendChild(badge("failed", "err"));
    const title = state.taskTitles.get(data.task_id);
    card.appendChild(el("h4", "card-title", title || data.task_id));
    if (data.error) card.appendChild(el("p", "card-text", data.error));
    return;
  }

  if (type === "task_skipped") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Task"));
    card.appendChild(badge("skipped", "warn"));
    const title = state.taskTitles.get(data.task_id);
    card.appendChild(el("h4", "card-title", title || data.task_id));
    if (data.reason) card.appendChild(el("p", "card-text", data.reason));
    return;
  }

  if (type === "confirmation_required") {
    renderApprovalCard(data, live);
    return;
  }

  if (type === "run_finished") {
    renderRunFinished(data, live);
    return;
  }

  if (type === "error") {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Error"));
    card.appendChild(badge("error", "err"));
    if (data.message) card.appendChild(el("p", "card-text", data.message));
    return;
  }

  // Unknown event type: show it compactly rather than dropping it silently.
  const card = appendCard();
  card.appendChild(el("p", "card-label", type));
  card.appendChild(preJson(data));
}

function actionChip(actionType) {
  const chip = el("span", "action-chip", actionType);
  return chip;
}

function preJson(value) {
  let text;
  try {
    text = JSON.stringify(value, null, 2);
  } catch (_) {
    text = String(value);
  }
  return el("pre", "card-code", text);
}

/* ---------- Approval gate ---------- */

function renderApprovalCard(data, live) {
  const cid = data.confirmation_id;
  if (!cid || state.approvalCards.has(cid)) return;

  const strong = data.decision === "CONFIRM_STRONG";
  const card = appendCard("approval-card");
  card.appendChild(el("p", "card-label", "Approval required"));
  card.appendChild(badge(strong ? "strong confirmation" : "confirmation", "warn"));
  card.appendChild(actionChip(data.action_type || "action"));

  const title = state.taskTitles.get(data.task_id);
  if (title) card.appendChild(el("p", "card-text", title));

  if (data.params && Object.keys(data.params).length) {
    card.appendChild(preJson(data.params));
  }

  const record = { resolved: false, element: card };
  state.approvalCards.set(cid, record);

  const actions = el("div", "approval-actions");

  const approveBtn = el("button", "btn btn-ok btn-sm", "Approve");
  const denyBtn = el("button", "btn btn-danger btn-sm", "Deny");
  const statusLine = el("p", "card-text");

  let challengeInput = null;
  if (strong) {
    const box = el("div", "challenge-box");
    box.appendChild(el("p", "card-label", "Type this challenge phrase to confirm"));
    box.appendChild(el("div", "challenge-phrase", data.challenge || "(unavailable)"));
    challengeInput = el("input", null);
    challengeInput.type = "text";
    challengeInput.placeholder = "Paste the phrase above…";
    challengeInput.spellcheck = false;
    challengeInput.autocomplete = "off";
    box.appendChild(challengeInput);
    card.appendChild(box);
  }

  approveBtn.addEventListener("click", () => resolveApproval(cid, record, approveBtn, denyBtn,
    statusLine, challengeInput));
  denyBtn.addEventListener("click", () => denyApproval(cid, record, approveBtn, denyBtn, statusLine));

  actions.appendChild(approveBtn);
  actions.appendChild(denyBtn);
  card.appendChild(actions);
  card.appendChild(statusLine);

  if (!live) {
    // History replay: reflect the server-side truth (the run is already over,
    // or was resumed elsewhere). Fetch status and render read-only.
    refreshApprovalCardState(cid, record, approveBtn, denyBtn, statusLine);
  }
}

async function refreshApprovalCardState(cid, record, approveBtn, denyBtn, statusLine) {
  try {
    const conf = await api("/v1/confirmations/" + encodeURIComponent(cid));
    if (conf.status !== "PENDING") {
      markResolved(cid, record, approveBtn, denyBtn, statusLine,
        "already " + conf.status.toLowerCase());
    }
  } catch (_) {
    // leave interactive; approve/deny will surface the real error
  }
}

function markResolved(cid, record, approveBtn, denyBtn, statusLine, message) {
  record.resolved = true;
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  statusLine.textContent = message;
  refreshContinueBars();
}

async function resolveApproval(cid, record, approveBtn, denyBtn, statusLine, challengeInput) {
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  statusLine.textContent = "Approving…";
  try {
    let conf;
    try {
      conf = await api("/v1/confirmations/" + encodeURIComponent(cid));
    } catch (err) {
      statusLine.textContent = "Could not load confirmation: " + err.message;
      approveBtn.disabled = false;
      denyBtn.disabled = false;
      return;
    }

    if (conf.status !== "PENDING") {
      markResolved(cid, record, approveBtn, denyBtn, statusLine,
        "already " + conf.status.toLowerCase());
      return;
    }

    const body = { action_type: conf.action_type, params: conf.action_params || {} };
    if (conf.challenge_required) {
      const phrase = (challengeInput && challengeInput.value) || "";
      if (!phrase.trim()) {
        statusLine.textContent = "Type the challenge phrase to approve.";
        approveBtn.disabled = false;
        denyBtn.disabled = false;
        return;
      }
      body.challenge = phrase;
    }

    await api("/v1/confirmations/" + encodeURIComponent(cid) + "/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    markResolved(cid, record, approveBtn, denyBtn, statusLine, "Approved ✓");
  } catch (err) {
    statusLine.textContent = "Approve failed: " + err.message;
    approveBtn.disabled = false;
    denyBtn.disabled = false;
  }
}

async function denyApproval(cid, record, approveBtn, denyBtn, statusLine) {
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  statusLine.textContent = "Denying…";
  try {
    await api("/v1/confirmations/" + encodeURIComponent(cid) + "/deny", {
      method: "POST",
    });
    markResolved(cid, record, approveBtn, denyBtn, statusLine, "Denied");
  } catch (err) {
    statusLine.textContent = "Deny failed: " + err.message;
    approveBtn.disabled = false;
    denyBtn.disabled = false;
  }
}

function refreshContinueBars() {
  document.querySelectorAll(".continue-bar .continue-button").forEach((btn) => {
    btn.disabled = state.streaming
      || !state.pendingIds.every((id) => {
        const rec = state.approvalCards.get(id);
        return rec && rec.resolved;
      });
  });
}

function renderContinueBar(pendingIds) {
  // Keep only the most recent continue bar in the timeline (a long run can
  // pause several times; stale bars would only clutter it).
  document.querySelectorAll(".continue-bar").forEach((node) => node.remove());

  state.pendingIds = pendingIds || [];
  const bar = appendCard("continue-bar");
  bar.classList.add("continue-bar");
  bar.classList.remove("card");
  const label = el("p", null,
    "The run is paused for approval. Resolve the requests above, then continue.");
  const btn = el("button", "btn btn-primary btn-sm continue-button", "Continue run");
  btn.disabled = true;
  bar.appendChild(label);
  bar.appendChild(btn);
  btn.addEventListener("click", () => continueActiveRun());
  refreshContinueBars();
}

/* ---------- Run finish ---------- */

function renderRunFinished(data, live) {
  const status = data.status;
  state.activeRunStatus = status;
  const kind = status === "completed" ? "ok"
    : status === "waiting_for_user" ? "info"
    : status === "budget_exceeded" ? "warn" : "err";

  const card = appendCard("card-goal");
  card.appendChild(el("p", "card-label", "Run finished"));
  card.appendChild(badge(status, kind));

  if (data.summary) card.appendChild(el("p", "card-text", data.summary));

  const stats = el("div", "summary-stats");
  if (data.tasks_completed !== undefined) {
    stats.appendChild(stat("tasks", data.tasks_completed + "/"
      + (data.tasks_completed + data.tasks_failed + data.tasks_skipped)));
  }
  if (data.tool_calls !== undefined) stats.appendChild(stat("tool calls", data.tool_calls));
  if (data.llm_calls !== undefined) stats.appendChild(stat("llm calls", data.llm_calls));
  if (data.estimated_cost_usd !== undefined) {
    stats.appendChild(stat("cost", "$" + Number(data.estimated_cost_usd).toFixed(4)));
  }
  if (stats.childElementCount) card.appendChild(stats);

  if (Array.isArray(data.artifacts) && data.artifacts.length) {
    card.appendChild(el("p", "card-label", "Artifacts"));
    const list = el("ul", "artifact-list");
    for (const a of data.artifacts) list.appendChild(el("li", null, a));
    card.appendChild(list);
  }

  if (Array.isArray(data.notes) && data.notes.length) {
    card.appendChild(el("p", "card-label", "Notes"));
    const list = el("ul", "notes-list");
    for (const n of data.notes) list.appendChild(el("li", null, n));
    card.appendChild(list);
  }

  // The continue affordance is rendered only on the live stream; when a run
  // is replayed from history, openRun() adds it once (avoiding duplicates).
  if (status === "waiting_for_user" && live) {
    renderContinueBar(data.pending_confirmations);
  }

  setStreaming(false);
  loadRuns().catch(() => {});
}

function stat(label, value) {
  const node = el("div", "stat");
  node.appendChild(el("b", null, String(value)));
  node.appendChild(el("span", null, " " + label));
  return node;
}

/* ------------------------------------------------------------------ *
 * Chat actions
 * ------------------------------------------------------------------ */

async function sendMessage(message) {
  if (state.streaming) return;
  if (!state.me.agent_enabled) {
    appendMetaCard("Agent disabled", "set ERA_AGENT_ENABLED=true", "err");
    return;
  }

  // Composing starts a fresh run unless the active run is paused for approval,
  // in which case the message continues it (same as the "Continue run" button).
  const isNew = state.activeRunId === null
    || state.activeRunStatus !== "waiting_for_user";
  if (isNew) {
    resetChat();
  }

  const userCard = appendCard();
  userCard.appendChild(el("p", "card-label", "You"));
  const text = el("p", "card-text", message);
  text.style.color = "var(--text)";
  userCard.appendChild(text);

  setStreaming(true);
  const payload = isNew ? { message: message } : { message: message, run_id: state.activeRunId };

  try {
    await streamChat(payload, (ev) => renderEvent(ev, true));
  } catch (err) {
    setStreaming(false);
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Error"));
    card.appendChild(badge(String(err.status || "stream"), "err"));
    card.appendChild(el("p", "card-text", err.message));
  } finally {
    setStreaming(false);
    loadRuns().catch(() => {});
  }
}

async function continueActiveRun() {
  if (state.streaming || !state.activeRunId) return;
  setStreaming(true);
  try {
    await streamChat({ message: "continue", run_id: state.activeRunId },
      (ev) => renderEvent(ev, true));
  } catch (err) {
    setStreaming(false);
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Error"));
    card.appendChild(badge(String(err.status || "stream"), "err"));
    card.appendChild(el("p", "card-text", err.message));
  } finally {
    setStreaming(false);
    loadRuns().catch(() => {});
  }
}

async function openRun(runId) {
  if (state.streaming) return;
  resetChat();
  state.activeRunId = runId;
  setRunTitle("Loading run…");

  try {
    const [record, history] = await Promise.all([
      api("/v1/agent/runs/" + encodeURIComponent(runId)),
      api("/v1/agent/runs/" + encodeURIComponent(runId) + "/events"),
    ]);
    setRunTitle(record.goal || runId);
    state.activeRunStatus = record.status;
    document.getElementById("run-status").textContent = record.status;
    for (const ev of (history.events || [])) {
      renderEvent(ev, false);
    }
    // Replay renders a read-only finish card; add the continue affordance if
    // the run is still paused for approval.
    if (record.status === "waiting_for_user") {
      renderContinueBar(record.pending_confirmations || []);
    }
  } catch (err) {
    const card = appendCard();
    card.appendChild(el("p", "card-label", "Error"));
    card.appendChild(badge(String(err.status || "load"), "err"));
    card.appendChild(el("p", "card-text", err.message));
  }
  refreshRunListActive();
}

/* ------------------------------------------------------------------ *
 * Wiring
 * ------------------------------------------------------------------ */

function autoResize(textarea) {
  textarea.style.height = "auto";
  textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
}

function wire() {
  const loginForm = document.getElementById("login-form");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("api-key-input");
    const button = document.getElementById("login-button");
    button.disabled = true;
    button.textContent = "Connecting…";
    const ok = await tryLogin(input.value);
    if (!ok) {
      button.disabled = false;
      button.textContent = "Connect";
    }
  });

  document.getElementById("logout-button").addEventListener("click", () => {
    state.key = "";
    state.me = null;
    localStorage.removeItem(KEY_STORAGE);
    renderAppShell();
    document.getElementById("api-key-input").value = "";
  });

  document.getElementById("new-chat-button").addEventListener("click", () => {
    if (state.streaming) return;
    resetChat();
    refreshRunListActive();
  });

  const form = document.getElementById("chat-form");
  const input = document.getElementById("message-input");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const message = input.value.trim();
    if (!message || state.streaming) return;
    input.value = "";
    autoResize(input);
    setComposerEnabled(true);
    sendMessage(message);
  });
  input.addEventListener("input", () => {
    autoResize(input);
    setComposerEnabled(!state.streaming);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit();
    }
  });

  // Mobile sidebar toggle
  const menuButton = document.getElementById("menu-button");
  const sidebar = document.querySelector(".sidebar");
  let backdrop = document.getElementById("sidebar-backdrop");
  if (!backdrop) {
    backdrop = el("div", null);
    backdrop.id = "sidebar-backdrop";
    document.body.appendChild(backdrop);
  }
  const closeSidebar = () => {
    sidebar.classList.remove("open");
    backdrop.classList.remove("show");
  };
  menuButton.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    backdrop.classList.toggle("show", sidebar.classList.contains("open"));
  });
  backdrop.addEventListener("click", closeSidebar);
}

  // Phase 4E: Tab navigation (Chat / Operator / Workflows)
  initTabNavigation();
}

function initTabNavigation() {
  const tabs = document.querySelectorAll(".nav-tab");
  const main = document.querySelector(".main");
  const timeline = document.getElementById("timeline");
  const composer = document.querySelector(".composer");
  const chatHead = document.querySelector(".chat-head");
  const operatorPanel = document.getElementById("operator-panel");
  const workflowsPanel = document.getElementById("workflows-panel");

  function showTab(tabName) {
    tabs.forEach(t => t.classList.toggle("active", t.dataset.tab === tabName));
    if (tabName === "chat") {
      if (chatHead) chatHead.hidden = false;
      if (timeline) timeline.hidden = false;
      if (composer) composer.hidden = false;
      if (operatorPanel) operatorPanel.hidden = true;
      if (workflowsPanel) workflowsPanel.hidden = true;
    } else if (tabName === "operator") {
      if (chatHead) chatHead.hidden = true;
      if (timeline) timeline.hidden = true;
      if (composer) composer.hidden = true;
      if (operatorPanel) operatorPanel.hidden = false;
      if (workflowsPanel) workflowsPanel.hidden = true;
      loadOperatorPanel();
    } else if (tabName === "workflows") {
      if (chatHead) chatHead.hidden = true;
      if (timeline) timeline.hidden = true;
      if (composer) composer.hidden = true;
      if (operatorPanel) operatorPanel.hidden = true;
      if (workflowsPanel) workflowsPanel.hidden = false;
      loadWorkflowsPanel();
    }
  }

  tabs.forEach(tab => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  });

  // Refresh buttons
  const refreshApprovals = document.getElementById("refresh-approvals-btn");
  if (refreshApprovals) refreshApprovals.addEventListener("click", loadOperatorPanel);
  const refreshWorkflows = document.getElementById("refresh-workflows-btn");
  if (refreshWorkflows) refreshWorkflows.addEventListener("click", loadWorkflowsPanel);
}

async function loadOperatorPanel() {
  // Load health status
  try {
    const healthRes = await api("/v1/health");
    if (healthRes.ok) {
      const health = await healthRes.json();
      const dbEl = document.getElementById("health-db");
      const leaderEl = document.getElementById("health-leader");
      const versionEl = document.getElementById("health-version");
      if (dbEl) {
        dbEl.textContent = health.database;
        dbEl.className = "health-value " + (health.database === "ok" ? "ok" : "error");
      }
      if (leaderEl) {
        const leaderId = health.scheduler_leader?.leader_id;
        leaderEl.textContent = leaderId ? (leaderId.substring(0, 8) + "…") : "None";
        leaderEl.className = "health-value " + (leaderId ? "ok" : "degraded");
      }
      if (versionEl) {
        versionEl.textContent = health.app_version;
        versionEl.className = "health-value";
      }
    }
  } catch (e) { /* ignore */ }

  // Load pending confirmations
  try {
    const confRes = await api("/v1/operator/pending-confirmations");
    const container = document.getElementById("pending-confirmations-list");
    if (container) {
      if (confRes.ok) {
        const data = await confRes.json();
        const confirmations = data.confirmations || [];
        if (confirmations.length === 0) {
          container.innerHTML = '<p class="empty-state">No pending confirmations</p>';
        } else {
          container.innerHTML = confirmations.map(c => `
            <div class="pending-card" data-id="${c.id}">
              <div class="pending-card-header">
                <span class="pending-card-action">${escHtml(c.action_type)}</span>
                <span class="pending-card-risk risk-${c.risk_level}">${escHtml(c.risk_level)}</span>
              </div>
              <div class="pending-card-details">
                Actor: ${escHtml(c.actor_id || "—")} · Expires: ${escHtml(c.expires_at || "—")}
              </div>
              <div class="pending-card-actions">
                <button class="btn-approve" onclick="operatorApprove('${c.id}')">Approve</button>
                <button class="btn-deny" onclick="operatorDeny('${c.id}')">Deny</button>
              </div>
            </div>
          `).join("");
        }
      } else {
        container.innerHTML = '<p class="empty-state">Access denied (admin role required)</p>';
      }
    }
  } catch (e) { /* ignore */ }
}

async function loadWorkflowsPanel() {
  try {
    const res = await api("/v1/workflows/awaiting?limit=20");
    const container = document.getElementById("awaiting-runs-list");
    if (container) {
      if (res.ok) {
        const data = await res.json();
        const runs = data.runs || [];
        if (runs.length === 0) {
          container.innerHTML = '<p class="empty-state">No runs awaiting attention</p>';
        } else {
          container.innerHTML = runs.map(r => `
            <div class="run-card">
              <div class="run-card-header">
                <span class="run-card-name">${escHtml(r.workflow_name)}</span>
                <span class="run-card-status status-${r.status}">${escHtml(r.status)}</span>
              </div>
              <div class="pending-card-details">
                Run: ${escHtml(r.id?.substring(0, 8) || "—")}… · Step: ${r.current_step ?? "—"}
              </div>
            </div>
          `).join("");
        }
      } else {
        container.innerHTML = '<p class="empty-state">Could not load awaiting runs</p>';
      }
    }
  } catch (e) { /* ignore */ }

  try {
    const res = await api("/v1/workflows/runs?limit=10");
    const container = document.getElementById("recent-runs-list");
    if (container) {
      if (res.ok) {
        const data = await res.json();
        const runs = data.runs || [];
        if (runs.length === 0) {
          container.innerHTML = '<p class="empty-state">No recent runs</p>';
        } else {
          container.innerHTML = runs.map(r => `
            <div class="run-card">
              <div class="run-card-header">
                <span class="run-card-name">${escHtml(r.workflow_name)}</span>
                <span class="run-card-status status-${r.status}">${escHtml(r.status)}</span>
              </div>
              <div class="pending-card-details">
                Run: ${escHtml(r.id?.substring(0, 8) || "—")}…
              </div>
            </div>
          `).join("");
        }
      } else {
        container.innerHTML = '<p class="empty-state">Could not load recent runs</p>';
      }
    }
  } catch (e) { /* ignore */ }
}

async function operatorApprove(confirmationId) {
  try {
    const res = await api(`/v1/operator/confirmations/${confirmationId}/approve`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({}),
    });
    if (res.ok) {
      loadOperatorPanel();
    } else {
      const err = await res.json().catch(() => ({}));
      alert("Approve failed: " + (err.detail || res.statusText));
    }
  } catch (e) {
    alert("Approve failed: " + e.message);
  }
}

async function operatorDeny(confirmationId) {
  try {
    const res = await api(`/v1/operator/confirmations/${confirmationId}/deny`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({}),
    });
    if (res.ok) {
      loadOperatorPanel();
    } else {
      const err = await res.json().catch(() => ({}));
      alert("Deny failed: " + (err.detail || res.statusText));
    }
  } catch (e) {
    alert("Deny failed: " + e.message);
  }
}

function escHtml(s) {
  if (!s) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function main() {
  wire();
  bootstrap();
}

document.addEventListener("DOMContentLoaded", main);
