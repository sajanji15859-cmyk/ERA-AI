# ERA AI

A personal autonomous computer-use assistant designed to help with knowledge,
research, productivity, reasoning, automation and daily digital work — ultimately
operating its owner's laptop and Android phone through permitted interfaces,
with an explicit permission and confirmation system for anything irreversible.

> **Status: Phase 1 (Agent core) — in progress.**
> - **Phase 0 (foundation) ✅** — package, CLI, layered config, logging, CI-ready tooling.
> - **Phase 1A (LLM adapter) ✅** — provider-agnostic LLM layer with offline mock and an
>   OpenAI-compatible client (works with OpenAI, Groq, OpenRouter, Ollama, llama.cpp server).
> - Next: 1B tools + registry → 1C permissions + audit → 1D memory → 1E execution loop →
>   1F `era agent` CLI. See the [roadmap](docs/ARCHITECTURE_AND_ROADMAP.md).

## Quick start

Requires Python ≥ 3.11.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
era            # status overview (default command)
era doctor     # environment health checks
era config show
```

The legacy keyword chat from the original scaffold is still reachable:

```bash
era chat           # or the deprecated: python main.py
```

## CLI

| Command | Description |
|---|---|
| `era` / `era status` | Short status overview |
| `era --version` | Print version |
| `era --debug ...` | Force debug logging for one run |
| `era doctor` | Health checks: Python version, config file, data dir, log file, legacy modules |
| `era config show` | Effective configuration + which layer (default/file/env) supplied each value |
| `era config path` | Config file location |
| `era chat` | Legacy keyword chat (placeholder until the Phase 1 LLM core) |

## Configuration

Layered — later wins: **defaults < `~/.era/config.toml` < `ERA_*` environment variables.**

| Setting | Default | Env override | Values |
|---|---|---|---|
| `general.debug` | `false` | `ERA_DEBUG` | bool |
| `logging.level` | `"info"` | `ERA_LOG_LEVEL` | `debug`, `info`, `warning`, `error` |
| `logging.to_file` | `true` | `ERA_LOG_FILE` | bool |

Paths: `ERA_HOME` relocates the data dir (default `~/.era`); `ERA_CONFIG` points at a
different config file.

Example `~/.era/config.toml`:

```toml
[general]
debug = false

[logging]
level = "info"
to_file = true
```

**Secrets never go in the config file.** Any secret-like key found there is flagged by
`era doctor` and `era config show`. Supply secrets via environment variables only.
(Later phases add an OS-keyring-backed vault.)

## Development

```bash
pip install -e ".[dev]"
pytest                       # run the test suite
ruff format . && ruff check .# format + lint (CI enforces both)
pre-commit install           # optional: run the same hooks on every commit
```

CI runs ruff (format check + lint) and pytest on Python 3.11/3.12/3.13
(`.github/workflows/ci.yml`).

## Project layout

```
era/                  The package
├── cli.py            CLI entry point (`era`, `python -m era`)
├── config.py         Layered configuration (defaults < TOML < env)
├── logging.py        Structured logging setup (console + rotating file)
├── llm/              Phase 1A: provider-agnostic LLM adapter layer
│   ├── base.py       ChatMessage, LLMResponse, LLMClient protocol, error taxonomy
│   ├── mock.py       Offline scripted client for tests/demos (records prompts)
│   ├── openai_compat.py  OpenAI-compatible chat-completions client (stdlib urllib)
│   └── factory.py    create_client() from config + env; key via ERA_LLM_API_KEY only
└── legacy/           Original v0.1 placeholder modules, bug-fixed and
                      clearly marked; removed as real phases land
tests/                pytest suite
docs/                 Architecture & roadmap
*.py (repo root)      Deprecated facades over era.legacy.* — kept briefly
                      for backwards compatibility
```

## Vision

ERA AI is a personal artificial intelligence assistant designed to help with
knowledge, research, productivity, reasoning, automation and daily digital work.

Its goal is not to be just another chatbot, but to become a long-term intelligent
assistant that can grow over time.

### Core capabilities (target)

- Research from reliable sources
- Philosophy, science, history and technology analysis
- PDF and document understanding
- Email assistance
- Writing and summarization
- Memory and knowledge management
- Task planning
- Automation
- Multi-AI support

### Long-Term Goal

ERA AI will evolve into a complete digital assistant capable of helping with
learning, thinking, organizing information and assisting in everyday work —
operating the laptop and (permitted parts of) the Android phone through a
planner, tool system, memory, permission/safety layer, confirmation system
for irreversible actions, and a supervised execution loop.

See [docs/ARCHITECTURE_AND_ROADMAP.md](docs/ARCHITECTURE_AND_ROADMAP.md) for the
full architecture, platform feasibility analysis (Android vs laptop) and the
phased development plan.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: package, CLI, config, logging, CI | ✅ done |
| 1 | Agent core: LLM layer, tools, execution loop, memory, permissions | next |
| 2 | Browser operator (Playwright/CDP) | planned |
| 3 | Desktop operator (Windows/macOS/Linux) | planned |
| 4 | Email, files, documents | planned |
| 5 | Android pilot (ADB, then on-device app) | planned |
| 6 | Autonomy & memory maturity | planned |
