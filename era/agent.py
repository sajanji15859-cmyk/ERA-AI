"""ERA agent CLI (Phase 3A).

    python -m era.agent demo [--root workspace] [--goal "..."] [--auto-approve]

``demo`` runs the Minimum Viable ERA Agent end-to-end: plan → tasks → tool
execution (through the permission/confirmation/audit gate) → verification →
retry/replan → final report. Without an LLM key it runs in free offline mode
(deterministic content packs); with ``ERA_AGENT_LLM_PROVIDER=openai`` and a key
it uses the real model.

The demo operator auto-approves only *workspace-scoped, non-destructive*
CONFIRM decisions (fs.write / fs.move / web.download inside the workspace) —
the same decisions the human approves in API mode. CONFIRM_STRONG actions are
always declined by the demo operator.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from era.agent_runtime import build_agent_container
from era.config import Settings
from era.core.action import Action
from era.core.enums import Decision

AUTO_APPROVABLE = frozenset({"fs.write", "fs.move", "web.download"})


def _demo_approver(execution_service, workspace_root: Path, verbose: bool = True):
    """Demo operator: approve safe workspace writes, decline everything else."""
    def approve(action: Action, response):
        decision = getattr(response, "decision", None)
        if decision != Decision.CONFIRM or action.action_type not in AUTO_APPROVABLE:
            print(f"  [operator] DENIED approval for {action.action_type} "
                  f"(risk: {decision})", file=sys.stderr)
            return "deny"
        path = (action.params or {}).get("path", "")
        try:
            resolved = (workspace_root / str(path)).resolve()
            inside = resolved == workspace_root or workspace_root in resolved.parents
        except (OSError, ValueError):
            inside = False
        if not inside:
            print(f"  [operator] DENIED approval for {action.action_type} "
                  f"{path!r} (outside workspace)", file=sys.stderr)
            return "deny"
        if verbose:
            print(f"  [operator] APPROVED {action.action_type} {path!r} (workspace-scoped)")
        return "approve"
    return approve


def cmd_demo(args) -> int:
    workspace_root = Path(args.root).resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    db_dir = tempfile.mkdtemp(prefix="era_demo_")
    db_path = Path(db_dir) / "demo.db"

    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        agent_workspace_root=str(workspace_root),
        agent_enabled=True,
    )
    llm_note = "offline deterministic mode (FREE — no API key)"
    print(f"ERA agent demo — workspace: {workspace_root}")
    print(f"                 demo db:   {db_path} (temporary)")
    print(f"                 LLM:       {llm_note}")

    container = build_agent_container(settings)

    # A local demo user (in-process only; the API derives identity server-side).
    user = container.auth_service.create_user(username="demo", role="user")
    from era.core.context import ExecutionContext
    ctx = ExecutionContext(actor_id=user.id, session_id="demo")

    goal = args.goal or "मेरे लिए एक welding training website बनाओ"
    print(f"\nGOAL: {goal}\n")

    approver = _demo_approver(container.execution_service, workspace_root) \
        if args.auto_approve else None
    if args.stream:
        # Phase 3B: live event stream (same events the SSE chat API emits).
        last_event = None
        for ev in container.agent_service.start_run_stream(
                goal, ctx, role="user", approval_handler=approver):
            last_event = ev
            data = json.dumps(ev.data, ensure_ascii=False)
            print(f"  [event] {ev.type.value}: {data[:150]}")
        record = container.agent_service.get_run(last_event.run_id, user.id) \
            if last_event is not None else None
    else:
        record = container.agent_service.start_run(goal, ctx, role="user",
                                                   approval_handler=approver)

    if record is None:
        print("run produced no record", file=sys.stderr)
        return 1

    print("=" * 70)
    print("RUN REPORT")
    print("=" * 70)
    print(json.dumps(record.result.model_dump(mode="json"), indent=2, ensure_ascii=False))
    print("\nTask timeline:")
    for task in record.tasks:
        mark = {"completed": "✓", "failed": "✗", "skipped": "-"}.get(task.status.value, "·")
        line = f"  {mark} {task.title} [{task.status.value}"
        if task.attempt:
            line += f", attempts={task.attempt + 1}"
        if task.error:
            line += f", note={task.error[:80]}"
        line += "]"
        print(line)

    if record.result.artifacts:
        print("\nArtifacts:")
        for artifact in record.result.artifacts:
            print(f"  - {workspace_root / artifact}")
    else:
        print("\nNo artifacts recorded.")

    if record.status.value == "waiting_for_user":
        print("\nRun PAUSED — pending confirmations:")
        for cid in record.pending_confirmations:
            print(f"  - {cid}")
    return 0


def cmd_run(args) -> int:
    """Run a one-off goal through the agent (library-style, no server)."""
    settings = Settings(agent_workspace_root=args.root, agent_enabled=True,
                        database_url=f"sqlite:///{args.db}")
    container = build_agent_container(settings)
    user = container.auth_service.create_user(username="run-user", role="user")
    from era.core.context import ExecutionContext
    ctx = ExecutionContext(actor_id=user.id, session_id="run")
    record = container.agent_service.start_run(args.goal, ctx, role="user")
    print(record.result.model_dump_json(indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="era-agent",
                                     description="ERA AI agent CLI (Phase 3A)")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the MVEA end-to-end demo")
    demo.add_argument("--root", default="workspace")
    demo.add_argument("--goal", default=None)
    demo.add_argument("--auto-approve", action="store_true",
                      help="demo operator auto-approves workspace-scoped CONFIRM actions")
    demo.add_argument("--stream", action="store_true",
                      help="print the live event stream (Phase 3B)")
    demo.set_defaults(func=cmd_demo)

    run = sub.add_parser("run", help="run a single goal (no approvals)")
    run.add_argument("goal")
    run.add_argument("--root", default="workspace")
    run.add_argument("--db", default="era_agent.db")
    run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
