"""ERA-AI management CLI (Phase 2A).

Bootstrap identity and manage users / API keys. API keys are shown exactly once
at creation; only their SHA-256 hash is stored.

Usage:
    python -m era.cli create-admin [--db sqlite:///era.db]
    python -m era.cli create-user --username alice --role user [--db ...]
    python -m era.cli add-key --username alice --name laptop [--db ...]
    python -m era.cli list-users [--db ...]
    python -m era.cli disable-user --username alice [--db ...]
    python -m era.cli revoke-key --key-id <id> [--db ...]
"""

from __future__ import annotations

import argparse

from era.config import Settings
from era.container import build_container


def _container(db_url: str | None):
    settings = Settings(database_url=db_url or "sqlite:///era.db")
    return build_container(settings)


def _print_key(user, raw: str) -> None:
    print("=" * 60)
    print(f"Created API key for user '{user.username}' (id={user.id})")
    print("Store this key NOW — it will never be shown again:")
    print(f"  {raw}")
    print("Authenticate with:  Authorization: Bearer <key>")
    print("=" * 60)


def _cmd_create_admin(args) -> None:
    c = _container(args.db)
    admin = c.auth_service.get_user_by_username("admin")
    if admin is None:
        admin = c.auth_service.create_user(username="admin", role="admin",
                                           display_name="System Administrator")
    _, raw = c.auth_service.create_api_key(admin.id, "admin-bootstrap")
    _print_key(admin, raw)


def _cmd_create_user(args) -> None:
    if args.role not in ("admin", "user"):
        raise SystemExit(f"invalid role {args.role!r} (must be admin|user)")
    c = _container(args.db)
    user = c.auth_service.create_user(username=args.username, role=args.role,
                                      display_name=args.display_name)
    _, raw = c.auth_service.create_api_key(user.id, "default")
    _print_key(user, raw)


def _cmd_add_key(args) -> None:
    c = _container(args.db)
    user = c.auth_service.get_user_by_username(args.username)
    if user is None:
        raise SystemExit(f"no such user: {args.username!r}")
    _, raw = c.auth_service.create_api_key(user.id, args.name)
    _print_key(user, raw)


def _cmd_list_users(args) -> None:
    c = _container(args.db)
    for u in c.auth_service.list_users():
        print(f"{u.username}\t{u.role}\tdisabled={u.disabled}\tid={u.id}")


def _cmd_disable_user(args) -> None:
    c = _container(args.db)
    user = c.auth_service.get_user_by_username(args.username)
    if user is None:
        raise SystemExit(f"no such user: {args.username!r}")
    c.auth_service.set_user_disabled(user.id, disabled=True)
    print(f"disabled user {args.username!r}")


def _cmd_revoke_key(args) -> None:
    c = _container(args.db)
    key = c.auth_service.revoke_key(args.key_id)
    if key is None:
        raise SystemExit(f"no such key: {args.key_id!r}")
    print(f"revoked key {args.key_id!r}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="era", description="ERA-AI management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="create the default admin user + a key")
    p.add_argument("--db", default=None)
    p.set_defaults(func=_cmd_create_admin)

    p = sub.add_parser("create-user", help="create a user + a key")
    p.add_argument("--db", default=None)
    p.add_argument("--username", required=True)
    p.add_argument("--role", default="user", choices=["admin", "user"])
    p.add_argument("--display-name", default=None)
    p.set_defaults(func=_cmd_create_user)

    p = sub.add_parser("add-key", help="add a key to an existing user")
    p.add_argument("--db", default=None)
    p.add_argument("--username", required=True)
    p.add_argument("--name", default="default")
    p.set_defaults(func=_cmd_add_key)

    p = sub.add_parser("list-users")
    p.add_argument("--db", default=None)
    p.set_defaults(func=_cmd_list_users)

    p = sub.add_parser("disable-user")
    p.add_argument("--db", default=None)
    p.add_argument("--username", required=True)
    p.set_defaults(func=_cmd_disable_user)

    p = sub.add_parser("revoke-key")
    p.add_argument("--db", default=None)
    p.add_argument("--key-id", required=True)
    p.set_defaults(func=_cmd_revoke_key)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
