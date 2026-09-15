"""CLI for `axguard api …` — local-first Security Intelligence API."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_api_parser(sub: argparse._SubParsersAction) -> None:
    api = sub.add_parser(
        "api",
        help="Local-first AXGuard API (bind 127.0.0.1:8787 by default)",
    )
    api_sub = api.add_subparsers(dest="api_command", required=True)

    start = api_sub.add_parser("start", help="Start the local API server")
    start.add_argument("--host", default=None, help="Bind host (default 127.0.0.1)")
    start.add_argument("--port", type=int, default=None, help="Bind port (default 8787)")
    start.add_argument("--data-dir", default=None, help="Data directory (~/.axguard/api)")
    start.add_argument("--reload", action="store_true", help="Dev reload (uvicorn)")

    api_sub.add_parser("status", help="Show API settings and provider status")
    api_sub.add_parser("projects", help="List local projects in the API DB")

    keys = api_sub.add_parser("keys", help="Manage local API keys")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    create = keys_sub.add_parser("create", help="Create a local API key")
    create.add_argument("--name", default="default")
    create.add_argument("--scopes", default="*", help="Comma-separated scopes or *")
    keys_sub.add_parser("list", help="List API keys (no secrets)")
    revoke = keys_sub.add_parser("revoke", help="Revoke an API key by id")
    revoke.add_argument("key_id")


def run_api_command(args: argparse.Namespace) -> int:
    from engines.api.auth import create_key_record, normalize_scopes
    from engines.api.providers.factory import get_provider, provider_status
    from engines.api.settings import load_settings
    from engines.api.storage import Store

    cmd = getattr(args, "api_command", None)
    settings = load_settings(
        host=getattr(args, "host", None),
        port=getattr(args, "port", None),
        data_dir=getattr(args, "data_dir", None),
    )

    if cmd == "start":
        try:
            import uvicorn
            from engines.api.app import create_app
        except ImportError:
            print(
                "uvicorn/fastapi required. Install with: pip install 'axguard[api]'",
                file=sys.stderr,
            )
            return 2
        app = create_app(settings)
        status = provider_status(get_provider(settings=settings), settings=settings)
        print("AXGuard Security Intelligence API")
        print(f"  listen:  http://{settings.host}:{settings.port}")
        print(f"  openapi: http://{settings.host}:{settings.port}/openapi.json")
        print(f"  data:    {settings.data_dir}")
        print(
            f"  llm:     mode={status.get('llm_mode')} provider={status.get('provider')}"
            " (no hosted model — BYOK / Ollama / no-llm)"
        )
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            reload=bool(getattr(args, "reload", False)),
            log_level="info",
        )
        return 0

    if cmd == "status":
        status = provider_status(get_provider(settings=settings), settings=settings)
        print(
            json.dumps(
                {
                    "host": settings.host,
                    "port": settings.port,
                    "data_dir": str(settings.data_dir),
                    "db_path": str(settings.db_path),
                    "require_auth": settings.require_auth,
                    "is_loopback": settings.is_loopback,
                    "provider": status,
                },
                indent=2,
            )
        )
        return 0

    if cmd == "projects":
        store = Store(settings.db_path)
        try:
            print(json.dumps(store.list_projects(), indent=2, default=str))
        finally:
            store.close()
        return 0

    if cmd == "keys":
        store = Store(settings.db_path)
        try:
            kcmd = getattr(args, "keys_command", None)
            if kcmd == "create":
                raw, record = create_key_record(
                    name=getattr(args, "name", None) or "default",
                    scopes=normalize_scopes(getattr(args, "scopes", "*")),
                )
                store.insert_api_key(record)
                print(
                    json.dumps(
                        {
                            "id": record["id"],
                            "name": record["name"],
                            "scopes": record["scopes"],
                            "prefix": record["prefix"],
                            "api_key": raw,
                            "message": "Store this key now — it will not be shown again.",
                        },
                        indent=2,
                    )
                )
                return 0
            if kcmd == "list":
                print(json.dumps(store.list_api_keys(), indent=2, default=str))
                return 0
            if kcmd == "revoke":
                key = store.revoke_api_key(args.key_id)
                if not key:
                    print(json.dumps({"error": "key not found"}))
                    return 1
                print(
                    json.dumps(
                        {"id": key["id"], "revoked_at": key.get("revoked_at")},
                        indent=2,
                    )
                )
                return 0
        finally:
            store.close()

    print(f"Unknown api command: {cmd}", file=sys.stderr)
    return 2
