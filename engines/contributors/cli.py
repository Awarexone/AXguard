"""CLI for ``axguard contribute …`` and ``axguard privacy …``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_privacy_parser(sub: argparse._SubParsersAction) -> None:
    privacy = sub.add_parser(
        "privacy",
        help="Local contribution / learning privacy prefs (no network)",
    )
    privacy_sub = privacy.add_subparsers(dest="privacy_command", required=True)

    privacy_sub.add_parser("status", help="Show privacy / opt-in status")
    privacy_sub.add_parser("show", help="Show status + included/excluded fields")

    opt_in = privacy_sub.add_parser("opt-in", help="Opt in to local contribution packaging")
    opt_in.add_argument(
        "--learning",
        action="store_true",
        help="Also enable local learning contribution_data (still no network)",
    )

    privacy_sub.add_parser("opt-out", help="Opt out of contribution packaging / learning")

    export = privacy_sub.add_parser("export", help="Export local privacy prefs JSON")
    export.add_argument(
        "-o",
        "--output",
        default=".findings/axguard/privacy-export.json",
        help="Output path (local only)",
    )

    privacy_sub.add_parser("delete", help="Delete local learning data")
    privacy_sub.add_parser("reset", help="Reset privacy prefs and clear learning data")


def add_contribute_parser(sub: argparse._SubParsersAction) -> None:
    contrib = sub.add_parser(
        "contribute",
        help="Local contribution suggestions and prepare (never auto-push)",
    )
    contrib_sub = contrib.add_subparsers(dest="contribute_command", required=True)

    contrib_sub.add_parser("status", help="Show contribute prefs and last invite state")
    suggest_p = contrib_sub.add_parser("suggest", help="Suggest one contribution from context")
    suggest_p.add_argument(
        "--context-json",
        default=None,
        help="Optional JSON file with local analysis context",
    )
    suggest_p.add_argument(
        "--force",
        action="store_true",
        help="Bypass cooldown (still respects never_prompts / type dismiss)",
    )

    prepare_p = contrib_sub.add_parser(
        "prepare",
        help="Prepare a local contribution package (no push / no PR)",
    )
    prepare_p.add_argument(
        "--type",
        dest="contribution_type",
        default=None,
        help="Contribution type (e.g. REGRESSION_TEST, FALSE_POSITIVE_FIX)",
    )
    prepare_p.add_argument(
        "--context-json",
        default=None,
        help="Optional JSON file with local analysis context",
    )
    prepare_p.add_argument(
        "--learning",
        action="store_true",
        help="Also write a learning copy (requires learning opt-in)",
    )
    prepare_p.add_argument(
        "--out-root",
        default=None,
        help="Project root for .findings/axguard/contribute/ (default: cwd)",
    )

    dismiss_p = contrib_sub.add_parser(
        "dismiss",
        help="Dismiss invites: not_now | never_prompts | type",
    )
    dismiss_p.add_argument(
        "mode",
        choices=("not_now", "never_prompts", "type"),
        help="Dismissal mode",
    )
    dismiss_p.add_argument(
        "--type",
        dest="contribution_type",
        default=None,
        help="Required when mode=type",
    )

    contrib_sub.add_parser("milestones", help="List local contribution milestones")
    contrib_sub.add_parser("templates", help="List contribution templates")


def _load_context(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("context JSON must be an object")
    return data


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def run_privacy_command(args: argparse.Namespace) -> int:
    from engines.contributors import privacy as priv

    cmd = getattr(args, "privacy_command", None)
    try:
        if cmd in ("status", "show"):
            _print_json(priv.status() if cmd == "status" else priv.show())
            return 0
        if cmd == "opt-in":
            _print_json(priv.opt_in(contribute=True, learning=bool(getattr(args, "learning", False))))
            print("Opted in locally. Nothing was uploaded.", file=sys.stderr)
            return 0
        if cmd == "opt-out":
            _print_json(priv.opt_out(clear_learning=False))
            print("Opted out locally.", file=sys.stderr)
            return 0
        if cmd == "export":
            dest = Path(getattr(args, "output") or ".findings/axguard/privacy-export.json")
            path = priv.export_privacy_bundle(dest)
            print(str(path))
            return 0
        if cmd == "delete":
            removed = priv.delete_learning_data()
            _print_json({"deleted": removed, "learning_data_dir": str(priv.learning_data_dir())})
            return 0
        if cmd == "reset":
            _print_json(priv.reset())
            print("Privacy prefs reset; learning data cleared.", file=sys.stderr)
            return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: privacy {cmd} failed: {exc}", file=sys.stderr)
        return 2
    print(f"error: unknown privacy command: {cmd}", file=sys.stderr)
    return 2


def run_contribute_command(args: argparse.Namespace) -> int:
    from engines.contributors import milestones as mile
    from engines.contributors import privacy as priv
    from engines.contributors.prepare import prepare
    from engines.contributors.suggest import dismiss, suggest
    from engines.contributors.templates import list_templates

    cmd = getattr(args, "contribute_command", None)
    try:
        if cmd == "status":
            st = mile.load_state()
            payload = {
                "privacy": priv.status(),
                "last_invite_at": st.get("last_invite_at"),
                "last_invite_type": st.get("last_invite_type"),
                "session_invite_count": st.get("session_invite_count"),
                "milestones": mile.list_milestones(),
                "note": "Prepare is local-only. auto_push and auto_pr stay false.",
            }
            _print_json(payload)
            return 0

        if cmd == "suggest":
            ctx = _load_context(getattr(args, "context_json", None))
            invite = suggest(ctx, force=bool(getattr(args, "force", False)))
            if invite is None:
                print("No strong contribution opportunity right now.")
                return 0
            print(invite.message)
            return 0

        if cmd == "prepare":
            ctx = _load_context(getattr(args, "context_json", None))
            root = Path(args.out_root) if getattr(args, "out_root", None) else None
            result = prepare(
                ctx,
                contribution_type=getattr(args, "contribution_type", None),
                project_root=root,
                write_learning_copy=bool(getattr(args, "learning", False)),
            )
            _print_json(result)
            return 0 if result.get("ok") else 2

        if cmd == "dismiss":
            result = dismiss(
                getattr(args, "mode"),
                contribution_type=getattr(args, "contribution_type", None),
            )
            _print_json(result)
            return 0 if result.get("ok") else 2

        if cmd == "milestones":
            _print_json(mile.list_milestones())
            return 0

        if cmd == "templates":
            _print_json(list_templates())
            return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: contribute {cmd} failed: {exc}", file=sys.stderr)
        return 2
    print(f"error: unknown contribute command: {cmd}", file=sys.stderr)
    return 2
