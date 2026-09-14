"""AXguard CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engines.audit import AuditOptions, run_audit
from engines.banner import print_banner
from engines.paths import default_rules_dir
from engines.report import render_report, write_reports
from engines.scanner import ScanOptions, run_scan

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axguard",
        description="Pre-ship security gate for source and build artifacts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a path for vulnerabilities")
    _add_target_args(scan)
    scan.add_argument(
        "--format",
        choices=("text", "json", "md", "html"),
        default="text",
        help="Report format",
    )
    scan.add_argument("-o", "--output", help="Write report to file")
    scan.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    audit = sub.add_parser(
        "audit",
        help="Full A-Z audit and write Markdown + HTML reports",
    )
    _add_target_args(audit)
    audit.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for report artifacts (default: .findings/axguard)",
    )
    audit.add_argument(
        "--open-summary",
        action="store_true",
        help="Print Markdown summary to stdout after writing files",
    )
    audit.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    sub.add_parser("version", help="Print version")
    sub.add_parser("help", help="Show Start Using workflow table")
    return parser


HELP_TEXT = """
AXguard — start with the workflow you need

  What you are doing              Command
  -----------------------------   -------------------------
  About to publish / open a PR    axguard audit .   |  /axguard-audit
  Quick check while coding        axguard scan .    |  /axguard-scan
  First look at a new codebase    /axguard-threat-model → /axguard-audit
  Secrets / auth / inject         /axguard-secrets · /axguard-auth · /axguard-inject
  SQL / SSTI / path               /axguard-sql · /axguard-ssti · /axguard-path
  SSRF / XSS / cloud              /axguard-ssrf · /axguard-xss · /axguard-cloud
  Crypto / supply / GraphQL       /axguard-crypto · /axguard-supply · /axguard-graphql
  Upload / debug / AI agent       /axguard-upload · /axguard-debug · /axguard-agent
  Triage → fix → report → CI      /axguard-triage · /axguard-fix · /axguard-report · /axguard-ci

Pipeline:
  threat-model → audit → triage → fix → report → ci

Reports land in:
  .findings/axguard/axguard-report.{html,md,json}

Cheat sheet: COMMANDS-QUICK-REF.md
""".strip()


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="none",
        help="Exit non-zero if any finding meets this severity",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Rules directory (default: packaged rules/)",
    )


def _should_fail(findings: list[dict], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(f.get("severity", "info"), 0) >= threshold for f in findings)


def _rules_dir(args: argparse.Namespace) -> Path:
    if args.rules:
        return Path(args.rules)
    return default_rules_dir()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print("axguard 0.2.0")
        return 0

    if args.command == "help":
        print_banner(compact=True)
        print()
        print(HELP_TEXT)
        return 0

    if args.command in {"scan", "audit"} and not getattr(args, "no_banner", False):
        print_banner()
        print()

    if args.command == "scan":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        result = run_scan(ScanOptions(target=target, rules_dir=_rules_dir(args)))
        body = render_report(result, fmt=args.format)
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(body)
        return 1 if _should_fail(result["findings"], args.fail_on) else 0

    if args.command == "audit":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        result = run_audit(
            AuditOptions(
                target=target,
                rules_dir=_rules_dir(args),
                out_dir=out_dir,
            )
        )
        paths = write_reports(result, out_dir)
        print(f"audit complete — {result['finding_count']} finding(s)")
        print(f"  json  {paths['json']}")
        print(f"  md    {paths['md']}")
        print(f"  html  {paths['html']}")
        if args.open_summary:
            print()
            print(render_report(result, "md"))
        return 1 if _should_fail(result["findings"], args.fail_on) else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
