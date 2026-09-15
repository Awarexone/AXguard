"""AXguard CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engines.app_model import build_application_model, write_application_model
from engines.attack_graph import run_attack_graph, write_attack_graph_report
from engines.audit import AuditOptions, run_audit
from engines.banner import print_banner
from engines.dataflow import analyze_dataflow, write_dataflow_report
from engines.engagement import (
    about_content,
    disable_promo,
    dismiss_support,
    emit_after_audit,
    emit_after_scan,
    emit_first_run_if_needed,
    emit_for_paths,
    enable_promo,
    load_state,
    record_event,
    render_cli,
)
from engines.engagement.schema import EVENT_ABOUT_VIEWED
from engines.evidence import run_evidence, write_evidence_report
from engines.paths import default_rules_dir
from engines.report import render_report, write_reports
from engines.scanner import ScanOptions, run_scan
from engines.adversary import run_adversary, write_adversary_report
from engines.verify import run_verification, write_verification_report

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
    scan.add_argument(
        "--no-engage",
        action="store_true",
        help="Skip contextual engagement messages",
    )

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
    audit.add_argument(
        "--no-engage",
        action="store_true",
        help="Skip contextual engagement messages",
    )

    surface = sub.add_parser(
        "surface",
        help="Build application understanding model (routes, sinks, stack)",
    )
    surface.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
    surface.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for application-model artifacts (default: .findings/axguard)",
    )
    surface.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    flow = sub.add_parser(
        "flow",
        help="Dataflow / taint analysis (diagnostic paths, not findings)",
    )
    flow.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
    flow.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for dataflow artifacts (default: .findings/axguard)",
    )
    flow.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    verify = sub.add_parser(
        "verify",
        help="Hunter → Judge verification diagnostic (not a vuln report)",
    )
    verify.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
    verify.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for verification artifacts (default: .findings/axguard)",
    )
    verify.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    adversary = sub.add_parser(
        "adversary",
        help="False Positive Adversary diagnostic (not a vuln report)",
    )
    adversary.add_argument(
        "path", nargs="?", default=".", help="Target path (default: .)"
    )
    adversary.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for adversary artifacts (default: .findings/axguard)",
    )
    adversary.add_argument(
        "--no-banner", action="store_true", help="Hide the ASCII banner"
    )

    evidence = sub.add_parser(
        "evidence",
        help="Evidence & Confidence diagnostic (not a vuln report)",
    )
    evidence.add_argument(
        "path", nargs="?", default=".", help="Target path (default: .)"
    )
    evidence.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for evidence artifacts (default: .findings/axguard)",
    )
    evidence.add_argument(
        "--no-banner", action="store_true", help="Hide the ASCII banner"
    )

    paths_cmd = sub.add_parser(
        "paths",
        aliases=["attack-paths"],
        help="Attack graph + vulnerability chaining diagnostic (not a vuln report)",
    )
    paths_cmd.add_argument(
        "path", nargs="?", default=".", help="Target path (default: .)"
    )
    paths_cmd.add_argument(
        "--out-dir",
        default=".findings/axguard",
        help="Directory for attack-path artifacts (default: .findings/axguard)",
    )
    paths_cmd.add_argument(
        "--no-banner", action="store_true", help="Hide the ASCII banner"
    )
    paths_cmd.add_argument(
        "--no-engage",
        action="store_true",
        help="Skip contextual engagement messages",
    )
    # Phase 6 Part 2 — attack-path intelligence view filters (display only; the
    # written attack-paths.json always contains the full, unfiltered path set).
    paths_cmd.add_argument(
        "--mode",
        choices=("CONFIRMED_ONLY", "CONFIRMED_AND_LIKELY", "INCLUDE_UNKNOWN"),
        default=None,
        help="Search mode: which path statuses count as live (default: INCLUDE_UNKNOWN)",
    )
    paths_cmd.add_argument(
        "--current",
        action="store_true",
        help="Show only currently-exploitable paths (CONFIRMED/LIKELY, not blocked)",
    )
    paths_cmd.add_argument(
        "--blocked",
        action="store_true",
        help="Show only paths blocked by an effective control",
    )
    paths_cmd.add_argument(
        "--unknown",
        action="store_true",
        help="Show only UNVERIFIED paths (unknown reachability/link — for review)",
    )
    paths_cmd.add_argument(
        "--critical",
        action="store_true",
        help="Show only paths reaching high-sensitivity assets (PII and above)",
    )
    paths_cmd.add_argument(
        "--shortest",
        action="store_true",
        help="Show only the shortest-credible path per (entry, target)",
    )
    # --- Phase 6 Part2 predictive ---
    # Advanced-analysis hooks (self-contained modules; never claim current vulns).
    paths_cmd.add_argument(
        "--predictive",
        action="store_true",
        help="Emit predictive risk / attack-surface signals (Predictive, not findings)",
    )
    paths_cmd.add_argument(
        "--diff",
        nargs=2,
        metavar=("PATH_A", "PATH_B"),
        default=None,
        help="Diff two attack-paths.json files (before after) and print changes",
    )
    paths_cmd.add_argument(
        "--what-if",
        dest="what_if",
        metavar="SCENARIO",
        default=None,
        help=(
            "Run a counterfactual scenario against the current graph "
            "(remove_authz | publicize_endpoint | unrestricted_egress | "
            "ai_tool_gains_fs | tenant_isolation_weakened | secret_leaks)"
        ),
    )
    # --- end Phase 6 Part2 predictive ---

    data_cmd = sub.add_parser(
        "data",
        help="Training-data registry & pipeline (Phase 9 — no model training)",
    )
    data_sub = data_cmd.add_subparsers(dest="data_command", required=True)
    for name, help_text in (
        ("discover", "Merge seed + references into local dataset registry"),
        ("inspect", "Show registry summary / one dataset"),
        ("approve", "Approve dataset (license gate enforced)"),
        ("reject", "Reject a dataset"),
        ("normalize", "Run normalize/dedupe/scrub/validate on fixtures"),
        ("dedupe", "Alias of normalize focusing on duplicates"),
        ("validate", "Validate registry + fixture examples"),
        ("benchmark", "Show BENCHMARK_ONLY / contamination guards"),
        ("prepare", "Prepare splits + DPO pairs (no training)"),
        ("report", "Write data-pipeline JSON/MD/HTML report"),
    ):
        p = data_sub.add_parser(name, help=help_text)
        p.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
        p.add_argument(
            "--out-dir",
            default=".findings/axguard/data",
            help="Artifact directory (default: .findings/axguard/data)",
        )
        p.add_argument("--no-banner", action="store_true")
        if name in {"approve", "reject", "inspect"}:
            p.add_argument("--id", dest="dataset_id", help="Dataset id")
        if name == "approve":
            p.add_argument(
                "--force-research-only",
                action="store_true",
                help="Force EVALUATION_ONLY instead of public TRAINING approval",
            )

    twin_cmd = sub.add_parser(
        "twin",
        help="Security Twin — symbolic model over attack-graph artifacts (no network)",
    )
    twin_sub = twin_cmd.add_subparsers(dest="twin_command", required=True)

    def _twin_common(p: argparse.ArgumentParser, *, with_path: bool = True) -> None:
        if with_path:
            p.add_argument("path", nargs="?", default=".", help="Target path (default: .)")
        p.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")
        p.add_argument(
            "--no-engage",
            action="store_true",
            help="Skip contextual engagement messages",
        )

    twin_build = twin_sub.add_parser("build", help="Build Security Twin and write artifacts")
    _twin_common(twin_build)
    twin_build.add_argument(
        "--out-dir",
        default=".findings/axguard/twin",
        help="Artifact directory (default: .findings/axguard/twin)",
    )
    twin_build.add_argument(
        "--no-simulate",
        action="store_true",
        help="Skip attack-path simulation",
    )
    twin_build.add_argument(
        "--profile",
        default="PUBLIC_USER",
        help="Virtual attacker profile (default: PUBLIC_USER)",
    )

    twin_show = twin_sub.add_parser("show", help="Build twin and print summary")
    _twin_common(twin_show)
    twin_show.add_argument(
        "--out-dir",
        default=".findings/axguard/twin",
        help="Artifact directory (default: .findings/axguard/twin)",
    )
    twin_show.add_argument(
        "--profile",
        default="PUBLIC_USER",
        help="Virtual attacker profile (default: PUBLIC_USER)",
    )

    twin_attack = twin_sub.add_parser(
        "attack", help="Symbolic attack simulation from twin"
    )
    _twin_common(twin_attack)
    twin_attack.add_argument(
        "--profile",
        default="PUBLIC_USER",
        help="Virtual attacker profile (default: PUBLIC_USER)",
    )

    twin_blast = twin_sub.add_parser(
        "blast-radius", help="Entity blast radius from twin"
    )
    _twin_common(twin_blast)
    twin_blast.add_argument(
        "--entity",
        required=True,
        help="Entity id (or resolvable label)",
    )

    twin_controls = twin_sub.add_parser(
        "controls", help="Control effectiveness analysis"
    )
    _twin_common(twin_controls)

    twin_whatif = twin_sub.add_parser(
        "what-if", help="Counterfactual / what-if analysis"
    )
    _twin_common(twin_whatif)
    twin_whatif.add_argument("--scenario", default=None, help="Scenario key")
    twin_whatif.add_argument(
        "--remove-control",
        default=None,
        help="Control id to hypothetically remove",
    )
    twin_whatif.add_argument(
        "--grant-agent-tool",
        default=None,
        help="Tool name to hypothetically grant an agent",
    )

    twin_compare = twin_sub.add_parser(
        "compare", help="Compare two twin JSON artifacts"
    )
    _twin_common(twin_compare, with_path=False)
    twin_compare.add_argument(
        "--before",
        required=True,
        help="Path to before security-twin.json",
    )
    twin_compare.add_argument(
        "--after",
        required=True,
        help="Path to after security-twin.json",
    )

    twin_reg = twin_sub.add_parser(
        "regression",
        help="Regression between two dirs (build) or twin JSON files",
    )
    _twin_common(twin_reg, with_path=False)
    twin_reg.add_argument(
        "--before",
        required=True,
        help="Before target directory or twin JSON",
    )
    twin_reg.add_argument(
        "--after",
        required=True,
        help="After target directory or twin JSON",
    )

    twin_query = twin_sub.add_parser("query", help="Deterministic Q/A over a twin")
    _twin_common(twin_query)
    twin_query.add_argument(
        "--question",
        required=True,
        help="Natural-language question (keyword-matched)",
    )

    twin_scenarios = twin_sub.add_parser(
        "scenarios", help="List Security Twin scenario templates"
    )
    _twin_common(twin_scenarios, with_path=False)

    twin_export = twin_sub.add_parser(
        "export-dataset",
        help="Export EVALUATION_ONLY Q/A examples from a twin",
    )
    _twin_common(twin_export)
    twin_export.add_argument(
        "--out-dir",
        default=".findings/axguard/twin",
        help="Artifact directory (default: .findings/axguard/twin)",
    )

    memory_cmd = sub.add_parser(
        "memory",
        help="Security Memory — longitudinal findings/controls/paths",
    )
    memory_sub = memory_cmd.add_subparsers(dest="memory_command", required=True)

    mem_record = memory_sub.add_parser(
        "record",
        help="Run attack graph (or ingest audit JSON) and record a memory snapshot",
    )
    mem_record.add_argument(
        "path", nargs="?", default=".", help="Target path or audit/attack-graph JSON"
    )
    mem_record.add_argument(
        "--out-dir",
        default=".findings/axguard/memory",
        help="Memory directory (default: .findings/axguard/memory)",
    )
    mem_record.add_argument(
        "--revision",
        default=None,
        help="Source revision label (default: git HEAD or UNKNOWN)",
    )
    mem_record.add_argument("--no-banner", action="store_true")
    mem_record.add_argument(
        "--no-engage",
        action="store_true",
        help="Skip contextual engagement messages",
    )

    def _mem_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--out-dir",
            default=".findings/axguard/memory",
            help="Memory directory (default: .findings/axguard/memory)",
        )
        p.add_argument("--no-banner", action="store_true")
        p.add_argument(
            "--no-engage",
            action="store_true",
            help="Skip contextual engagement messages",
        )

    mem_show = memory_sub.add_parser("show", help="Show current Security Memory state")
    _mem_common(mem_show)

    mem_history = memory_sub.add_parser(
        "history", help="List memory snapshots (or one finding's ledger entry)"
    )
    _mem_common(mem_history)
    mem_history.add_argument(
        "--finding",
        dest="finding_id",
        default=None,
        help="Finding fingerprint / id to look up in the ledger",
    )

    mem_changes = memory_sub.add_parser(
        "changes", help="Diff two memory snapshots (default: latest pair)"
    )
    _mem_common(mem_changes)
    mem_changes.add_argument("--before", dest="before_id", default=None)
    mem_changes.add_argument("--after", dest="after_id", default=None)

    mem_regressions = memory_sub.add_parser(
        "regressions", help="Detect regressions between snapshots"
    )
    _mem_common(mem_regressions)

    mem_findings = memory_sub.add_parser(
        "findings", help="List remembered findings (current snapshot)"
    )
    _mem_common(mem_findings)
    mem_findings.add_argument(
        "--rejected",
        action="store_true",
        help="Show rejected / false-positive findings only",
    )

    mem_controls = memory_sub.add_parser(
        "controls", help="List remembered controls"
    )
    _mem_common(mem_controls)

    mem_paths = memory_sub.add_parser(
        "paths", help="List remembered attack paths"
    )
    _mem_common(mem_paths)

    mem_unknowns = memory_sub.add_parser(
        "unknowns", help="List remembered unknowns"
    )
    _mem_common(mem_unknowns)

    mem_query = memory_sub.add_parser(
        "query", help="Ask a structured question of Security Memory"
    )
    _mem_common(mem_query)
    mem_query.add_argument(
        "--question",
        required=True,
        help='Natural-language question (e.g. "what changed")',
    )

    inv_cmd = sub.add_parser(
        "investigate",
        help="Investigation Agent — evidence-driven candidate investigation",
    )
    inv_cmd.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target path or audit/adversary JSON (default: .)",
    )
    inv_cmd.add_argument(
        "--finding",
        default=None,
        help="Investigate a single finding / candidate id",
    )
    inv_cmd.add_argument(
        "--explain",
        default=None,
        metavar="FINDING_ID",
        help="Explain an investigation for FINDING_ID (uses --out-dir artifacts when present)",
    )
    inv_budget = inv_cmd.add_mutually_exclusive_group()
    inv_budget.add_argument(
        "--fast",
        action="store_true",
        help="FAST budget — limited actions",
    )
    inv_budget.add_argument(
        "--deep",
        action="store_true",
        help="DEEP budget — broader evidence collection",
    )
    inv_cmd.add_argument(
        "--budget",
        choices=("FAST", "BALANCED", "DEEP"),
        default=None,
        help="Investigation budget (default: BALANCED)",
    )
    inv_cmd.add_argument(
        "--out-dir",
        default=".findings/axguard/investigation",
        help="Artifact directory (default: .findings/axguard/investigation)",
    )
    inv_cmd.add_argument(
        "--memory-dir",
        default=".findings/axguard/memory",
        help="Security Memory directory for reuse/invalidation",
    )
    inv_cmd.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print investigation JSON to stdout",
    )
    inv_cmd.add_argument(
        "--no-twin",
        action="store_true",
        help="Skip Security Twin soft integration",
    )
    inv_cmd.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")
    inv_cmd.add_argument(
        "--no-engage",
        action="store_true",
        help="Skip engagement / first-run messaging",
    )

    sub.add_parser("version", help="Print version")
    sub.add_parser("help", help="Show Start Using workflow table")

    about = sub.add_parser("about", help="About AXGuard (project story, no banner spam)")
    about.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")

    engage = sub.add_parser(
        "engage",
        help="Engagement preferences (local; no telemetry)",
    )
    engage_sub = engage.add_subparsers(dest="engage_command", required=True)
    engage_sub.add_parser("disable", help="Disable promotional / support messaging")
    engage_sub.add_parser("enable", help="Re-enable promotional messaging")
    engage_sub.add_parser("dismiss", help="Dismiss the latest support ask (cooldown)")

    github_cmd = sub.add_parser(
        "github",
        help="GitHub Security Bot — setup / validate / test / status",
    )
    github_sub = github_cmd.add_subparsers(dest="github_command", required=True)

    gh_setup = github_sub.add_parser(
        "setup",
        help="Print App setup steps and write example .axguard.yml",
    )
    gh_setup.add_argument(
        "path", nargs="?", default=".", help="Project path (default: .)"
    )
    gh_setup.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .axguard.yml with the example",
    )
    gh_setup.add_argument(
        "--no-write",
        action="store_true",
        help="Print steps only; do not write .axguard.yml",
    )
    gh_setup.add_argument("--no-banner", action="store_true")

    def _gh_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "path", nargs="?", default=".", help="Project path (default: .)"
        )
        p.add_argument(
            "--config",
            default=None,
            help="Path to .axguard.yml (default: search upward from path)",
        )
        p.add_argument("--no-banner", action="store_true")

    _gh_common(
        github_sub.add_parser(
            "validate",
            help="Validate .axguard.yml + credential env presence (no API call)",
        )
    )
    _gh_common(
        github_sub.add_parser(
            "test",
            help="Local dry-run (config + optional webhook HMAC self-check)",
        )
    )
    _gh_common(
        github_sub.add_parser(
            "status",
            help="Show adapter/config status (secrets redacted)",
        )
    )
    return parser


HELP_TEXT = """
AXguard — start with the workflow you need

  What you are doing              Command
  -----------------------------   -------------------------
  About to publish / open a PR    axguard audit .   |  /axguard-audit
  Quick check while coding        axguard scan .    |  /axguard-scan
  Map attack surface / app model  axguard surface . |  /axguard-surface
  Dataflow / taint paths          axguard flow .    |  /axguard-flow
  Hunter → Judge verification     axguard verify .  |  /axguard-verify
  False Positive Adversary        axguard adversary .  |  /axguard-adversary
  Evidence & Confidence engine    axguard evidence .  |  /axguard-evidence
  Attack graph / vuln chaining    axguard paths .   |  /axguard-paths
  Training-data pipeline          axguard data …    |  /axguard-data
  Security Twin (symbolic)        axguard twin …    |  docs/twin/README.md
  Security Memory (longitudinal)  axguard memory …  |  docs/memory/README.md
  Investigation Agent             axguard investigate …  |  docs/investigation/README.md
  GitHub Security Bot             axguard github …  |  docs/github/README.md
  About AXGuard                   axguard about
  Engagement prefs                axguard engage disable | enable | dismiss
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
Docs: docs/engagement.md (local prefs, no telemetry)
""".strip()


def _print_engagement(text: str | None) -> None:
    if text:
        print()
        print(text.rstrip())


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

    if args.command == "about":
        # Explicit about — no banner spam; best-effort ABOUT_VIEWED record
        try:
            record_event(EVENT_ABOUT_VIEWED, {"command": "about"})
        except Exception:  # noqa: BLE001 — still print about content
            pass
        try:
            text = render_cli(about_content(load_state())).rstrip()
            if text:
                print(text)
        except Exception as exc:  # noqa: BLE001
            print(f"error: about failed: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "engage":
        action = args.engage_command
        try:
            if action == "disable":
                disable_promo()
                print("Engagement promotional messaging disabled.")
                print("State: ~/.axguard/engagement.json")
            elif action == "enable":
                enable_promo()
                print("Engagement promotional messaging enabled.")
            elif action == "dismiss":
                dismiss_support()
                print("Support ask dismissed (cooldown started).")
            else:
                parser.print_help()
                return 2
        except Exception as exc:  # noqa: BLE001
            print(f"error: engage {action} failed: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.command == "github":
        if not getattr(args, "no_banner", False):
            print_banner()
            print()
        return _run_github_command(args)

    if args.command in {
        "scan",
        "audit",
        "surface",
        "flow",
        "verify",
        "adversary",
        "evidence",
        "paths",
        "attack-paths",
        "data",
        "twin",
        "memory",
        "investigate",
    } and not getattr(args, "no_banner", False):
        print_banner()
        print()

    # First-run intro once (never for about/engage/version/help — handled above)
    if not getattr(args, "no_engage", False):
        _print_engagement(emit_first_run_if_needed())

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
        # Skip engagement for json so stdout stays machine-readable
        if not getattr(args, "no_engage", False) and args.format != "json":
            _print_engagement(
                emit_after_scan(result, html_written=(args.format == "html"))
            )
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
        if result.get("application_model_paths"):
            amp = result["application_model_paths"]
            print(f"  model {amp.get('json')}")
            print(f"  model {amp.get('markdown')}")
        if result.get("dataflow_paths"):
            dfp = result["dataflow_paths"]
            print(f"  flow  {dfp.get('json')}")
            print(f"  flow  {dfp.get('markdown')}")
        if result.get("verification_paths"):
            vp = result["verification_paths"]
            print(f"  verify {vp.get('json')}")
            print(f"  verify {vp.get('markdown')}")
        if result.get("verification_summary"):
            vs = result["verification_summary"]
            print(
                "  verify counts: "
                f"candidates={vs.get('candidate_count', 0)} "
                f"VERIFIED={vs.get('VERIFIED', 0)} "
                f"LIKELY={vs.get('LIKELY', 0)} "
                f"UNVERIFIED={vs.get('UNVERIFIED', 0)} "
                f"FALSE_POSITIVE={vs.get('FALSE_POSITIVE', 0)}"
            )
        if result.get("adversary_paths"):
            ap = result["adversary_paths"]
            print(f"  adversary {ap.get('json')}")
            print(f"  adversary {ap.get('markdown')}")
        if result.get("adversary_summary"):
            ads = result["adversary_summary"]
            print(
                "  adversary counts: "
                f"findings={ads.get('finding_count', 0)} "
                f"CONFIRMED={ads.get('CONFIRMED', 0)} "
                f"LIKELY={ads.get('LIKELY', 0)} "
                f"UNVERIFIED={ads.get('UNVERIFIED', 0)} "
                f"FALSE_POSITIVE={ads.get('FALSE_POSITIVE', 0)} "
                f"REQUIRES_REVIEW={ads.get('REQUIRES_REVIEW', 0)}"
            )
        if result.get("evidence_paths"):
            ep = result["evidence_paths"]
            print(f"  evidence {ep.get('json')}")
            print(f"  evidence {ep.get('markdown')}")
        if result.get("evidence_summary"):
            es = result["evidence_summary"]
            ec = es.get("by_confidence") or {}
            print(
                "  evidence counts: "
                f"findings={es.get('finding_count', 0)} "
                f"unique={es.get('unique_evidence_count', 0)} "
                f"reused={es.get('reused_evidence_count', 0)} "
                f"conflicts={es.get('conflict_count', 0)} "
                f"VERY_HIGH={ec.get('VERY_HIGH', 0)} "
                f"HIGH={ec.get('HIGH', 0)} "
                f"MEDIUM={ec.get('MEDIUM', 0)} "
                f"LOW={ec.get('LOW', 0)} "
                f"UNKNOWN={ec.get('UNKNOWN', 0)}"
            )
        if result.get("attack_graph_paths"):
            agp = result["attack_graph_paths"]
            print(f"  paths {agp.get('json')}")
            print(f"  paths {agp.get('markdown')}")
        if result.get("attack_graph_summary"):
            ags = result["attack_graph_summary"]
            bs = ags.get("by_status") or {}
            print(
                "  paths counts: "
                f"paths={ags.get('path_count', 0)} "
                f"CONFIRMED={bs.get('CONFIRMED', 0)} "
                f"LIKELY={bs.get('LIKELY', 0)} "
                f"UNVERIFIED={bs.get('UNVERIFIED', 0)} "
                f"BLOCKED={bs.get('BLOCKED', 0)} "
                f"INVALID={bs.get('INVALID', 0)} "
                f"dead_ends={ags.get('dead_end_count', 0)}"
            )
        if args.open_summary:
            print()
            print(render_report(result, "md"))
        if not getattr(args, "no_engage", False):
            _print_engagement(emit_after_audit(result))
        return 1 if _should_fail(result["findings"], args.fail_on) else 0

    if args.command == "surface":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        model = build_application_model(target)
        paths = write_application_model(model, out_dir)
        summary = model.get("summary") or {}
        langs = [
            x.get("name") if isinstance(x, dict) else x
            for x in (model.get("application") or {}).get("languages") or []
        ]
        frameworks = summary.get("frameworks") or []
        print("application understanding complete")
        print(f"  endpoints   {summary.get('endpoint_count', 0)}")
        print(f"  sinks       {summary.get('sink_count', 0)}")
        print(f"  externals   {summary.get('external_service_count', 0)}")
        print(f"  AI comps    {summary.get('ai_component_count', 0)}")
        print(f"  languages   {', '.join(str(x) for x in langs) or 'unknown'}")
        print(f"  frameworks  {', '.join(str(x) for x in frameworks) or 'unknown'}")
        print(f"  json        {paths['json']}")
        print(f"  md          {paths['markdown']}")
        return 0

    if args.command == "flow":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        flow_result = analyze_dataflow(target)
        paths = write_dataflow_report(flow_result, out_dir)
        summary = flow_result.get("summary") or {}
        print("dataflow analysis complete (diagnostic — not findings)")
        print(f"  sources     {summary.get('source_count', 0)}")
        print(f"  sinks       {summary.get('sink_count', 0)}")
        print(f"  paths       {summary.get('path_count', 0)}")
        print(f"  unsanitized {summary.get('unsanitized_path_count', 0)}")
        top = (flow_result.get("taint_paths") or [])[:8]
        if top:
            print("  top paths:")
            for p in top:
                src = p.get("source") or {}
                sink = p.get("sink") or {}
                print(
                    f"    - [{p.get('taint_state')}/{p.get('confidence')}] "
                    f"{src.get('name')} → {sink.get('type')}:{sink.get('symbol')} "
                    f"@ {sink.get('file')}:{sink.get('line')}"
                )
        print(f"  json        {paths['json']}")
        print(f"  md          {paths['markdown']}")
        return 0

    if args.command == "verify":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        verify_result = run_verification(target)
        paths = write_verification_report(verify_result, out_dir)
        summary = verify_result.get("summary") or {}
        print("verification complete (diagnostic — not a vuln report)")
        print(f"  candidates      {summary.get('candidate_count', 0)}")
        print(f"  VERIFIED        {summary.get('VERIFIED', 0)}")
        print(f"  LIKELY          {summary.get('LIKELY', 0)}")
        print(f"  UNVERIFIED      {summary.get('UNVERIFIED', 0)}")
        print(f"  FALSE_POSITIVE  {summary.get('FALSE_POSITIVE', 0)}")
        print(f"  json            {paths['json']}")
        print(f"  md              {paths['markdown']}")
        return 0

    if args.command == "adversary":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        adv_result = run_adversary(target)
        paths = write_adversary_report(adv_result, out_dir)
        summary = adv_result.get("summary") or {}
        print("adversary complete (diagnostic — not a vuln report)")
        print(f"  findings         {summary.get('finding_count', 0)}")
        print(f"  challenged       {summary.get('challenged_count', 0)}")
        print(f"  CONFIRMED        {summary.get('CONFIRMED', 0)}")
        print(f"  LIKELY           {summary.get('LIKELY', 0)}")
        print(f"  UNVERIFIED       {summary.get('UNVERIFIED', 0)}")
        print(f"  FALSE_POSITIVE   {summary.get('FALSE_POSITIVE', 0)}")
        print(f"  REQUIRES_REVIEW  {summary.get('REQUIRES_REVIEW', 0)}")
        print(f"  json             {paths['json']}")
        print(f"  md               {paths['markdown']}")
        return 0

    if args.command == "evidence":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)
        ev_result = run_evidence(target)
        paths = write_evidence_report(ev_result, out_dir)
        summary = ev_result.get("summary") or {}
        by_conf = summary.get("by_confidence") or {}
        print("evidence & confidence complete (diagnostic — not a vuln report)")
        print(f"  findings          {summary.get('finding_count', 0)}")
        print(f"  unique evidence   {summary.get('unique_evidence_count', 0)}")
        print(f"  reused evidence   {summary.get('reused_evidence_count', 0)}")
        print(f"  conflicts         {summary.get('conflict_count', 0)}")
        print(f"  unknowns          {summary.get('unknown_count', 0)}")
        print(f"  VERY_HIGH         {by_conf.get('VERY_HIGH', 0)}")
        print(f"  HIGH              {by_conf.get('HIGH', 0)}")
        print(f"  MEDIUM            {by_conf.get('MEDIUM', 0)}")
        print(f"  LOW               {by_conf.get('LOW', 0)}")
        print(f"  UNKNOWN           {by_conf.get('UNKNOWN', 0)}")
        print(f"  json              {paths['json']}")
        print(f"  md                {paths['markdown']}")
        return 0

    if args.command in {"paths", "attack-paths"}:
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        out_dir = Path(args.out_dir)

        # --- Phase 6 Part2 predictive ---
        # `--diff` compares two saved attack-paths.json files and needs no run.
        if getattr(args, "diff", None):
            from engines.attack_graph import diff as ag_diff

            a_path, b_path = args.diff
            comparison = ag_diff.compare_attack_graphs(a_path, b_path)
            print(ag_diff.render_diff_markdown(comparison))
            return 0
        # --- end Phase 6 Part2 predictive ---

        mode = getattr(args, "mode", None)
        ag_result = (
            run_attack_graph(target, search_mode=mode)
            if mode
            else run_attack_graph(target)
        )
        paths = write_attack_graph_report(ag_result, out_dir)
        summary = ag_result.get("summary") or {}
        by_status = summary.get("by_status") or {}
        posture = ag_result.get("posture") or {}
        print("attack graph complete (diagnostic — not a vuln report)")
        print(f"  paths             {summary.get('path_count', 0)}")
        print(f"  dead ends         {summary.get('dead_end_count', 0)}")
        print(f"  CONFIRMED         {by_status.get('CONFIRMED', 0)}")
        print(f"  LIKELY            {by_status.get('LIKELY', 0)}")
        print(f"  UNVERIFIED        {by_status.get('UNVERIFIED', 0)}")
        print(f"  BLOCKED           {by_status.get('BLOCKED', 0)}")
        print(f"  INVALID           {by_status.get('INVALID', 0)}")
        print(f"  search mode       {ag_result.get('search_mode')}")
        print(f"  max sensitivity   {posture.get('max_sensitivity_reachable', 'UNKNOWN')}")
        print(
            "  privilege         "
            f"{posture.get('privilege_pattern_counts') or {}}"
        )
        filtered = _filter_attack_paths(ag_result, args)
        label = _attack_path_filter_label(args)
        top = _top_attack_paths({"graph": ag_result.get("graph"), "paths": filtered}, limit=8)
        if top:
            print(f"  top paths{label}:")
            for line in top:
                for row in line:
                    print(f"    {row}")
        elif label:
            print(f"  top paths{label}: (none matched)")
        print(f"  json              {paths['json']}")
        print(f"  md                {paths['markdown']}")

        # --- Phase 6 Part2 predictive ---
        if getattr(args, "what_if", None):
            from engines.attack_graph import whatif as ag_whatif

            try:
                whatif_result = ag_whatif.run_what_if(ag_result, args.what_if)
            except KeyError:
                print(
                    "  what-if: unknown scenario "
                    f"{args.what_if!r}; valid: {ag_whatif.available_scenarios()}",
                    file=sys.stderr,
                )
                return 2
            print(
                f"  what-if [{whatif_result['scenario']}] "
                f"({whatif_result['status']}, {whatif_result['hypothetical_path_count']} hypothetical):"
            )
            nbi = {n.get("id"): n for n in (ag_result.get("graph") or {}).get("nodes") or []}
            for hp in whatif_result["hypothetical_paths"]:
                labels = hp.get("hop_labels") or [
                    str((nbi.get(h) or {}).get("label", h)) for h in hp.get("hops") or []
                ]
                print(f"    - {hp['id']}: {' → '.join(str(x) for x in labels)}")
                print(f"      premise: {hp['premise']}")
            if whatif_result.get("note"):
                print(f"    ({whatif_result['note']})")

        if getattr(args, "predictive", False):
            from engines.attack_graph import predictive as ag_predictive

            report = ag_predictive.surface_report(ag_result)
            print(f"  predictive surface ({report['status']}):")
            for sig in report.get("signals") or []:
                print(f"    - [{sig['direction']}] {sig['language']}: {sig['signal']}")
            if not report.get("signals"):
                print("    (no emerging-surface signals on this target)")
        # --- end Phase 6 Part2 predictive ---
        if not getattr(args, "no_engage", False):
            _print_engagement(emit_for_paths(ag_result))
        return 0

    if args.command == "data":
        return _run_data_command(args)

    if args.command == "twin":
        return _run_twin_command(args)

    if args.command == "memory":
        return _run_memory_command(args)

    if args.command == "investigate":
        return _run_investigate_command(args)

    parser.print_help()
    return 2


def _run_github_command(args: argparse.Namespace) -> int:
    """GitHub Security Bot CLI — thin wrappers over engines.github."""
    action = getattr(args, "github_command", None)
    try:
        from engines.github.cli import run_github_command
    except ImportError as exc:
        print(
            f"error: GitHub adapter CLI unavailable ({exc}). "
            "See docs/github/README.md",
            file=sys.stderr,
        )
        return 2
    try:
        return int(run_github_command(action, args))
    except Exception as exc:  # noqa: BLE001
        print(f"error: github {action} failed: {exc}", file=sys.stderr)
        return 2


def _run_investigate_command(args: argparse.Namespace) -> int:
    """Investigation Agent CLI — orchestrate evidence-driven investigation."""
    import json as _json

    from engines.investigation import (
        explain_investigation,
        find_investigation,
        render_investigation_markdown,
        run_investigation,
    )

    out_dir = Path(args.out_dir)
    budget = getattr(args, "budget", None)
    if getattr(args, "fast", False):
        budget = "FAST"
    elif getattr(args, "deep", False):
        budget = "DEEP"
    elif not budget:
        budget = "BALANCED"

    explain_id = getattr(args, "explain", None)
    if explain_id:
        # Prefer existing JSON artifact; else run a focused investigation
        artifact = out_dir / "investigation.json"
        result = None
        if artifact.is_file():
            try:
                result = _json.loads(artifact.read_text(encoding="utf-8"))
            except (OSError, _json.JSONDecodeError):
                result = None
        if not isinstance(result, dict):
            target = Path(args.path)
            result = run_investigation(
                target,
                finding_id=explain_id,
                budget=budget,
                memory_dir=Path(args.memory_dir),
                out_dir=out_dir,
                write_report=True,
                parallel=False,
                with_twin=not getattr(args, "no_twin", False),
            )
        inv = find_investigation(result, explain_id)
        if inv is None and (result.get("investigations") or []):
            inv = result["investigations"][0]
        if inv is None:
            print(f"error: no investigation for: {explain_id}", file=sys.stderr)
            return 2
        print(explain_investigation(inv))
        return 0

    target = Path(args.path)
    source: Path | dict
    if target.is_file() and target.suffix.lower() == ".json":
        try:
            payload = _json.loads(target.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as exc:
            print(f"error: cannot load JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(payload, dict):
            print("error: JSON root must be an object", file=sys.stderr)
            return 2
        source = payload
    else:
        source = target.resolve()
        if not source.exists():
            print(f"error: path not found: {source}", file=sys.stderr)
            return 2

    result = run_investigation(
        source,
        finding_id=getattr(args, "finding", None),
        budget=budget,
        memory_dir=Path(args.memory_dir),
        out_dir=out_dir,
        write_report=True,
        with_twin=not getattr(args, "no_twin", False),
    )

    if getattr(args, "as_json", False):
        print(_json.dumps(result, indent=2, default=str))
        return 0

    summary = result.get("summary") or {}
    print("investigation complete")
    print(f"  target          {result.get('target')}")
    print(f"  budget          {result.get('budget')}")
    print(f"  investigations  {summary.get('investigation_count', 0)}")
    print(f"  verified        {summary.get('verified', 0)}")
    print(f"  likely          {summary.get('likely', 0)}")
    print(f"  false_positive  {summary.get('false_positive', 0)}")
    print(f"  unverified      {summary.get('unverified', 0)}")
    print(f"  requires_review {summary.get('requires_review', 0)}")
    report = result.get("report") or {}
    if report.get("markdown"):
        print(f"  md              {report['markdown']}")
    if report.get("json"):
        print(f"  json            {report['json']}")
    # Short markdown digest for humans
    print()
    print(render_investigation_markdown(result))
    return 0


def _run_memory_command(args: argparse.Namespace) -> int:
    """Security Memory CLI — project-local longitudinal store."""
    import json as _json

    from engines.memory import (
        answer_memory_query,
        get_attack_paths,
        get_controls,
        get_current_state,
        get_findings,
        get_history,
        get_rejected_findings,
        get_unknowns,
        load_ledger,
        render_memory_markdown,
        run_memory_changes,
        run_memory_record,
        run_memory_regressions,
        write_memory_report,
    )

    action = args.memory_command
    out_dir = Path(args.out_dir)

    if action == "record":
        target = Path(args.path)
        source: Path | dict
        if target.is_file() and target.suffix.lower() == ".json":
            try:
                payload = _json.loads(target.read_text(encoding="utf-8"))
            except (OSError, _json.JSONDecodeError) as exc:
                print(f"error: cannot load audit/graph JSON: {exc}", file=sys.stderr)
                return 2
            if not isinstance(payload, dict):
                print("error: JSON root must be an object", file=sys.stderr)
                return 2
            source = payload
        else:
            source = target.resolve()
            if not source.exists():
                print(f"error: path not found: {source}", file=sys.stderr)
                return 2
        result = run_memory_record(
            source,
            memory_dir=out_dir,
            revision=getattr(args, "revision", None),
            write_report=True,
        )
        summary = result.get("summary") or {}
        print("memory record complete")
        print(f"  snapshot   {result.get('snapshot_id')}")
        print(f"  findings   {summary.get('finding_count', 0)}")
        print(f"  controls   {summary.get('control_count', 0)}")
        print(f"  paths      {summary.get('path_count', 0)}")
        print(f"  unknowns   {summary.get('unknown_count', 0)}")
        print(f"  memory     {result.get('memory_dir')}")
        report = result.get("report") or {}
        if report.get("markdown"):
            print(f"  md         {report['markdown']}")
        if report.get("html_section"):
            print(f"  html       {report['html_section']}")
        return 0

    if action == "show":
        state = get_current_state(out_dir)
        print(render_memory_markdown(state, memory_dir=out_dir))
        paths = write_memory_report(state, memory_dir=out_dir, out_dir=out_dir)
        print(f"  md    {paths.get('markdown')}")
        print(f"  html  {paths.get('html_section')}")
        return 0

    if action == "history":
        finding_id = getattr(args, "finding_id", None)
        if finding_id:
            led = load_ledger(out_dir)
            entry = (led.get("entries") or {}).get(finding_id)
            if entry is None:
                # Soft match on rule_id / substring fingerprint
                for fp, ent in (led.get("entries") or {}).items():
                    if finding_id in str(fp) or finding_id == str(
                        ent.get("rule_id") or ""
                    ):
                        entry = ent
                        break
            if entry is None:
                print(f"error: no ledger entry for finding: {finding_id}", file=sys.stderr)
                return 2
            print(_json.dumps(entry, indent=2))
            return 0
        hist = get_history(out_dir)
        print("memory history")
        print(f"  snapshots  {len(hist.get('snapshot_ids') or [])}")
        for sid in hist.get("snapshot_ids") or []:
            print(f"  - {sid}")
        for snap in hist.get("snapshots") or []:
            s = snap.get("summary") or {}
            print(
                f"    {snap.get('snapshot_id')}: findings={s.get('finding_count', 0)} "
                f"paths={s.get('path_count', 0)} rev={snap.get('source_revision')}"
            )
        return 0

    if action == "changes":
        diff = run_memory_changes(
            out_dir,
            before_id=getattr(args, "before_id", None),
            after_id=getattr(args, "after_id", None),
        )
        print(_json.dumps(diff, indent=2))
        return 0

    if action == "regressions":
        regs = run_memory_regressions(out_dir)
        print(_json.dumps(regs, indent=2))
        return 0

    if action == "findings":
        if getattr(args, "rejected", False):
            items = get_rejected_findings(out_dir)
        else:
            items = get_findings(out_dir)
        print(_json.dumps(items, indent=2))
        return 0

    if action == "controls":
        print(_json.dumps(get_controls(out_dir), indent=2))
        return 0

    if action == "paths":
        print(_json.dumps(get_attack_paths(out_dir), indent=2))
        return 0

    if action == "unknowns":
        print(_json.dumps(get_unknowns(out_dir), indent=2))
        return 0

    if action == "query":
        question = getattr(args, "question", None) or ""
        if not question.strip():
            print("error: --question is required", file=sys.stderr)
            return 2
        answer = answer_memory_query(out_dir, question)
        print(_json.dumps(answer, indent=2))
        return 0

    print(f"error: unknown memory command: {action}", file=sys.stderr)
    return 2

def _run_twin_command(args: argparse.Namespace) -> int:
    """Security Twin CLI — local symbolic analysis only (never network)."""
    import json as _json

    from engines.twin import (
        answer_query,
        build_security_twin,
        control_effectiveness,
        entity_blast_radius,
        export_twin_examples,
        list_scenarios,
        run_twin,
        run_twin_compare,
        run_twin_what_if,
        simulate_attack,
        twin_regression,
        write_twin_report,
    )

    action = args.twin_command

    def _load_twin_payload(path: Path) -> dict:
        """Load a twin dict from JSON report or build from a directory."""
        if path.is_file():
            data = _json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("twin"), dict):
                return data["twin"]
            if isinstance(data, dict):
                return data
            raise ValueError(f"not a twin JSON object: {path}")
        return build_security_twin(path)

    try:
        if action == "scenarios":
            for sc in list_scenarios():
                key = sc.get("key", "?")
                title = sc.get("title", "")
                theme = sc.get("theme", "")
                print(f"  {key:28} {title}  [{theme}]")
            return 0

        if action == "compare":
            before = _load_twin_payload(Path(args.before).resolve())
            after = _load_twin_payload(Path(args.after).resolve())
            result = run_twin_compare(before, after)
            reg = result.get("regression") or {}
            print("twin compare")
            print(f"  changes   {len(reg.get('changes') or [])}")
            for c in (reg.get("changes") or [])[:12]:
                ctype = c.get("change_type") or c.get("type") or c.get("kind") or "?"
                print(f"  - {ctype}: {c.get('id') or c.get('description') or c}")
            print(_json.dumps({"regression_summary": reg.get("summary") or reg}, indent=2, default=str))
            return 0

        if action == "regression":
            before = _load_twin_payload(Path(args.before).resolve())
            after = _load_twin_payload(Path(args.after).resolve())
            reg = twin_regression(before, after)
            print("twin regression")
            print(f"  changes   {len(reg.get('changes') or [])}")
            for c in (reg.get("changes") or [])[:12]:
                ctype = c.get("change_type") or c.get("type") or c.get("kind") or "?"
                print(f"  - {ctype}: {c.get('id') or c.get('description') or c}")
            if reg.get("summary"):
                print(_json.dumps(reg["summary"], indent=2, default=str))
            return 0

        target = Path(getattr(args, "path", ".")).resolve()
        if action != "scenarios" and not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2

        if action == "build":
            out_dir = Path(args.out_dir)
            result = run_twin(
                target,
                simulate=not getattr(args, "no_simulate", False),
                controls=True,
                attacker_profile=getattr(args, "profile", "PUBLIC_USER"),
                write_report=out_dir,
            )
            twin = result.get("twin") or {}
            summary = twin.get("summary") or {}
            # run_twin already wrote via write_report=out_dir
            print("twin build complete (symbolic — no network)")
            print(f"  entities     {summary.get('entity_count', 0)}")
            print(f"  relationships {summary.get('relationship_count', 0)}")
            print(f"  paths        {summary.get('attack_graph_path_count', 0)}")
            print(f"  controls     {summary.get('control_count', 0)}")
            print(f"  json         {out_dir / 'security-twin.json'}")
            print(f"  md           {out_dir / 'security-twin.md'}")
            print(f"  html         {out_dir / 'security-twin.html'}")
            return 0

        if action == "show":
            out_dir = Path(args.out_dir)
            result = run_twin(
                target,
                simulate=True,
                controls=True,
                attacker_profile=getattr(args, "profile", "PUBLIC_USER"),
                write_report=out_dir,
            )
            twin = result.get("twin") or {}
            summary = twin.get("summary") or {}
            print("twin summary")
            for k, v in sorted(summary.items()):
                print(f"  {k:28} {v}")
            sim = result.get("simulation") or {}
            print(f"  observed_paths             {len(sim.get('observed_paths') or [])}")
            print(f"  simulated_paths            {len(sim.get('simulated_paths') or [])}")
            print(f"  controls_analyzed          {len(result.get('controls') or [])}")
            return 0

        if action == "attack":
            twin = build_security_twin(target)
            sim = simulate_attack(
                twin, attacker_profile=getattr(args, "profile", "PUBLIC_USER")
            )
            print(f"twin attack [{getattr(args, 'profile', 'PUBLIC_USER')}]")
            print(f"  observed   {len(sim.get('observed_paths') or [])}")
            print(f"  simulated  {len(sim.get('simulated_paths') or [])}")
            for p in (sim.get("observed_paths") or [])[:6]:
                print(f"  - OBS {p.get('path_id') or p.get('id')}: {p.get('status')}")
            for p in (sim.get("simulated_paths") or [])[:6]:
                print(f"  - SIM {p.get('path_id') or p.get('id')}: {p.get('status')}")
            return 0

        if action == "blast-radius":
            twin = build_security_twin(target)
            blast = entity_blast_radius(twin, args.entity)
            raw = blast.get("blast") or {}
            print(f"twin blast-radius [{blast.get('entity_id')}]")
            print(f"  exists           {raw.get('exists')}")
            print(f"  node_count       {raw.get('node_count', 0)}")
            print(f"  max_sensitivity  {raw.get('max_sensitivity')}")
            for imp in (blast.get("impact_classifications") or [])[:8]:
                print(f"  - {imp.get('impact') or imp.get('class')}: {imp.get('id') or imp}")
            return 0

        if action == "controls":
            twin = build_security_twin(target)
            controls = control_effectiveness(twin)
            print(f"twin controls ({len(controls)})")
            for c in controls[:15]:
                prot = c.get("protected_path_count", {})
                exp = c.get("paths_exposed_if_removed", {})
                pv = prot.get("value", prot) if isinstance(prot, dict) else prot
                ev = exp.get("value", exp) if isinstance(exp, dict) else exp
                print(f"  - {c.get('control_id')}: protected={pv} exposed_if_removed={ev}")
            return 0

        if action == "what-if":
            result = run_twin_what_if(
                target,
                scenario=getattr(args, "scenario", None),
                remove_control=getattr(args, "remove_control", None),
                grant_agent_tool=getattr(args, "grant_agent_tool", None),
            )
            cf = result.get("counterfactual") or {}
            sc = cf.get("scenario")
            sc_label = sc.get("value", sc) if isinstance(sc, dict) else (sc or "custom")
            print(f"twin what-if [{sc_label}]")
            print(f"  assumptions         {len(cf.get('assumptions') or [])}")
            print(f"  simulated_paths     {len(cf.get('simulated_paths') or [])}")
            print(f"  layer               SIMULATED (not OBSERVED findings)")
            for p in (cf.get("simulated_paths") or [])[:8]:
                premise = p.get("premise") or {}
                pv = premise.get("value", premise) if isinstance(premise, dict) else premise
                print(f"  - {p.get('title') or p.get('id')}: {pv}")
            if cf.get("disclaimer"):
                print(f"  note: {cf['disclaimer']}")
            return 0

        if action == "query":
            twin = build_security_twin(target)
            ans = answer_query(twin, args.question)
            print(f"twin query [{ans.get('intent')}]")
            print(_json.dumps(ans.get("answer") or ans, indent=2, default=str))
            return 0

        if action == "export-dataset":
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            twin = build_security_twin(target)
            examples = export_twin_examples(twin)
            out_path = out_dir / "twin-examples.json"
            out_path.write_text(
                _json.dumps(examples, indent=2, default=str) + "\n", encoding="utf-8"
            )
            print("twin export-dataset (EVALUATION_ONLY)")
            print(f"  examples  {len(examples)}")
            print(f"  json      {out_path}")
            return 0

        print(f"error: unknown twin command: {action}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — never network; soft-fail CLI
        print(f"error: twin {action} failed: {exc}", file=sys.stderr)
        return 2


def _run_data_command(args: argparse.Namespace) -> int:
    """Phase 9 training-data CLI — never trains a model."""
    from engines.data import (
        discover,
        load_registry,
        run_data_pipeline,
        save_registry,
        set_status,
        write_data_pipeline_report,
    )
    from engines.data.registry import DEFAULT_REGISTRY_PATH, get_dataset

    action = args.data_command
    target = Path(args.path).resolve()
    out_dir = Path(args.out_dir)

    if action == "discover":
        reg = discover()
        print("data discover complete (no downloads)")
        print(f"  datasets  {(reg.get('summary') or {}).get('dataset_count', 0)}")
        print(f"  registry  {DEFAULT_REGISTRY_PATH}")
        return 0

    if action == "inspect":
        reg = load_registry()
        did = getattr(args, "dataset_id", None)
        if did:
            entry = get_dataset(reg, did)
            if not entry:
                print(f"error: unknown dataset id: {did}", file=sys.stderr)
                return 2
            import json as _json

            print(_json.dumps(entry, indent=2))
            return 0
        summary = reg.get("summary") or {}
        print("data registry")
        print(f"  datasets          {summary.get('dataset_count', 0)}")
        print(f"  APPROVED          {summary.get('approved_training', 0)}")
        print(f"  REJECTED          {summary.get('rejected', 0)}")
        print(f"  RESTRICTED        {summary.get('restricted', 0)}")
        print(f"  EVALUATION_ONLY   {summary.get('evaluation_only', 0)}")
        for d in reg.get("datasets") or []:
            print(f"  - {d.get('dataset_id')} [{d.get('status')}] license={d.get('license')}")
        return 0

    if action in {"approve", "reject"}:
        did = getattr(args, "dataset_id", None)
        if not did:
            print("error: --id DATASET_ID required", file=sys.stderr)
            return 2
        reg = load_registry()
        try:
            if action == "approve":
                reg = set_status(
                    reg,
                    did,
                    "APPROVED",
                    force_research_only=bool(
                        getattr(args, "force_research_only", False)
                    ),
                )
            else:
                reg = set_status(reg, did, "REJECTED")
        except (KeyError, PermissionError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        save_registry(reg)
        entry = get_dataset(reg, did)
        print(f"data {action}: {did} → {entry.get('status') if entry else '?'}")
        return 0

    # normalize / dedupe / validate / benchmark / prepare / report
    result = run_data_pipeline(target)
    paths = write_data_pipeline_report(result, out_dir)
    summary = result.get("summary") or {}
    print(f"data {action} complete (diagnostic — no training)")
    print(f"  examples     {summary.get('example_count', 0)}")
    print(f"  duplicates   {summary.get('duplicate_count', 0)}")
    print(f"  scrub hits   {summary.get('scrub_count', 0)}")
    print(f"  poison flags {summary.get('poison_count', 0)}")
    print(f"  TRAINING     {summary.get('TRAINING', 0)}")
    print(f"  BENCHMARK    {summary.get('BENCHMARK_ONLY', 0)}")
    print(f"  blocked      {summary.get('blocked', 0)}")
    if action == "benchmark":
        blocked = (result.get("prepare") or {}).get("blocked_from_training") or []
        for b in blocked[:12]:
            print(f"  - {b.get('example_id')}: {b.get('reason')}")
    print(f"  json         {paths['json']}")
    print(f"  md           {paths['markdown']}")
    print(f"  html         {paths['html']}")
    return 0


def _filter_attack_paths(result: dict, args: argparse.Namespace) -> list[dict]:
    """Apply the Part 2 view filters (``--current/--blocked/--unknown/--critical
    /--shortest/--mode``) to the enumerated paths. Display only — the written
    ``attack-paths.json`` is never filtered.
    """
    from engines.attack_graph import api as ag_api
    from engines.attack_graph import modes as ag_modes

    paths = list(result.get("paths") or [])
    mode = getattr(args, "mode", None)
    if mode:
        paths = ag_modes.filter_paths(paths, mode)

    if getattr(args, "current", False):
        paths = [p for p in paths if str(p.get("status")) in {"CONFIRMED", "LIKELY"}]
    if getattr(args, "blocked", False):
        paths = [p for p in paths if str(p.get("status")) == "BLOCKED"]
    if getattr(args, "unknown", False):
        paths = [p for p in paths if str(p.get("status")) == "UNVERIFIED"]
    if getattr(args, "shortest", False):
        paths = [p for p in paths if "shortest_credible" in (p.get("selection") or [])]
    if getattr(args, "critical", False):
        crit: list[dict] = []
        for p in paths:
            sens = ag_api.analyze_path_sensitivity(result, str(p.get("id")))
            if sens.get("max_impact_weight", 0.0) >= 0.75:
                crit.append(p)
        paths = crit
    return paths


def _attack_path_filter_label(args: argparse.Namespace) -> str:
    active = [
        name
        for name in ("current", "blocked", "unknown", "critical", "shortest")
        if getattr(args, name, False)
    ]
    if getattr(args, "mode", None):
        active.append(f"mode={args.mode}")
    return f" [{', '.join(active)}]" if active else ""


def _top_attack_paths(result: dict, limit: int = 5) -> list[list[str]]:
    """Render top paths as: 'Entry → Finding → … → Impact' + status/conf/score."""
    graph = result.get("graph") or {}
    labels = {n.get("id"): n.get("label") or n.get("id") for n in graph.get("nodes") or []}
    out: list[list[str]] = []
    for p in (result.get("paths") or [])[:limit]:
        arrow = " → ".join(str(labels.get(h, h)) for h in p.get("hops") or [])
        meta = f"{p.get('status')}/{p.get('confidence_level')}/score={p.get('score')}"
        out.append([arrow, meta])
    return out


if __name__ == "__main__":
    raise SystemExit(main())
