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

    sub.add_parser("version", help="Print version")
    sub.add_parser("help", help="Show Start Using workflow table")
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
    } and not getattr(args, "no_banner", False):
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
        ag_result = run_attack_graph(target)
        paths = write_attack_graph_report(ag_result, out_dir)
        summary = ag_result.get("summary") or {}
        by_status = summary.get("by_status") or {}
        print("attack graph complete (diagnostic — not a vuln report)")
        print(f"  paths             {summary.get('path_count', 0)}")
        print(f"  dead ends         {summary.get('dead_end_count', 0)}")
        print(f"  CONFIRMED         {by_status.get('CONFIRMED', 0)}")
        print(f"  LIKELY            {by_status.get('LIKELY', 0)}")
        print(f"  UNVERIFIED        {by_status.get('UNVERIFIED', 0)}")
        print(f"  BLOCKED           {by_status.get('BLOCKED', 0)}")
        print(f"  INVALID           {by_status.get('INVALID', 0)}")
        top = _top_attack_paths(ag_result, limit=5)
        if top:
            print("  top paths:")
            for line in top:
                for row in line:
                    print(f"    {row}")
        print(f"  json              {paths['json']}")
        print(f"  md                {paths['markdown']}")
        return 0

    parser.print_help()
    return 2


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
