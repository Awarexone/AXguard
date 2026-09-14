"""A-Z audit orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from engines.paths import default_rules_dir
from engines.scanner import ScanOptions, run_scan

AUDIT_PHASES = (
    ("surface", "Map attack surface (routes, sinks, configs)"),
    ("secrets", "Secrets and credential material"),
    ("auth", "AuthZ / IDOR / session footguns"),
    ("injection", "Injection and code-execution sinks"),
    ("sql", "SQL injection and raw query sinks"),
    ("nosql", "NoSQL / Mongo operator injection"),
    ("ssti", "Server-side template injection"),
    ("path", "Path traversal and LFI sinks"),
    ("ssrf", "SSRF and unsafe egress"),
    ("xss", "XSS and client HTML sinks"),
    ("upload", "Unsafe file upload handling"),
    ("crypto", "Weak crypto and TLS footguns"),
    ("supply", "Supply-chain and install-script risks"),
    ("graphql", "GraphQL misconfiguration"),
    ("debug", "Debug mode and verbose error leaks"),
    ("cloud", "Cloud, CORS, and metadata exposure"),
    ("agent", "AI agent / tool-wiring risks"),
    ("report", "Compile findings into report artifacts"),
)

PHASE_RULE_PREFIX = {
    "secrets": "secrets.",
    "auth": "auth.",
    "injection": "injection.",
    "ssrf": "ssrf.",
    "xss": "xss.",
    "cloud": "cloud.",
    "agent": "agent.",
    "sql": "sql.",
    "ssti": "ssti.",
    "path": "path.",
    "crypto": "crypto.",
    "supply": "supply.",
    "graphql": "graphql.",
    "upload": "upload.",
    "debug": "debug.",
    "nosql": "nosql.",
}


@dataclass
class AuditOptions:
    target: Path
    rules_dir: Path | None = None
    out_dir: Path | None = None
    phases: list[str] = field(default_factory=list)


def run_audit(options: AuditOptions) -> dict:
    rules_dir = options.rules_dir or default_rules_dir()
    out_dir = options.out_dir or (Path.cwd() / ".findings" / "axguard")
    out_dir.mkdir(parents=True, exist_ok=True)

    started = datetime.now(timezone.utc)
    scan = run_scan(ScanOptions(target=options.target, rules_dir=rules_dir))
    findings = scan["findings"]

    selected = options.phases or [p for p, _ in AUDIT_PHASES]
    phase_results = []
    for phase_id, label in AUDIT_PHASES:
        if phase_id not in selected and phase_id != "report":
            continue
        if phase_id in {"surface", "report"}:
            phase_findings = []
        else:
            prefix = PHASE_RULE_PREFIX.get(phase_id, "")
            phase_findings = [f for f in findings if str(f.get("id", "")).startswith(prefix)]
        phase_results.append(
            {
                "id": phase_id,
                "label": label,
                "status": "ok",
                "finding_count": len(phase_findings),
                "findings": phase_findings,
            }
        )

    counts = _severity_counts(findings)
    finished = datetime.now(timezone.utc)
    result = {
        "tool": "axguard",
        "mode": "audit",
        "version": "0.2.0",
        "target": str(options.target),
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        "finding_count": len(findings),
        "severity_counts": counts,
        "phases": phase_results,
        "findings": findings,
        "out_dir": str(out_dir),
    }
    return result


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts
