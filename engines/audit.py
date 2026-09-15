"""A-Z audit orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from engines.adversary import run_adversary, write_adversary_report
from engines.app_model import build_application_model, write_application_model
from engines.attack_graph import run_attack_graph, write_attack_graph_report
from engines.dataflow import analyze_dataflow, write_dataflow_report
from engines.evidence import run_evidence, write_evidence_report
from engines.paths import default_rules_dir
from engines.scanner import ScanOptions, run_scan
from engines.verify import run_verification, write_verification_report

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
    application_model: dict | None = None
    application_model_summary: dict | None = None
    application_model_paths: dict | None = None
    dataflow_result: dict | None = None
    dataflow_summary: dict | None = None
    dataflow_paths: dict | None = None
    verification_result: dict | None = None
    verification_summary: dict | None = None
    verification_paths: dict | None = None
    adversary_result: dict | None = None
    adversary_summary: dict | None = None
    adversary_paths: dict | None = None
    evidence_result: dict | None = None
    evidence_summary: dict | None = None
    evidence_paths: dict | None = None
    attack_graph_result: dict | None = None
    attack_graph_summary: dict | None = None
    attack_graph_paths: dict | None = None
    twin_summary: dict | None = None
    security_twin: dict | None = None

    for phase_id, label in AUDIT_PHASES:
        if phase_id not in selected and phase_id != "report":
            continue
        if phase_id in {"surface", "report"}:
            phase_findings = []
        else:
            prefix = PHASE_RULE_PREFIX.get(phase_id, "")
            phase_findings = [f for f in findings if str(f.get("id", "")).startswith(prefix)]

        phase_entry: dict = {
            "id": phase_id,
            "label": label,
            "status": "ok",
            "finding_count": len(phase_findings),
            "findings": phase_findings,
        }

        if phase_id == "surface":
            try:
                application_model = build_application_model(options.target)
                application_model_summary = dict(application_model.get("summary") or {})
                application_model_paths = write_application_model(application_model, out_dir)
                phase_entry["application_model_summary"] = application_model_summary
                phase_entry["status"] = "ok"
                # Optional Phase 2 dataflow — never fail audit on errors
                try:
                    dataflow_result = analyze_dataflow(
                        options.target, application_model=application_model
                    )
                    dataflow_summary = dict(dataflow_result.get("summary") or {})
                    dataflow_paths = write_dataflow_report(dataflow_result, out_dir)
                    # Re-write enriched application model after taint attach
                    application_model_paths = write_application_model(
                        application_model, out_dir
                    )
                    phase_entry["dataflow_summary"] = dataflow_summary
                except Exception as df_exc:  # noqa: BLE001
                    phase_entry["dataflow_status"] = "error"
                    phase_entry["dataflow_error"] = str(df_exc)
                # Optional Phase 3 Hunter→Judge — never fail audit on errors
                try:
                    verification_result = run_verification(
                        options.target,
                        application_model=application_model,
                        dataflow=dataflow_result,
                    )
                    verification_summary = dict(
                        verification_result.get("summary") or {}
                    )
                    verification_paths = write_verification_report(
                        verification_result, out_dir
                    )
                    phase_entry["verification_summary"] = verification_summary
                except Exception as v_exc:  # noqa: BLE001
                    phase_entry["verification_status"] = "error"
                    phase_entry["verification_error"] = str(v_exc)
                # Optional Phase 4 False Positive Adversary — never fail audit
                try:
                    adversary_result = run_adversary(
                        options.target,
                        verification=verification_result,
                    )
                    adversary_summary = dict(adversary_result.get("summary") or {})
                    adversary_paths = write_adversary_report(
                        adversary_result, out_dir
                    )
                    phase_entry["adversary_summary"] = adversary_summary
                except Exception as a_exc:  # noqa: BLE001
                    phase_entry["adversary_status"] = "error"
                    phase_entry["adversary_error"] = str(a_exc)
                # Optional Phase 5 Evidence & Confidence — never fail audit
                try:
                    if adversary_result is not None:
                        evidence_result = run_evidence(
                            options.target,
                            adversary=adversary_result,
                        )
                        evidence_summary = dict(
                            evidence_result.get("summary") or {}
                        )
                        evidence_paths = write_evidence_report(
                            evidence_result, out_dir
                        )
                        phase_entry["evidence_summary"] = evidence_summary
                except Exception as e_exc:  # noqa: BLE001
                    phase_entry["evidence_status"] = "error"
                    phase_entry["evidence_error"] = str(e_exc)
                # Optional Phase 6 Attack Graph — never fail audit on errors
                try:
                    if evidence_result is not None:
                        attack_graph_result = run_attack_graph(
                            options.target,
                            evidence=evidence_result,
                        )
                        attack_graph_summary = dict(
                            attack_graph_result.get("summary") or {}
                        )
                        attack_graph_paths = write_attack_graph_report(
                            attack_graph_result, out_dir
                        )
                        phase_entry["attack_graph_summary"] = attack_graph_summary
                        # Soft-wire Security Twin summary (never fail audit)
                        try:
                            from engines.twin import build_security_twin

                            twin = build_security_twin(
                                options.target,
                                attack_graph=attack_graph_result,
                                application_model=application_model,
                            )
                            twin_summary = dict(twin.get("summary") or {})
                            security_twin = {
                                "schema_version": twin.get("schema_version"),
                                "summary": twin_summary,
                                "entity_count": twin_summary.get("entity_count", 0),
                                "relationship_count": twin_summary.get(
                                    "relationship_count", 0
                                ),
                                "disclaimer": twin.get("disclaimer"),
                            }
                            phase_entry["twin_summary"] = twin_summary
                        except Exception as twin_exc:  # noqa: BLE001
                            phase_entry["twin_status"] = "error"
                            phase_entry["twin_error"] = str(twin_exc)
                except Exception as ag_exc:  # noqa: BLE001
                    phase_entry["attack_graph_status"] = "error"
                    phase_entry["attack_graph_error"] = str(ag_exc)
            except Exception as exc:  # noqa: BLE001 — never fail audit on surface model
                phase_entry["status"] = "error"
                phase_entry["error"] = str(exc)
                phase_entry["application_model_summary"] = {
                    "endpoint_count": 0,
                    "sink_count": 0,
                    "frameworks": [],
                }

        phase_results.append(phase_entry)

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
    if application_model is not None:
        result["application_model"] = application_model
    if application_model_summary is not None:
        result["application_model_summary"] = application_model_summary
    if application_model_paths is not None:
        result["application_model_paths"] = application_model_paths
    if dataflow_result is not None:
        result["dataflow"] = dataflow_result
    if dataflow_summary is not None:
        result["dataflow_summary"] = dataflow_summary
    if dataflow_paths is not None:
        result["dataflow_paths"] = dataflow_paths
    if verification_result is not None:
        # Drop soft private model refs before attaching to audit payload
        verification_result = {
            k: v
            for k, v in verification_result.items()
            if not str(k).startswith("_")
        }
        result["verification"] = verification_result
    if verification_summary is not None:
        result["verification_summary"] = verification_summary
    if verification_paths is not None:
        result["verification_paths"] = verification_paths
    if adversary_result is not None:
        adversary_result = {
            k: v
            for k, v in adversary_result.items()
            if not str(k).startswith("_")
        }
        result["adversary"] = adversary_result
    if adversary_summary is not None:
        result["adversary_summary"] = adversary_summary
    if adversary_paths is not None:
        result["adversary_paths"] = adversary_paths
    if evidence_result is not None:
        evidence_public = {
            k: v
            for k, v in evidence_result.items()
            if not str(k).startswith("_")
        }
        result["evidence"] = evidence_public
    if evidence_summary is not None:
        result["evidence_summary"] = evidence_summary
    if evidence_paths is not None:
        result["evidence_paths"] = evidence_paths
    if attack_graph_result is not None:
        attack_graph_public = {
            k: v
            for k, v in attack_graph_result.items()
            if not str(k).startswith("_")
        }
        result["attack_graph"] = attack_graph_public
    if attack_graph_summary is not None:
        result["attack_graph_summary"] = attack_graph_summary
    if attack_graph_paths is not None:
        result["attack_graph_paths"] = attack_graph_paths
    if twin_summary is not None:
        result["twin_summary"] = twin_summary
    if security_twin is not None:
        result["security_twin"] = security_twin
    return result


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts
