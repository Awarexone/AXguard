"""Scan / review pipeline — wraps existing engines; does not reimplement scanners."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from engines.api.providers.factory import get_provider, require_provider_for_enrichment
from engines.api.settings import Settings
from engines.api.storage import Store
from engines.paths import default_rules_dir


def artifacts_dir(project_path: Path) -> Path:
    out = project_path / ".findings" / "axguard"
    out.mkdir(parents=True, exist_ok=True)
    return out


def stable_finding_id(
    project_id: str,
    *,
    rule_id: str,
    file: str,
    line: int,
    snippet: str = "",
) -> str:
    raw = f"{project_id}|{rule_id}|{file}|{line}|{snippet[:80]}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"fnd_{digest}"


def finding_fingerprint(rule_id: str, file: str, line: int) -> str:
    raw = f"{rule_id}|{file}|{line}"
    return "fp_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def normalize_finding(
    raw: dict[str, Any],
    *,
    project_id: str,
    scan_id: str,
) -> dict[str, Any]:
    rule_id = str(raw.get("id") or raw.get("rule_id") or "unknown")
    file = str(raw.get("file") or "")
    line = int(raw.get("line") or 0)
    fid = stable_finding_id(
        project_id,
        rule_id=rule_id,
        file=file,
        line=line,
        snippet=str(raw.get("snippet") or ""),
    )
    return {
        "id": fid,
        "project_id": project_id,
        "scan_id": scan_id,
        "fingerprint": finding_fingerprint(rule_id, file, line),
        "type": rule_id,
        "rule_id": rule_id,
        "title": raw.get("title") or rule_id,
        "severity": str(raw.get("severity") or "medium").lower(),
        "status": raw.get("status") or "UNVERIFIED",
        "confidence": raw.get("confidence") or "UNKNOWN",
        "location": {"file": file, "line": line},
        "file": file,
        "line": line,
        "snippet": raw.get("snippet"),
        "message": raw.get("message"),
        "cwe": raw.get("cwe"),
        "fix": raw.get("fix"),
        "evidence": raw.get("evidence") or [],
        "counter_evidence": raw.get("counter_evidence") or [],
        "unknowns": raw.get("unknowns") or [],
        "created_at": time.time(),
        "updated_at": time.time(),
    }


def index_findings(
    store: Store,
    findings: list[dict[str, Any]],
    *,
    project_id: str,
    scan_id: str,
) -> list[dict[str, Any]]:
    indexed: list[dict[str, Any]] = []
    for raw in findings:
        item = normalize_finding(raw, project_id=project_id, scan_id=scan_id)
        store.upsert_finding(item)
        indexed.append(item)
    return indexed


def _write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def _soft(label: str, fn, warnings: list[str]) -> Any | None:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"{label}: {exc}")
        return None


def load_project_json(project_path: Path, *names: str) -> dict[str, Any] | None:
    base = project_path / ".findings" / "axguard"
    for name in names:
        for candidate in (base / name, base / f"{name}.json"):
            if candidate.is_file():
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict):
                    return data
    if base.is_dir():
        for p in base.rglob("*.json"):
            stem = p.stem.lower().replace("-", "_")
            if any(n.lower().replace("-", "_") in stem for n in names):
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict):
                    return data
    return None


def run_scan_job(store: Store, settings: Settings, scan: dict[str, Any]) -> dict[str, Any]:
    """Execute lite|balanced|deep|max by wrapping engines — never reimplements scanners."""
    from engines.scanner import ScanOptions, run_scan

    payload = scan.get("payload") or {}
    project_id = scan.get("project_id")
    if not project_id:
        return {"job_status": "failed", "error": "missing project_id"}
    project = store.get_project(project_id)
    if not project:
        return {"job_status": "failed", "error": "project not found"}

    target = Path(project["path"])
    if not target.exists():
        return {"job_status": "failed", "error": f"project path does not exist: {target}"}

    mode = (scan.get("mode") or payload.get("mode") or "balanced").lower()
    enrichment = (scan.get("enrichment") or payload.get("enrichment") or "none").lower()
    scan_id = scan["id"]
    out_dir = artifacts_dir(target)
    warnings: list[str] = []
    phases: list[dict[str, Any]] = []
    provider = get_provider(settings=settings)

    try:
        require_provider_for_enrichment(enrichment, provider)
    except Exception as exc:  # noqa: BLE001 — ApiError or unexpected
        return {"job_status": "failed", "error": str(exc), "warnings": warnings}

    def _phase(name: str, **extra: Any) -> None:
        phases.append({"id": name, "status": "ok", **extra})
        store.update_scan(
            scan_id,
            current_phase=name,
            progress=min(0.95, 0.08 + 0.08 * len(phases)),
        )

    # --- lite / shared scan ---
    _phase("scan")
    scan_result = run_scan(ScanOptions(target=target, rules_dir=default_rules_dir()))
    findings_raw = list(scan_result.get("findings") or [])
    indexed = index_findings(store, findings_raw, project_id=project_id, scan_id=scan_id)
    _write_json(out_dir / "scan_result.json", {**scan_result, "findings": findings_raw})
    store.put_artifact(
        {
            "project_id": project_id,
            "scan_id": scan_id,
            "kind": "scan",
            "path": str(out_dir / "scan_result.json"),
            "payload": {"finding_count": len(indexed), "mode": mode},
        }
    )

    app_model = None
    dataflow = None
    verification = None
    attack_graph = None
    twin_result = None
    predictive = None
    memory_result = None

    if mode in {"balanced", "deep", "max"}:
        def _app():
            nonlocal app_model
            from engines.app_model import build_application_model, write_application_model

            app_model = build_application_model(target)
            write_application_model(app_model, out_dir)
            store.set_artifact(project_id, "application_model", app_model, scan_id=scan_id)
            return app_model

        _phase("application_model")
        _soft("application_model", _app, warnings)

        def _flow():
            nonlocal dataflow
            from engines.dataflow import analyze_dataflow, write_dataflow_report

            dataflow = analyze_dataflow(target, application_model=app_model)
            write_dataflow_report(dataflow, out_dir)
            store.set_artifact(project_id, "dataflow", dataflow, scan_id=scan_id)
            return dataflow

        _phase("dataflow")
        _soft("dataflow", _flow, warnings)

    if mode in {"deep", "max"}:
        def _verify():
            nonlocal verification
            from engines.verify import run_verification

            verification = run_verification(target)
            _write_json(out_dir / "verification.json", verification)
            store.set_artifact(project_id, "verification", verification, scan_id=scan_id)
            return verification

        _phase("verification")
        _soft("verification", _verify, warnings)

        def _ag():
            nonlocal attack_graph
            from engines.attack_graph import run_attack_graph, write_attack_graph_report

            attack_graph = run_attack_graph(target)
            write_attack_graph_report(attack_graph, out_dir)
            store.set_artifact(project_id, "attack_graph", attack_graph, scan_id=scan_id)
            return attack_graph

        _phase("attack_graph")
        _soft("attack_graph", _ag, warnings)

        def _pred():
            nonlocal predictive
            try:
                from engines.predictive import run_predict

                predictive = run_predict(target, attack_graph=attack_graph, out_dir=out_dir)
            except Exception:
                from engines.attack_graph import run_attack_graph as _rag
                from engines.attack_graph import predictive as ag_predictive

                ag = attack_graph or _rag(target)
                predictive = ag_predictive.surface_report(ag)
            store.set_artifact(project_id, "predictive", predictive, scan_id=scan_id)
            return predictive

        _phase("predictive")
        _soft("predictive", _pred, warnings)

        def _twin():
            nonlocal twin_result
            from engines.twin import run_twin

            twin_result = run_twin(
                target,
                attack_graph=attack_graph,
                application_model=app_model,
                write_report=out_dir,
            )
            store.set_artifact(project_id, "twin", twin_result, scan_id=scan_id)
            return twin_result

        _phase("twin")
        _soft("twin", _twin, warnings)

        def _mem():
            nonlocal memory_result
            from engines.memory import run_memory_record

            memory_result = run_memory_record(target)
            store.set_artifact(project_id, "memory", memory_result, scan_id=scan_id)
            return memory_result

        _phase("memory")
        _soft("memory", _mem, warnings)

    enrichment_summary = None
    if enrichment == "llm":
        def _enrich():
            nonlocal enrichment_summary
            sample = indexed[:5]
            messages = [
                {
                    "role": "system",
                    "content": "Summarize security findings briefly. No exploitation steps.",
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        [{"id": f.get("id"), "rule": f.get("rule_id"), "sev": f.get("severity")} for f in sample],
                        default=str,
                    ),
                },
            ]
            enrichment_summary = provider.complete(messages)
            store.set_artifact(
                project_id, "llm_enrichment", enrichment_summary, scan_id=scan_id
            )
            return enrichment_summary

        _phase("llm_enrichment")
        _soft("llm_enrichment", _enrich, warnings)

    store.update_project(project_id, last_analysis=time.time())
    job_status = "partial" if warnings and mode != "lite" else "completed"
    return {
        "job_status": job_status,
        "status": job_status,
        "scan_id": scan_id,
        "mode": mode,
        "finding_count": len(indexed),
        "findings": indexed[:200],
        "phases": phases,
        "artifacts_dir": str(out_dir),
        "warnings": warnings,
        "enrichment": enrichment,
        "enrichment_summary": enrichment_summary,
        "application_model_summary": (app_model or {}).get("summary") if isinstance(app_model, dict) else None,
        "dataflow_summary": (dataflow or {}).get("summary") if isinstance(dataflow, dict) else None,
        "verification_summary": (verification or {}).get("summary") if isinstance(verification, dict) else None,
        "attack_graph_summary": (attack_graph or {}).get("summary") if isinstance(attack_graph, dict) else None,
        "predictive": predictive,
        "twin": twin_result,
        "memory": memory_result,
    }


def run_review_sync(store: Store, project: dict[str, Any], body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Synchronous review using run_audit when possible."""
    body = body or {}
    target = Path(project["path"])
    out_dir = artifacts_dir(target)
    warnings: list[str] = []
    try:
        from engines.audit import AuditOptions, run_audit

        audit = run_audit(AuditOptions(target=target, out_dir=out_dir))
        findings_raw = list(audit.get("findings") or [])
        scan_id = f"review_{int(time.time())}"
        indexed = index_findings(
            store, findings_raw, project_id=project["id"], scan_id=scan_id
        )
        store.update_project(project["id"], last_analysis=time.time())
        store.set_artifact(project["id"], "review", {"finding_count": len(indexed), "audit": True})
        return {
            "review_id": scan_id,
            "status": "completed",
            "finding_count": len(indexed),
            "findings": indexed[:100],
            "verified_findings": [
                f for f in indexed if str(f.get("status", "")).upper() == "VERIFIED"
            ],
            "warnings": warnings,
            "artifacts_dir": str(out_dir),
        }
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"run_audit failed: {exc}")
        from engines.scanner import ScanOptions, run_scan

        scan = run_scan(ScanOptions(target=target, rules_dir=default_rules_dir()))
        findings_raw = list(scan.get("findings") or [])
        scan_id = f"review_{int(time.time())}"
        indexed = index_findings(
            store, findings_raw, project_id=project["id"], scan_id=scan_id
        )
        return {
            "review_id": scan_id,
            "status": "partial",
            "finding_count": len(indexed),
            "findings": indexed[:100],
            "warnings": warnings,
            "artifacts_dir": str(out_dir),
        }
