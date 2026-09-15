"""Ingest audit / attack-graph results into Security Memory."""

from __future__ import annotations

import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engines.memory.fingerprints import (
    control_fingerprint,
    evidence_fingerprint,
    finding_fingerprint,
    path_fingerprint,
)
from engines.memory.lifecycle import transition_finding
from engines.memory.poisoning import sanitize_ingest
from engines.memory.schema import (
    CONTROL_PRESENT,
    CONTROL_UNKNOWN,
    ITEM_ATTACK_PATH,
    ITEM_CONTROL,
    ITEM_DECISION,
    ITEM_EVIDENCE,
    ITEM_FINDING,
    ITEM_UNKNOWN,
    ITEM_VERIFICATION,
    LIFE_FALSE_POSITIVE,
    LIFE_NEW,
    UNKNOWN,
    VALIDITY_CURRENT,
    empty_snapshot,
)
from engines.memory.store import (
    load_ledger,
    resolve_memory_dir,
    save_ledger,
    write_snapshot,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_source_revision(
    revision: str | None = None,
    *,
    cwd: Path | str | None = None,
) -> str:
    """Return git HEAD when available; never invent — UNKNOWN on failure."""
    if revision is not None and str(revision).strip():
        return str(revision).strip()
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return UNKNOWN


def _try_security_twin(ag_or_audit: dict[str, Any]) -> Any:
    """Soft-optional twin: import engines.twin if source exists; else None."""
    try:
        import engines.twin as twin_mod  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        return None
    for attr in ("extract_twin_summary", "from_attack_graph", "summarize"):
        fn = getattr(twin_mod, attr, None)
        if callable(fn):
            try:
                return fn(ag_or_audit)
            except Exception:  # noqa: BLE001
                return None
    return None


def _ledger_entry(
    *,
    fingerprint: str,
    item_type: str,
    lifecycle: str | None = None,
    validity: str = VALIDITY_CURRENT,
    status: str | None = None,
    control_state: str | None = None,
    files: list[str] | None = None,
    snapshot_id: str | None = None,
    source_revision: str = UNKNOWN,
    related: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "fingerprint": fingerprint,
        "item_type": item_type,
        "lifecycle": lifecycle,
        "validity": validity,
        "status": status,
        "control_state": control_state,
        "files": list(files or []),
        "latest_snapshot_id": snapshot_id,
        "source_revision": source_revision,
        "updated_at": _utc_now_iso(),
        "related_fingerprints": list(related or []),
        "needs_reevaluation": False,
    }
    if extra:
        entry.update(extra)
    return entry


def _update_ledger_entry(
    ledger: dict[str, Any],
    fingerprint: str,
    new_entry: dict[str, Any],
) -> dict[str, Any]:
    """Immutable ledger update: return new ledger dict."""
    out = deepcopy(ledger)
    entries = dict(out.get("entries") or {})
    prev = entries.get(fingerprint) or {}
    merged = dict(prev)
    merged.update({k: v for k, v in new_entry.items() if v is not None})
    if prev:
        merged["prior_lifecycle"] = prev.get("lifecycle")
        merged["prior_status"] = prev.get("status")
        merged["prior_validity"] = prev.get("validity")
    entries[fingerprint] = merged
    out["entries"] = entries
    return out


def _add_relationship(
    ledger: dict[str, Any],
    *,
    src: str,
    dst: str,
    rel: str,
) -> dict[str, Any]:
    out = deepcopy(ledger)
    rels = list(out.get("relationships") or [])
    rec = {"from": src, "to": dst, "rel": rel}
    if rec not in rels:
        rels.append(rec)
    out["relationships"] = rels
    return out


def record_finding(
    finding: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    snapshot_id: str | None = None,
    ledger: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Record one finding summary; returns ``(summary, updated_ledger)``."""
    clean = sanitize_ingest(finding if isinstance(finding, dict) else {})
    fp = finding_fingerprint(clean)
    root = resolve_memory_dir(memory_dir)
    led = ledger if ledger is not None else load_ledger(root)
    prev = (led.get("entries") or {}).get(fp) or {}
    new_status = str(clean.get("status") or clean.get("lifecycle") or "UNVERIFIED")
    prev_status = prev.get("status") or prev.get("lifecycle")
    lifecycle, validity = transition_finding(prev_status, new_status)
    if prev_status is None and lifecycle == LIFE_NEW:
        pass

    loc = clean.get("location") if isinstance(clean.get("location"), dict) else {}
    file = str(
        loc.get("file")
        or clean.get("file")
        or (clean.get("root_cause") or {}).get("file")
        or UNKNOWN
    )
    summary = {
        "fingerprint": fp,
        "item_type": ITEM_FINDING,
        "lifecycle": lifecycle,
        "validity": validity,
        "status": new_status,
        "rule_id": clean.get("rule_id") or clean.get("id") or UNKNOWN,
        "severity": clean.get("severity") or UNKNOWN,
        "confidence": clean.get("confidence") or UNKNOWN,
        "file": file,
        "symbol": loc.get("symbol")
        or clean.get("symbol")
        or (clean.get("root_cause") or {}).get("symbol")
        or UNKNOWN,
        "line": loc.get("line") or clean.get("line"),
        "evidence_ids": list(clean.get("evidence_ids") or [])[:20],
        "source_revision": resolve_source_revision(revision),
    }
    led = _update_ledger_entry(
        led,
        fp,
        _ledger_entry(
            fingerprint=fp,
            item_type=ITEM_FINDING,
            lifecycle=lifecycle,
            validity=validity,
            status=new_status,
            files=[file] if file and file != UNKNOWN else [],
            snapshot_id=snapshot_id,
            source_revision=summary["source_revision"],
        ),
    )
    return summary, led


def record_control(
    control: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    snapshot_id: str | None = None,
    ledger: dict[str, Any] | None = None,
    related_path_fps: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    clean = sanitize_ingest(control if isinstance(control, dict) else {})
    fp = control_fingerprint(clean)
    root = resolve_memory_dir(memory_dir)
    led = ledger if ledger is not None else load_ledger(root)
    prev = (led.get("entries") or {}).get(fp) or {}
    state = CONTROL_PRESENT
    if prev and prev.get("control_state") and prev.get("effectiveness") != clean.get(
        "effectiveness"
    ):
        state = "CONTROL_CHANGED"
    if not clean.get("id") and not clean.get("name"):
        state = CONTROL_UNKNOWN

    file = str(clean.get("file") or UNKNOWN)
    summary = {
        "fingerprint": fp,
        "item_type": ITEM_CONTROL,
        "control_state": state,
        "validity": VALIDITY_CURRENT,
        "id": clean.get("id") or UNKNOWN,
        "name": clean.get("name") or clean.get("label") or UNKNOWN,
        "effectiveness": clean.get("effectiveness") or UNKNOWN,
        "file": file,
        "source_revision": resolve_source_revision(revision),
    }
    led = _update_ledger_entry(
        led,
        fp,
        _ledger_entry(
            fingerprint=fp,
            item_type=ITEM_CONTROL,
            validity=VALIDITY_CURRENT,
            control_state=state,
            files=[file] if file != UNKNOWN else [],
            snapshot_id=snapshot_id,
            source_revision=summary["source_revision"],
            related=related_path_fps,
            extra={"effectiveness": summary["effectiveness"]},
        ),
    )
    for pfp in related_path_fps or []:
        led = _add_relationship(led, src=fp, dst=pfp, rel="controls")
    return summary, led


def record_attack_path(
    path: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    snapshot_id: str | None = None,
    ledger: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    clean = sanitize_ingest(path if isinstance(path, dict) else {})
    fp = path_fingerprint(clean)
    root = resolve_memory_dir(memory_dir)
    led = ledger if ledger is not None else load_ledger(root)
    status = str(clean.get("status") or UNKNOWN)
    hops = list(clean.get("hops") or [])
    control_fps: list[str] = []
    for c in clean.get("controls_encountered") or []:
        if isinstance(c, dict):
            cfp = control_fingerprint(c)
            control_fps.append(cfp)
            led = _add_relationship(led, src=cfp, dst=fp, rel="controls")

    summary = {
        "fingerprint": fp,
        "item_type": ITEM_ATTACK_PATH,
        "validity": VALIDITY_CURRENT,
        "status": status,
        "hops": hops,
        "entry": clean.get("entry") or UNKNOWN,
        "target": clean.get("target") or UNKNOWN,
        "tags": list(clean.get("tags") or []),
        "control_fingerprints": control_fps,
        "source_revision": resolve_source_revision(revision),
    }
    # Infer files from hop labels when possible (entrypoint/file fragments)
    files = []
    for h in hops:
        if ":" in str(h) and "/" not in str(h):
            continue
        if ".py" in str(h) or ".js" in str(h) or ".ts" in str(h):
            files.append(str(h))
    led = _update_ledger_entry(
        led,
        fp,
        _ledger_entry(
            fingerprint=fp,
            item_type=ITEM_ATTACK_PATH,
            validity=VALIDITY_CURRENT,
            status=status,
            files=files,
            snapshot_id=snapshot_id,
            source_revision=summary["source_revision"],
            related=control_fps,
        ),
    )
    return summary, led


def record_verification(
    verification: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    snapshot_id: str | None = None,
    ledger: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    clean = sanitize_ingest(verification if isinstance(verification, dict) else {})
    # Prefer linking via finding fingerprint when present
    related_fp = clean.get("finding_fingerprint")
    if not related_fp and clean.get("finding"):
        related_fp = finding_fingerprint(clean["finding"])
    fp_seed = related_fp or evidence_fingerprint(clean) or "verification"
    from engines.memory.fingerprints import sha1_short

    fp = sha1_short(f"ver|{fp_seed}|{clean.get('status')}", prefix="mem.e.")
    root = resolve_memory_dir(memory_dir)
    led = ledger if ledger is not None else load_ledger(root)
    summary = {
        "fingerprint": fp,
        "item_type": ITEM_VERIFICATION,
        "validity": VALIDITY_CURRENT,
        "status": clean.get("status") or UNKNOWN,
        "finding_fingerprint": related_fp or UNKNOWN,
        "source_revision": resolve_source_revision(revision),
    }
    led = _update_ledger_entry(
        led,
        fp,
        _ledger_entry(
            fingerprint=fp,
            item_type=ITEM_VERIFICATION,
            validity=VALIDITY_CURRENT,
            status=summary["status"],
            snapshot_id=snapshot_id,
            source_revision=summary["source_revision"],
            related=[related_fp] if related_fp else [],
        ),
    )
    if related_fp:
        led = _add_relationship(led, src=fp, dst=related_fp, rel="verifies")
    return summary, led


def record_decision(
    decision: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    snapshot_id: str | None = None,
    ledger: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    clean = sanitize_ingest(decision if isinstance(decision, dict) else {})
    from engines.memory.fingerprints import sha1_short

    cited = list(clean.get("cited_controls") or clean.get("control_fingerprints") or [])
    finding_fp = clean.get("finding_fingerprint")
    if not finding_fp and clean.get("finding"):
        finding_fp = finding_fingerprint(clean["finding"])
    seed = f"dec|{finding_fp or ''}|{clean.get('outcome')}|{','.join(cited)}"
    fp = sha1_short(seed, prefix="mem.e.")
    root = resolve_memory_dir(memory_dir)
    led = ledger if ledger is not None else load_ledger(root)
    outcome = str(clean.get("outcome") or clean.get("status") or UNKNOWN)
    summary = {
        "fingerprint": fp,
        "item_type": ITEM_DECISION,
        "validity": VALIDITY_CURRENT,
        "outcome": outcome,
        "finding_fingerprint": finding_fp or UNKNOWN,
        "cited_controls": cited,
        "reason": clean.get("reason") or clean.get("reasoning") or UNKNOWN,
        "needs_reevaluation": bool(clean.get("needs_reevaluation")),
        "source_revision": resolve_source_revision(revision),
    }
    led = _update_ledger_entry(
        led,
        fp,
        _ledger_entry(
            fingerprint=fp,
            item_type=ITEM_DECISION,
            validity=VALIDITY_CURRENT,
            status=outcome,
            snapshot_id=snapshot_id,
            source_revision=summary["source_revision"],
            related=[*cited, *([finding_fp] if finding_fp else [])],
            extra={"needs_reevaluation": summary["needs_reevaluation"]},
        ),
    )
    for cfp in cited:
        led = _add_relationship(led, src=fp, dst=cfp, rel="cites_control")
    if finding_fp:
        led = _add_relationship(led, src=fp, dst=finding_fp, rel="decides")
    return summary, led


def _evidence_ref_summary(item: dict[str, Any], revision: str) -> dict[str, Any]:
    clean = sanitize_ingest(item)
    return {
        "fingerprint": evidence_fingerprint(clean),
        "item_type": ITEM_EVIDENCE,
        "validity": VALIDITY_CURRENT,
        "content_hash": clean.get("content_hash") or UNKNOWN,
        "file": clean.get("file") or UNKNOWN,
        "type": clean.get("type") or UNKNOWN,
        "source_revision": revision,
    }


def _snapshot_id_for(revision: str) -> str:
    ts = _utc_now_iso().replace(":", "").replace("-", "")
    short = (revision or UNKNOWN)[:12]
    return f"snap.{short}.{ts}"


def remember_from_attack_graph(
    ag_result: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Ingest an attack-graph result into project-local memory. Returns snapshot."""
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    rev = resolve_source_revision(
        revision,
        cwd=(ag_result.get("target") if isinstance(ag_result.get("target"), str) else None),
    )
    sid = _snapshot_id_for(rev)
    snap = empty_snapshot(
        snapshot_id=sid,
        source_revision=rev,
        target=str(ag_result.get("target") or UNKNOWN),
    )
    snap["provenance"] = {
        "ingest": "attack_graph",
        "git_revision": rev,
    }

    led = load_ledger(root)
    findings_out: list[dict[str, Any]] = []
    controls_out: list[dict[str, Any]] = []
    paths_out: list[dict[str, Any]] = []
    evidence_out: list[dict[str, Any]] = []
    decisions_out: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    # Paths + controls
    for path in ag_result.get("paths") or []:
        if not isinstance(path, dict):
            continue
        psum, led = record_attack_path(
            path, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
        )
        paths_out.append(psum)
        for c in path.get("controls_encountered") or []:
            if not isinstance(c, dict):
                continue
            csum, led = record_control(
                c,
                memory_dir=root,
                revision=rev,
                snapshot_id=sid,
                ledger=led,
                related_path_fps=[psum["fingerprint"]],
            )
            controls_out.append(csum)

    # Adversary findings via embedded evidence private ref or public adversary
    adversary = {}
    evidence = ag_result.get("_evidence") or {}
    if isinstance(evidence, dict):
        adversary = evidence.get("_adversary") or {}
    if not adversary and isinstance(ag_result.get("adversary"), dict):
        adversary = ag_result["adversary"]

    for finding in adversary.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        fsum, led = record_finding(
            finding, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
        )
        findings_out.append(fsum)
        # FP decisions that cite controls
        if str(finding.get("status")) == "FALSE_POSITIVE":
            cited = []
            for ce in finding.get("counter_evidence") or []:
                if isinstance(ce, dict) and (
                    ce.get("type") in {"control", "CONTROL", "authorization"}
                    or "control" in str(ce.get("description") or "").lower()
                ):
                    cited.append(control_fingerprint(ce))
            dsum, led = record_decision(
                {
                    "finding": finding,
                    "finding_fingerprint": fsum["fingerprint"],
                    "outcome": LIFE_FALSE_POSITIVE,
                    "cited_controls": cited,
                    "reason": finding.get("reasoning")
                    or "; ".join(finding.get("false_positive_reasons") or [])
                    or UNKNOWN,
                },
                memory_dir=root,
                revision=rev,
                snapshot_id=sid,
                ledger=led,
            )
            decisions_out.append(dsum)

        for eid in finding.get("evidence_ids") or []:
            evidence_out.append(
                {
                    "fingerprint": f"mem.e.ref.{eid}",
                    "item_type": ITEM_EVIDENCE,
                    "validity": VALIDITY_CURRENT,
                    "content_hash": str(eid),
                    "file": fsum.get("file") or UNKNOWN,
                    "type": "ref",
                    "source_revision": rev,
                }
            )

    # Graph-level control nodes
    for node in (ag_result.get("graph") or {}).get("nodes") or []:
        if isinstance(node, dict) and node.get("type") == "control":
            csum, led = record_control(
                node, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
            )
            controls_out.append(csum)

    twin = _try_security_twin(ag_result)
    if twin is not None:
        snap["security_twin"] = twin
    else:
        unknowns.append(
            {
                "item_type": ITEM_UNKNOWN,
                "topic": "security_twin",
                "detail": "engines.twin unavailable or soft-degraded",
                "validity": VALIDITY_CURRENT,
            }
        )

    # Dedupe control summaries by fingerprint
    seen_c: set[str] = set()
    controls_deduped = []
    for c in controls_out:
        if c["fingerprint"] in seen_c:
            continue
        seen_c.add(c["fingerprint"])
        controls_deduped.append(c)

    snap["findings"] = findings_out
    snap["controls"] = controls_deduped
    snap["attack_paths"] = paths_out
    snap["evidence_refs"] = evidence_out
    snap["decisions"] = decisions_out
    snap["unknowns"] = unknowns
    snap["summary"] = {
        "finding_count": len(findings_out),
        "control_count": len(controls_deduped),
        "path_count": len(paths_out),
        "evidence_ref_count": len(evidence_out),
        "unknown_count": len(unknowns),
        "decision_count": len(decisions_out),
        "by_lifecycle": _count_by(findings_out, "lifecycle"),
        "by_validity": _count_by(findings_out, "validity"),
    }

    write_snapshot(snap, root)
    save_ledger(led, root)
    return snap


def remember_from_audit(
    result: dict[str, Any],
    *,
    memory_dir: Path | str | None = None,
    revision: str | None = None,
    state_path: Path | str | None = None,
) -> dict[str, Any]:
    """Ingest a full audit result (findings + adversary + attack_graph + evidence)."""
    root = resolve_memory_dir(memory_dir, state_path=state_path)
    rev = resolve_source_revision(revision, cwd=result.get("target"))
    sid = _snapshot_id_for(rev)
    snap = empty_snapshot(
        snapshot_id=sid,
        source_revision=rev,
        target=str(result.get("target") or UNKNOWN),
    )
    snap["provenance"] = {"ingest": "audit", "git_revision": rev}

    led = load_ledger(root)
    findings_out: list[dict[str, Any]] = []
    controls_out: list[dict[str, Any]] = []
    paths_out: list[dict[str, Any]] = []
    evidence_out: list[dict[str, Any]] = []
    verifications_out: list[dict[str, Any]] = []
    decisions_out: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    # Prefer adversary findings when present; else raw scan findings
    adversary = result.get("adversary") or {}
    adv_findings = adversary.get("findings") if isinstance(adversary, dict) else None
    raw_findings = adv_findings if adv_findings else (result.get("findings") or [])

    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        fsum, led = record_finding(
            finding, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
        )
        findings_out.append(fsum)
        if str(finding.get("status")) == "FALSE_POSITIVE":
            dsum, led = record_decision(
                {
                    "finding": finding,
                    "finding_fingerprint": fsum["fingerprint"],
                    "outcome": LIFE_FALSE_POSITIVE,
                    "reason": finding.get("reasoning") or UNKNOWN,
                },
                memory_dir=root,
                revision=rev,
                snapshot_id=sid,
                ledger=led,
            )
            decisions_out.append(dsum)

    ag = result.get("attack_graph") or {}
    if isinstance(ag, dict) and ag.get("paths"):
        for path in ag.get("paths") or []:
            if not isinstance(path, dict):
                continue
            psum, led = record_attack_path(
                path, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
            )
            paths_out.append(psum)
            for c in path.get("controls_encountered") or []:
                if isinstance(c, dict):
                    csum, led = record_control(
                        c,
                        memory_dir=root,
                        revision=rev,
                        snapshot_id=sid,
                        ledger=led,
                        related_path_fps=[psum["fingerprint"]],
                    )
                    controls_out.append(csum)

    evidence = result.get("evidence") or {}
    if isinstance(evidence, dict):
        for item in evidence.get("items") or evidence.get("evidence") or []:
            if isinstance(item, dict):
                evidence_out.append(_evidence_ref_summary(item, rev))

    verification = result.get("verification") or {}
    if isinstance(verification, dict):
        for v in verification.get("judgments") or verification.get("results") or []:
            if isinstance(v, dict):
                vsum, led = record_verification(
                    v, memory_dir=root, revision=rev, snapshot_id=sid, ledger=led
                )
                verifications_out.append(vsum)

    twin = _try_security_twin(result)
    if twin is not None:
        snap["security_twin"] = twin
    else:
        unknowns.append(
            {
                "item_type": ITEM_UNKNOWN,
                "topic": "security_twin",
                "detail": "engines.twin unavailable or soft-degraded",
                "validity": VALIDITY_CURRENT,
            }
        )

    seen_c: set[str] = set()
    controls_deduped = []
    for c in controls_out:
        if c["fingerprint"] in seen_c:
            continue
        seen_c.add(c["fingerprint"])
        controls_deduped.append(c)

    snap["findings"] = findings_out
    snap["controls"] = controls_deduped
    snap["attack_paths"] = paths_out
    snap["evidence_refs"] = evidence_out
    snap["verifications"] = verifications_out
    snap["decisions"] = decisions_out
    snap["unknowns"] = unknowns
    snap["summary"] = {
        "finding_count": len(findings_out),
        "control_count": len(controls_deduped),
        "path_count": len(paths_out),
        "evidence_ref_count": len(evidence_out),
        "unknown_count": len(unknowns),
        "by_lifecycle": _count_by(findings_out, "lifecycle"),
        "by_validity": _count_by(findings_out, "validity"),
    }

    write_snapshot(snap, root)
    save_ledger(led, root)
    return snap


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for it in items:
        k = str(it.get(key) or UNKNOWN)
        counts[k] = counts.get(k, 0) + 1
    return counts
