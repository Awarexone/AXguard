"""SecurityHunter protocol and CandidateFinding builder."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from engines.verify.evidence import make_evidence
from engines.verify.schema import (
    CANDIDATE_STATUS,
    CONFIDENCE_UNKNOWN,
    DEFAULT_SEVERITY,
    EV_PATTERN_ONLY,
    EV_SINK_MATCH,
    EV_SOURCE_MATCH,
    EV_TAINT_PATH,
)


@runtime_checkable
class SecurityHunter(Protocol):
    """Hunter emits candidates only — never auto-VERIFIED judgments."""

    name: str
    vulnerability_type: str

    def hunt(
        self,
        target: Path,
        *,
        application_model: dict[str, Any],
        dataflow: dict[str, Any],
    ) -> list[dict[str, Any]]:
        ...


def candidate_id(
    vulnerability_type: str,
    file: str,
    line: int | None,
    sink_symbol: str | None = None,
) -> str:
    raw = f"{vulnerability_type}|{file}|{line or 0}|{sink_symbol or ''}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"cand.{vulnerability_type}.{digest}"


def build_candidate(
    *,
    vulnerability_type: str,
    title: str,
    severity: str | None = None,
    source: dict[str, Any] | None = None,
    sink: dict[str, Any] | None = None,
    data_flow: dict[str, Any] | None = None,
    location: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    confidence: str = CONFIDENCE_UNKNOWN,
    reasoning: str = "",
    controls: list[Any] | None = None,
    assumptions: list[str] | None = None,
    unknowns: list[str] | None = None,
    hunter: str | None = None,
) -> dict[str, Any]:
    """
    Build a candidate finding.

    Always ``status=candidate``. Never invent VERIFIED.
    """
    sink = dict(sink or {})
    source = dict(source or {})
    loc = dict(location or {})
    if not loc:
        loc = {
            "file": sink.get("file") or source.get("file") or "",
            "line": sink.get("line") or source.get("line") or 0,
        }

    cid = candidate_id(
        vulnerability_type,
        str(loc.get("file") or ""),
        int(loc.get("line") or 0) if loc.get("line") is not None else None,
        str(sink.get("symbol") or sink.get("id") or "") or None,
    )

    return {
        "id": cid,
        "vulnerability_type": vulnerability_type,
        "title": title,
        "severity": severity or DEFAULT_SEVERITY.get(vulnerability_type, "medium"),
        "status": CANDIDATE_STATUS,
        "source": source,
        "sink": sink,
        "data_flow": dict(data_flow or {}),
        "location": loc,
        "evidence": list(evidence or []),
        "confidence": confidence,
        "reasoning": reasoning,
        "controls": list(controls or []),
        "assumptions": list(assumptions or []),
        "unknowns": list(unknowns or []),
        "hunter": hunter or "",
    }


def candidate_from_taint_path(
    path: dict[str, Any],
    *,
    vulnerability_type: str,
    title: str,
    hunter: str,
    severity: str | None = None,
) -> dict[str, Any]:
    """Promote a Phase 2 taint path into a weak/strong candidate (still not VERIFIED)."""
    src = path.get("source") or {}
    sink = path.get("sink") or {}
    taint_state = str(path.get("taint_state") or "UNKNOWN")
    path_conf = str(path.get("confidence") or CONFIDENCE_UNKNOWN)

    evidence = [
        make_evidence(
            EV_TAINT_PATH,
            file=str(sink.get("file") or src.get("file") or ""),
            line=int(sink.get("line") or 0) or None,
            symbol=str(sink.get("symbol") or ""),
            reason=f"Taint path {path.get('id')} state={taint_state} confidence={path_conf}",
        ),
        make_evidence(
            EV_SOURCE_MATCH,
            file=str(src.get("file") or ""),
            line=int(src.get("line") or 0) or None,
            symbol=str(src.get("name") or ""),
            reason=f"Source kind={src.get('kind')} trust={src.get('trust_level')}",
        ),
        make_evidence(
            EV_SINK_MATCH,
            file=str(sink.get("file") or ""),
            line=int(sink.get("line") or 0) or None,
            symbol=str(sink.get("symbol") or ""),
            reason=f"Sink type={sink.get('type')}",
        ),
    ]
    # Carry path evidence snippets if present (already redacted upstream)
    for ev in path.get("evidence") or []:
        if isinstance(ev, dict):
            evidence.append(
                make_evidence(
                    EV_TAINT_PATH,
                    file=ev.get("file"),
                    line=ev.get("line"),
                    symbol=ev.get("symbol"),
                    reason=str(ev.get("reason") or "path evidence"),
                    snippet=ev.get("snippet"),
                    weight=10,
                )
            )

    unknowns: list[str] = []
    assumptions: list[str] = [
        "Intraprocedural taint only; interprocedural reachability unknown",
    ]
    if path_conf == CONFIDENCE_UNKNOWN:
        unknowns.append("Path confidence is unknown")
    if taint_state == "UNKNOWN":
        unknowns.append("Taint state unresolved")

    # Hunter confidence mirrors path confidence, never upgrades to confirmed alone
    conf = path_conf if path_conf in {"confirmed", "likely", "unknown"} else CONFIDENCE_UNKNOWN
    if conf == "confirmed":
        # Prefer likely at hunter stage — Judge decides VERIFIED
        conf = "likely"

    return build_candidate(
        vulnerability_type=vulnerability_type,
        title=title,
        severity=severity,
        source=dict(src),
        sink=dict(sink),
        data_flow={
            "path_id": path.get("id"),
            "taint_state": taint_state,
            "controls_seen": list(path.get("controls_seen") or []),
            "steps": list(path.get("steps") or []),
            "confidence": path_conf,
        },
        location={
            "file": sink.get("file") or src.get("file") or "",
            "line": sink.get("line") or 0,
        },
        evidence=evidence,
        confidence=conf,
        reasoning=(
            f"Hunter saw taint path to {sink.get('type')} sink "
            f"with taint_state={taint_state}."
        ),
        controls=list(path.get("controls_seen") or []),
        assumptions=assumptions,
        unknowns=unknowns,
        hunter=hunter,
    )


def weak_candidate_from_sink(
    sink: dict[str, Any],
    *,
    vulnerability_type: str,
    title: str,
    hunter: str,
    severity: str | None = None,
    reason: str = "Pattern/sink inventory only — no confirmed dataflow link",
) -> dict[str, Any]:
    """App-model / regex sink without taint path → confidence unknown."""
    evidence = [
        make_evidence(
            EV_PATTERN_ONLY,
            file=str(sink.get("file") or ""),
            line=int(sink.get("line") or 0) or None,
            symbol=str(sink.get("symbol") or ""),
            reason=reason,
        ),
        make_evidence(
            EV_SINK_MATCH,
            file=str(sink.get("file") or ""),
            line=int(sink.get("line") or 0) or None,
            symbol=str(sink.get("symbol") or ""),
            reason=f"Sink type={sink.get('type')}",
        ),
    ]
    return build_candidate(
        vulnerability_type=vulnerability_type,
        title=title,
        severity=severity,
        source={},
        sink=dict(sink),
        data_flow={},
        location={
            "file": sink.get("file") or "",
            "line": sink.get("line") or 0,
        },
        evidence=evidence,
        confidence=CONFIDENCE_UNKNOWN,
        reasoning=reason,
        controls=[],
        assumptions=["No Phase 2 taint path linked this sink"],
        unknowns=["Missing source→sink dataflow link", "Attacker control unproven"],
        hunter=hunter,
    )
