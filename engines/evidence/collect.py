"""Collect evidence for a finding from adversary + verification + dataflow + app model.

Reuses the models already computed by earlier phases — it does **not** rebuild
call/dataflow graphs. Never invents locations: when a location is unknown it is
recorded as ``UNKNOWN`` and the evidence quality reflects that. Repository
comments (adversary ``ignored_comment`` hits) are never turned into evidence of
safety.
"""

from __future__ import annotations

from typing import Any

from engines.evidence.quality import score_quality
from engines.evidence.schema import (
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    CONF_UNKNOWN,
    EV_AUTHORIZATION,
    EV_CODE_PATTERN,
    EV_CONFIGURATION,
    EV_DATA_FLOW,
    EV_FRAMEWORK_BEHAVIOR,
    EV_REACHABILITY,
    EV_SECURITY_CONTROL,
    EV_SANITIZATION,
    EV_SINK,
    EV_SOURCE,
    EV_TRUST_BOUNDARY,
    EV_VALIDATION,
    PROV_CONFIGURATION,
    PROV_FRAMEWORK_KNOWLEDGE,
    PROV_SOURCE_CODE,
    PROV_STATIC_ANALYSIS,
    QUALITY_MODERATE,
    QUALITY_RANK,
    QUALITY_STRONG,
    QUALITY_WEAK,
    REL_COUNTER,
    REL_SUPPORTING,
    evidence_item,
)

# adversary counter-evidence kind → (evidence type, provenance)
_KIND_MAP: dict[str, tuple[str, str]] = {
    "parameterization": (EV_SECURITY_CONTROL, PROV_SOURCE_CODE),
    "allowlist": (EV_VALIDATION, PROV_SOURCE_CODE),
    "path_jail": (EV_SECURITY_CONTROL, PROV_SOURCE_CODE),
    "sanitization": (EV_SANITIZATION, PROV_SOURCE_CODE),
    "validation": (EV_VALIDATION, PROV_SOURCE_CODE),
    "authorization": (EV_AUTHORIZATION, PROV_SOURCE_CODE),
    "authentication": (EV_AUTHORIZATION, PROV_SOURCE_CODE),
    "tenant_isolation": (EV_AUTHORIZATION, PROV_SOURCE_CODE),
    "framework": (EV_FRAMEWORK_BEHAVIOR, PROV_FRAMEWORK_KNOWLEDGE),
    "configuration": (EV_CONFIGURATION, PROV_CONFIGURATION),
    "dead_code": (EV_REACHABILITY, PROV_STATIC_ANALYSIS),
    "csrf": (EV_SECURITY_CONTROL, PROV_SOURCE_CODE),
    "cors": (EV_SECURITY_CONTROL, PROV_SOURCE_CODE),
    "control": (EV_SECURITY_CONTROL, PROV_STATIC_ANALYSIS),
}

# Kinds that are never evidence of *safety* (comments) — dropped entirely.
_NEVER_EVIDENCE = frozenset({"ignored_comment"})


def _conf_from_quality(quality: str) -> str:
    rank = QUALITY_RANK.get(str(quality), 0)
    if rank >= QUALITY_RANK[QUALITY_STRONG]:
        return CONF_HIGH
    if rank >= QUALITY_RANK[QUALITY_MODERATE]:
        return CONF_MEDIUM
    if rank >= QUALITY_RANK[QUALITY_WEAK]:
        return CONF_LOW
    return CONF_UNKNOWN


def _trust_quality(trust: str) -> tuple[str, str]:
    """Return (quality, human note) for a source trust level."""
    t = str(trust or "").lower()
    if t == "untrusted":
        return QUALITY_STRONG, "untrusted (attacker-controlled) source"
    if t == "semi_trusted":
        return QUALITY_MODERATE, "semi-trusted source"
    if t == "trusted":
        return QUALITY_WEAK, "trusted source (unlikely attacker-controlled)"
    return "UNKNOWN", "source trust level unknown"


def collect_evidence(
    finding: dict[str, Any],
    *,
    candidate: dict[str, Any] | None,
    dataflow: dict[str, Any] | None = None,
    application_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return a list of (unstored) evidence items for a single finding."""
    cand = candidate or {}
    items: list[dict[str, Any]] = []

    _collect_source(items, finding, cand)
    _collect_sink(items, finding, cand)
    _collect_dataflow(items, finding, cand, dataflow)
    _collect_reachability(items, finding, cand)
    _collect_surviving(items, finding)
    _collect_control_analysis(items, finding)
    _collect_counter(items, finding)

    return items


def _tag(item: dict[str, Any], kind: str, *, name_only: bool = False) -> dict[str, Any]:
    item["kind"] = kind
    if name_only:
        item["name_only"] = True
    return item


def _collect_source(items: list, finding: dict, cand: dict) -> None:
    src = cand.get("source") or {}
    if not src:
        # No source in scope — explicit unknown, never fabricated.
        item = evidence_item(
            type=EV_SOURCE,
            description="No attacker-controlled source resolved in scope",
            relationship=REL_SUPPORTING,
            quality="UNKNOWN",
            confidence=CONF_UNKNOWN,
            provenance=PROV_STATIC_ANALYSIS,
            source="collect",
        )
        items.append(_tag(item, "source_unknown"))
        return
    trust = str(src.get("trust_level") or "")
    quality, note = _trust_quality(trust)
    located = bool(src.get("file"))
    q = score_quality(
        {"type": EV_SOURCE, "provenance": PROV_SOURCE_CODE,
         "file": src.get("file"), "line_start": src.get("line")},
        direct_observation=located,
    )
    q = q if QUALITY_RANK.get(q, 0) >= QUALITY_RANK.get(quality, 0) else quality
    if quality == "UNKNOWN":
        q = "UNKNOWN"
    item = evidence_item(
        type=EV_SOURCE,
        description=f"Source `{src.get('name') or 'input'}` — {note}",
        relationship=REL_SUPPORTING,
        file=src.get("file"),
        line_start=src.get("line"),
        symbol=src.get("name"),
        quality=q,
        confidence=_conf_from_quality(q),
        provenance=PROV_SOURCE_CODE,
        source="collect",
    )
    items.append(_tag(item, "source"))

    # Trust boundary as a distinct signal
    tb = evidence_item(
        type=EV_TRUST_BOUNDARY,
        description=f"Trust boundary crossed: {note}",
        relationship=REL_SUPPORTING,
        file=src.get("file"),
        line_start=src.get("line"),
        symbol=src.get("name"),
        quality=quality,
        confidence=_conf_from_quality(quality),
        provenance=PROV_STATIC_ANALYSIS,
        source="collect",
    )
    items.append(_tag(tb, "trust_boundary"))


def _collect_sink(items: list, finding: dict, cand: dict) -> None:
    sink = cand.get("sink") or {}
    loc = finding.get("location") or {}
    file = sink.get("file") or loc.get("file")
    line = sink.get("line") or loc.get("line")
    symbol = sink.get("symbol")
    stype = sink.get("type")
    if not (file or symbol or stype):
        item = evidence_item(
            type=EV_SINK,
            description="Dangerous sink location unknown",
            relationship=REL_SUPPORTING,
            quality="UNKNOWN",
            confidence=CONF_UNKNOWN,
            provenance=PROV_STATIC_ANALYSIS,
            source="collect",
        )
        items.append(_tag(item, "sink_unknown"))
        return
    q = score_quality(
        {"type": EV_SINK, "provenance": PROV_SOURCE_CODE,
         "file": file, "line_start": line},
        direct_observation=bool(file and line),
    )
    item = evidence_item(
        type=EV_SINK,
        description=f"Dangerous sink type=`{stype or 'unknown'}` symbol=`{symbol or 'unknown'}`",
        relationship=REL_SUPPORTING,
        file=file,
        line_start=line,
        symbol=symbol,
        quality=q,
        confidence=_conf_from_quality(q),
        provenance=PROV_SOURCE_CODE,
        source="collect",
    )
    items.append(_tag(item, "sink"))


def _collect_dataflow(items: list, finding: dict, cand: dict, dataflow: dict | None) -> None:
    df = cand.get("data_flow") or {}
    path_id = df.get("path_id")
    if not path_id:
        item = evidence_item(
            type=EV_DATA_FLOW,
            description="No confirmed source→sink taint path linked",
            relationship=REL_SUPPORTING,
            quality="UNKNOWN",
            confidence=CONF_UNKNOWN,
            provenance=PROV_STATIC_ANALYSIS,
            source="collect",
        )
        items.append(_tag(item, "dataflow_unknown"))
        return
    path_conf = str(df.get("confidence") or "unknown")
    taint_state = str(df.get("taint_state") or "UNKNOWN")
    quality = {
        "confirmed": QUALITY_STRONG,
        "likely": QUALITY_MODERATE,
    }.get(path_conf, QUALITY_WEAK)
    if taint_state == "UNKNOWN":
        quality = QUALITY_WEAK
    sink = cand.get("sink") or {}
    item = evidence_item(
        type=EV_DATA_FLOW,
        description=(
            f"Taint path `{path_id}` taint_state={taint_state} confidence={path_conf}"
        ),
        relationship=REL_SUPPORTING,
        file=sink.get("file") or (cand.get("location") or {}).get("file"),
        line_start=sink.get("line"),
        symbol=sink.get("symbol"),
        quality=quality,
        confidence=_conf_from_quality(quality),
        provenance=PROV_STATIC_ANALYSIS,
        source="collect",
    )
    items.append(_tag(item, "data_flow"))


def _collect_reachability(items: list, finding: dict, cand: dict) -> None:
    challenges = finding.get("challenges") or {}
    reaches = str(challenges.get("taint_reaches_sink") or "")
    sink_reach = str(challenges.get("sink_reachable") or "")
    df = cand.get("data_flow") or {}
    has_path = bool(df.get("path_id"))
    if reaches == "yes" and has_path:
        quality, desc, conf = QUALITY_STRONG, "Tainted value reaches sink along a resolved path", CONF_HIGH
    elif reaches in {"partial"} or (has_path and reaches != "no"):
        quality, desc, conf = QUALITY_MODERATE, "Partial reachability — path present, full reach unconfirmed", CONF_MEDIUM
    elif reaches == "no":
        quality, desc, conf = QUALITY_WEAK, "Taint does not appear to reach the sink", CONF_LOW
    else:
        quality, desc, conf = "UNKNOWN", "Reachability of sink is unknown", CONF_UNKNOWN
    sink = cand.get("sink") or {}
    item = evidence_item(
        type=EV_REACHABILITY,
        description=desc,
        relationship=REL_SUPPORTING,
        file=sink.get("file") or (finding.get("location") or {}).get("file"),
        line_start=sink.get("line") or (finding.get("location") or {}).get("line"),
        quality=quality,
        confidence=conf,
        provenance=PROV_STATIC_ANALYSIS,
        source="collect",
    )
    _ = sink_reach
    items.append(_tag(item, "reachability"))


def _collect_surviving(items: list, finding: dict) -> None:
    for ev in finding.get("surviving_evidence") or []:
        if not isinstance(ev, dict):
            continue
        snippet = ev.get("snippet")
        reason = str(ev.get("reason") or ev.get("type") or "supporting code pattern")
        file = ev.get("file")
        line = ev.get("line")
        q = score_quality(
            {"type": EV_CODE_PATTERN, "provenance": PROV_SOURCE_CODE,
             "file": file, "line_start": line},
        )
        item = evidence_item(
            type=EV_CODE_PATTERN,
            description=f"Surviving evidence: {reason}",
            relationship=REL_SUPPORTING,
            file=file,
            line_start=line,
            symbol=ev.get("symbol"),
            quality=q,
            confidence=_conf_from_quality(q),
            provenance=PROV_SOURCE_CODE,
            source="adversary.surviving",
            snippet=snippet,
        )
        items.append(_tag(item, "surviving"))


def _collect_control_analysis(items: list, finding: dict) -> None:
    ca = finding.get("control_analysis") or {}
    if not ca:
        return
    eff = str(ca.get("effectiveness") or "unknown")
    name_only = bool(ca.get("name_only_control"))
    if eff == "ineffective":
        # An ineffective control supports the finding (won't stop the attack).
        item = evidence_item(
            type=EV_SECURITY_CONTROL,
            description="Nearby control analysed as ineffective / bypassable",
            relationship=REL_SUPPORTING,
            quality=QUALITY_MODERATE,
            confidence=CONF_MEDIUM,
            provenance=PROV_STATIC_ANALYSIS,
            source="adversary.control",
        )
        items.append(_tag(item, "control_ineffective"))
    if name_only:
        item = evidence_item(
            type=EV_CODE_PATTERN,
            description="Name-only control (e.g. `sanitize()`) — proves nothing on its own",
            relationship=REL_COUNTER,
            quality=QUALITY_WEAK,
            confidence=CONF_LOW,
            provenance=PROV_SOURCE_CODE,
            source="adversary.control",
        )
        items.append(_tag(item, "name_only_control", name_only=True))


def _collect_counter(items: list, finding: dict) -> None:
    for hit in finding.get("counter_evidence") or []:
        if not isinstance(hit, dict):
            continue
        kind = str(hit.get("kind") or "")
        if kind in _NEVER_EVIDENCE:
            continue  # comments are never evidence of safety
        strength = str(hit.get("strength") or "weak")
        ev = hit.get("evidence") or {}
        name_only = kind == "name_only_control"
        etype, provenance = _KIND_MAP.get(kind, (EV_CODE_PATTERN, PROV_STATIC_ANALYSIS))
        if name_only:
            etype, provenance = EV_CODE_PATTERN, PROV_SOURCE_CODE
        q = score_quality(
            {"type": etype, "provenance": provenance,
             "file": ev.get("file"), "line_start": ev.get("line")},
            strength=strength,
            name_only=name_only,
        )
        item = evidence_item(
            type=etype,
            description=str(ev.get("reason") or f"counter-evidence: {kind}"),
            relationship=REL_COUNTER,
            file=ev.get("file"),
            line_start=ev.get("line"),
            symbol=ev.get("symbol") or kind,
            quality=q,
            confidence=_conf_from_quality(q),
            provenance=provenance,
            source=f"adversary.counter.{hit.get('source') or 'scan'}",
            snippet=ev.get("snippet"),
        )
        items.append(_tag(item, kind or "counter", name_only=name_only))
