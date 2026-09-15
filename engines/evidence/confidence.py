"""Confidence engine.

Produces an explainable ``VERY_HIGH / HIGH / MEDIUM / LOW / UNKNOWN`` confidence
for each finding from its supporting and counter evidence. Design rules:

* Unknowns **pull down** the final confidence.
* A single HIGH component must **not** hide a critical UNKNOWN (source, flow,
  sink, reachability). Any critical unknown caps the result at MEDIUM and demotes
  it further per missing critical component.
* Effective controls / strong counter-evidence demote confidence in a vuln.
* Confidence never exceeds what the adversary status supports (no invented HIGH).
"""

from __future__ import annotations

from typing import Any

from engines.evidence.schema import (
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    CONF_UNKNOWN,
    CONF_VERY_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_RANK,
    EV_AUTHORIZATION,
    EV_CONFIGURATION,
    EV_DATA_FLOW,
    EV_FRAMEWORK_BEHAVIOR,
    EV_REACHABILITY,
    EV_SANITIZATION,
    EV_SECURITY_CONTROL,
    EV_SINK,
    EV_SOURCE,
    EV_VALIDATION,
    QUALITY_MODERATE,
    QUALITY_RANK,
    QUALITY_STRONG,
    QUALITY_WEAK,
    REL_COUNTER,
    STATUS_CONFIDENCE_ANCHOR,
)

_STRONG_COUNTER_KINDS = frozenset(
    {"parameterization", "allowlist", "path_jail", "sanitization", "validation"}
)


def _idx(level: str) -> int:
    return CONFIDENCE_RANK.get(str(level), 0)


def _level(idx: int) -> str:
    idx = max(0, min(idx, len(CONFIDENCE_LEVELS) - 1))
    return CONFIDENCE_LEVELS[idx]


def _quality_to_level(quality: str) -> str:
    rank = QUALITY_RANK.get(str(quality), 0)
    if rank >= QUALITY_RANK[QUALITY_STRONG]:
        return CONF_HIGH
    if rank >= QUALITY_RANK[QUALITY_MODERATE]:
        return CONF_MEDIUM
    if rank >= QUALITY_RANK[QUALITY_WEAK]:
        return CONF_LOW
    return CONF_UNKNOWN


def _best_supporting(refs: list[dict[str, Any]], etype: str) -> dict[str, Any] | None:
    best = None
    best_rank = -1
    for r in refs:
        if str(r.get("type")) != etype:
            continue
        if str(r.get("relationship")) == REL_COUNTER:
            continue
        rank = QUALITY_RANK.get(str(r.get("quality")), 0)
        if rank > best_rank:
            best, best_rank = r, rank
    return best


def compute_confidence(
    finding: dict[str, Any],
    evidence_refs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute the confidence result for one finding.

    ``evidence_refs`` are resolved evidence items (with ``type``, ``quality``,
    ``relationship``, ``kind``, ``name_only``).
    """
    status = str(finding.get("status") or "UNVERIFIED")
    components: dict[str, dict[str, str]] = {}
    reasons: list[str] = []
    unknowns: list[str] = []

    # --- critical components -------------------------------------------
    def critical(name: str, etype: str, label: str) -> str:
        ref = _best_supporting(evidence_refs, etype)
        if ref is None:
            level = CONF_UNKNOWN
            reason = f"no {label} evidence"
        else:
            level = _quality_to_level(str(ref.get("quality")))
            reason = f"{label} quality={ref.get('quality')}"
        components[name] = {"level": level, "reason": reason}
        if level == CONF_UNKNOWN:
            unknowns.append(f"{name}: {reason}")
        return level

    src = critical("source_certainty", EV_SOURCE, "source")
    flow = critical("data_flow_certainty", EV_DATA_FLOW, "data-flow")
    sink = critical("sink_certainty", EV_SINK, "sink")
    reach = critical("reachability", EV_REACHABILITY, "reachability")
    critical_levels = {
        "source_certainty": src,
        "data_flow_certainty": flow,
        "sink_certainty": sink,
        "reachability": reach,
    }

    # --- security control presence / effectiveness ---------------------
    control_refs = [
        r
        for r in evidence_refs
        if str(r.get("type"))
        in {EV_SECURITY_CONTROL, EV_VALIDATION, EV_SANITIZATION, EV_AUTHORIZATION}
    ]
    if control_refs:
        best_ctrl = max(control_refs, key=lambda r: QUALITY_RANK.get(str(r.get("quality")), 0))
        components["security_control_certainty"] = {
            "level": _quality_to_level(str(best_ctrl.get("quality"))),
            "reason": f"{len(control_refs)} control-related item(s)",
        }
    else:
        components["security_control_certainty"] = {
            "level": CONF_UNKNOWN,
            "reason": "no security control observed",
        }

    ca = finding.get("control_analysis") or {}
    eff = str(ca.get("effectiveness") or "unknown")
    eff_level = {
        "confirmed": CONF_HIGH,
        "likely": CONF_MEDIUM,
        "ineffective": CONF_LOW,
    }.get(eff, CONF_UNKNOWN)
    components["control_effectiveness"] = {
        "level": eff_level,
        "reason": f"control effectiveness={eff}",
    }

    # --- framework / configuration -------------------------------------
    fw = _best_supporting_any(evidence_refs, EV_FRAMEWORK_BEHAVIOR)
    components["framework_certainty"] = {
        "level": _quality_to_level(fw) if fw else CONF_UNKNOWN,
        "reason": "framework protection evidence" if fw else "no framework evidence",
    }
    cfg = _best_supporting_any(evidence_refs, EV_CONFIGURATION)
    components["configuration_certainty"] = {
        "level": _quality_to_level(cfg) if cfg else CONF_UNKNOWN,
        "reason": "configuration evidence" if cfg else "no configuration evidence",
    }

    # --- counter-evidence ----------------------------------------------
    counter = [
        r
        for r in evidence_refs
        if str(r.get("relationship")) == REL_COUNTER and not r.get("name_only")
    ]
    strong_counter = [
        r for r in counter if str(r.get("kind")) in _STRONG_COUNTER_KINDS
        and QUALITY_RANK.get(str(r.get("quality")), 0) >= QUALITY_RANK[QUALITY_STRONG]
    ]
    components["counter_evidence"] = {
        "level": CONF_HIGH if strong_counter else (CONF_MEDIUM if counter else CONF_UNKNOWN),
        "reason": f"{len(counter)} counter item(s), {len(strong_counter)} strong",
    }

    # --- name-only controls flagged as unknowns (must not boost) --------
    if any(r.get("name_only") for r in evidence_refs):
        unknowns.append("name-only control present (not proof of safety)")

    # --- aggregate ------------------------------------------------------
    anchor = STATUS_CONFIDENCE_ANCHOR.get(status, CONF_UNKNOWN)
    final_idx = _idx(anchor)
    reasons.append(f"anchor={anchor} from status={status}")

    critical_unknowns = [n for n, lv in critical_levels.items() if lv == CONF_UNKNOWN]

    # Promotion to VERY_HIGH only when everything critical is HIGH & clean.
    if (
        anchor == CONF_HIGH
        and all(lv == CONF_HIGH for lv in critical_levels.values())
        and not counter
        and not critical_unknowns
    ):
        final_idx = _idx(CONF_VERY_HIGH)
        reasons.append("all critical components HIGH with no counter-evidence → VERY_HIGH")

    # Effective control demotes vuln confidence (unless adversary CONFIRMED it).
    if eff == "confirmed" and status != "CONFIRMED":
        final_idx = min(final_idx, _idx(CONF_LOW))
        reasons.append("confirmed effective control → capped LOW")

    if strong_counter and status in {"REQUIRES_REVIEW", "UNVERIFIED", "FALSE_POSITIVE"}:
        final_idx = min(final_idx, _idx(CONF_LOW))
        reasons.append("strong counter-evidence on non-confirmed finding → capped LOW")

    # Unknown handling: a critical UNKNOWN caps at MEDIUM and demotes per gap.
    if critical_unknowns:
        final_idx = min(final_idx, _idx(CONF_MEDIUM))
        final_idx = max(_idx(CONF_UNKNOWN), final_idx - (len(critical_unknowns) - 1))
        reasons.append(
            "critical unknown(s) "
            f"{critical_unknowns} → capped MEDIUM and demoted"
        )

    if status == "FALSE_POSITIVE":
        final_idx = min(final_idx, _idx(CONF_LOW))
        reasons.append("FALSE_POSITIVE → low confidence this is a real vuln")

    final = _level(final_idx)

    return {
        "level": final,
        "score": round(final_idx / (len(CONFIDENCE_LEVELS) - 1), 3),
        "anchor": anchor,
        "components": components,
        "reasons": reasons,
        "unknowns": unknowns,
        "critical_unknowns": critical_unknowns,
        "counter_evidence_count": len(counter),
        "strong_counter_evidence_count": len(strong_counter),
        "capped_by_unknown": bool(critical_unknowns),
        "propagated": False,
    }


def _best_supporting_any(refs: list[dict[str, Any]], etype: str) -> str | None:
    best = None
    best_rank = -1
    for r in refs:
        if str(r.get("type")) != etype:
            continue
        rank = QUALITY_RANK.get(str(r.get("quality")), 0)
        if rank > best_rank:
            best, best_rank = str(r.get("quality")), rank
    return best


def propagate_confidence(
    entries: list[dict[str, Any]],
    store: Any,
) -> None:
    """Propagate shared-evidence uncertainty across findings.

    When two findings share a supporting critical evidence item that is **stale**
    (content hash changed) or has UNKNOWN quality, the uncertainty propagates:
    every finding relying on that item is demoted one level and records the
    shared unknown. This mutates each entry's ``evidence_confidence`` in place.
    """
    # Map evidence id → entries that reference it as supporting.
    ref_map: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        for eid in entry.get("supporting_evidence_ids") or []:
            ref_map.setdefault(str(eid), []).append(entry)

    for eid, referencing in ref_map.items():
        if len(referencing) < 2:
            continue
        item = store.get(eid) if hasattr(store, "get") else None
        if item is None:
            continue
        stale = store.is_stale(eid) if hasattr(store, "is_stale") else False
        weak = QUALITY_RANK.get(str(item.get("quality")), 0) <= QUALITY_RANK[QUALITY_WEAK]
        if not (stale or weak):
            continue
        note = f"shared {'stale' if stale else 'weak'} evidence {eid}"
        for entry in referencing:
            conf = entry.get("evidence_confidence") or {}
            if note in (conf.get("unknowns") or []):
                continue
            conf.setdefault("unknowns", []).append(note)
            conf.setdefault("reasons", []).append(f"propagation: {note}")
            new_idx = max(_idx(CONF_UNKNOWN), _idx(str(conf.get("level"))) - 1)
            conf["level"] = _level(new_idx)
            conf["score"] = round(new_idx / (len(CONFIDENCE_LEVELS) - 1), 3)
            conf["propagated"] = True
            entry["confidence_level"] = conf["level"]
