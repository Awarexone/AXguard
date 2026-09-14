"""Merge duplicate candidates by root cause / sink location."""

from __future__ import annotations

from typing import Any


def merge_key(candidate: dict[str, Any]) -> tuple[str, str, int, str]:
    """Root-cause key: vuln type + sink file/line (+ symbol when present)."""
    loc = candidate.get("location") or {}
    sink = candidate.get("sink") or {}
    file_s = str(loc.get("file") or sink.get("file") or "")
    line = int(loc.get("line") or sink.get("line") or 0)
    symbol = str(sink.get("symbol") or sink.get("id") or "")
    vtype = str(candidate.get("vulnerability_type") or "")
    return (vtype, file_s, line, symbol)


def merge_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collapse duplicates that share vuln type + sink location.

    Prefer candidates with taint_path / higher confidence; union evidence.
    """
    buckets: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    order: list[tuple[str, str, int, str]] = []

    conf_rank = {"confirmed": 3, "likely": 2, "unknown": 1}

    for cand in candidates:
        key = merge_key(cand)
        if key not in buckets:
            buckets[key] = _clone(cand)
            order.append(key)
            continue

        existing = buckets[key]
        # Prefer richer data_flow
        if not (existing.get("data_flow") or {}).get("path_id") and (
            cand.get("data_flow") or {}
        ).get("path_id"):
            existing["data_flow"] = dict(cand.get("data_flow") or {})
            existing["source"] = dict(cand.get("source") or existing.get("source") or {})
            existing["controls"] = list(
                cand.get("controls") or existing.get("controls") or []
            )
            existing["reasoning"] = cand.get("reasoning") or existing.get("reasoning")

        # Confidence: take max
        e_conf = str(existing.get("confidence") or "unknown")
        c_conf = str(cand.get("confidence") or "unknown")
        if conf_rank.get(c_conf, 0) > conf_rank.get(e_conf, 0):
            existing["confidence"] = c_conf

        # Union evidence by (type, file, line, reason)
        seen = {
            (
                str(e.get("type") or ""),
                str(e.get("file") or ""),
                int(e.get("line") or 0),
                str(e.get("reason") or ""),
            )
            for e in (existing.get("evidence") or [])
        }
        for e in cand.get("evidence") or []:
            sig = (
                str(e.get("type") or ""),
                str(e.get("file") or ""),
                int(e.get("line") or 0),
                str(e.get("reason") or ""),
            )
            if sig not in seen:
                existing.setdefault("evidence", []).append(e)
                seen.add(sig)

        # Union unknowns / assumptions
        existing["unknowns"] = _uniq_str(
            list(existing.get("unknowns") or []) + list(cand.get("unknowns") or [])
        )
        existing["assumptions"] = _uniq_str(
            list(existing.get("assumptions") or [])
            + list(cand.get("assumptions") or [])
        )

        # Track hunters that contributed
        hunters = []
        for h in (existing.get("hunter"), cand.get("hunter")):
            if h and h not in hunters:
                hunters.append(h)
        if len(hunters) > 1:
            existing["hunter"] = ",".join(hunters)
        elif hunters:
            existing["hunter"] = hunters[0]

    return [buckets[k] for k in order]


def _clone(cand: dict[str, Any]) -> dict[str, Any]:
    return {
        **cand,
        "source": dict(cand.get("source") or {}),
        "sink": dict(cand.get("sink") or {}),
        "data_flow": dict(cand.get("data_flow") or {}),
        "location": dict(cand.get("location") or {}),
        "evidence": list(cand.get("evidence") or []),
        "controls": list(cand.get("controls") or []),
        "assumptions": list(cand.get("assumptions") or []),
        "unknowns": list(cand.get("unknowns") or []),
    }


def _uniq_str(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        s = str(x)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out
