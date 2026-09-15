"""Deterministic fingerprints for Security Memory ledger keys."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from engines.attack_graph.diff import _path_signature


def sha1_short(payload: str, *, prefix: str, n: int = 12) -> str:
    """Deterministic short sha1 id with a ``mem.*`` prefix."""
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:n]
    return f"{prefix}{digest}"


# Back-compat private alias
_sha1_short = sha1_short


def _norm_path(file: str | None) -> str:
    raw = str(file or "").strip().replace("\\", "/")
    if not raw or raw.upper() == "UNKNOWN":
        return "UNKNOWN"
    # Drop leading ./ and collapse duplicate slashes
    raw = re.sub(r"^\./+", "", raw)
    raw = re.sub(r"/+", "/", raw)
    return raw.lower()


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _finding_rule_class(finding: dict[str, Any]) -> str:
    for key in ("rule_id", "id", "vuln_class", "type", "kind", "category"):
        v = finding.get(key)
        if v:
            s = str(v)
            # Prefer rule-ish ids (secrets.x / sql.y) over opaque adv.* ids when
            # a better field exists; still fall through if only id present.
            if key == "id" and s.startswith("adv."):
                continue
            return s
    # adversary findings often encode class in evidence_summary / root_cause
    root = finding.get("root_cause") or {}
    if isinstance(root, dict) and root.get("kind"):
        return str(root.get("kind"))
    status_hint = finding.get("from_judgment_id") or finding.get("prior_judge_status")
    if status_hint:
        return str(status_hint).split(".")[0]
    return "UNKNOWN"


def _finding_location(finding: dict[str, Any]) -> tuple[str, str, int]:
    loc = finding.get("location") or {}
    if not isinstance(loc, dict):
        loc = {}
    file = _norm_path(
        loc.get("file")
        or finding.get("file")
        or (finding.get("sink") or {}).get("file")
        or (finding.get("root_cause") or {}).get("file")
    )
    symbol = _as_str(
        loc.get("symbol")
        or finding.get("function")
        or finding.get("symbol")
        or (finding.get("root_cause") or {}).get("symbol")
        or (finding.get("sink") or {}).get("symbol")
    )
    line_raw = (
        loc.get("line")
        or finding.get("line")
        or (finding.get("root_cause") or {}).get("line")
        or (finding.get("sink") or {}).get("line")
        or 0
    )
    try:
        line = int(line_raw or 0)
    except (TypeError, ValueError):
        line = 0
    return file, symbol, line


def _sink_hints(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    sink = finding.get("sink")
    if isinstance(sink, dict):
        for k in ("type", "kind", "name", "symbol"):
            if sink.get(k):
                parts.append(str(sink[k]))
    for key in ("sink_type", "sink_kind", "affected_paths"):
        v = finding.get(key)
        if isinstance(v, list):
            parts.extend(str(x) for x in v[:3])
        elif v:
            parts.append(str(v))
    root = finding.get("root_cause")
    if isinstance(root, dict) and root.get("kind"):
        parts.append(str(root["kind"]))
    return "|".join(parts) if parts else "UNKNOWN"


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Hash of (rule/vuln class, normalized file, symbol, sink hints).

    Line number is secondary — included but never the sole identity key.
    """
    rule = _finding_rule_class(finding)
    file, symbol, line = _finding_location(finding)
    sinks = _sink_hints(finding)
    primary = f"{rule}|{file}|{symbol or 'UNKNOWN'}|{sinks}"
    secondary = f"|line:{line}"
    return _sha1_short(primary + secondary, prefix="mem.f.")


def path_fingerprint(path: dict[str, Any]) -> str:
    """Reuse hop-tuple identity from ``engines.attack_graph.diff``."""
    sig = _path_signature(path if isinstance(path, dict) else {})
    payload = "|".join(sig) if sig else "UNKNOWN"
    return _sha1_short(payload, prefix="mem.p.")


def control_fingerprint(control: dict[str, Any]) -> str:
    """Stable id for a control node / encounter record."""
    cid = _as_str(control.get("id") or control.get("control_id"))
    name = _as_str(control.get("name") or control.get("label") or control.get("type"))
    file = _norm_path(control.get("file") or control.get("path"))
    effectiveness = _as_str(control.get("effectiveness") or "UNKNOWN")
    # Identity excludes volatile effectiveness so weaken/strengthen shares the key;
    # effectiveness is stored as ledger state, not fingerprint material for name/id.
    primary = f"{cid or name or 'UNKNOWN'}|{file}"
    _ = effectiveness  # documented: not part of identity
    return _sha1_short(primary, prefix="mem.c.")


def evidence_fingerprint(item: dict[str, Any]) -> str:
    """Prefer existing content_hash; otherwise hash stable location fields."""
    existing = item.get("content_hash") or item.get("id")
    if existing and str(existing).startswith("ev."):
        return _sha1_short(str(existing), prefix="mem.e.")
    if item.get("content_hash"):
        return _sha1_short(str(item["content_hash"]), prefix="mem.e.")
    payload = "|".join(
        [
            _as_str(item.get("type")),
            _norm_path(item.get("file")),
            _as_str(item.get("symbol")),
            _as_str(item.get("line_start") or item.get("line") or 0),
            _as_str(item.get("description"))[:200],
        ]
    )
    return _sha1_short(payload, prefix="mem.e.")
