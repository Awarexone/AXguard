"""Thin explanation templates over structured Security Memory fields.

Never invents history — templates only reference keys present on the item.
"""

from __future__ import annotations

from typing import Any

from engines.memory.schema import UNKNOWN


def explain_finding(item: dict[str, Any]) -> str:
    fp = item.get("fingerprint") or UNKNOWN
    life = item.get("lifecycle") or UNKNOWN
    status = item.get("status") or UNKNOWN
    file = item.get("file") or UNKNOWN
    rev = item.get("source_revision") or UNKNOWN
    return (
        f"Finding `{fp}` lifecycle={life} status={status} "
        f"file=`{file}` revision=`{rev}`."
    )


def explain_path(item: dict[str, Any]) -> str:
    fp = item.get("fingerprint") or UNKNOWN
    status = item.get("status") or UNKNOWN
    hops = item.get("hops") or []
    hop_s = " → ".join(str(h) for h in hops[:8]) if hops else UNKNOWN
    return f"Attack path `{fp}` status={status} hops={hop_s}."


def explain_control(item: dict[str, Any]) -> str:
    fp = item.get("fingerprint") or UNKNOWN
    state = item.get("control_state") or UNKNOWN
    eff = item.get("effectiveness") or UNKNOWN
    return f"Control `{fp}` state={state} effectiveness={eff}."


def explain_regression(item: dict[str, Any]) -> str:
    kind = item.get("kind") or UNKNOWN
    fp = item.get("fingerprint") or UNKNOWN
    outcome = item.get("outcome") or UNKNOWN
    prior = item.get("prior_status")
    status = item.get("status")
    extra = ""
    if prior is not None or status is not None:
        extra = f" {prior or UNKNOWN} → {status or UNKNOWN}"
    return f"Regression ({kind}) `{fp}` outcome={outcome}.{extra}".strip()


def explain_item(item: dict[str, Any]) -> str:
    itype = str(item.get("item_type") or item.get("kind") or "").upper()
    if itype in {"FINDING", ""} and item.get("lifecycle"):
        return explain_finding(item)
    if itype in {"ATTACK_PATH"} or item.get("hops") is not None:
        return explain_path(item)
    if itype in {"CONTROL"} or item.get("control_state"):
        return explain_control(item)
    if item.get("outcome") == "REGRESSED" or itype == "REGRESSION":
        return explain_regression(item)
    return f"Memory item `{item.get('fingerprint') or UNKNOWN}` type={itype or UNKNOWN}."
