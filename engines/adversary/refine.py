"""Refine findings: severity/confidence, narrow paths, root cause."""

from __future__ import annotations

import hashlib
from typing import Any

from engines.adversary.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    FP_CONTRADICTORY_EVIDENCE,
    FP_DATA_FLOW_NOT_CONFIRMED,
    FP_INSUFFICIENT_EVIDENCE,
    FP_SOURCE_NOT_CONTROLLED,
    FP_TRUSTED_INPUT,
    FP_UNREACHABLE_CODE,
    JUDGE_TO_START,
    SEVERITY_RANK,
    STATUS_CONFIRMED,
    STATUS_FALSE_POSITIVE,
    STATUS_LIKELY,
    STATUS_REQUIRES_REVIEW,
    STATUS_UNVERIFIED,
)


def finding_id(judgment: dict[str, Any], candidate: dict[str, Any] | None) -> str:
    cid = str(
        (candidate or {}).get("id")
        or judgment.get("candidate_id")
        or judgment.get("id")
        or "unknown"
    )
    digest = hashlib.sha1(cid.encode("utf-8")).hexdigest()[:10]
    return f"adv.{digest}"


def map_judge_status(judge_status: str) -> str:
    return JUDGE_TO_START.get(str(judge_status), STATUS_UNVERIFIED)


def downgrade_severity(severity: str | None, steps: int = 1) -> str:
    """Lower severity by ``steps`` levels; never invent higher."""
    sev = str(severity or "medium").lower()
    rank = SEVERITY_RANK.get(sev, 2)
    new_rank = max(0, rank - max(0, steps))
    inv = {v: k for k, v in SEVERITY_RANK.items()}
    return inv.get(new_rank, "info")


def refine_confidence(
    *,
    status: str,
    prior: str | None,
    control_effectiveness: str,
) -> str:
    if status == STATUS_FALSE_POSITIVE:
        return CONFIDENCE_LIKELY
    if status == STATUS_CONFIRMED:
        return CONFIDENCE_CONFIRMED
    if status == STATUS_LIKELY:
        return CONFIDENCE_LIKELY
    if status in {STATUS_UNVERIFIED, STATUS_REQUIRES_REVIEW}:
        if control_effectiveness in {"likely", "confirmed"}:
            return CONFIDENCE_LIKELY
        return CONFIDENCE_UNKNOWN
    return str(prior or CONFIDENCE_UNKNOWN)


def decide_outcome(
    *,
    judge_status: str,
    challenges: dict[str, str],
    control_report: dict[str, Any],
    counter_hits: list[dict[str, Any]],
    light: bool = False,
) -> tuple[str, list[str], str]:
    """
    Return (status, fp_reasons, reasoning).

    Prefer UNVERIFIED / REQUIRES_REVIEW over inventing SAFE.
    Protect true positives: no FP from name-only sanitize/validate.
    """
    fp_reasons: list[str] = []
    start = map_judge_status(judge_status)
    eff = str(control_report.get("effectiveness") or "unknown")
    bypass = str(control_report.get("bypassable") or "unknown")
    name_only = bool(control_report.get("name_only_control"))
    surviving = bool(control_report.get("surviving_risk", True))
    ctrl_fps = list(control_report.get("fp_reasons") or [])

    # Dead / unreachable
    if challenges.get("unreachable_or_dead") == "yes":
        fp_reasons.append(FP_UNREACHABLE_CODE)
        return (
            STATUS_FALSE_POSITIVE,
            fp_reasons,
            "Counter-evidence suggests unreachable or dead code path.",
        )

    # Trusted / not attacker-controlled with supporting evidence
    if challenges.get("attacker_controlled") == "no":
        fp_reasons.append(FP_SOURCE_NOT_CONTROLLED)
        fp_reasons.append(FP_TRUSTED_INPUT)
        return (
            STATUS_FALSE_POSITIVE,
            fp_reasons,
            "Source does not appear attacker-controlled.",
        )

    # Dataflow not confirmed on a light/UNVERIFIED challenge
    if challenges.get("taint_reaches_sink") == "no":
        fp_reasons.append(FP_DATA_FLOW_NOT_CONFIRMED)
        if light or start == STATUS_UNVERIFIED:
            return (
                STATUS_UNVERIFIED,
                fp_reasons + [FP_INSUFFICIENT_EVIDENCE],
                "No confirmed taint reachability — prefer UNVERIFIED.",
            )

    # Effective control, not bypassable → FALSE_POSITIVE
    if eff == "confirmed" and bypass == "no" and not surviving and not name_only:
        fp_reasons.extend(ctrl_fps or [FP_CONTRADICTORY_EVIDENCE])
        return (
            STATUS_FALSE_POSITIVE,
            _uniq(fp_reasons),
            "Effective control with no clear bypass — finding disproved.",
        )

    # Control exists but bypass unclear → REQUIRES_REVIEW or keep LIKELY
    if eff in {"confirmed", "likely"} and bypass in {"unclear", "unknown"}:
        fp_reasons.extend(ctrl_fps)
        if start == STATUS_CONFIRMED:
            return (
                STATUS_LIKELY,
                _uniq(fp_reasons),
                "Control present but bypass unclear — downgraded to LIKELY.",
            )
        if start == STATUS_LIKELY:
            return (
                STATUS_REQUIRES_REVIEW,
                _uniq(fp_reasons + [FP_INSUFFICIENT_EVIDENCE]),
                "Partial/unclear control effectiveness — REQUIRES_REVIEW.",
            )
        return (
            STATUS_REQUIRES_REVIEW,
            _uniq(fp_reasons + [FP_INSUFFICIENT_EVIDENCE]),
            "Ambiguous control — REQUIRES_REVIEW.",
        )

    if eff == "likely" and bypass == "no" and not name_only:
        fp_reasons.extend(ctrl_fps)
        return (
            STATUS_REQUIRES_REVIEW if start != STATUS_CONFIRMED else STATUS_LIKELY,
            _uniq(fp_reasons),
            "Likely-effective control — prefer review over inventing SAFE.",
        )

    # If control analysis says ineffective / bypassable, protect true positives:
    # do not REQUIRES_REVIEW solely because weak/distant counter-hits exist.
    if eff == "ineffective" or (surviving and bypass == "yes"):
        if start == STATUS_CONFIRMED or judge_status == "VERIFIED":
            return (
                STATUS_CONFIRMED,
                [],
                "Control ineffective or bypassable — CONFIRMED (true-positive protected).",
            )
        if start == STATUS_LIKELY or judge_status == "LIKELY":
            return (
                STATUS_LIKELY,
                [],
                "Control ineffective or bypassable — keep LIKELY.",
            )

    # Contradictory confirmed counter-evidence without clear effectiveness
    strong = [
        h
        for h in counter_hits
        if h.get("strength") == "confirmed"
        and h.get("kind")
        not in {"ignored_comment", "name_only_control"}
        and h.get("kind")
        in {
            "parameterization",
            "allowlist",
            "path_jail",
            "sanitization",
            "validation",
        }
    ]
    if strong and surviving and eff in {"likely", "confirmed"}:
        fp_reasons.append(FP_CONTRADICTORY_EVIDENCE)
        return (
            STATUS_REQUIRES_REVIEW,
            _uniq(fp_reasons),
            "Confirmed counter-evidence conflicts with surviving risk — REQUIRES_REVIEW.",
        )

    # No disproving counter-evidence → preserve / promote
    real_hits = [
        h
        for h in counter_hits
        if h.get("kind") not in {"ignored_comment", "name_only_control"}
    ]
    if not real_hits or (eff in {"unknown", "ineffective"} and surviving):
        if start == STATUS_CONFIRMED or judge_status == "VERIFIED":
            return (
                STATUS_CONFIRMED,
                [],
                "No disproving counter-evidence — CONFIRMED from VERIFIED.",
            )
        if start == STATUS_LIKELY or judge_status == "LIKELY":
            return (
                STATUS_LIKELY,
                [],
                "No disproving counter-evidence — keep LIKELY.",
            )
        if light:
            return (
                STATUS_UNVERIFIED,
                [FP_INSUFFICIENT_EVIDENCE],
                "Light challenge on UNVERIFIED — still insufficient evidence.",
            )
        return (
            STATUS_UNVERIFIED,
            [FP_INSUFFICIENT_EVIDENCE],
            "Insufficient evidence to confirm or disprove.",
        )

    # Default: do not invent SAFE
    if start == STATUS_CONFIRMED:
        return STATUS_CONFIRMED, [], "Survived adversarial challenge."
    if start == STATUS_LIKELY:
        return STATUS_LIKELY, [], "Survived adversarial challenge as LIKELY."
    return (
        STATUS_UNVERIFIED,
        [FP_INSUFFICIENT_EVIDENCE],
        "Uncertainty remains — UNVERIFIED.",
    )


def attach_root_cause(
    finding: dict[str, Any],
    candidate: dict[str, Any] | None,
    *,
    siblings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Attach root_cause / affected_paths when a shared sink helper is visible.

    Never invents a root cause without evidence from candidate sink/source.
    """
    cand = candidate or {}
    sink = cand.get("sink") or {}
    symbol = str(sink.get("symbol") or sink.get("name") or "")
    file_s = str(sink.get("file") or (cand.get("location") or {}).get("file") or "")
    path_id = str((cand.get("data_flow") or {}).get("path_id") or "")

    affected = list(finding.get("affected_paths") or [])
    if path_id and path_id not in affected:
        affected.append(path_id)
    loc = cand.get("location") or {}
    loc_key = f"{loc.get('file')}:{loc.get('line')}"
    if loc.get("file") and loc_key not in affected:
        affected.append(loc_key)

    root = None
    if symbol and file_s:
        root = {
            "kind": "sink_helper",
            "symbol": symbol,
            "file": file_s,
            "line": sink.get("line"),
            "reason": "Shared sink symbol from Phase 2/3 candidate",
        }
    elif file_s:
        root = {
            "kind": "sink_location",
            "file": file_s,
            "line": sink.get("line") or loc.get("line"),
            "reason": "Sink location from candidate",
        }

    # Link siblings that share the same sink symbol/file
    if siblings and root and symbol:
        for sib in siblings:
            if sib.get("id") == finding.get("id"):
                continue
            # siblings are findings; match via surviving_evidence file hints
            for path in sib.get("affected_paths") or []:
                if file_s and file_s in str(path) and path not in affected:
                    affected.append(path)

    finding["root_cause"] = root
    finding["affected_paths"] = affected
    return finding


def surviving_evidence_from(
    judgment: dict[str, Any],
    candidate: dict[str, Any] | None,
    counter_hits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Evidence that still supports the finding after challenge."""
    out: list[dict[str, Any]] = []
    for ev in list(judgment.get("evidence") or []) + list(
        (candidate or {}).get("evidence") or []
    ):
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("type") or "")
        # Drop strong FP evidence types from surviving set
        if et in {
            "parameterization",
            "allowlist",
            "sanitization",
            "validation",
            "contradiction",
            "comment_or_fixture",
        }:
            continue
        out.append(dict(ev))
    # If we have confirmed counter-evidence that killed the finding, surviving may be empty
    _ = counter_hits
    return out[:40]


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out
