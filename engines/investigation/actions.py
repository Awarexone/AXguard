"""Action registry and symbolic executors over existing AXGuard artifacts.

Actions inspect candidate + context (adversary, dataflow, AG, twin, memory).
They never exploit, network, or execute repository code.
"""

from __future__ import annotations

from typing import Any, Callable

from engines.investigation.schema import (
    ACTION_ANALYZE_GIT_CHANGE,
    ACTION_BUILD_ATTACK_PATH,
    ACTION_CHECK_AGENT_PERMISSION,
    ACTION_CHECK_ALTERNATE_PATH,
    ACTION_CHECK_AUTHENTICATION,
    ACTION_CHECK_AUTHORIZATION,
    ACTION_CHECK_CONFIGURATION,
    ACTION_CHECK_DEPENDENCY,
    ACTION_CHECK_FRAMEWORK_BEHAVIOR,
    ACTION_CHECK_IDENTITY_PROPAGATION,
    ACTION_CHECK_MCP_TRUST,
    ACTION_CHECK_PARAMETERIZATION,
    ACTION_CHECK_REACHABILITY,
    ACTION_CHECK_SANITIZATION,
    ACTION_CHECK_SECURITY_MEMORY,
    ACTION_CHECK_TENANT_ISOLATION,
    ACTION_CHECK_TOOL_PERMISSION,
    ACTION_CHECK_TRUST_BOUNDARY,
    ACTION_CHECK_VALIDATION,
    ACTION_COMPARE_SECURITY_TWIN,
    ACTION_SEARCH_COUNTER_EVIDENCE,
    ACTION_TRACE_CALLEES,
    ACTION_TRACE_CALLERS,
    ACTION_TRACE_DATA_FLOW,
    COST_HIGH,
    COST_LOW,
    COST_MEDIUM,
    COST_VERY_HIGH,
    UNKNOWN,
    empty_action,
    empty_evidence_item,
)

ActionHandler = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any]]


def _text_blob(candidate: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "vulnerability_type",
        "status",
        "reasoning",
        "message",
        "title",
        "id",
    ):
        if candidate.get(key):
            parts.append(str(candidate[key]))
    for key in ("false_positive_reasons", "fp_reasons"):
        for item in candidate.get(key) or []:
            parts.append(str(item))
    for ev in candidate.get("surviving_evidence") or []:
        if isinstance(ev, dict):
            parts.append(str(ev.get("reason") or ev.get("type") or ""))
        else:
            parts.append(str(ev))
    for ev in candidate.get("counter_evidence") or []:
        if isinstance(ev, dict):
            parts.append(str(ev.get("description") or ev.get("type") or ""))
        else:
            parts.append(str(ev))
    return " ".join(parts).lower()


def _has_any(blob: str, *needles: str) -> bool:
    return any(n in blob for n in needles)


def _result(
    *,
    answered: list[tuple[str, str, Any]],
    evidence: list[dict[str, Any]],
    counter: list[dict[str, Any]] | None = None,
    unknowns: list[str] | None = None,
    controls: list[dict[str, Any]] | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "answered_questions": [
            {"question_id": q, "status": st, "answer": ans} for q, st, ans in answered
        ],
        "evidence": evidence,
        "counter_evidence": list(counter or []),
        "unknowns": list(unknowns or []),
        "controls": list(controls or []),
        "attack_paths": list(attack_paths or []),
        "notes": notes,
    }


def _exec_trace_data_flow(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = action
    blob = _text_blob(candidate)
    evidence: list[dict[str, Any]] = []
    answered: list[tuple[str, str, Any]] = []
    surviving = candidate.get("surviving_evidence") or []
    taint_hits = [
        e
        for e in surviving
        if isinstance(e, dict)
        and str(e.get("type", "")).lower() in {"taint_path", "data_flow", "source_match"}
    ]
    df = ctx.get("dataflow") or {}
    if taint_hits:
        for e in taint_hits[:3]:
            evidence.append(
                empty_evidence_item(
                    kind="DATA_FLOW",
                    summary=str(e.get("reason") or e.get("type")),
                    strength="DATA_FLOW",
                    supports="hypothesis",
                    source="adversary.surviving_evidence",
                    refs={"file": e.get("file"), "line": e.get("line")},
                )
            )
        state = "UNKNOWN"
        for e in taint_hits:
            reason = str(e.get("reason") or "").lower()
            if "sanitized" in reason or "parameterized" in reason:
                state = "SANITIZED"
                break
            if "taint" in reason or "reaches" in reason:
                state = "TAINTED"
        answered.append(
            (
                "Q_DATA_REACHES_SINK",
                "ANSWERED",
                "yes" if state != "SANITIZED" else "mitigated_or_sanitized",
            )
        )
        if _has_any(blob, "untrusted", "request", "user", "attacker"):
            answered.append(("Q_SOURCE_CONTROLLED", "ANSWERED", "likely_yes"))
            evidence.append(
                empty_evidence_item(
                    kind="SOURCE",
                    summary="Untrusted / attacker-influenced source indicated in evidence",
                    strength="DATA_FLOW",
                    supports="hypothesis",
                    source="adversary",
                )
            )
        if state == "SANITIZED":
            return _result(
                answered=answered
                + [("Q_CONTROL_PRESENT", "ANSWERED", "sanitizer_or_parameterization")],
                evidence=evidence,
                counter=[
                    empty_evidence_item(
                        kind="SANITIZER",
                        summary="Taint path marked SANITIZED / parameterized",
                        strength="SECURITY_CONTROL",
                        supports="counter",
                        source="dataflow",
                    )
                ],
                notes="data flow present but sanitized",
            )
        return _result(answered=answered, evidence=evidence, notes="taint evidence present")

    if df.get("summary") or df.get("flows"):
        answered.append(("Q_DATA_REACHES_SINK", "UNKNOWN", UNKNOWN))
        return _result(
            answered=answered,
            evidence=[],
            unknowns=["dataflow_present_but_no_candidate_taint_link"],
            notes="dataflow context available without direct candidate link",
        )

    answered.append(("Q_DATA_REACHES_SINK", "UNKNOWN", UNKNOWN))
    return _result(
        answered=answered,
        evidence=[],
        unknowns=["no_taint_evidence_for_candidate"],
        notes="no data-flow evidence",
    )


def _exec_counter_evidence(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = action, ctx
    blob = _text_blob(candidate)
    counter: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    answered: list[tuple[str, str, Any]] = []

    fp_reasons = list(candidate.get("false_positive_reasons") or [])
    for reason in fp_reasons:
        counter.append(
            empty_evidence_item(
                kind="FP_REASON",
                summary=str(reason),
                strength="SECURITY_CONTROL",
                supports="counter",
                source="adversary.false_positive_reasons",
            )
        )
        controls.append({"name": str(reason), "source": "fp_reason"})

    for ev in candidate.get("counter_evidence") or []:
        if isinstance(ev, dict):
            counter.append(
                empty_evidence_item(
                    kind=str(ev.get("type") or "COUNTER"),
                    summary=str(ev.get("description") or ev.get("name") or ev.get("type")),
                    strength="SECURITY_CONTROL",
                    supports="counter",
                    source="adversary.counter_evidence",
                    refs={"id": ev.get("id"), "file": ev.get("file")},
                )
            )
            controls.append(ev)

    # Heuristic safe patterns (deterministic keyword scan of structured fields only)
    patterns = [
        ("parameterized", "CHECK_PARAMETERIZATION", "parameterized_or_bound_args"),
        ("prepared statement", "CHECK_PARAMETERIZATION", "prepared_statement"),
        ("allowlist", "CHECK_VALIDATION", "destination_allowlist"),
        ("whitelist", "CHECK_VALIDATION", "destination_allowlist"),
        ("ownership", "CHECK_AUTHORIZATION", "ownership_check"),
        ("tenant", "CHECK_TENANT_ISOLATION", "tenant_check"),
        ("shell=false", "CHECK_SANITIZATION", "safe_command_execution"),
        ("array of args", "CHECK_SANITIZATION", "safe_command_execution"),
        ("html escape", "CHECK_SANITIZATION", "output_encoding"),
        ("autoescape", "CHECK_FRAMEWORK_BEHAVIOR", "template_autoescape"),
    ]
    for needle, _action, label in patterns:
        if needle in blob:
            counter.append(
                empty_evidence_item(
                    kind=label.upper(),
                    summary=f"Structured fields indicate {label}",
                    strength="SECURITY_CONTROL",
                    supports="counter",
                    source="heuristic_structured_scan",
                )
            )
            controls.append({"name": label, "matched": needle})

    if counter:
        answered.append(("Q_CONTROL_PRESENT", "ANSWERED", "counter_evidence_found"))
        answered.append(("Q_CONTRADICTIONS", "ANSWERED", "hypothesis_challenged"))
        return _result(
            answered=answered,
            evidence=[],
            counter=counter,
            controls=controls,
            notes="counter-evidence located",
        )

    answered.append(("Q_CONTROL_PRESENT", "UNKNOWN", UNKNOWN))
    answered.append(("Q_CONTRADICTIONS", "ANSWERED", "none_found_yet"))
    return _result(
        answered=answered,
        evidence=[],
        unknowns=["no_counter_evidence_located"],
        notes="no counter-evidence",
    )


def _exec_authz(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    blob = _text_blob(candidate)
    atype = action.get("type")
    if atype == ACTION_CHECK_TENANT_ISOLATION:
        qid = "Q_TENANT"
        if _has_any(blob, "tenant", "org_id", "workspace_id", "cross-tenant"):
            if _has_any(blob, "missing", "absent", "not propagated", "without"):
                return _result(
                    answered=[(qid, "ANSWERED", "tenant_isolation_absent")],
                    evidence=[
                        empty_evidence_item(
                            kind="TENANT",
                            summary="Tenant isolation appears absent on path",
                            strength="STATIC_INFERENCE",
                            supports="hypothesis",
                            source="candidate_fields",
                        )
                    ],
                )
            return _result(
                answered=[(qid, "ANSWERED", "tenant_signals_present")],
                evidence=[],
                counter=[
                    empty_evidence_item(
                        kind="TENANT",
                        summary="Tenant-related control language present",
                        strength="STATIC_INFERENCE",
                        supports="counter",
                        source="candidate_fields",
                    )
                ],
            )
        return _result(
            answered=[(qid, "UNKNOWN", UNKNOWN)],
            evidence=[],
            unknowns=["tenant_isolation_not_observable_in_artifacts"],
        )

    qid = "Q_AUTHZ"
    if _has_any(blob, "authorization", "authz", "ownership", "middleware", "rbac", "policy"):
        if _has_any(blob, "missing", "absent", "bypass", "without"):
            return _result(
                answered=[(qid, "ANSWERED", "authorization_gap")],
                evidence=[
                    empty_evidence_item(
                        kind="AUTHZ",
                        summary="Authorization gap indicated",
                        strength="STATIC_INFERENCE",
                        supports="hypothesis",
                        source="candidate_fields",
                    )
                ],
            )
        return _result(
            answered=[(qid, "ANSWERED", "authorization_signals_present")],
            evidence=[],
            counter=[
                empty_evidence_item(
                    kind="AUTHZ",
                    summary="Authorization / ownership / middleware indicated",
                    strength="SECURITY_CONTROL",
                    supports="counter",
                    source="candidate_fields",
                )
            ],
            controls=[{"name": "authorization_signal"}],
        )

    # Soft look at attack-graph controls
    ag = ctx.get("attack_graph") or {}
    paths = ag.get("paths") or []
    for p in paths[:20]:
        controls = p.get("controls_encountered") or []
        if controls:
            return _result(
                answered=[(qid, "ANSWERED", "controls_on_attack_paths")],
                evidence=[],
                counter=[
                    empty_evidence_item(
                        kind="AUTHZ",
                        summary="Attack-graph path encounters controls",
                        strength="CONTROL_FLOW",
                        supports="counter",
                        source="attack_graph",
                    )
                ],
                controls=list(controls)[:5],
            )

    return _result(
        answered=[(qid, "UNKNOWN", UNKNOWN)],
        evidence=[],
        unknowns=["authorization_not_observable_in_artifacts"],
    )


def _exec_reachability(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = action
    blob = _text_blob(candidate)
    ag = ctx.get("attack_graph") or {}
    paths = ag.get("paths") or []
    if _has_any(blob, "unreachable", "dead code", "unreachable_code"):
        return _result(
            answered=[
                ("Q_SOURCE_REACHABLE", "ANSWERED", "unreachable"),
                ("Q_PATH_REACHABLE", "ANSWERED", "unreachable"),
            ],
            evidence=[],
            counter=[
                empty_evidence_item(
                    kind="REACHABILITY",
                    summary="Unreachable / dead-code signal in candidate",
                    strength="CONTROL_FLOW",
                    supports="counter",
                    source="candidate_fields",
                )
            ],
        )
    open_paths = [
        p
        for p in paths
        if str(p.get("status") or "").upper() in {"OPEN", "REACHABLE", "EXPLOITABLE"}
    ]
    blocked = [p for p in paths if str(p.get("status") or "").upper() == "BLOCKED"]
    if open_paths:
        return _result(
            answered=[
                ("Q_SOURCE_REACHABLE", "ANSWERED", "path_open"),
                ("Q_PATH_REACHABLE", "ANSWERED", "yes"),
            ],
            evidence=[
                empty_evidence_item(
                    kind="REACHABILITY",
                    summary=f"{len(open_paths)} open attack-graph path(s)",
                    strength="CONTROL_FLOW",
                    supports="hypothesis",
                    source="attack_graph",
                )
            ],
            attack_paths=[{"hops": p.get("hops"), "status": p.get("status")} for p in open_paths[:5]],
        )
    if blocked:
        return _result(
            answered=[
                ("Q_PATH_REACHABLE", "ANSWERED", "blocked"),
                ("Q_CONTROL_PRESENT", "ANSWERED", "path_blocked"),
            ],
            evidence=[],
            counter=[
                empty_evidence_item(
                    kind="REACHABILITY",
                    summary=f"{len(blocked)} blocked attack-graph path(s)",
                    strength="SECURITY_CONTROL",
                    supports="counter",
                    source="attack_graph",
                )
            ],
            attack_paths=[{"hops": p.get("hops"), "status": p.get("status")} for p in blocked[:5]],
        )
    return _result(
        answered=[
            ("Q_SOURCE_REACHABLE", "UNKNOWN", UNKNOWN),
            ("Q_PATH_REACHABLE", "UNKNOWN", UNKNOWN),
        ],
        evidence=[],
        unknowns=["reachability_not_established"],
    )


def _exec_memory(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = action
    mem = ctx.get("memory_hit")
    if not isinstance(mem, dict) or not mem:
        return _result(
            answered=[("Q_UNKNOWNS", "ANSWERED", "no_memory_hit")],
            evidence=[],
            unknowns=["no_prior_memory_for_candidate"],
            notes="security memory miss",
        )
    lifecycle = str(mem.get("lifecycle") or mem.get("status") or UNKNOWN)
    validity = str(mem.get("validity") or "CURRENT")
    if lifecycle.upper() == "FALSE_POSITIVE" and validity.upper() in {
        "CURRENT",
        "RECONFIRMED",
    }:
        return _result(
            answered=[
                ("Q_CONTROL_PRESENT", "ANSWERED", "memory_fp_current"),
                ("Q_UNKNOWNS", "ANSWERED", "reused_prior_fp"),
            ],
            evidence=[],
            counter=[
                empty_evidence_item(
                    kind="MEMORY",
                    summary=f"Security Memory prior FALSE_POSITIVE (validity={validity})",
                    strength="SECURITY_CONTROL",
                    supports="counter",
                    source="security_memory",
                    refs={"fingerprint": mem.get("fingerprint"), "lifecycle": lifecycle},
                )
            ],
            notes="memory_reuse_fp",
        )
    if validity.upper() in {"INVALIDATED", "REGRESSED"}:
        return _result(
            answered=[("Q_UNKNOWNS", "ANSWERED", "memory_invalidated_must_reinvestigate")],
            evidence=[
                empty_evidence_item(
                    kind="MEMORY",
                    summary=f"Prior memory invalidated/regressed ({validity})",
                    strength="STATIC_INFERENCE",
                    supports="hypothesis",
                    source="security_memory",
                    refs=mem,
                )
            ],
            notes="memory_invalidated",
        )
    return _result(
        answered=[("Q_UNKNOWNS", "ANSWERED", f"memory_{lifecycle}")],
        evidence=[
            empty_evidence_item(
                kind="MEMORY",
                summary=f"Memory hit lifecycle={lifecycle} validity={validity}",
                strength="STATIC_INFERENCE",
                supports="unknown",
                source="security_memory",
                refs={"fingerprint": mem.get("fingerprint")},
            )
        ],
    )


def _exec_twin(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = action
    twin = ctx.get("twin") or ctx.get("twin_summary") or {}
    sim = ctx.get("twin_simulation") or {}
    kind = str(
        candidate.get("vulnerability_type")
        or candidate.get("type")
        or ""
    ).lower()
    # Prompt/agent/MCP: need privileged tool reachability
    if any(k in kind for k in ("prompt", "agent", "mcp", "llm")):
        paths = sim.get("paths") or sim.get("simulated_paths") or []
        privileged = [
            p
            for p in paths
            if any(
                str(x).lower().find("privileged") >= 0
                or str(x).lower().find("database") >= 0
                or str(x).lower().find("secret") >= 0
                for x in (p.get("hops") or p.get("steps") or [])
            )
        ]
        if privileged:
            return _result(
                answered=[
                    ("Q_ASSET", "ANSWERED", "privileged_tool_reachable"),
                    ("Q_IMPACT", "ANSWERED", "realistic_via_twin"),
                ],
                evidence=[
                    empty_evidence_item(
                        kind="TWIN",
                        summary="Twin simulation shows path toward privileged asset",
                        strength="STATIC_INFERENCE",
                        supports="hypothesis",
                        source="security_twin",
                    )
                ],
                attack_paths=privileged[:5],
            )
        if twin or sim:
            return _result(
                answered=[
                    ("Q_ASSET", "ANSWERED", "no_privileged_path_observed"),
                    ("Q_IMPACT", "ANSWERED", "impact_blocked_or_absent"),
                ],
                evidence=[],
                counter=[
                    empty_evidence_item(
                        kind="TWIN",
                        summary="No privileged tool/asset path observed in twin simulation",
                        strength="STATIC_INFERENCE",
                        supports="counter",
                        source="security_twin",
                    )
                ],
                notes="twin_blocks_impact",
            )
        return _result(
            answered=[
                ("Q_ASSET", "UNKNOWN", UNKNOWN),
                ("Q_IMPACT", "UNKNOWN", UNKNOWN),
            ],
            evidence=[],
            unknowns=["security_twin_unavailable"],
        )

    summary = twin.get("summary") if isinstance(twin.get("summary"), dict) else twin
    if summary:
        return _result(
            answered=[
                ("Q_ASSET", "ANSWERED", "twin_summary_present"),
                ("Q_IMPACT", "UNKNOWN", UNKNOWN),
            ],
            evidence=[
                empty_evidence_item(
                    kind="TWIN",
                    summary="Security Twin summary available for asset context",
                    strength="STATIC_INFERENCE",
                    supports="unknown",
                    source="security_twin",
                    refs={"summary_keys": list(summary.keys())[:12]},
                )
            ],
        )
    return _result(
        answered=[("Q_ASSET", "UNKNOWN", UNKNOWN), ("Q_IMPACT", "UNKNOWN", UNKNOWN)],
        evidence=[],
        unknowns=["security_twin_unavailable"],
    )


def _exec_attack_path(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    _ = candidate
    ag = ctx.get("attack_graph") or {}
    paths = list(ag.get("paths") or [])
    atype = action.get("type")
    if atype == ACTION_CHECK_ALTERNATE_PATH:
        # Look for same sink with missing control on another path
        by_target: dict[str, list[dict[str, Any]]] = {}
        for p in paths:
            key = str(p.get("target") or p.get("sink") or "unknown")
            by_target.setdefault(key, []).append(p)
        alternates = []
        for key, group in by_target.items():
            if len(group) < 2:
                continue
            statuses = {str(g.get("status") or "").upper() for g in group}
            if "BLOCKED" in statuses and (
                "OPEN" in statuses or "REACHABLE" in statuses or "EXPLOITABLE" in statuses
            ):
                alternates.extend(group)
        if alternates:
            return _result(
                answered=[
                    ("Q_CONTROL_BYPASS", "ANSWERED", "alternate_path_bypasses_control"),
                    ("Q_PATH_REACHABLE", "ANSWERED", "yes_via_alternate"),
                ],
                evidence=[
                    empty_evidence_item(
                        kind="ALTERNATE_PATH",
                        summary="Alternate path reaches same target without block",
                        strength="CONTROL_FLOW",
                        supports="hypothesis",
                        source="attack_graph",
                    )
                ],
                attack_paths=[
                    {"hops": p.get("hops"), "status": p.get("status")} for p in alternates[:5]
                ],
            )
        return _result(
            answered=[("Q_CONTROL_BYPASS", "UNKNOWN", UNKNOWN)],
            evidence=[],
            unknowns=["no_alternate_bypass_observed"],
        )

    if not paths:
        return _result(
            answered=[("Q_PATH_REACHABLE", "UNKNOWN", UNKNOWN)],
            evidence=[],
            unknowns=["no_attack_paths_in_context"],
        )
    return _result(
        answered=[("Q_PATH_REACHABLE", "ANSWERED", f"{len(paths)}_paths")],
        evidence=[
            empty_evidence_item(
                kind="ATTACK_PATH",
                summary=f"Attack graph provides {len(paths)} path(s)",
                strength="CONTROL_FLOW",
                supports="hypothesis",
                source="attack_graph",
            )
        ],
        attack_paths=[{"hops": p.get("hops"), "status": p.get("status")} for p in paths[:8]],
    )


def _exec_generic_check(
    action: dict[str, Any], candidate: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Low-cost structured field checks for validation/sanitization/etc."""
    _ = ctx
    blob = _text_blob(candidate)
    atype = str(action.get("type") or "")
    mapping = {
        ACTION_CHECK_PARAMETERIZATION: (
            "Q_CONTROL_PRESENT",
            ("parameterized", "bound args", "prepared"),
            "parameterization_present",
        ),
        ACTION_CHECK_SANITIZATION: (
            "Q_CONTROL_PRESENT",
            ("sanitiz", "escape", "encode", "shell=false"),
            "sanitization_present",
        ),
        ACTION_CHECK_VALIDATION: (
            "Q_CONTROL_PRESENT",
            ("validat", "allowlist", "whitelist"),
            "validation_present",
        ),
        ACTION_CHECK_AUTHENTICATION: (
            "Q_PRIVILEGE",
            ("authenticat", "login", "session", "bearer"),
            "authentication_signal",
        ),
        ACTION_CHECK_CONFIGURATION: (
            "Q_CONFIG",
            ("config", "setting", "env"),
            "configuration_signal",
        ),
        ACTION_CHECK_FRAMEWORK_BEHAVIOR: (
            "Q_SINK_DANGEROUS",
            ("autoescape", "orm", "safe"),
            "framework_mitigation_signal",
        ),
        ACTION_CHECK_DEPENDENCY: (
            "Q_UNKNOWNS",
            ("dependency", "package", "cve"),
            "dependency_signal",
        ),
        ACTION_CHECK_TRUST_BOUNDARY: (
            "Q_SOURCE_CONTROLLED",
            ("trust", "boundary", "untrusted"),
            "trust_boundary_signal",
        ),
        ACTION_CHECK_IDENTITY_PROPAGATION: (
            "Q_TENANT",
            ("identity", "principal", "subject", "tenant"),
            "identity_propagation_signal",
        ),
        ACTION_CHECK_TOOL_PERMISSION: (
            "Q_PRIVILEGE",
            ("tool permission", "allow_tools", "privileged tool"),
            "tool_permission_signal",
        ),
        ACTION_CHECK_AGENT_PERMISSION: (
            "Q_PRIVILEGE",
            ("agent", "tool", "permission"),
            "agent_permission_signal",
        ),
        ACTION_CHECK_MCP_TRUST: (
            "Q_PRIVILEGE",
            ("mcp", "model context"),
            "mcp_signal",
        ),
        ACTION_TRACE_CALLERS: (
            "Q_SOURCE_REACHABLE",
            ("caller", "entrypoint", "route"),
            "caller_signal",
        ),
        ACTION_TRACE_CALLEES: (
            "Q_SINK_DANGEROUS",
            ("sink", "execute", "fetch", "render"),
            "callee_sink_signal",
        ),
        ACTION_ANALYZE_GIT_CHANGE: (
            "Q_UNKNOWNS",
            ("changed", "diff", "revision"),
            "change_signal",
        ),
    }
    spec = mapping.get(atype)
    if not spec:
        return _result(
            answered=[],
            evidence=[],
            unknowns=[f"unsupported_action:{atype}"],
        )
    qid, needles, label = spec
    if _has_any(blob, *needles):
        return _result(
            answered=[(qid, "ANSWERED", label)],
            evidence=[],
            counter=[
                empty_evidence_item(
                    kind=atype,
                    summary=f"Structured evidence suggests {label}",
                    strength="STATIC_INFERENCE",
                    supports="counter",
                    source="candidate_fields",
                )
            ],
            controls=[{"name": label}],
        )
    # Sink dangerous default when vulnerability type implies sink
    if atype == ACTION_TRACE_CALLEES and candidate.get("sink"):
        return _result(
            answered=[("Q_SINK_DANGEROUS", "ANSWERED", "sink_declared")],
            evidence=[
                empty_evidence_item(
                    kind="SINK",
                    summary=f"Sink declared: {candidate.get('sink')}",
                    strength="DIRECT_CODE",
                    supports="hypothesis",
                    source="candidate.sink",
                    refs={"sink": candidate.get("sink")},
                )
            ],
        )
    return _result(
        answered=[(qid, "UNKNOWN", UNKNOWN)],
        evidence=[],
        unknowns=[f"{label}_not_observed"],
    )


ACTION_META: dict[str, dict[str, Any]] = {
    ACTION_TRACE_DATA_FLOW: {
        "cost": COST_MEDIUM,
        "priority": 20,
        "purpose": "Determine whether attacker data reaches the sink",
        "handler": _exec_trace_data_flow,
    },
    ACTION_SEARCH_COUNTER_EVIDENCE: {
        "cost": COST_LOW,
        "priority": 10,
        "purpose": "Actively search for evidence that disproves the hypothesis",
        "handler": _exec_counter_evidence,
    },
    ACTION_CHECK_SECURITY_MEMORY: {
        "cost": COST_LOW,
        "priority": 5,
        "purpose": "Reuse or invalidate prior Security Memory conclusions",
        "handler": _exec_memory,
    },
    ACTION_COMPARE_SECURITY_TWIN: {
        "cost": COST_MEDIUM,
        "priority": 40,
        "purpose": "Ask system-level Twin questions (impact / privileged reach)",
        "handler": _exec_twin,
    },
    ACTION_CHECK_AUTHORIZATION: {
        "cost": COST_LOW,
        "priority": 15,
        "purpose": "Check authorization / ownership signals",
        "handler": _exec_authz,
    },
    ACTION_CHECK_AUTHENTICATION: {
        "cost": COST_LOW,
        "priority": 25,
        "purpose": "Check authentication / privilege requirement",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_TENANT_ISOLATION: {
        "cost": COST_LOW,
        "priority": 18,
        "purpose": "Check tenant isolation / identity propagation",
        "handler": _exec_authz,
    },
    ACTION_CHECK_REACHABILITY: {
        "cost": COST_MEDIUM,
        "priority": 22,
        "purpose": "Check whether the path is reachable or blocked",
        "handler": _exec_reachability,
    },
    ACTION_BUILD_ATTACK_PATH: {
        "cost": COST_HIGH,
        "priority": 45,
        "purpose": "Use Attack Graph paths for chaining / reachability",
        "handler": _exec_attack_path,
    },
    ACTION_CHECK_ALTERNATE_PATH: {
        "cost": COST_HIGH,
        "priority": 35,
        "purpose": "Find alternate paths that bypass a control",
        "handler": _exec_attack_path,
    },
    ACTION_CHECK_PARAMETERIZATION: {
        "cost": COST_LOW,
        "priority": 12,
        "purpose": "Look for parameterized / prepared query controls",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_SANITIZATION: {
        "cost": COST_LOW,
        "priority": 14,
        "purpose": "Look for sanitization / safe execution patterns",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_VALIDATION: {
        "cost": COST_LOW,
        "priority": 16,
        "purpose": "Look for validation / allowlists",
        "handler": _exec_generic_check,
    },
    ACTION_TRACE_CALLERS: {
        "cost": COST_MEDIUM,
        "priority": 30,
        "purpose": "Trace callers / entrypoints",
        "handler": _exec_generic_check,
    },
    ACTION_TRACE_CALLEES: {
        "cost": COST_MEDIUM,
        "priority": 28,
        "purpose": "Trace callees / sink danger",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_CONFIGURATION: {
        "cost": COST_MEDIUM,
        "priority": 50,
        "purpose": "Check configuration-sensitive behavior",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_FRAMEWORK_BEHAVIOR: {
        "cost": COST_MEDIUM,
        "priority": 48,
        "purpose": "Check framework mitigations",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_DEPENDENCY: {
        "cost": COST_VERY_HIGH,
        "priority": 70,
        "purpose": "Dependency-level analysis (expensive)",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_TRUST_BOUNDARY: {
        "cost": COST_LOW,
        "priority": 24,
        "purpose": "Check trust boundary crossing",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_IDENTITY_PROPAGATION: {
        "cost": COST_MEDIUM,
        "priority": 26,
        "purpose": "Check identity / tenant context propagation",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_TOOL_PERMISSION: {
        "cost": COST_MEDIUM,
        "priority": 32,
        "purpose": "Check agent tool permissions",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_AGENT_PERMISSION: {
        "cost": COST_MEDIUM,
        "priority": 33,
        "purpose": "Check agent privilege",
        "handler": _exec_generic_check,
    },
    ACTION_CHECK_MCP_TRUST: {
        "cost": COST_MEDIUM,
        "priority": 34,
        "purpose": "Check MCP trust boundary",
        "handler": _exec_generic_check,
    },
    ACTION_ANALYZE_GIT_CHANGE: {
        "cost": COST_MEDIUM,
        "priority": 55,
        "purpose": "Relate investigation to revision / change signals",
        "handler": _exec_generic_check,
    },
}


def make_action(action_type: str, *, question_id: str | None = None) -> dict[str, Any]:
    meta = ACTION_META.get(action_type, {})
    return empty_action(
        action_type=action_type,
        purpose=str(meta.get("purpose") or action_type),
        question_id=question_id,
        cost=str(meta.get("cost") or COST_LOW),
        priority=int(meta.get("priority") or 50),
        expected_evidence=["structured_artifact_fields"],
    )


def execute_action(
    action: dict[str, Any],
    candidate: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Run a symbolic action handler. Never invents repository files."""
    atype = str(action.get("type") or "")
    meta = ACTION_META.get(atype)
    if not meta:
        result = _result(
            answered=[],
            evidence=[],
            unknowns=[f"unknown_action:{atype}"],
            notes="no handler",
        )
    else:
        handler: ActionHandler = meta["handler"]
        result = handler(action, candidate, context)
    action["result"] = result
    action["status"] = "DONE"
    return result
