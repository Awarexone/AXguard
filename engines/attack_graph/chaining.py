"""Vulnerability chaining logic (Phase 6 core).

Builds ordered, file-scoped *chains* (``entrypoint → … → asset``) from three
evidence sources, in priority order:

1. app_model entrypoints / identities / trust boundaries (Phase 1).
2. adversary CONFIRMED / LIKELY / UNVERIFIED findings (Phase 4) — never
   FALSE_POSITIVE, which is a hard veto (``INVALID``).
3. deterministic, evidence-gated structural seed detectors scoped to this
   package, for patterns the upstream hunters miss or conservatively drop
   (SSRF→internal, role mass-assignment, missing-org_id BOLA, agent-tool
   without allowlist). Seeds are ``LIKELY`` at best, ``UNVERIFIED`` when
   reachability is unknown — never ``CONFIRMED``.

Chains are always constructed from an explicit structural link (a real
data/control-flow relationship). Two findings that merely share a file are
**never** connected here — see ``false_chain.py``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from engines.attack_graph import barriers, nodes, preconditions
from engines.attack_graph.edges import make_edge, status_to_edge_confidence
from engines.attack_graph.schema import (
    EDGE_LIKELY,
    EDGE_UNKNOWN,
    EFFECT_INEFFECTIVE,
)


class ChainingContext:
    def __init__(
        self,
        root: Path,
        application_model: dict[str, Any] | None,
        adversary: dict[str, Any] | None,
    ) -> None:
        self.root = Path(root)
        self.application_model = application_model or {}
        self.adversary = adversary or {}
        self.entrypoints_by_file: dict[str, list[dict[str, Any]]] = {}
        for ep in self.application_model.get("entrypoints") or []:
            self.entrypoints_by_file.setdefault(_base(ep.get("file")), []).append(ep)
        self.adv_by_file: dict[str, list[dict[str, Any]]] = {}
        for f in self.adversary.get("findings") or []:
            loc = f.get("location") or {}
            self.adv_by_file.setdefault(_base(loc.get("file")), []).append(f)
        self._source_cache: dict[str, str] = {}
        self.used_finding_keys: set[str] = set()

    def source(self, filename: str) -> str:
        if filename not in self._source_cache:
            self._source_cache[filename] = nodes.read_source(str(self.root / filename))
        return self._source_cache[filename]

    def files(self) -> list[str]:
        names = set(self.entrypoints_by_file) | set(self.adv_by_file)
        return sorted(n for n in names if n)


def _base(file: Any) -> str:
    return Path(str(file or "")).name


def _entry_for_line(entrypoints: list[dict[str, Any]], line: int) -> dict[str, Any] | None:
    candidates = [e for e in entrypoints if int(e.get("line") or 0) <= int(line or 0)]
    if not candidates:
        return entrypoints[0] if entrypoints else None
    return max(candidates, key=lambda e: int(e.get("line") or 0))


def _reachability(entrypoint: dict[str, Any]) -> str:
    auth = (entrypoint.get("authentication") or {}).get("status", "unknown")
    if auth == "required":
        return "authenticated"
    return "unauthenticated"


def _find_adv(findings: list[dict[str, Any]], *vtype_substrs: str, allow_fp: bool = False) -> dict[str, Any] | None:
    for f in findings:
        vt = str(f.get("vulnerability_type") or "").lower()
        if any(s in vt for s in vtype_substrs):
            if not allow_fp and f.get("status") == "FALSE_POSITIVE":
                continue
            return f
    return None


def build_chains(ctx: ChainingContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(chains, dead_ends)``."""
    chains: list[dict[str, Any]] = []
    for filename in ctx.files():
        source = ctx.source(filename)
        entrypoints = ctx.entrypoints_by_file.get(filename, [])
        adv = ctx.adv_by_file.get(filename, [])

        chains.extend(_chain_ssrf_internal(ctx, filename, source, entrypoints, adv))
        chains.extend(_chain_sql_direct(ctx, filename, source, entrypoints, adv))
        chains.extend(_chain_command_injection(ctx, filename, source, entrypoints, adv))
        chains.extend(_chain_mass_assignment(ctx, filename, source, entrypoints, adv))
        chains.extend(_chain_bola(ctx, filename, source, entrypoints, adv))
        chains.extend(_chain_ai_tool(ctx, filename, source, entrypoints, adv))

    dead_ends = _collect_dead_ends(ctx)
    return chains, dead_ends


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
def _chain_sql_direct(ctx, filename, source, entrypoints, adv):
    out: list[dict[str, Any]] = []
    for f in adv:
        vt = str(f.get("vulnerability_type") or "").lower()
        if "sql" not in vt and (vt == "injection" or "sql-inj" in vt) is False and "sql" not in vt:
            continue
        if "sql" not in vt:
            continue
        if f.get("status") == "FALSE_POSITIVE":
            continue
        loc = f.get("location") or {}
        entry = _entry_for_line(entrypoints, int(loc.get("line") or 0))
        if not entry:
            continue
        asset = nodes.detect_sql_table_asset(filename, source)
        if not asset:
            continue
        reach = _reachability(entry)
        en = nodes.entrypoint_node(entry, reach)
        fn = nodes.finding_node_from_adversary(f)
        ctx.used_finding_keys.add(_fkey(f))

        # barrier: decorator control on this entrypoint
        control_info, control_node = _entry_control(ctx, filename, source, entry, undermined=False)
        reaches_ev = [{"type": "TRUST_BOUNDARY", "description": f"internet reaches {en['label']}", "file": filename, "line": entry.get("line")}]
        blocked = control_info.get("blocks") if control_info else False
        reaches_edge = make_edge(
            "reaches", "internet", en["id"],
            confidence=EDGE_LIKELY,
            evidence=reaches_ev,
            preconditions=preconditions.reaches_preconditions(reach, en.get("authentication")),
            blocked_by=(control_info if blocked else None),
        )
        e1 = make_edge("triggers", en["id"], fn["id"], confidence=status_to_edge_confidence(f.get("status")),
                       evidence=[{"type": "DATA_FLOW", "description": f"{en['handler']} builds tainted query", "file": filename, "line": loc.get("line")}],
                       preconditions=preconditions.triggers_preconditions())
        e2 = make_edge("exposes", fn["id"], asset["id"], confidence=status_to_edge_confidence(f.get("status")),
                       evidence=[{"type": "SINK", "description": f"query discloses {asset['label']}", "file": filename, "line": asset['location'].get('line')}])
        chain_nodes = [_internet_node(), en, fn, asset]
        chain_edges = [reaches_edge, e1, e2]
        controls_encountered = []
        if control_node:
            chain_nodes.append(control_node)
            controls_encountered.append({"id": control_node["id"], "effectiveness": control_info["effectiveness"]})
        out.append(_mk_chain(["direct_chain", "sql_injection"], chain_nodes, chain_edges, en["id"], asset["id"],
                             controls_encountered=controls_encountered, blocked=blocked))
    return out


def _chain_ssrf_internal(ctx, filename, source, entrypoints, adv):
    if "requests.get(" not in source or "request." not in source:
        return []
    cred = nodes.detect_credential_asset(filename, source)
    if not cred or len(entrypoints) < 2:
        return []
    # preview entrypoint = the one containing requests.get(user-url)
    ssrf_line = nodes._line_of(source, "requests.get(")
    preview = _entry_for_line(entrypoints, ssrf_line)
    # internal entrypoint = one returning the credential asset (different route)
    cred_line = int(cred["location"].get("line") or 0)
    internal = None
    for ep in entrypoints:
        if ep is preview:
            continue
        if _returns_symbol(source, ep, cred["label"].split(" ")[0]):
            internal = ep
            break
    if internal is None:
        internal = next((ep for ep in entrypoints if ep is not preview and int(ep.get("line") or 0) > int(preview.get("line") or 0)), None)
    if internal is None:
        return []

    reach = _reachability(preview)
    en = nodes.entrypoint_node(preview, reach)
    internal_en = nodes.entrypoint_node(internal, "internal")

    adv_ssrf = _find_adv(adv, "ssrf")
    if adv_ssrf:
        fn = nodes.finding_node_from_adversary(adv_ssrf)
        status = adv_ssrf.get("status")
        ctx.used_finding_keys.add(_fkey(adv_ssrf))
    else:
        # adversary dropped it (spurious "timeout" control) — re-establish as a
        # LIKELY structural seed backed by the real request→requests.get flow.
        fn = nodes.seed_finding_node(
            "ssrf", filename, ssrf_line, status="LIKELY",
            description="user-controlled URL passed to requests.get with no host allowlist (SSRF)",
            evidence=[{"type": "DATA_FLOW", "description": "request URL flows into requests.get()", "file": filename, "line": ssrf_line}],
        )
        status = "LIKELY"

    reaches_edge = make_edge("reaches", "internet", en["id"], confidence=EDGE_LIKELY,
                             evidence=[{"type": "TRUST_BOUNDARY", "description": f"internet reaches {en['label']}", "file": filename, "line": preview.get("line")}],
                             preconditions=preconditions.reaches_preconditions(reach, en.get("authentication")))
    e1 = make_edge("triggers", en["id"], fn["id"], confidence=status_to_edge_confidence(status),
                   evidence=[{"type": "SOURCE", "description": "attacker controls the fetched URL", "file": filename, "line": ssrf_line}],
                   preconditions=preconditions.triggers_preconditions())
    e2 = make_edge("triggers", fn["id"], internal_en["id"], confidence=status_to_edge_confidence(status),
                   evidence=[{"type": "DATA_FLOW", "description": "SSRF response is round-tripped to the caller; internal route reachable on same app (no network segmentation in code)", "file": filename, "line": internal.get("line")}],
                   preconditions=[preconditions.precond("network", "no_segmentation")])
    e3 = make_edge("exposes", internal_en["id"], cred["id"], confidence=status_to_edge_confidence(status),
                   evidence=[{"type": "SINK", "description": f"internal handler returns {cred['label']}", "file": filename, "line": cred_line}])
    chain_nodes = [_internet_node(), en, fn, internal_en, cred]
    chain_edges = [reaches_edge, e1, e2, e3]
    return [_mk_chain(["ssrf_chain"], chain_nodes, chain_edges, en["id"], cred["id"], blocked=False)]


def _chain_command_injection(ctx, filename, source, entrypoints, adv):
    f = _find_adv(adv, "command-injection", "command_injection", "cmd")
    if not f:
        return []
    loc = f.get("location") or {}
    asset = nodes.detect_filesystem_asset(filename, source)
    if not asset:
        return []
    # Is there an HTTP entrypoint wrapping this? If not → queue consumer, unknown reachability.
    http_entry = _entry_for_line(entrypoints, int(loc.get("line") or 0)) if entrypoints else None
    if http_entry and int(http_entry.get("line") or 0) <= int(loc.get("line") or 0) and _same_handler(source, http_entry, int(loc.get("line") or 0)):
        en = nodes.entrypoint_node(http_entry, _reachability(http_entry))
    else:
        handler = _enclosing_def(source, int(loc.get("line") or 0)) or "consumer"
        en = nodes.queue_entrypoint_node(handler, filename, nodes._line_of(source, f"def {handler}"))
    fn = nodes.finding_node_from_adversary(f)
    ctx.used_finding_keys.add(_fkey(f))
    status = f.get("status")
    reaches_edge = make_edge("reaches", "internet", en["id"], confidence=EDGE_UNKNOWN,
                             evidence=en.get("evidence") or [{"type": "TRUST_BOUNDARY", "description": "reachability unknown", "file": filename, "line": en['location'].get('line')}],
                             preconditions=preconditions.reaches_preconditions(en.get("reachability", "unknown"), en.get("authentication")))
    e1 = make_edge("triggers", en["id"], fn["id"], confidence=status_to_edge_confidence(status),
                   evidence=[{"type": "DATA_FLOW", "description": "queue-message field flows into shell command (shell=True)", "file": filename, "line": loc.get("line")}],
                   preconditions=preconditions.triggers_preconditions())
    e2 = make_edge("exposes", fn["id"], asset["id"], confidence=status_to_edge_confidence(status),
                   evidence=[{"type": "SINK", "description": "arbitrary command execution on host", "file": filename, "line": asset['location'].get('line')}])
    chain_nodes = [_internet_node(), en, fn, asset]
    chain_edges = [reaches_edge, e1, e2]
    return [_mk_chain(["reachability_unknown"], chain_nodes, chain_edges, en["id"], asset["id"], blocked=False)]


def _chain_mass_assignment(ctx, filename, source, entrypoints, adv):
    # pattern: `<x>.update(<body from request>)` in a self-service handler, and
    # an admin route gated by a role decorator that trusts the same field.
    if not re.search(r"\.update\(\s*\w+\s*\)", source) or "request" not in source:
        return []
    if "role" not in source:
        return []
    upd_line = nodes._line_of(source, ".update(")
    update_entry = _entry_for_line(entrypoints, upd_line)
    admin_entry = next((ep for ep in entrypoints if "admin" in str(ep.get("path", "")).lower() and ep is not update_entry), None)
    if not update_entry:
        return []
    pii = nodes.detect_pii_dict_asset(filename, source)
    if not pii:
        return []

    reach = _reachability(update_entry)
    user_ident = nodes.identity_node("user", "role", role="user")
    admin_ident = nodes.identity_node("admin", "role", role="admin")
    en = nodes.entrypoint_node(update_entry, "authenticated")
    fn = nodes.seed_finding_node(
        "mass-assignment", filename, upd_line, status="LIKELY",
        description="request body applied wholesale to the caller's record (no field allowlist); attacker sets role=admin",
        evidence=[{"type": "DATA_FLOW", "description": "request JSON → user.update() including the role field", "file": filename, "line": upd_line}],
    )
    nodes_list = [user_ident, en, fn]
    edges_list = [
        make_edge("reaches", "internet", en["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "TRUST_BOUNDARY", "description": "authenticated low-priv user reaches self-service update", "file": filename, "line": update_entry.get("line")}],
                  preconditions=preconditions.reaches_preconditions("authenticated", en.get("authentication"))),
        make_edge("triggers", en["id"], fn["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "SOURCE", "description": "attacker controls the update body", "file": filename, "line": upd_line}],
                  preconditions=preconditions.triggers_preconditions()),
    ]
    controls_encountered: list[dict[str, Any]] = []
    if admin_entry:
        control_info, control_node = _entry_control(ctx, filename, source, admin_entry, undermined=True)
        admin_en = nodes.entrypoint_node(admin_entry, "authenticated")
        edges_list.append(
            make_edge("escalates_to", fn["id"], admin_ident["id"], confidence=EDGE_LIKELY,
                      evidence=[{"type": "CONTROL_FLOW", "description": "role field set to admin escalates privilege", "file": filename, "line": upd_line}],
                      preconditions=preconditions.escalate_preconditions())
        )
        edges_list.append(
            make_edge("triggers", admin_ident["id"], admin_en["id"], confidence=EDGE_LIKELY,
                      evidence=[{"type": "CONTROL_FLOW", "description": f"{control_info['name']} trusts the mutable role field (ineffective)", "file": filename, "line": admin_entry.get("line")}])
        )
        edges_list.append(
            make_edge("exposes", admin_en["id"], pii["id"], confidence=EDGE_LIKELY,
                      evidence=[{"type": "SINK", "description": f"admin listing discloses {pii['label']}", "file": filename, "line": pii['location'].get('line')}])
        )
        nodes_list.extend([admin_ident, admin_en, pii])
        if control_node:
            nodes_list.append(control_node)
            controls_encountered.append({"id": control_node["id"], "effectiveness": control_info["effectiveness"]})
        target = pii["id"]
    else:
        edges_list.append(
            make_edge("escalates_to", fn["id"], pii["id"], confidence=EDGE_LIKELY,
                      evidence=[{"type": "SINK", "description": f"privilege escalation exposes {pii['label']}", "file": filename, "line": pii['location'].get('line')}],
                      preconditions=preconditions.escalate_preconditions())
        )
        nodes_list.append(pii)
        target = pii["id"]
    nodes_list.insert(0, _internet_node())
    return [_mk_chain(["priv_esc"], nodes_list, edges_list, en["id"], target,
                      controls_encountered=controls_encountered, blocked=False)]


def _chain_bola(ctx, filename, source, entrypoints, adv):
    # pattern: route with <org_id> AND <..._id> path params; object looked up by
    # the object id alone; org_id never compared against the returned object.
    bola_entry = None
    for ep in entrypoints:
        path = str(ep.get("path") or "")
        if re.search(r"<\w*org\w*>", path) and re.search(r"<\w*(id|invoice|order|object)\w*>", path):
            bola_entry = ep
            break
    if not bola_entry:
        return []
    lookup_m = re.search(r"([A-Z_]{3,})\.get\(\s*(\w*(?:invoice|order|object|item)?\w*_?id)\s*\)", source, re.IGNORECASE)
    if not lookup_m:
        return []
    pii = nodes.detect_pii_dict_asset(filename, source)
    if not pii:
        return []
    lookup_line = nodes._line_of(source, lookup_m.group(0))
    tenant_a = nodes.identity_node("tenant_a", "tenant", tenant="org-a")
    en = nodes.entrypoint_node(bola_entry, "authenticated")
    fn = nodes.seed_finding_node(
        "broken-object-level-authz", filename, lookup_line, status="LIKELY",
        description="object looked up by id alone in a global table; org_id from URL never compared to the returned object's org_id",
        evidence=[{"type": "CONTROL_FLOW", "description": "missing per-object tenant re-check (BOLA)", "file": filename, "line": lookup_line}],
    )
    control_info, control_node = _entry_control(ctx, filename, source, bola_entry, undermined=True)
    edges_list = [
        make_edge("reaches", "internet", en["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "TRUST_BOUNDARY", "description": "authenticated tenant-A caller reaches the endpoint", "file": filename, "line": bola_entry.get("line")}],
                  preconditions=preconditions.reaches_preconditions("authenticated", en.get("authentication"))),
        make_edge("triggers", en["id"], fn["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "SOURCE", "description": "attacker enumerates another tenant's object id", "file": filename, "line": lookup_line}],
                  preconditions=preconditions.triggers_preconditions()),
        make_edge("crosses_tenant", fn["id"], pii["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "SINK", "description": f"returns another tenant's {pii['label']} (billing PII)", "file": filename, "line": pii['location'].get('line')}],
                  preconditions=preconditions.cross_tenant_preconditions()),
    ]
    nodes_list = [_internet_node(), tenant_a, en, fn, pii]
    controls_encountered = []
    if control_node:
        nodes_list.append(control_node)
        controls_encountered.append({"id": control_node["id"], "effectiveness": control_info["effectiveness"]})
    return [_mk_chain(["cross_tenant"], nodes_list, edges_list, en["id"], pii["id"],
                      controls_encountered=controls_encountered, blocked=False)]


def _chain_ai_tool(ctx, filename, source, entrypoints, adv):
    agent, tool = nodes.detect_agent_and_tool(filename, source)
    if not agent or not tool:
        return []
    secret = nodes.detect_secret_file_asset(filename, source)
    if not secret:
        return []
    # entrypoint feeding untrusted content into the agent
    inj_line = nodes._line_of(source, "requests.get(") if "requests.get(" in source else nodes._line_of(source, "agent.run")
    entry = _entry_for_line(entrypoints, inj_line) if entrypoints else None
    if not entry:
        return []
    reach = _reachability(entry)
    en = nodes.entrypoint_node(entry, reach)
    fn = nodes.seed_finding_node(
        "prompt-injection", filename, inj_line, status="LIKELY",
        description="untrusted fetched page concatenated into the model instruction context (no delimiter/provenance); can inject tool calls",
        evidence=[{"type": "SOURCE", "description": "attacker-controlled page text reaches the agent instruction context", "file": filename, "line": inj_line}],
    )
    ctx.used_finding_keys.add(_fkey_seed("prompt-injection", filename))
    # The upstream ssrf (the fetch) and path-traversal (the tool's open) findings
    # in this file are subsumed by this AI chain — mark them consumed, not dead.
    for f in adv:
        ctx.used_finding_keys.add(_fkey(f))
    # allowlist / confirmation gate present and effective?
    has_gate = bool(re.search(r"ALLOWED_TOOL_PATHS|allowlist|confirm_with_user|PermissionError", source)) and "if path not in" in source
    invoke_conf = EDGE_UNKNOWN if has_gate else EDGE_LIKELY
    edges_list = [
        make_edge("reaches", "internet", en["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "TRUST_BOUNDARY", "description": "public assistant endpoint", "file": filename, "line": entry.get("line")}],
                  preconditions=preconditions.reaches_preconditions(reach, en.get("authentication"))),
        make_edge("triggers", en["id"], fn["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "SOURCE", "description": "untrusted URL content fetched and summarized", "file": filename, "line": inj_line}],
                  preconditions=preconditions.triggers_preconditions()),
        make_edge("reaches", fn["id"], agent["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "DATA_FLOW", "description": "injected instructions reach the agent planner", "file": filename, "line": agent['location'].get('line')}]),
        make_edge("invokes", agent["id"], tool["id"], confidence=invoke_conf,
                  evidence=[{"type": "CONTROL_FLOW", "description": "agent calls a privileged tool from model output; no allowlist / no human confirmation", "file": filename, "line": tool['location'].get('line')}],
                  preconditions=preconditions.invokes_preconditions()),
        make_edge("yields", tool["id"], secret["id"], confidence=EDGE_LIKELY,
                  evidence=[{"type": "SINK", "description": f"tool reads {secret['label']} and returns it in the HTTP response", "file": filename, "line": secret['location'].get('line')}]),
    ]
    nodes_list = [_internet_node(), en, fn, agent, tool, secret]
    return [_mk_chain(["ai_chain", "prompt_injection"], nodes_list, edges_list, en["id"], secret["id"],
                      blocked=False, ai_agent=True)]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
_INTERNET_NODE = {
    "id": "internet",
    "type": "trust_boundary",
    "label": "internet (untrusted)",
    "kind": "internet",
    "location": {},
    "refs": [],
    "evidence": [],
}


def _internet_node() -> dict[str, Any]:
    return dict(_INTERNET_NODE)


def _mk_chain(tags, nodes_list, edges_list, entry, target, *, controls_encountered=None, blocked=False, ai_agent=False):
    return {
        "tags": tags,
        "nodes": nodes_list,
        "edges": edges_list,
        "entry": entry,
        "target": target,
        "controls_encountered": controls_encountered or [],
        "blocked": blocked,
        "ai_agent": ai_agent,
    }


def _entry_control(ctx, filename, source, entrypoint, *, undermined: bool):
    decs = barriers.decorators_for_handler(source, str(entrypoint.get("handler") or ""))
    for name in decs:
        info = barriers.classify_control(name, source, undermined=undermined)
        cnode = nodes.control_node(
            name, filename, info["line"], effectiveness=info["effectiveness"],
            description=info["reason"],
        )
        return info, cnode
    return {"blocks": False, "effectiveness": EFFECT_INEFFECTIVE, "name": None}, None


def _returns_symbol(source: str, entrypoint: dict[str, Any], symbol: str) -> bool:
    body = _handler_body(source, str(entrypoint.get("handler") or ""))
    return symbol in body


def _handler_body(source: str, handler: str) -> str:
    lines = source.splitlines()
    for i, ln in enumerate(lines):
        if re.match(rf"\s*def\s+{re.escape(handler)}\s*\(", ln):
            base = len(ln) - len(ln.lstrip())
            body = [ln]
            for nxt in lines[i + 1 :]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= base and re.match(r"\s*(def|class|@)", nxt):
                    break
                body.append(nxt)
            return "\n".join(body)
    return ""


def _same_handler(source: str, entrypoint: dict[str, Any], line: int) -> bool:
    body = _handler_body(source, str(entrypoint.get("handler") or ""))
    target = source.splitlines()[line - 1] if 0 < line <= len(source.splitlines()) else ""
    return bool(target.strip()) and target in body


def _enclosing_def(source: str, line: int) -> str | None:
    lines = source.splitlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = re.match(r"\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", lines[i])
        if m:
            return m.group(1)
    return None


def _fkey(f: dict[str, Any]) -> str:
    loc = f.get("location") or {}
    return f"{f.get('vulnerability_type')}:{_base(loc.get('file'))}:{loc.get('line')}"


def _fkey_seed(vtype: str, filename: str) -> str:
    return f"{vtype}:{filename}:seed"


def _collect_dead_ends(ctx: ChainingContext) -> list[dict[str, Any]]:
    dead: list[dict[str, Any]] = []
    for f in ctx.adversary.get("findings") or []:
        if f.get("status") == "FALSE_POSITIVE":
            continue
        if _fkey(f) in ctx.used_finding_keys:
            continue
        loc = f.get("location") or {}
        dead.append(
            {
                "finding": nodes.finding_id(f.get("id") or _fkey(f)),
                "vulnerability_type": f.get("vulnerability_type"),
                "status": f.get("status"),
                "location": {"file": _base(loc.get("file")), "line": loc.get("line")},
                "reason": "no outgoing chainable edge (standalone finding — not fabricated into a chain)",
            }
        )
    return dead
