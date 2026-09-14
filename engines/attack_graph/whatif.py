"""Counterfactual "what-if" scenarios (Phase 6 Part 2).

Given a *current* attack-graph result (the output of
:func:`engines.attack_graph.run_attack_graph`), this module answers "what would
change if the architecture were weakened in a specific way?".

**Honesty contract.** Every path this module emits is *predictive /
counterfactual*, not a current finding:

- each hypothetical path carries ``hypothetical: true`` and
  ``status: "PREDICTIVE"``;
- each carries an explicit ``premise`` ("IF <change> …") and a ``disclaimer``;
- a scenario only emits a path when the *current* graph already contains the
  real elements the counterfactual would act on (an entrypoint, an asset, an
  agent, …). A scenario that matches nothing emits nothing — it never
  fabricates nodes, edges, credentials, or reachability.

Nothing here is ever merged into the real ``paths[]`` list; callers keep
``hypothetical_paths`` in a clearly separate bucket. The wording deliberately
avoids the word "vulnerability" for these predictive artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

# Predictive paths use their own status label so they can NEVER be confused with
# the real CONFIRMED/LIKELY/UNVERIFIED/BLOCKED/INVALID path statuses.
HYPOTHETICAL_STATUS = "PREDICTIVE"

_DISCLAIMER = (
    "Predictive / counterfactual — NOT a current security finding. This path "
    "only materialises IF the stated hypothetical architecture change is made; "
    "the current graph does not contain it."
)


# ---------------------------------------------------------------------------
# small read-only helpers over a run_attack_graph() result dict
# ---------------------------------------------------------------------------
def _nodes(result: dict[str, Any]) -> list[dict[str, Any]]:
    return list((result.get("graph") or {}).get("nodes") or [])


def _nodes_by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {n.get("id"): n for n in _nodes(result)}


def _nodes_of_type(result: dict[str, Any], *types: str) -> list[dict[str, Any]]:
    want = set(types)
    return [n for n in _nodes(result) if n.get("type") in want]


def _paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    return list(result.get("paths") or [])


def _label(nodes_by_id: dict[str, Any], node_id: str) -> str:
    n = nodes_by_id.get(node_id) or {}
    return str(n.get("label") or node_id)


def _hop_labels(result: dict[str, Any], hops: list[str]) -> list[str]:
    nbi = _nodes_by_id(result)
    return [_label(nbi, h) for h in hops]


def _mk_hypo(
    scenario: str,
    title: str,
    premise: str,
    predicted_effect: str,
    *,
    hops: list[str],
    based_on: str | None = None,
    node_labels: list[str] | None = None,
    evidence_basis: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "hypothetical": True,
        "status": HYPOTHETICAL_STATUS,
        "scenario": scenario,
        "title": title,
        "premise": premise,
        "predicted_effect": predicted_effect,
        "based_on_path": based_on,
        "hops": list(hops),
        "hop_labels": node_labels or [],
        # We reference the *real* nodes the counterfactual would act on so a
        # reader can audit the basis — but the link itself is predictive.
        "evidence_basis": evidence_basis or [],
        "disclaimer": _DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# scenario generators — each returns a list of hypothetical paths (possibly [])
# ---------------------------------------------------------------------------
def _scn_remove_authz(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF an effective authorization control were removed / regressed."""
    out: list[dict[str, Any]] = []
    for p in _paths(result):
        controls = p.get("controls_encountered") or []
        effective = [c for c in controls if c.get("effectiveness") in {"confirmed", "likely"}]
        if p.get("status") != "BLOCKED" and not effective:
            continue
        labels = _hop_labels(result, p.get("hops") or [])
        ctrl_ids = [c.get("id") for c in (effective or controls)]
        out.append(
            _mk_hypo(
                "remove_authz",
                "Authorization control removed / regressed",
                premise=(
                    "IF the authorization control(s) "
                    f"{ctrl_ids} on path {p.get('id')} were removed, weakened, "
                    "or bypassed"
                ),
                predicted_effect=(
                    "the currently-BLOCKED chain would become reachable at the "
                    "weakest-hop confidence of its underlying findings — increasing "
                    "security risk. Not exploitable today while the control holds."
                ),
                hops=p.get("hops") or [],
                based_on=p.get("id"),
                node_labels=labels,
                evidence_basis=[{"control": cid} for cid in ctrl_ids if cid],
            )
        )
    return out


def _scn_publicize_endpoint(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF an authenticated / internal / unknown-reachability endpoint were made public."""
    out: list[dict[str, Any]] = []
    nbi = _nodes_by_id(result)
    for p in _paths(result):
        entry = p.get("entry")
        en = nbi.get(entry) or {}
        if en.get("type") != "entrypoint":
            continue
        reach = str(en.get("reachability") or "unknown")
        if reach in {"public", "unauthenticated"}:
            continue  # already public — nothing counterfactual to add
        labels = _hop_labels(result, p.get("hops") or [])
        out.append(
            _mk_hypo(
                "publicize_endpoint",
                "Endpoint made publicly reachable",
                premise=(
                    f"IF entrypoint `{en.get('label')}` (currently {reach}) were "
                    "exposed publicly / had its authentication removed"
                ),
                predicted_effect=(
                    "the reachability tier of this chain would rise to public, "
                    "enlarging the emerging attack surface and raising triage "
                    "priority for the downstream asset."
                ),
                hops=p.get("hops") or [],
                based_on=p.get("id"),
                node_labels=labels,
                evidence_basis=[{"entrypoint": entry, "current_reachability": reach}],
            )
        )
    return out


def _scn_unrestricted_egress(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF outbound network egress were unrestricted (exfiltration / SSRF pivot)."""
    out: list[dict[str, Any]] = []
    externals = _nodes_of_type(result, "external_service")
    # SSRF-flavoured findings/seeds are a natural egress pivot.
    ssrf_like = [
        n
        for n in _nodes_of_type(result, "finding", "candidate_seed")
        if "ssrf" in str(n.get("kind") or "").lower()
    ]
    secrets = [
        n
        for n in _nodes_of_type(result, "asset")
        if str(n.get("kind")) in {"secret", "credential", "token"}
    ]
    if not (externals or ssrf_like) or not secrets:
        return out
    basis_node = (ssrf_like or externals)[0]
    secret = secrets[0]
    out.append(
        _mk_hypo(
            "unrestricted_egress",
            "Unrestricted outbound egress",
            premise=(
                "IF outbound egress from the app/worker were unrestricted (no "
                "allowlist / no network segmentation)"
            ),
            predicted_effect=(
                f"an attacker at `{basis_node.get('label')}` could exfiltrate "
                f"`{secret.get('label')}` to an external host — an emerging "
                "exfiltration surface. No such egress path is proven in the "
                "current graph."
            ),
            hops=[basis_node.get("id"), secret.get("id")],
            node_labels=[basis_node.get("label"), secret.get("label")],
            evidence_basis=[{"pivot": basis_node.get("id"), "asset": secret.get("id")}],
        )
    )
    return out


def _scn_ai_tool_gains_fs(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF an agent's tool gained filesystem / shell access it lacks today."""
    out: list[dict[str, Any]] = []
    agents = _nodes_of_type(result, "ai_component")
    tools = _nodes_of_type(result, "tool")
    if not agents:
        return out
    agent = agents[0]
    fs_assets = [
        n
        for n in _nodes_of_type(result, "asset")
        if str(n.get("kind")) in {"filesystem", "secret", "credential"}
    ]
    target = fs_assets[0] if fs_assets else None
    tool = tools[0] if tools else None
    hops = [agent.get("id")]
    labels = [agent.get("label")]
    if tool:
        hops.append(tool.get("id"))
        labels.append(tool.get("label"))
    if target:
        hops.append(target.get("id"))
        labels.append(target.get("label"))
    out.append(
        _mk_hypo(
            "ai_tool_gains_fs",
            "AI tool gains filesystem / shell access",
            premise=(
                f"IF the agent `{agent.get('label')}` were granted a new tool "
                "with filesystem read/write or shell execution (a capability it "
                "does not have in the current graph)"
            ),
            predicted_effect=(
                "prompt-injected tool calls could reach the host filesystem — an "
                "emerging agent attack surface. Predictive only; the capability "
                "is not present today."
            ),
            hops=hops,
            node_labels=labels,
            evidence_basis=[{"agent": agent.get("id"), "existing_tool": tool.get("id") if tool else None}],
        )
    )
    return out


def _scn_tenant_isolation_weakened(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF a tenant-isolation check were weakened / removed."""
    out: list[dict[str, Any]] = []
    tenant_identities = [
        n for n in _nodes_of_type(result, "identity") if n.get("tenant")
    ]
    pii_assets = [
        n
        for n in _nodes_of_type(result, "asset")
        if str(n.get("kind")) in {"pii", "financial", "database", "credential"}
    ]
    if not pii_assets:
        return out
    asset = pii_assets[0]
    ident = tenant_identities[0] if tenant_identities else None
    hops = ([ident.get("id")] if ident else []) + [asset.get("id")]
    labels = ([ident.get("label")] if ident else []) + [asset.get("label")]
    out.append(
        _mk_hypo(
            "tenant_isolation_weakened",
            "Tenant isolation weakened",
            premise=(
                "IF a tenant-scoping / org_id re-check were weakened or removed "
                "on the query returning "
                f"`{asset.get('label')}`"
            ),
            predicted_effect=(
                "a caller from one tenant could read another tenant's records — "
                "an emerging cross-tenant exposure. Predictive; depends on the "
                "isolation control regressing."
            ),
            hops=hops,
            node_labels=labels,
            evidence_basis=[{"asset": asset.get("id"), "tenant_identity": ident.get("id") if ident else None}],
        )
    )
    return out


def _scn_secret_leaks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """IF a secret/credential leaked (committed to VCS, logged, or shared)."""
    out: list[dict[str, Any]] = []
    secrets = [
        n
        for n in _nodes_of_type(result, "asset")
        if str(n.get("kind")) in {"secret", "credential", "token"}
    ]
    for secret in secrets:
        out.append(
            _mk_hypo(
                "secret_leaks",
                "Secret / credential leaks out of band",
                premise=(
                    f"IF the secret backing `{secret.get('label')}` leaked "
                    "(committed to VCS, written to logs, or shared with a third "
                    "party)"
                ),
                predicted_effect=(
                    "an attacker who never touches the app could use the leaked "
                    "credential directly — an emerging out-of-band risk. This is "
                    "not evidence the secret has leaked; it is a counterfactual."
                ),
                hops=[secret.get("id")],
                node_labels=[secret.get("label")],
                evidence_basis=[{"asset": secret.get("id")}],
            )
        )
    return out


SCENARIOS: dict[str, dict[str, Any]] = {
    "remove_authz": {
        "title": "Authorization control removed / regressed",
        "description": "What becomes reachable if an effective authz barrier is dropped?",
        "generate": _scn_remove_authz,
    },
    "publicize_endpoint": {
        "title": "Endpoint made publicly reachable",
        "description": "What surface grows if an internal/authenticated route goes public?",
        "generate": _scn_publicize_endpoint,
    },
    "unrestricted_egress": {
        "title": "Unrestricted outbound egress",
        "description": "What can be exfiltrated if egress/segmentation is removed?",
        "generate": _scn_unrestricted_egress,
    },
    "ai_tool_gains_fs": {
        "title": "AI tool gains filesystem / shell access",
        "description": "What can a prompt-injected agent reach if a tool is over-scoped?",
        "generate": _scn_ai_tool_gains_fs,
    },
    "tenant_isolation_weakened": {
        "title": "Tenant isolation weakened",
        "description": "What cross-tenant exposure emerges if an org_id check regresses?",
        "generate": _scn_tenant_isolation_weakened,
    },
    "secret_leaks": {
        "title": "Secret / credential leaks out of band",
        "description": "What direct access emerges if a stored credential leaks?",
        "generate": _scn_secret_leaks,
    },
}


def available_scenarios() -> list[str]:
    """Return the sorted list of supported ``--what-if`` scenario keys."""
    return sorted(SCENARIOS)


def run_what_if(result: dict[str, Any], scenario: str) -> dict[str, Any]:
    """Run one counterfactual ``scenario`` against a current attack-graph result.

    Returns a self-contained dict with ``hypothetical_paths`` (each marked
    ``hypothetical: true`` / ``status: PREDICTIVE``). Raises ``KeyError`` for an
    unknown scenario key so callers can list the valid ones.
    """
    key = str(scenario or "").strip()
    if key not in SCENARIOS:
        raise KeyError(
            f"unknown what-if scenario {key!r}; valid: {available_scenarios()}"
        )
    spec = SCENARIOS[key]
    generate: Callable[[dict[str, Any]], list[dict[str, Any]]] = spec["generate"]
    hypo_paths = generate(result)
    for i, p in enumerate(hypo_paths, 1):
        p["id"] = f"hypothetical-{i:04d}"
    return {
        "scenario": key,
        "title": spec["title"],
        "description": spec["description"],
        "status": HYPOTHETICAL_STATUS,
        "hypothetical": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hypothetical_path_count": len(hypo_paths),
        "hypothetical_paths": hypo_paths,
        "disclaimer": _DISCLAIMER,
        "note": (
            "no matching graph elements for this scenario — nothing predicted "
            "(the engine never fabricates a counterfactual with no real basis)"
            if not hypo_paths
            else ""
        ),
    }


def run_all_what_if(result: dict[str, Any]) -> dict[str, Any]:
    """Run every scenario; convenience for reports/benchmarks."""
    return {key: run_what_if(result, key) for key in available_scenarios()}
