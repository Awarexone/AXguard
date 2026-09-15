"""Virtual attacker profiles for symbolic simulation."""

from __future__ import annotations

from typing import Any

from engines.twin.schema import (
    ATTACKER_ADMIN,
    ATTACKER_AUTHENTICATED_USER,
    ATTACKER_COMPROMISED_AGENT,
    ATTACKER_COMPROMISED_EXTERNAL_SERVICE,
    ATTACKER_COMPROMISED_TOOL,
    ATTACKER_LOW_PRIVILEGE_USER,
    ATTACKER_MALICIOUS_DEPENDENCY,
    ATTACKER_MALICIOUS_DOCUMENT,
    ATTACKER_PROFILES,
    ATTACKER_PUBLIC_USER,
    ATTACKER_TENANT_USER,
    LAYER_ASSUMED,
    LAYER_INFERRED,
    LAYER_OBSERVED,
    LAYER_SIMULATED,
    tagged,
)

_PROFILE_SPECS: dict[str, dict[str, Any]] = {
    ATTACKER_PUBLIC_USER: {
        "starting_identity": "ANONYMOUS",
        "trust_level": "none",
        "capabilities": ["reach_public_endpoints"],
        "description": "Unauthenticated internet user with no prior access.",
    },
    ATTACKER_AUTHENTICATED_USER: {
        "starting_identity": "AUTHENTICATED_USER",
        "trust_level": "low",
        "capabilities": ["valid_session", "reach_authenticated_endpoints"],
        "description": "Authenticated low-privilege user with a valid session.",
    },
    ATTACKER_LOW_PRIVILEGE_USER: {
        "starting_identity": "AUTHENTICATED_USER",
        "trust_level": "low",
        "capabilities": ["valid_session", "limited_scope"],
        "description": "Authenticated user with explicitly low privileges.",
    },
    ATTACKER_TENANT_USER: {
        "starting_identity": "TENANT_USER",
        "trust_level": "tenant_scoped",
        "capabilities": ["valid_session", "tenant_scope"],
        "description": "Authenticated user scoped to a single tenant.",
    },
    ATTACKER_ADMIN: {
        "starting_identity": "PRIVILEGED_USER",
        "trust_level": "high",
        "capabilities": ["admin_session", "elevated_operations"],
        "description": "Administrator or privileged-role holder (assumed for what-if).",
    },
    ATTACKER_COMPROMISED_AGENT: {
        "starting_identity": "AI_AGENT",
        "trust_level": "agent_compromised",
        "capabilities": ["tool_invocation", "prompt_injection_vector"],
        "description": "AI agent whose instruction context was compromised.",
    },
    ATTACKER_COMPROMISED_TOOL: {
        "starting_identity": "AI_AGENT",
        "trust_level": "tool_compromised",
        "capabilities": ["malicious_tool_output", "confused_deputy"],
        "description": "Agent operating with a compromised or malicious tool.",
    },
    ATTACKER_MALICIOUS_DOCUMENT: {
        "starting_identity": "AUTHENTICATED_USER",
        "trust_level": "document_vector",
        "capabilities": ["indirect_prompt_injection"],
        "description": "Attacker via malicious document ingested by an agent.",
    },
    ATTACKER_MALICIOUS_DEPENDENCY: {
        "starting_identity": "UNKNOWN",
        "trust_level": "supply_chain",
        "capabilities": ["dependency_execution", "build_time_access"],
        "description": "Attacker via compromised dependency in the supply chain.",
    },
    ATTACKER_COMPROMISED_EXTERNAL_SERVICE: {
        "starting_identity": "SERVICE",
        "trust_level": "external_compromised",
        "capabilities": ["webhook_callback", "oauth_token_abuse"],
        "description": "Attacker controlling a trusted external integration.",
    },
}


def virtual_attacker(profile: str, twin: dict[str, Any]) -> dict[str, Any]:
    """Return a symbolic attacker position derived from ``profile`` and ``twin``.

    All fields are tagged ASSUMED or SIMULATED — never presented as observed fact.
    """
    key = str(profile or ATTACKER_PUBLIC_USER).strip().upper()
    if key not in ATTACKER_PROFILES:
        key = ATTACKER_PUBLIC_USER

    spec = _PROFILE_SPECS[key]
    entrypoints = _observed_public_entries(twin)

    return {
        "profile": tagged(key, LAYER_ASSUMED),
        "starting_identity": tagged(spec["starting_identity"], LAYER_ASSUMED),
        "trust_level": tagged(spec["trust_level"], LAYER_ASSUMED),
        "capabilities": tagged(list(spec["capabilities"]), LAYER_SIMULATED),
        "description": tagged(spec["description"], LAYER_ASSUMED),
        "starting_entrypoints": tagged(entrypoints, LAYER_OBSERVED if entrypoints else LAYER_INFERRED),
        "layer": LAYER_SIMULATED,
        "disclaimer": (
            "Virtual attacker profile — symbolic starting position only. "
            "Does not execute exploits or perform network actions."
        ),
    }


def _observed_public_entries(twin: dict[str, Any]) -> list[str]:
    out: list[str] = []
    ag = twin.get("attack_graph") or {}
    graph = ag.get("graph") or {}
    for node in graph.get("nodes") or []:
        if node.get("type") != "entrypoint":
            continue
        reach = str(node.get("reachability") or "unknown")
        if reach in {"public", "unauthenticated"}:
            out.append(str(node.get("id")))
    return sorted(out)
