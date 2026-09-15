"""Specialist selection — do not run every specialist on every finding."""

from __future__ import annotations

from typing import Any

# Conceptual specialists mapped to AXGuard capabilities (orchestration labels)
SPECIALIST_SQL = "SQL_HUNTER"
SPECIALIST_EGRESS = "EGRESS_HUNTER"
SPECIALIST_ACCESS = "ACCESS_CONTROL"
SPECIALIST_CLIENT = "CLIENT_SECURITY"
SPECIALIST_AGENT = "AGENT_SECURITY"
SPECIALIST_DATAFLOW = "DATA_FLOW"
SPECIALIST_JUDGE = "SECURITY_JUDGE"
SPECIALIST_ADVERSARY = "FALSE_POSITIVE_ADVERSARY"
SPECIALIST_ATTACK_GRAPH = "ATTACK_GRAPH"
SPECIALIST_TWIN = "SECURITY_TWIN"
SPECIALIST_MEMORY = "SECURITY_MEMORY"
SPECIALIST_MCP = "MCP_ANALYSIS"

_KIND_MAP: list[tuple[tuple[str, ...], list[str]]] = [
    (
        ("sql", "sqli", "sql-injection", "sql_injection"),
        [SPECIALIST_SQL, SPECIALIST_DATAFLOW, SPECIALIST_JUDGE, SPECIALIST_ADVERSARY],
    ),
    (
        ("ssrf", "egress", "url-fetch", "server-side-request"),
        [SPECIALIST_EGRESS, SPECIALIST_DATAFLOW, SPECIALIST_ATTACK_GRAPH, SPECIALIST_JUDGE],
    ),
    (
        ("idor", "bola", "broken-object", "access-control", "authz"),
        [
            SPECIALIST_ACCESS,
            SPECIALIST_DATAFLOW,
            SPECIALIST_ATTACK_GRAPH,
            SPECIALIST_ADVERSARY,
        ],
    ),
    (
        ("xss", "cross-site", "html-injection", "dom-xss"),
        [SPECIALIST_CLIENT, SPECIALIST_DATAFLOW, SPECIALIST_JUDGE],
    ),
    (
        ("prompt", "agent", "llm", "tool-poison", "jailbreak"),
        [
            SPECIALIST_AGENT,
            SPECIALIST_TWIN,
            SPECIALIST_ATTACK_GRAPH,
            SPECIALIST_JUDGE,
        ],
    ),
    (
        ("mcp", "model-context", "tool-permission"),
        [
            SPECIALIST_MCP,
            SPECIALIST_AGENT,
            SPECIALIST_TWIN,
            SPECIALIST_ATTACK_GRAPH,
        ],
    ),
    (
        ("cmdi", "command", "os-command", "rce", "shell"),
        [SPECIALIST_DATAFLOW, SPECIALIST_ADVERSARY, SPECIALIST_JUDGE],
    ),
    (
        ("path", "traversal", "lfi", "rfi"),
        [SPECIALIST_DATAFLOW, SPECIALIST_JUDGE, SPECIALIST_ADVERSARY],
    ),
]


def candidate_kind(candidate: dict[str, Any]) -> str:
    raw: Any = candidate.get("vulnerability_type") or candidate.get("type")
    root = candidate.get("root_cause")
    if not raw and isinstance(root, dict):
        raw = root.get("kind")
    if not raw:
        raw = candidate.get("id") or ""
    return str(raw).lower().replace("_", "-")


def select_specialists(
    candidate: dict[str, Any],
    *,
    max_specialists: int = 4,
    include_memory: bool = True,
) -> list[str]:
    """Return ordered specialist labels for this candidate kind."""
    kind = candidate_kind(candidate)
    chosen: list[str] = []
    for needles, specs in _KIND_MAP:
        if any(n in kind for n in needles):
            chosen.extend(specs)
            break
    if not chosen:
        chosen = [SPECIALIST_DATAFLOW, SPECIALIST_JUDGE, SPECIALIST_ADVERSARY]
    # Always allow memory check first when available
    if include_memory and SPECIALIST_MEMORY not in chosen:
        chosen = [SPECIALIST_MEMORY] + chosen
    # Dedupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for s in chosen:
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= max_specialists:
            break
    return out
