"""Scenario template catalog (metadata only)."""

from __future__ import annotations

from typing import Any

from engines.twin.schema import SCENARIO_LIBRARY_KEYS

_TEMPLATES: dict[str, dict[str, Any]] = {
    "prompt_injection": {
        "title": "Prompt injection via user content",
        "theme": "OWASP LLM01",
        "description": "Attacker embeds instructions in content processed by an AI agent.",
        "attack_graph_scenario": None,
        "tags": ["ai", "prompt_injection"],
    },
    "tool_misuse": {
        "title": "Agent tool misuse / over-scoped tool",
        "theme": "OWASP LLM06",
        "description": "Compromised agent invokes a tool beyond its intended scope.",
        "attack_graph_scenario": "ai_tool_gains_fs",
        "tags": ["ai", "tool"],
    },
    "mcp_supply_chain": {
        "title": "MCP server supply-chain compromise",
        "theme": "MCP security",
        "description": "Malicious or compromised MCP server exposes agent capabilities.",
        "attack_graph_scenario": "ai_tool_gains_fs",
        "tags": ["mcp", "supply_chain"],
    },
    "agent_privilege_escalation": {
        "title": "Agent privilege escalation",
        "theme": "OWASP LLM08",
        "description": "Agent gains elevated privileges via confused deputy or tool chaining.",
        "attack_graph_scenario": "remove_authz",
        "tags": ["ai", "privilege"],
    },
    "cross_tenant_agent": {
        "title": "Cross-tenant data access via agent",
        "theme": "Multi-tenancy",
        "description": "Agent or tool bypasses tenant isolation boundaries.",
        "attack_graph_scenario": "tenant_isolation_weakened",
        "tags": ["tenant", "ai"],
    },
    "secret_exposure": {
        "title": "Secret / credential exposure",
        "theme": "Secrets management",
        "description": "Credential leaks via logs, VCS, or agent context.",
        "attack_graph_scenario": "secret_leaks",
        "tags": ["secret", "credential"],
    },
    "public_endpoint": {
        "title": "Internal endpoint made public",
        "theme": "Attack surface",
        "description": "Authenticated or internal route exposed without auth.",
        "attack_graph_scenario": "publicize_endpoint",
        "tags": ["endpoint", "auth"],
    },
    "authz_regression": {
        "title": "Authorization control regression",
        "theme": "Broken access control",
        "description": "Effective authorization barrier removed or weakened.",
        "attack_graph_scenario": "remove_authz",
        "tags": ["authz", "control"],
    },
    "unrestricted_egress": {
        "title": "Unrestricted outbound egress",
        "theme": "SSRF / exfiltration",
        "description": "Network egress allowlist removed enabling exfiltration.",
        "attack_graph_scenario": "unrestricted_egress",
        "tags": ["network", "ssrf"],
    },
    "compromised_mcp_server": {
        "title": "Compromised MCP server",
        "theme": "MCP security",
        "description": "Attacker controls MCP server trusted by the agent runtime.",
        "attack_graph_scenario": "ai_tool_gains_fs",
        "tags": ["mcp", "supply_chain"],
    },
    "malicious_dependency": {
        "title": "Malicious dependency injection",
        "theme": "Supply chain",
        "description": "Compromised package executes during build or runtime.",
        "attack_graph_scenario": None,
        "tags": ["supply_chain", "dependency"],
    },
    "confused_deputy": {
        "title": "Confused deputy via trusted component",
        "theme": "Authorization",
        "description": "Trusted service performs action on attacker's behalf.",
        "attack_graph_scenario": "remove_authz",
        "tags": ["authz", "deputy"],
    },
}


def list_scenarios() -> list[dict[str, Any]]:
    """Return scenario template metadata sorted by key."""
    out: list[dict[str, Any]] = []
    for key in SCENARIO_LIBRARY_KEYS:
        spec = _TEMPLATES.get(key, {})
        out.append({"key": key, **spec})
    return out


def get_scenario(key: str) -> dict[str, Any] | None:
    spec = _TEMPLATES.get(str(key).strip())
    if not spec:
        return None
    return {"key": key, **spec}
