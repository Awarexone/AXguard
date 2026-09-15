"""Domain / category classification helpers."""

from __future__ import annotations

from typing import Any

from engines.data.schema import CATEGORIES


_KEYWORD_MAP: list[tuple[str, tuple[str, ...]]] = [
    ("PROMPT_INJECTION", ("prompt injection", "jailbreak", "system prompt")),
    ("MCP_SECURITY", ("mcp", "model context protocol")),
    ("AI_AGENT_SECURITY", ("agent", "tool abuse", "tool permission")),
    ("AI_SECURITY", ("llm", "rag poisoning", "ai security")),
    ("FALSE_POSITIVE", ("false positive", "safe parameterization")),
    ("ATTACK_GRAPH", ("attack path", "attack graph", "attack chain")),
    ("SUPPLY_CHAIN", ("sbom", "dependency", "supply chain")),
    ("AUTHORIZATION", ("idor", "bola", "authz", "tenant")),
    ("AUTHENTICATION", ("authn", "jwt", "session", "oauth")),
    ("WEB_SECURITY", ("xss", "csrf", "ssrf")),
    ("CODE_VULNERABILITY", ("sql injection", "cwe-", "vulnerable")),
]


def classify_text(text: str) -> list[str]:
    low = text.lower()
    hits: list[str] = []
    for cat, kws in _KEYWORD_MAP:
        if any(k in low for k in kws):
            hits.append(cat)
    return [h for h in hits if h in CATEGORIES]


def classify_example(example: dict[str, Any]) -> list[str]:
    parts = [
        str(example.get("kind") or ""),
        str(example.get("vulnerability_type") or ""),
        str(example.get("category") or ""),
        str(example.get("prompt") or "")[:200],
        str(example.get("code") or "")[:200],
    ]
    found = classify_text(" ".join(parts))
    kind = str(example.get("kind") or "")
    if kind and kind in CATEGORIES and kind not in found:
        found.insert(0, kind)
    return found
