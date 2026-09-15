"""Inert LLM attack-path narrator stub.

This stub documents the seam where an LLM *could* narrate an attack path in
prose in the future. It makes **no** external calls and can only rephrase
nodes/edges that already exist in the graph. It can never invent a node, an
edge, a credential, an impact claim, or a reachability assertion. Asked to
explain something with no backing graph element, it returns
``REQUIRES_REVIEW`` / ``UNKNOWN``.
"""

from __future__ import annotations

from typing import Any


class LLMAttackPathStub:
    """Explain-only, non-inventing attack-path narrator (no network calls)."""

    name = "llm-attackpath-stub"

    def explain(self, path: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
        """Return a plain-language restatement of an *existing* path only."""
        nodes_by_id = {n.get("id"): n for n in (graph.get("nodes") or [])}
        hop_ids = list(path.get("hops") or []) if path else []
        resolved = [nodes_by_id[h] for h in hop_ids if h in nodes_by_id]

        if not resolved:
            return {
                "explainer": self.name,
                "verdict": "REQUIRES_REVIEW",
                "confidence": "UNKNOWN",
                "explanation": (
                    "No existing graph nodes to explain; the LLM stub never "
                    "invents nodes, edges, credentials, impact, or reachability."
                ),
                "hops": [],
                "invented": False,
            }

        line = " → ".join(
            f"[{n.get('type')}] {n.get('label') or n.get('id')}" for n in resolved
        )
        return {
            "explainer": self.name,
            "verdict": "EXPLAINED",
            "confidence": "UNKNOWN",  # a stub never asserts confidence itself
            "explanation": "Existing path, restated (no new claims):\n" + line,
            "hops": [str(n.get("id")) for n in resolved],
            "invented": False,
        }

    def invent(self, *args: Any, **kwargs: Any) -> None:
        """Explicitly unsupported — the stub can never invent graph elements."""
        raise NotImplementedError(
            "LLMAttackPathStub cannot invent nodes, edges, credentials, impact, "
            "or reachability; it may only explain existing graph elements."
        )


def default_llm_stub() -> LLMAttackPathStub:
    return LLMAttackPathStub()
