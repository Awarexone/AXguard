"""Inert LLM evidence stub.

This stub exists to document the seam where an LLM *could* narrate evidence in
the future. It makes **no** external calls and can only rephrase evidence that
already exists in the store. It can never create new evidence, upgrade quality,
change a location, or turn a comment into proof of safety. If asked to explain
something with no backing evidence it returns ``REQUIRES_REVIEW`` / ``UNKNOWN``.
"""

from __future__ import annotations

from typing import Any


class LLMEvidenceStub:
    """Explain-only, non-inventing evidence narrator (no network calls)."""

    name = "llm-stub"

    def explain(
        self,
        evidence_ids: list[str],
        store: Any,
    ) -> dict[str, Any]:
        """Return a plain-language explanation of *existing* evidence only."""
        resolved: list[dict[str, Any]] = []
        for eid in evidence_ids or []:
            item = store.get(eid) if hasattr(store, "get") else None
            if item is not None:
                resolved.append(item)

        if not resolved:
            return {
                "explainer": self.name,
                "verdict": "REQUIRES_REVIEW",
                "confidence": "UNKNOWN",
                "explanation": (
                    "No existing evidence to explain; the LLM stub never invents "
                    "evidence. Prefer manual review."
                ),
                "evidence_ids": [],
                "invented_evidence": False,
            }

        lines = [
            f"- [{it.get('quality')}] {it.get('type')} @ "
            f"{it.get('file')}:{it.get('line_start')} — {it.get('description')}"
            for it in resolved
        ]
        return {
            "explainer": self.name,
            "verdict": "EXPLAINED",
            "confidence": "UNKNOWN",  # a stub never asserts confidence itself
            "explanation": "Existing evidence, restated (no new claims):\n"
            + "\n".join(lines),
            "evidence_ids": [str(it.get("id")) for it in resolved],
            "invented_evidence": False,
        }

    def invent(self, *args: Any, **kwargs: Any) -> None:
        """Explicitly unsupported — the stub can never invent evidence."""
        raise NotImplementedError(
            "LLMEvidenceStub cannot invent evidence; it may only explain existing items."
        )


def default_llm_stub() -> LLMEvidenceStub:
    return LLMEvidenceStub()
