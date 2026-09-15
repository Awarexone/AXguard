"""Export Q/A examples from a Security Twin (evaluation-only)."""

from __future__ import annotations

from typing import Any

from engines.data.schema import STATUS_EVALUATION_ONLY
from engines.twin.query import answer_query

_CATEGORY = "SECURITY_REASONING"


def export_twin_examples(
    twin: dict[str, Any],
    counterfactual_results: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Produce training-compatible Q/A examples tagged EVALUATION_ONLY."""
    target = twin.get("target") or "unknown"
    examples: list[dict[str, Any]] = []

    questions = [
        "What is the blast radius of the primary agent?",
        "Which controls protect the most paths?",
        "Are there cross-tenant attack paths?",
        "What is the highest privilege agent?",
        "What if authorization control is removed?",
        "What happens if MCP server is compromised?",
    ]

    for i, q in enumerate(questions):
        result = answer_query(twin, q)
        examples.append(
            _make_example(
                example_id=f"twin-{target}-{i:03d}",
                question=q,
                answer=result.get("answer"),
                intent=result.get("intent"),
                fact_layers=_extract_layers(result),
            )
        )

    if counterfactual_results:
        cf_q = f"What if {counterfactual_results.get('scenario', {}).get('value', 'scenario')}?"
        examples.append(
            _make_example(
                example_id=f"twin-{target}-cf",
                question=cf_q,
                answer={
                    "simulated_paths": len(counterfactual_results.get("simulated_paths") or []),
                    "assumptions": counterfactual_results.get("assumptions"),
                },
                intent="counterfactual",
                fact_layers=["SIMULATED", "ASSUMED"],
            )
        )

    summary = twin.get("summary") or {}
    examples.append(
        _make_example(
            example_id=f"twin-{target}-summary",
            question=f"Summarize the security twin for {target}",
            answer=summary,
            intent="summary",
            fact_layers=["OBSERVED"],
        )
    )

    return examples


def _make_example(
    *,
    example_id: str,
    question: str,
    answer: Any,
    intent: str,
    fact_layers: list[str],
) -> dict[str, Any]:
    return {
        "id": example_id,
        "question": question,
        "answer": answer,
        "labels": {
            "category": _CATEGORY,
            "intent": intent,
            "status": STATUS_EVALUATION_ONLY,
        },
        "fact_layers": fact_layers,
        "metadata": {"source": "security_twin", "training": False},
    }


def _extract_layers(result: dict[str, Any]) -> list[str]:
    layer = result.get("layer")
    if layer:
        return [str(layer)]
    return ["OBSERVED"]
