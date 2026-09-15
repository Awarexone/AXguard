"""Soft Security Twin bridge — system-level impact questions."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_or_build_twin(
    target: Path | None,
    *,
    attack_graph: dict[str, Any] | None = None,
    application_model: dict[str, Any] | None = None,
    twin: dict[str, Any] | None = None,
    simulate: bool = True,
) -> dict[str, Any]:
    """Return ``{twin, simulation?}`` or empty dict on soft failure."""
    if twin is not None:
        out: dict[str, Any] = {"twin": twin}
        if simulate:
            try:
                from engines.twin.simulate import simulate_attack

                out["simulation"] = simulate_attack(twin)
            except Exception:  # noqa: BLE001
                pass
        return out
    if target is None:
        return {}
    try:
        from engines.twin import build_security_twin
        from engines.twin.simulate import simulate_attack

        built = build_security_twin(
            target,
            attack_graph=attack_graph,
            application_model=application_model,
        )
        out = {"twin": built}
        if simulate:
            out["simulation"] = simulate_attack(built)
        return out
    except Exception:  # noqa: BLE001
        return {}
