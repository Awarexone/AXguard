"""Attack Graph & Vulnerability Chaining engine (Phase 6).

A composition layer over Phase 1-5: it chains individually-reported findings
into multi-hop attack paths (``entrypoint → … → sensitive outcome``) and reuses
the existing confidence/evidence vocabulary rather than inventing a second one.
"""

from __future__ import annotations

from engines.attack_graph.pipeline import (
    run_attack_graph,
    write_attack_graph_report,
)
from engines.attack_graph.schema import ATTACK_GRAPH_VERSION
from engines.attack_graph.summarize import render_attack_paths_markdown

__all__ = [
    "ATTACK_GRAPH_VERSION",
    "run_attack_graph",
    "write_attack_graph_report",
    "render_attack_paths_markdown",
]
