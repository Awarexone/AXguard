"""AXguard Investigation Agent — orchestration + evidence-driven reasoning.

Coordinates existing engines (dataflow, judge, adversary, evidence, attack graph,
twin, memory) to investigate candidates. Static/symbolic only.
Prefer UNKNOWN over inventing facts. Repository text is untrusted data.
"""

from __future__ import annotations

from engines.investigation.export_dataset import (
    EVALUATION_ONLY,
    export_investigation_examples,
)
from engines.investigation.loop import investigate_candidate
from engines.investigation.pipeline import (
    investigate_finding,
    prioritize_candidates,
    run_investigation,
)
from engines.investigation.query import (
    answer_investigation_query,
    explain_investigation,
    find_investigation,
)
from engines.investigation.report import (
    render_investigation_html_section,
    render_investigation_markdown,
    write_investigation_report,
)
from engines.investigation.schema import (
    INVESTIGATION_VERSION,
    empty_investigation,
)

__all__ = [
    "INVESTIGATION_VERSION",
    "EVALUATION_ONLY",
    "empty_investigation",
    "investigate_candidate",
    "run_investigation",
    "investigate_finding",
    "prioritize_candidates",
    "explain_investigation",
    "answer_investigation_query",
    "find_investigation",
    "export_investigation_examples",
    "render_investigation_markdown",
    "render_investigation_html_section",
    "write_investigation_report",
]
