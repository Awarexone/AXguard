"""AXguard Security Memory — persistent longitudinal security intelligence.

Project-local store under ``.findings/axguard/memory/`` (never ``~/.axguard``).
Prefer UNKNOWN over inventing. Immutable updates. Soft-optional twin import.
"""

from __future__ import annotations

from engines.memory.changes import compare_revisions, compare_snapshots
from engines.memory.explain import explain_item
from engines.memory.export_dataset import EVALUATION_ONLY, export_evaluation_dataset
from engines.memory.fingerprints import (
    control_fingerprint,
    evidence_fingerprint,
    finding_fingerprint,
    path_fingerprint,
)
from engines.memory.invalidate import (
    invalidate_control,
    invalidate_for_file_changes,
    mark_fp_for_reevaluation,
)
from engines.memory.lifecycle import assert_consistency, transition_finding
from engines.memory.pipeline import (
    list_memory_snapshots,
    run_memory_changes,
    run_memory_record,
    run_memory_regressions,
)
from engines.memory.poisoning import sanitize_ingest
from engines.memory.query import (
    answer_memory_query,
    get_assumptions,
    get_attack_paths,
    get_changes,
    get_controls,
    get_current_state,
    get_findings,
    get_history,
    get_invalidated_evidence,
    get_memory,
    get_regressions,
    get_rejected_findings,
    get_unknowns,
)
from engines.memory.record import (
    remember_from_attack_graph,
    remember_from_audit,
    record_attack_path,
    record_control,
    record_decision,
    record_finding,
    record_verification,
)
from engines.memory.regress import detect_regressions
from engines.memory.report import (
    render_memory_html_section,
    render_memory_markdown,
    write_memory_report,
)
from engines.memory.schema import (
    SECURITY_MEMORY_VERSION,
    empty_ledger,
    empty_memory_index,
    empty_snapshot,
)
from engines.memory.store import (
    DEFAULT_MEMORY_DIR,
    list_snapshots,
    load_index,
    load_ledger,
    load_snapshot,
    save_index,
    save_ledger,
    write_snapshot,
)

__all__ = [
    "SECURITY_MEMORY_VERSION",
    "DEFAULT_MEMORY_DIR",
    "EVALUATION_ONLY",
    "empty_memory_index",
    "empty_snapshot",
    "empty_ledger",
    "finding_fingerprint",
    "path_fingerprint",
    "control_fingerprint",
    "evidence_fingerprint",
    "load_index",
    "save_index",
    "load_ledger",
    "save_ledger",
    "write_snapshot",
    "load_snapshot",
    "list_snapshots",
    "remember_from_audit",
    "remember_from_attack_graph",
    "record_finding",
    "record_control",
    "record_attack_path",
    "record_verification",
    "record_decision",
    "transition_finding",
    "assert_consistency",
    "invalidate_for_file_changes",
    "invalidate_control",
    "mark_fp_for_reevaluation",
    "detect_regressions",
    "compare_revisions",
    "compare_snapshots",
    "answer_memory_query",
    "get_memory",
    "get_history",
    "get_current_state",
    "get_findings",
    "get_rejected_findings",
    "get_controls",
    "get_attack_paths",
    "get_changes",
    "get_regressions",
    "get_invalidated_evidence",
    "get_unknowns",
    "get_assumptions",
    "sanitize_ingest",
    "export_evaluation_dataset",
    "render_memory_markdown",
    "render_memory_html_section",
    "write_memory_report",
    "run_memory_record",
    "run_memory_changes",
    "run_memory_regressions",
    "list_memory_snapshots",
    "explain_item",
]
