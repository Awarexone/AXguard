"""AXGuard Contributor Engagement & Learning System.

Transparent, respectful, opt-in, privacy-preserving.
Local-only by default. Never silently push or open PRs.
"""

from __future__ import annotations

from engines.contributors.cli import (
    add_contribute_parser,
    add_privacy_parser,
    run_contribute_command,
    run_privacy_command,
)
from engines.contributors.extract import extract_pattern
from engines.contributors.hooks import (
    emit_after_adversary_soft,
    emit_after_audit_soft,
    emit_after_memory_soft,
)
from engines.contributors.milestones import list_milestones, record_prepare_milestone
from engines.contributors.prepare import prepare
from engines.contributors.privacy import (
    delete_learning_data,
    export_privacy_bundle,
    is_contribute_opted_in,
    is_learning_opted_in,
    opt_in,
    opt_out,
    reset,
    status as privacy_status,
)
from engines.contributors.quality import assess_quality, filter_strong
from engines.contributors.recognize import (
    CONTRIBUTE_MESSAGE_CATALOG,
    build_recognition_message,
    recognize,
)
from engines.contributors.sanitize import sanitize_example, sanitize_text
from engines.contributors.schema import (
    CONTRIBUTION_TYPES,
    DEFAULT_CONTRIBUTIONS_CONFIG,
    DIFFICULTIES,
    PROVENANCE_STATES,
)
from engines.contributors.signals import OpportunitySignal, best_opportunity, signals_from_context
from engines.contributors.suggest import ContributionInvite, dismiss, suggest
from engines.contributors.templates import get_template, list_templates

__all__ = [
    "add_contribute_parser",
    "add_privacy_parser",
    "run_contribute_command",
    "run_privacy_command",
    "privacy_status",
    "opt_in",
    "opt_out",
    "export_privacy_bundle",
    "delete_learning_data",
    "reset",
    "is_contribute_opted_in",
    "is_learning_opted_in",
    "OpportunitySignal",
    "signals_from_context",
    "best_opportunity",
    "assess_quality",
    "filter_strong",
    "build_recognition_message",
    "recognize",
    "CONTRIBUTE_MESSAGE_CATALOG",
    "ContributionInvite",
    "suggest",
    "dismiss",
    "sanitize_text",
    "sanitize_example",
    "extract_pattern",
    "prepare",
    "list_templates",
    "get_template",
    "list_milestones",
    "record_prepare_milestone",
    "emit_after_audit_soft",
    "emit_after_adversary_soft",
    "emit_after_memory_soft",
    "CONTRIBUTION_TYPES",
    "DIFFICULTIES",
    "PROVENANCE_STATES",
    "DEFAULT_CONTRIBUTIONS_CONFIG",
]
