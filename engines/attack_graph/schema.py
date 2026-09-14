"""Attack Graph engine (Phase 6) schema constants and factories.

Phase 6 is a **composition layer**. It invents no new confidence system and no
new evidence-weight table: it consumes the Phase 1-5 vocabulary
(``engines.app_model`` / ``engines.dataflow`` / ``engines.verify`` /
``engines.adversary`` and the Phase 5 evidence ledger) and reuses
``engines.dataflow.schema.ensure_no_secret_values`` for redaction.

This module only defines the *vocabulary* (node/edge/path/status constants),
the scoring constants (documented in ``docs/attack-graph.md``), and the empty
result factory. All graph construction lives in the sibling modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ATTACK_GRAPH_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# ---------------------------------------------------------------------------
# Node types (see docs/attack-graph.md "Node types")
# ---------------------------------------------------------------------------
NODE_ENTRYPOINT = "entrypoint"
NODE_FINDING = "finding"
NODE_CONTROL = "control"
NODE_ASSET = "asset"
NODE_IDENTITY = "identity"
NODE_AI_COMPONENT = "ai_component"
NODE_TOOL = "tool"
NODE_EXTERNAL_SERVICE = "external_service"
NODE_TRUST_BOUNDARY = "trust_boundary"
NODE_CANDIDATE_SEED = "candidate_seed"  # attack-graph-scoped finding-like node

NODE_TYPES = frozenset(
    {
        NODE_ENTRYPOINT,
        NODE_FINDING,
        NODE_CONTROL,
        NODE_ASSET,
        NODE_IDENTITY,
        NODE_AI_COMPONENT,
        NODE_TOOL,
        NODE_EXTERNAL_SERVICE,
        NODE_TRUST_BOUNDARY,
        NODE_CANDIDATE_SEED,
    }
)

# ---------------------------------------------------------------------------
# Edge types (see docs/attack-graph.md "Edge types")
# ---------------------------------------------------------------------------
EDGE_REACHES = "reaches"
EDGE_TRIGGERS = "triggers"
EDGE_EXPOSES = "exposes"
EDGE_ESCALATES_TO = "escalates_to"
EDGE_CROSSES_TENANT = "crosses_tenant"
EDGE_INVOKES = "invokes"
EDGE_YIELDS = "yields"
EDGE_BLOCKED_BY = "blocked_by"
EDGE_CHAINS_TO = "chains_to"

EDGE_TYPES = frozenset(
    {
        EDGE_REACHES,
        EDGE_TRIGGERS,
        EDGE_EXPOSES,
        EDGE_ESCALATES_TO,
        EDGE_CROSSES_TENANT,
        EDGE_INVOKES,
        EDGE_YIELDS,
        EDGE_BLOCKED_BY,
        EDGE_CHAINS_TO,
    }
)

# ---------------------------------------------------------------------------
# Edge / hop confidence — legacy Phase 1-5 vocabulary (NOT a new scale)
# ---------------------------------------------------------------------------
EDGE_CONFIRMED = "confirmed"
EDGE_LIKELY = "likely"
EDGE_UNKNOWN = "unknown"
EDGE_CONFIDENCES = frozenset({EDGE_CONFIRMED, EDGE_LIKELY, EDGE_UNKNOWN})

# ---------------------------------------------------------------------------
# Path status (property of the whole chain — never averaged, never invented)
# ---------------------------------------------------------------------------
PATH_CONFIRMED = "CONFIRMED"
PATH_LIKELY = "LIKELY"
PATH_UNVERIFIED = "UNVERIFIED"
PATH_INVALID = "INVALID"
PATH_BLOCKED = "BLOCKED"
PATH_STATUSES = frozenset(
    {
        PATH_CONFIRMED,
        PATH_LIKELY,
        PATH_UNVERIFIED,
        PATH_INVALID,
        PATH_BLOCKED,
    }
)

# Map an adversary/finding status → the path-status tier that a single hop of
# that status can contribute. FALSE_POSITIVE vetoes the whole chain.
FINDING_STATUS_TO_PATH = {
    "CONFIRMED": PATH_CONFIRMED,
    "LIKELY": PATH_LIKELY,
    "UNVERIFIED": PATH_UNVERIFIED,
    "REQUIRES_REVIEW": PATH_UNVERIFIED,
    "FALSE_POSITIVE": PATH_INVALID,
    "INVALID": PATH_INVALID,
}

# Weakest-link ordering (worst first). Used to compute a path's status from the
# statuses of its hops: the path is only as strong as its weakest hop.
PATH_TIER_RANK = {
    PATH_INVALID: 0,
    PATH_BLOCKED: 1,
    PATH_UNVERIFIED: 2,
    PATH_LIKELY: 3,
    PATH_CONFIRMED: 4,
}

# ---------------------------------------------------------------------------
# Phase 5 confidence levels (reused verbatim for path.confidence_level)
# ---------------------------------------------------------------------------
CONF_UNKNOWN = "UNKNOWN"
CONF_LOW = "LOW"
CONF_MEDIUM = "MEDIUM"
CONF_HIGH = "HIGH"
CONF_VERY_HIGH = "VERY_HIGH"
CONFIDENCE_LEVELS = (CONF_UNKNOWN, CONF_LOW, CONF_MEDIUM, CONF_HIGH, CONF_VERY_HIGH)
CONFIDENCE_RANK = {name: i for i, name in enumerate(CONFIDENCE_LEVELS)}

# Fallback anchor for attack-graph seed nodes that carry no Phase 5 evidence
# confidence_level of their own (structural seeds). These never exceed MEDIUM —
# a structural pattern is at best "likely", never "confirmed".
SEED_STATUS_TO_CONFIDENCE = {
    "CONFIRMED": CONF_HIGH,
    "LIKELY": CONF_MEDIUM,
    "UNVERIFIED": CONF_UNKNOWN,
    "INVALID": CONF_LOW,
}

# ---------------------------------------------------------------------------
# Control effectiveness (mirrors engines/dataflow/controls.py vocabulary)
# ---------------------------------------------------------------------------
EFFECT_CONFIRMED = "confirmed"
EFFECT_LIKELY = "likely"
EFFECT_UNKNOWN = "unknown"
EFFECT_INEFFECTIVE = "ineffective"

# ---------------------------------------------------------------------------
# Scoring constants (documented in docs/attack-graph.md "Scoring factors").
# Score is a ranking aid for triage order, NOT a new severity system.
# ---------------------------------------------------------------------------
# 1. Weakest-link confidence (dominant factor).
SCORE_STATUS_WEIGHT = {
    PATH_CONFIRMED: 1.0,
    PATH_LIKELY: 0.65,
    PATH_UNVERIFIED: 0.35,
    PATH_BLOCKED: 0.15,
    PATH_INVALID: 0.0,
}
# 3. Asset impact tier (credentials/secrets/admin > PII/financial > internal).
ASSET_IMPACT_TIER = {
    "secret": 1.0,
    "credential": 1.0,
    "token": 1.0,
    "admin": 1.0,
    "filesystem": 0.85,
    "pii": 0.75,
    "financial": 0.75,
    "database": 0.6,
    "internal": 0.4,
    "info": 0.2,
    "unknown": 0.3,
}
# 4. Reachability tier (public unauth > authenticated > internal/queue > prior).
REACHABILITY_TIER = {
    "public": 1.0,
    "unauthenticated": 1.0,
    "authenticated": 0.7,
    "internal": 0.5,
    "queue": 0.45,
    "unknown": 0.4,
    "requires_prior_compromise": 0.35,
}
# 6. AI/agent multiplier — a chain ending in autonomous tool execution is
# higher priority at equal confidence (impact can be automated / repeated).
AI_AGENT_MULTIPLIER = 1.15

# Weights for combining scoring factors (sum documented in the design doc).
SCORE_WEIGHTS = {
    "confidence": 0.5,  # weakest-link confidence dominates
    "asset_impact": 0.25,
    "reachability": 0.15,
    "directness": 0.10,  # shorter paths outrank longer at equal confidence
}

# ---------------------------------------------------------------------------
# Enumeration limits (bounded search — never fabricate depth for drama)
# ---------------------------------------------------------------------------
MAX_PATH_DEPTH = 8  # max hops (nodes) in a single path
MAX_PATHS = 200  # global cap on enumerated paths


def empty_attack_graph(target: Path) -> dict[str, Any]:
    root = str(Path(target).resolve())
    return {
        "schema_version": ATTACK_GRAPH_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "graph": {"nodes": [], "edges": []},
        "paths": [],
        "dead_ends": [],
        "alternate_paths": [],
        "summary": {
            "path_count": 0,
            "dead_end_count": 0,
            "node_count": 0,
            "edge_count": 0,
            "by_status": {s: 0 for s in sorted(PATH_STATUSES)},
        },
        "meta": {},
    }
