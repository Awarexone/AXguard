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


# ===========================================================================
# Phase 6 Part 2 — attack-path INTELLIGENCE foundation (backward compatible)
# ---------------------------------------------------------------------------
# Part 2 adds identity/state/privilege reasoning, sensitivity weighting,
# search modes, three-valued precondition logic, blast radius, choke points,
# fix-impact and equivalence analysis. It invents **no** new confidence scale
# and **no** new evidence-weight table: it reuses the Phase 1-5 vocabulary
# above and reads only evidence-backed nodes/edges already in the graph. All of
# the constants below are additive — nothing existing is renamed or removed.
# ===========================================================================

# ---------------------------------------------------------------------------
# Three-valued (Kleene) truth for precondition logic (logic.py).
# UNKNOWN is *never* promoted to TRUE — a hop whose precondition is unknown is
# surfaced for review, never silently assumed satisfied.
# ---------------------------------------------------------------------------
TRUTH_TRUE = "TRUE"
TRUTH_FALSE = "FALSE"
TRUTH_UNKNOWN = "UNKNOWN"
TRUTH_VALUES = frozenset({TRUTH_TRUE, TRUTH_FALSE, TRUTH_UNKNOWN})

# Logic expression node operators (logic.py).
LOGIC_AND = "AND"
LOGIC_OR = "OR"
LOGIC_ATOM = "ATOM"
LOGIC_OPS = frozenset({LOGIC_AND, LOGIC_OR, LOGIC_ATOM})

# ---------------------------------------------------------------------------
# Identity types (identity.py). An attack path moves an actor between these.
# ---------------------------------------------------------------------------
ID_ANONYMOUS = "ANONYMOUS"  # no session — the raw internet
ID_ATTACKER = "ATTACKER"  # anonymous actor with malicious intent (== start)
ID_AUTHENTICATED_USER = "AUTHENTICATED_USER"  # a valid low-priv session
ID_TENANT_USER = "TENANT_USER"  # authenticated, scoped to one tenant/org
ID_PRIVILEGED_USER = "PRIVILEGED_USER"  # admin / elevated role
ID_SERVICE = "SERVICE"  # service account / internal caller
ID_SYSTEM = "SYSTEM"  # host / worker / os-level context
ID_AI_AGENT = "AI_AGENT"  # an autonomous tool-calling agent identity
ID_UNKNOWN = "UNKNOWN"

IDENTITY_TYPES = frozenset(
    {
        ID_ANONYMOUS,
        ID_ATTACKER,
        ID_AUTHENTICATED_USER,
        ID_TENANT_USER,
        ID_PRIVILEGED_USER,
        ID_SERVICE,
        ID_SYSTEM,
        ID_AI_AGENT,
        ID_UNKNOWN,
    }
)

# Rough privilege ordering (higher == more powerful). Used only to *describe* a
# transition as elevating/lateral/lowering — never to invent a transition.
IDENTITY_PRIV_RANK = {
    ID_ANONYMOUS: 0,
    ID_ATTACKER: 0,
    ID_UNKNOWN: 0,
    ID_AUTHENTICATED_USER: 1,
    ID_TENANT_USER: 1,
    ID_SERVICE: 2,
    ID_AI_AGENT: 2,
    ID_PRIVILEGED_USER: 3,
    ID_SYSTEM: 4,
}

# ---------------------------------------------------------------------------
# Application states (state_model.py). Inferred *lightly* from middleware /
# guards on the path; never invented when there is no code-visible guard.
# ---------------------------------------------------------------------------
STATE_UNAUTHENTICATED = "UNAUTHENTICATED"
STATE_AUTHENTICATED = "AUTHENTICATED"
STATE_AUTHORIZED = "AUTHORIZED"
STATE_TENANT_SCOPED = "TENANT_SCOPED"
STATE_PRIVILEGED = "PRIVILEGED"
STATE_TOOL_EXECUTION = "TOOL_EXECUTION"  # an agent is running a privileged tool
STATE_COMPROMISED = "COMPROMISED"  # a sensitive asset has been reached
STATE_UNKNOWN = "UNKNOWN"

APP_STATES = frozenset(
    {
        STATE_UNAUTHENTICATED,
        STATE_AUTHENTICATED,
        STATE_AUTHORIZED,
        STATE_TENANT_SCOPED,
        STATE_PRIVILEGED,
        STATE_TOOL_EXECUTION,
        STATE_COMPROMISED,
        STATE_UNKNOWN,
    }
)

# ---------------------------------------------------------------------------
# Privilege-transition patterns (privilege.py).
# ---------------------------------------------------------------------------
PRIV_VERTICAL = "vertical"  # user → admin (gain a higher role)
PRIV_HORIZONTAL = "horizontal"  # tenant-A → tenant-B (same tier, other scope)
PRIV_CONFUSED_DEPUTY = "confused_deputy"  # a trusted component acts for attacker
PRIV_PATTERNS = frozenset({PRIV_VERTICAL, PRIV_HORIZONTAL, PRIV_CONFUSED_DEPUTY})

# ---------------------------------------------------------------------------
# Sensitive-data categories + impact weight (sensitivity_data.py).
# Weight is an *impact* multiplier for assets, in [0, 1]; it is not a
# confidence and not a severity. UNKNOWN is deliberately low, never high.
# ---------------------------------------------------------------------------
SENS_PUBLIC = "PUBLIC"
SENS_INTERNAL = "INTERNAL"
SENS_CONFIDENTIAL = "CONFIDENTIAL"
SENS_PII = "PII"
SENS_FINANCIAL = "FINANCIAL"
SENS_CREDENTIAL = "CREDENTIAL"
SENS_SECRET = "SECRET"
SENS_AI_CONTEXT = "AI_CONTEXT"  # the model instruction context / agent memory
SENS_UNKNOWN = "UNKNOWN"

SENSITIVITY_CATEGORIES = (
    SENS_PUBLIC,
    SENS_INTERNAL,
    SENS_CONFIDENTIAL,
    SENS_PII,
    SENS_FINANCIAL,
    SENS_CREDENTIAL,
    SENS_SECRET,
    SENS_AI_CONTEXT,
    SENS_UNKNOWN,
)

SENSITIVITY_IMPACT = {
    SENS_PUBLIC: 0.10,
    SENS_INTERNAL: 0.40,
    SENS_CONFIDENTIAL: 0.60,
    SENS_AI_CONTEXT: 0.70,
    SENS_PII: 0.75,
    SENS_FINANCIAL: 0.80,
    SENS_CREDENTIAL: 0.95,
    SENS_SECRET: 1.00,
    SENS_UNKNOWN: 0.30,
}

# Map the existing app_model/attack_graph ``asset.kind`` vocabulary onto a
# sensitivity category. Anything unmapped falls back to UNKNOWN (low), never to
# a high tier — we do not over-claim impact for data we cannot categorise.
ASSET_KIND_TO_SENSITIVITY = {
    "secret": SENS_SECRET,
    "credential": SENS_CREDENTIAL,
    "token": SENS_CREDENTIAL,
    "admin": SENS_CREDENTIAL,
    "filesystem": SENS_SECRET,
    "pii": SENS_PII,
    "financial": SENS_FINANCIAL,
    "database": SENS_CONFIDENTIAL,
    "internal": SENS_INTERNAL,
    "info": SENS_PUBLIC,
    "ai_context": SENS_AI_CONTEXT,
    "unknown": SENS_UNKNOWN,
}

# ---------------------------------------------------------------------------
# Search modes (modes.py). A mode is a *status filter* over live attack paths.
# BLOCKED / INVALID are never "live" in any mode — they are rejected paths.
# ---------------------------------------------------------------------------
MODE_CONFIRMED_ONLY = "CONFIRMED_ONLY"
MODE_CONFIRMED_AND_LIKELY = "CONFIRMED_AND_LIKELY"
MODE_INCLUDE_UNKNOWN = "INCLUDE_UNKNOWN"
SEARCH_MODES = (MODE_CONFIRMED_ONLY, MODE_CONFIRMED_AND_LIKELY, MODE_INCLUDE_UNKNOWN)
# Default keeps the full ``paths[]`` list intact (nothing filtered out of the
# artifact); modes are applied as an explicit, opt-in view.
DEFAULT_SEARCH_MODE = MODE_INCLUDE_UNKNOWN

MODE_ALLOWED_STATUSES = {
    MODE_CONFIRMED_ONLY: frozenset({PATH_CONFIRMED}),
    MODE_CONFIRMED_AND_LIKELY: frozenset({PATH_CONFIRMED, PATH_LIKELY}),
    MODE_INCLUDE_UNKNOWN: frozenset({PATH_CONFIRMED, PATH_LIKELY, PATH_UNVERIFIED}),
}

# Statuses that are always "rejected" (a barrier stops them, or the chain does
# not exist) — never live in any search mode.
REJECTED_STATUSES = frozenset({PATH_BLOCKED, PATH_INVALID})

# Bounded-search caps for the generic graph search (search.py). These mirror
# the enumeration limits above so Part 2 search never explodes combinatorially.
MAX_SEARCH_DEPTH = MAX_PATH_DEPTH
MAX_SEARCH_RESULTS = MAX_PATHS
MAX_BLAST_NODES = 500  # cap on nodes returned by a blast-radius walk


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
