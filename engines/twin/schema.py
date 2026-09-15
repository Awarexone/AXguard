"""Security Twin schema constants and empty factory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECURITY_TWIN_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# ---------------------------------------------------------------------------
# Fact layers — every field in a twin report must be tagged with one of these.
# ---------------------------------------------------------------------------
LAYER_OBSERVED = "OBSERVED"
LAYER_INFERRED = "INFERRED"
LAYER_SIMULATED = "SIMULATED"
LAYER_ASSUMED = "ASSUMED"
FACT_LAYERS = frozenset({LAYER_OBSERVED, LAYER_INFERRED, LAYER_SIMULATED, LAYER_ASSUMED})

# ---------------------------------------------------------------------------
# Entity types (twin vocabulary; mapped from attack-graph / app_model types)
# ---------------------------------------------------------------------------
ENTITY_APPLICATION = "Application"
ENTITY_REPOSITORY = "Repository"
ENTITY_SERVICE = "Service"
ENTITY_ENDPOINT = "Endpoint"
ENTITY_IDENTITY = "Identity"
ENTITY_ASSET = "Asset"
ENTITY_SECURITY_CONTROL = "SecurityControl"
ENTITY_AI_MODEL = "AIModel"
ENTITY_AI_AGENT = "AIAgent"
ENTITY_AI_TOOL = "AITool"
ENTITY_MCP_SERVER = "MCPServer"
ENTITY_TRUST_BOUNDARY = "TrustBoundary"
ENTITY_FINDING = "Finding"
ENTITY_ATTACK_PATH = "AttackPath"
ENTITY_EXTERNAL_SERVICE = "ExternalService"
ENTITY_CLOUD_RESOURCE = "CloudResource"
ENTITY_SECRET = "Secret"
ENTITY_CREDENTIAL = "Credential"
ENTITY_DATABASE = "Database"
ENTITY_QUEUE = "Queue"
ENTITY_WEBHOOK = "Webhook"
ENTITY_STORAGE = "Storage"
ENTITY_PERMISSION = "Permission"
ENTITY_ROLE = "Role"
ENTITY_TENANT = "Tenant"
ENTITY_PARAMETER = "Parameter"
ENTITY_FUNCTION = "Function"

ENTITY_TYPES = frozenset(
    {
        ENTITY_APPLICATION,
        ENTITY_REPOSITORY,
        ENTITY_SERVICE,
        ENTITY_ENDPOINT,
        ENTITY_IDENTITY,
        ENTITY_ASSET,
        ENTITY_SECURITY_CONTROL,
        ENTITY_AI_MODEL,
        ENTITY_AI_AGENT,
        ENTITY_AI_TOOL,
        ENTITY_MCP_SERVER,
        ENTITY_TRUST_BOUNDARY,
        ENTITY_FINDING,
        ENTITY_ATTACK_PATH,
        ENTITY_EXTERNAL_SERVICE,
        ENTITY_CLOUD_RESOURCE,
        ENTITY_SECRET,
        ENTITY_CREDENTIAL,
        ENTITY_DATABASE,
        ENTITY_QUEUE,
        ENTITY_WEBHOOK,
        ENTITY_STORAGE,
        ENTITY_PERMISSION,
        ENTITY_ROLE,
        ENTITY_TENANT,
        ENTITY_PARAMETER,
        ENTITY_FUNCTION,
    }
)

# Map attack-graph node types → twin entity types
AG_NODE_TO_ENTITY = {
    "entrypoint": ENTITY_ENDPOINT,
    "finding": ENTITY_FINDING,
    "candidate_seed": ENTITY_FINDING,
    "control": ENTITY_SECURITY_CONTROL,
    "asset": ENTITY_ASSET,
    "identity": ENTITY_IDENTITY,
    "ai_component": ENTITY_AI_AGENT,
    "tool": ENTITY_AI_TOOL,
    "external_service": ENTITY_EXTERNAL_SERVICE,
    "trust_boundary": ENTITY_TRUST_BOUNDARY,
}

# Map asset kinds → more specific entity types
ASSET_KIND_TO_ENTITY = {
    "secret": ENTITY_SECRET,
    "credential": ENTITY_CREDENTIAL,
    "token": ENTITY_CREDENTIAL,
    "database": ENTITY_DATABASE,
    "filesystem": ENTITY_STORAGE,
    "queue": ENTITY_QUEUE,
    "webhook": ENTITY_WEBHOOK,
}

# ---------------------------------------------------------------------------
# Relationship names (twin vocabulary; mapped to AG edge types when emitting)
# ---------------------------------------------------------------------------
REL_CAN_REACH = "CAN_REACH"
REL_CALLS = "CALLS"
REL_TRIGGERS = "TRIGGERS"
REL_EXPOSES = "EXPOSES"
REL_ESCALATES_TO = "ESCALATES_TO"
REL_CROSSES_TENANT = "CROSSES_TENANT"
REL_INVOKES = "INVOKES"
REL_YIELDS = "YIELDS"
REL_BLOCKED_BY = "BLOCKED_BY"
REL_CHAINS_TO = "CHAINS_TO"
REL_HANDLES = "HANDLES"
REL_DEPENDS_ON = "DEPENDS_ON"
REL_GRANTS = "GRANTS"
REL_CONTAINS = "CONTAINS"
REL_ACCESSES = "ACCESSES"
REL_TRUSTS = "TRUSTS"
REL_COMMUNICATES_WITH = "COMMUNICATES_WITH"

# AG edge type → twin relationship name
AG_EDGE_TO_REL = {
    "reaches": REL_CAN_REACH,
    "triggers": REL_TRIGGERS,
    "exposes": REL_EXPOSES,
    "escalates_to": REL_ESCALATES_TO,
    "crosses_tenant": REL_CROSSES_TENANT,
    "invokes": REL_INVOKES,
    "yields": REL_YIELDS,
    "blocked_by": REL_BLOCKED_BY,
    "chains_to": REL_CHAINS_TO,
    "handled_by": REL_HANDLES,
    "co_located": REL_CONTAINS,
    "calls": REL_CALLS,
}

# ---------------------------------------------------------------------------
# Tool permission classes
# ---------------------------------------------------------------------------
PERM_READ_ONLY = "READ_ONLY"
PERM_LOW_RISK = "LOW_RISK"
PERM_SENSITIVE_READ = "SENSITIVE_READ"
PERM_WRITE = "WRITE"
PERM_DESTRUCTIVE = "DESTRUCTIVE"
PERM_PRIVILEGED = "PRIVILEGED"
PERM_EXTERNAL_NETWORK = "EXTERNAL_NETWORK"
PERM_CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
PERM_CODE_EXECUTION = "CODE_EXECUTION"
PERM_UNKNOWN = "UNKNOWN"

TOOL_PERMISSIONS = frozenset(
    {
        PERM_READ_ONLY,
        PERM_LOW_RISK,
        PERM_SENSITIVE_READ,
        PERM_WRITE,
        PERM_DESTRUCTIVE,
        PERM_PRIVILEGED,
        PERM_EXTERNAL_NETWORK,
        PERM_CREDENTIAL_ACCESS,
        PERM_CODE_EXECUTION,
        PERM_UNKNOWN,
    }
)

# ---------------------------------------------------------------------------
# Attacker profiles
# ---------------------------------------------------------------------------
ATTACKER_PUBLIC_USER = "PUBLIC_USER"
ATTACKER_AUTHENTICATED_USER = "AUTHENTICATED_USER"
ATTACKER_LOW_PRIVILEGE_USER = "LOW_PRIVILEGE_USER"
ATTACKER_TENANT_USER = "TENANT_USER"
ATTACKER_ADMIN = "ADMIN"
ATTACKER_COMPROMISED_AGENT = "COMPROMISED_AGENT"
ATTACKER_COMPROMISED_TOOL = "COMPROMISED_TOOL"
ATTACKER_MALICIOUS_DOCUMENT = "MALICIOUS_DOCUMENT"
ATTACKER_MALICIOUS_DEPENDENCY = "MALICIOUS_DEPENDENCY"
ATTACKER_COMPROMISED_EXTERNAL_SERVICE = "COMPROMISED_EXTERNAL_SERVICE"

ATTACKER_PROFILES = frozenset(
    {
        ATTACKER_PUBLIC_USER,
        ATTACKER_AUTHENTICATED_USER,
        ATTACKER_LOW_PRIVILEGE_USER,
        ATTACKER_TENANT_USER,
        ATTACKER_ADMIN,
        ATTACKER_COMPROMISED_AGENT,
        ATTACKER_COMPROMISED_TOOL,
        ATTACKER_MALICIOUS_DOCUMENT,
        ATTACKER_MALICIOUS_DEPENDENCY,
        ATTACKER_COMPROMISED_EXTERNAL_SERVICE,
    }
)

# ---------------------------------------------------------------------------
# Simulation / path statuses
# ---------------------------------------------------------------------------
SIM_CONFIRMED = "CONFIRMED"
SIM_LIKELY = "LIKELY"
SIM_POSSIBLE = "POSSIBLE"
SIM_BLOCKED = "BLOCKED"
SIM_UNKNOWN = "UNKNOWN"
SIM_INVALID = "INVALID"

SIMULATION_STATUSES = frozenset(
    {SIM_CONFIRMED, SIM_LIKELY, SIM_POSSIBLE, SIM_BLOCKED, SIM_UNKNOWN, SIM_INVALID}
)

# Map attack-graph path status → twin simulation status
AG_STATUS_TO_SIM = {
    "CONFIRMED": SIM_CONFIRMED,
    "LIKELY": SIM_LIKELY,
    "UNVERIFIED": SIM_POSSIBLE,
    "BLOCKED": SIM_BLOCKED,
    "INVALID": SIM_INVALID,
    "PREDICTIVE": SIM_POSSIBLE,
}

# ---------------------------------------------------------------------------
# Impact kinds
# ---------------------------------------------------------------------------
IMPACT_DIRECT = "DIRECT_IMPACT"
IMPACT_INDIRECT = "INDIRECT_IMPACT"
IMPACT_DEPENDENCY = "DEPENDENCY_IMPACT"
IMPACT_TENANT = "TENANT_IMPACT"
IMPACT_DATA = "DATA_IMPACT"
IMPACT_PRIVILEGE = "PRIVILEGE_IMPACT"

IMPACT_KINDS = frozenset(
    {
        IMPACT_DIRECT,
        IMPACT_INDIRECT,
        IMPACT_DEPENDENCY,
        IMPACT_TENANT,
        IMPACT_DATA,
        IMPACT_PRIVILEGE,
    }
)

# ---------------------------------------------------------------------------
# Scenario library keys (OWASP-ish agentic themes; metadata in scenarios.py)
# ---------------------------------------------------------------------------
SCENARIO_LIBRARY_KEYS = (
    "prompt_injection",
    "tool_misuse",
    "mcp_supply_chain",
    "agent_privilege_escalation",
    "cross_tenant_agent",
    "secret_exposure",
    "public_endpoint",
    "authz_regression",
    "unrestricted_egress",
    "compromised_mcp_server",
    "malicious_dependency",
    "confused_deputy",
)

_DISCLAIMER = (
    "Security Twin output is symbolic and evidence-bounded. SIMULATED and "
    "ASSUMED sections are counterfactual or hypothetical — not confirmed findings."
)


def empty_twin(target: Path) -> dict[str, Any]:
    root = str(Path(target).resolve())
    return {
        "schema_version": SECURITY_TWIN_VERSION,
        "tool": TOOL_NAME,
        "target": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entities": [],
        "relationships": [],
        "attack_graph": None,
        "application_model": None,
        "dataflow": None,
        "evidence": None,
        "adversary": None,
        "summary": {
            "entity_count": 0,
            "relationship_count": 0,
            "observed_path_count": 0,
            "simulated_path_count": 0,
            "control_count": 0,
            "ai_agent_count": 0,
            "ai_tool_count": 0,
            "mcp_server_count": 0,
        },
        "disclaimer": _DISCLAIMER,
        "meta": {},
    }


def tagged(value: Any, layer: str, *, evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Wrap a value with its fact layer."""
    out: dict[str, Any] = {"value": value, "layer": layer}
    if evidence:
        out["evidence"] = list(evidence)
    return out
