"""Per-hop preconditions (auth / role / input / network).

Preconditions are descriptive metadata attached to edges: what an attacker
must already have or control for a hop to be traversable. They feed the
reachability scoring factor and make a path auditable ("this hop assumes an
authenticated caller", "this hop assumes attacker-controlled input").
"""

from __future__ import annotations

from typing import Any

# precondition kinds
PRE_NETWORK = "network"
PRE_AUTH = "auth"
PRE_ROLE = "role"
PRE_INPUT = "input"
PRE_TENANT = "tenant"


def precond(kind: str, value: str, satisfied_by: str = "attacker") -> dict[str, Any]:
    return {"kind": kind, "value": value, "satisfied_by": satisfied_by}


def reaches_preconditions(reachability: str, authentication: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if reachability in {"public", "unauthenticated"}:
        out.append(precond(PRE_NETWORK, "public_internet"))
    elif reachability == "authenticated":
        out.append(precond(PRE_AUTH, "authenticated_session", satisfied_by="low_priv_user"))
    elif reachability == "queue":
        out.append(precond(PRE_NETWORK, "queue_publisher"))
    elif reachability == "unknown":
        out.append(precond(PRE_NETWORK, "unknown_publisher"))
    else:
        out.append(precond(PRE_NETWORK, reachability))
    if authentication == "required" and reachability != "authenticated":
        out.append(precond(PRE_AUTH, "authentication_required"))
    return out


def triggers_preconditions() -> list[dict[str, Any]]:
    return [precond(PRE_INPUT, "attacker_controlled_input")]


def escalate_preconditions() -> list[dict[str, Any]]:
    return [precond(PRE_AUTH, "authenticated_low_priv"), precond(PRE_ROLE, "user->admin")]


def cross_tenant_preconditions() -> list[dict[str, Any]]:
    return [precond(PRE_TENANT, "tenant_a->tenant_b"), precond(PRE_INPUT, "enumerated_object_id")]


def invokes_preconditions() -> list[dict[str, Any]]:
    return [precond(PRE_INPUT, "injected_instruction_reaches_tool")]
