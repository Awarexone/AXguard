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


# ---------------------------------------------------------------------------
# Phase 6 Part 2 — AND/OR precondition expressions (logic.py).
#
# The flat helpers above stay untouched (every existing caller keeps working).
# These new helpers express the *same* preconditions as three-valued AND/OR
# logic trees, which capture genuine alternatives (e.g. "public network OR an
# authenticated session") that a flat list cannot. They are additive: callers
# that want richer reasoning opt in, everyone else keeps the flat list.
# ---------------------------------------------------------------------------
def reaches_precondition_expr(reachability: str, authentication: str) -> dict[str, Any] | None:
    """Build an AND/OR expression for a ``reaches`` hop.

    A public entrypoint needs public network access (attacker-satisfied, TRUE).
    An authenticated entrypoint needs *either* a stolen/held session (UNKNOWN
    until proven) — expressed as an OR of the ways an attacker could hold one —
    so the hop is UNKNOWN, never silently TRUE.
    """
    from engines.attack_graph import logic

    if reachability in {"public", "unauthenticated"}:
        return logic.atom(PRE_NETWORK, "public_internet", truth=logic.TRUTH_TRUE, satisfied_by="attacker")
    if reachability == "authenticated":
        # attacker needs an authenticated session: via valid signup OR stolen
        # credentials — both UNKNOWN from static evidence alone.
        return logic.or_(
            logic.atom(PRE_AUTH, "self_registered_low_priv_session"),
            logic.atom(PRE_AUTH, "stolen_or_replayed_session"),
        )
    if reachability == "queue":
        return logic.atom(PRE_NETWORK, "queue_publisher")
    if reachability == "unknown":
        return logic.atom(PRE_NETWORK, "unknown_publisher")
    return logic.atom(PRE_NETWORK, reachability)


def triggers_precondition_expr() -> dict[str, Any]:
    from engines.attack_graph import logic

    return logic.atom(PRE_INPUT, "attacker_controlled_input", truth=logic.TRUTH_TRUE, satisfied_by="attacker")


def escalate_precondition_expr() -> dict[str, Any]:
    """Vertical escalation needs an authenticated low-priv session AND a way to
    set an elevated role (the mass-assignment write) — an AND of both.
    """
    from engines.attack_graph import logic

    return logic.and_(
        logic.atom(PRE_AUTH, "authenticated_low_priv"),
        logic.atom(PRE_ROLE, "user->admin"),
    )


def cross_tenant_precondition_expr() -> dict[str, Any]:
    from engines.attack_graph import logic

    return logic.and_(
        logic.atom(PRE_TENANT, "tenant_a->tenant_b"),
        logic.atom(PRE_INPUT, "enumerated_object_id", truth=logic.TRUTH_TRUE, satisfied_by="attacker"),
    )


def as_expr(preconds: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Convert any flat precondition list into an AND-of-atoms expression."""
    from engines.attack_graph import logic

    return logic.from_precondition_list(preconds)
