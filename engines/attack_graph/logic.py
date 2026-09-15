"""Three-valued (Kleene) precondition logic for attack paths (Phase 6 Part 2).

A hop rarely has a single flat precondition. Real reachability is an
expression: "(public network **OR** an authenticated session) **AND**
attacker-controlled input". This module represents such expressions and
evaluates them under a *known / unknown* context using **three-valued logic**
(``TRUE`` / ``FALSE`` / ``UNKNOWN``).

The one non-negotiable rule: **UNKNOWN is never promoted to TRUE.** A hop whose
precondition cannot be established from evidence evaluates to ``UNKNOWN`` and is
surfaced for review — it is never silently assumed satisfied. This mirrors the
whole-project honesty contract: unknown reachability yields ``UNVERIFIED``, not
a confident exploit claim.

Expressions are plain JSON-serialisable dicts so they can live on an edge and
be written to ``attack-paths.json`` unchanged::

    {"op": "ATOM", "kind": "network", "value": "public_internet", "truth": "TRUE"}
    {"op": "AND", "operands": [ ...expr... ]}
    {"op": "OR",  "operands": [ ...expr... ]}
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from engines.attack_graph.schema import (
    LOGIC_AND,
    LOGIC_ATOM,
    LOGIC_OR,
    TRUTH_FALSE,
    TRUTH_TRUE,
    TRUTH_UNKNOWN,
)

Expr = dict[str, Any]


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
def atom(kind: str, value: str, *, truth: str = TRUTH_UNKNOWN, satisfied_by: str | None = None) -> Expr:
    """A leaf precondition. ``truth`` defaults to UNKNOWN — an atom is only
    ``TRUE`` when we have positive evidence it holds (never by default).
    """
    node: Expr = {"op": LOGIC_ATOM, "kind": str(kind), "value": str(value), "truth": _coerce(truth)}
    if satisfied_by is not None:
        node["satisfied_by"] = str(satisfied_by)
    return node


def and_(*operands: Expr) -> Expr:
    return {"op": LOGIC_AND, "operands": _flatten(operands, LOGIC_AND)}


def or_(*operands: Expr) -> Expr:
    return {"op": LOGIC_OR, "operands": _flatten(operands, LOGIC_OR)}


def _flatten(operands: Iterable[Expr], op: str) -> list[Expr]:
    """Flatten nested same-op nodes and drop ``None`` for a stable, minimal
    tree. Order is preserved (deterministic).
    """
    out: list[Expr] = []
    for o in operands:
        if not o:
            continue
        if o.get("op") == op:
            out.extend(o.get("operands") or [])
        else:
            out.append(o)
    return out


def _coerce(truth: Any) -> str:
    t = str(truth).upper()
    return t if t in {TRUTH_TRUE, TRUTH_FALSE, TRUTH_UNKNOWN} else TRUTH_UNKNOWN


# ---------------------------------------------------------------------------
# evaluation (Kleene three-valued logic)
# ---------------------------------------------------------------------------
def evaluate(expr: Expr | None, resolver: Callable[[Expr], str] | None = None) -> str:
    """Evaluate ``expr`` to ``TRUE`` / ``FALSE`` / ``UNKNOWN``.

    ``resolver`` maps an *atom* to its truth value given the current context.
    If omitted, each atom's own ``truth`` field is used (default UNKNOWN).

    Kleene semantics (UNKNOWN is a genuine third value, never TRUE):
      * AND → FALSE if any FALSE; else UNKNOWN if any UNKNOWN; else TRUE.
      * OR  → TRUE if any TRUE;  else UNKNOWN if any UNKNOWN; else FALSE.
      * empty AND → TRUE (vacuous), empty OR → FALSE.
    """
    if not expr:
        return TRUTH_TRUE  # no precondition == trivially satisfiable
    op = expr.get("op")

    if op == LOGIC_ATOM:
        if resolver is not None:
            return _coerce(resolver(expr))
        return _coerce(expr.get("truth", TRUTH_UNKNOWN))

    operands = expr.get("operands") or []
    child_truths = [evaluate(o, resolver) for o in operands]

    if op == LOGIC_AND:
        if any(t == TRUTH_FALSE for t in child_truths):
            return TRUTH_FALSE
        if any(t == TRUTH_UNKNOWN for t in child_truths):
            return TRUTH_UNKNOWN  # explicitly NOT promoted to TRUE
        return TRUTH_TRUE

    if op == LOGIC_OR:
        if any(t == TRUTH_TRUE for t in child_truths):
            return TRUTH_TRUE
        if any(t == TRUTH_UNKNOWN for t in child_truths):
            return TRUTH_UNKNOWN  # explicitly NOT promoted to TRUE
        return TRUTH_FALSE

    # Unknown operator → be conservative, never assert TRUE.
    return TRUTH_UNKNOWN


def is_satisfied(expr: Expr | None, resolver: Callable[[Expr], str] | None = None) -> bool:
    """``True`` **only** when the expression evaluates to ``TRUE``. UNKNOWN and
    FALSE both return ``False`` — unknown is never treated as satisfied.
    """
    return evaluate(expr, resolver) == TRUTH_TRUE


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------
def from_precondition_list(preconds: list[dict[str, Any]] | None) -> Expr | None:
    """Turn a flat ``preconditions[]`` list (as attached to edges by
    ``preconditions.py``) into an AND-of-atoms expression. Preconditions that
    share a ``kind`` and are marked ``alternatives`` collapse into an OR.

    A precondition ``satisfied_by == "attacker"`` is treated as ``TRUE`` (the
    attacker supplies it by definition); everything else stays ``UNKNOWN`` until
    an explicit resolver says otherwise.
    """
    if not preconds:
        return None
    atoms: list[Expr] = []
    for p in preconds:
        satisfied_by = p.get("satisfied_by")
        truth = TRUTH_TRUE if satisfied_by == "attacker" else TRUTH_UNKNOWN
        atoms.append(
            atom(
                str(p.get("kind") or "unknown"),
                str(p.get("value") or ""),
                truth=truth,
                satisfied_by=satisfied_by,
            )
        )
    return and_(*atoms)


def path_precondition_expr(path: dict[str, Any], graph: dict[str, Any]) -> Expr | None:
    """AND together the precondition expressions of every edge on ``path``.

    The whole path is traversable only if *all* of its hops are — a classic
    AND. Any single UNKNOWN hop makes the whole path UNKNOWN (never TRUE).
    """
    edges_by_pair = _edge_index(graph)
    hops = path.get("hops") or []
    exprs: list[Expr] = []
    for src, dst in zip(hops, hops[1:]):
        edge = edges_by_pair.get((str(src), str(dst)))
        if not edge:
            continue
        e = from_precondition_list(edge.get("preconditions"))
        if e:
            exprs.append(e)
    if not exprs:
        return None
    return and_(*exprs)


def evaluate_path(
    path: dict[str, Any],
    graph: dict[str, Any],
    context: dict[str, str] | None = None,
) -> str:
    """Evaluate whether a path's preconditions are satisfied under ``context``.

    ``context`` maps ``"kind:value"`` → truth (``TRUE``/``FALSE``/``UNKNOWN``);
    anything not in the context keeps the atom's own truth (attacker-supplied
    atoms are TRUE, the rest UNKNOWN). Returns a three-valued result.
    """
    expr = path_precondition_expr(path, graph)
    ctx = context or {}

    def resolver(a: Expr) -> str:
        key = f"{a.get('kind')}:{a.get('value')}"
        if key in ctx:
            return _coerce(ctx[key])
        return _coerce(a.get("truth", TRUTH_UNKNOWN))

    return evaluate(expr, resolver)


def _edge_index(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for e in graph.get("edges") or []:
        idx.setdefault((str(e.get("from")), str(e.get("to"))), e)
    return idx
