"""Intraprocedural taint propagation heuristics (Python + JS/TS)."""

from __future__ import annotations

import re
from typing import Any

# Simple assignment: lhs = rhs (single line)
_ASSIGN = re.compile(
    r"^\s*(?P<lhs>[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+?)(?:;|\s*#|//|$)"
)

# Augmented / concat assignment
_AUG_ASSIGN = re.compile(
    r"^\s*(?P<lhs>[A-Za-z_][\w]*)\s*(?:\+=|\|=)\s*(?P<rhs>.+?)(?:;|\s*#|//|$)"
)

# Property / subscript write: obj.attr = rhs / obj[k] = rhs — track attr as name when simple
_PROP_ASSIGN = re.compile(
    r"^\s*(?P<obj>[A-Za-z_][\w]*)\.(?P<attr>[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+?)(?:;|\s*#|//|$)"
)

# Return statement carrying an expression
_RETURN = re.compile(r"^\s*return\s+(?P<expr>.+?)(?:;|\s*#|//|$)")

# Function / method call capturing first positional arg name-ish
_CALL_ARG = re.compile(
    r"(?P<callee>[A-Za-z_][\w\.]*)\s*\(\s*(?P<args>[^)]*)\)"
)

_IDENT = re.compile(r"\b([A-Za-z_][\w]*)\b")

# Words that are not useful taint carriers
_STOP = frozenset(
    {
        "True",
        "False",
        "None",
        "null",
        "undefined",
        "self",
        "cls",
        "this",
        "if",
        "else",
        "elif",
        "for",
        "while",
        "return",
        "import",
        "from",
        "def",
        "class",
        "async",
        "await",
        "const",
        "let",
        "var",
        "function",
        "new",
        "and",
        "or",
        "not",
        "in",
        "is",
        "as",
        "with",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "len",
        "print",
        "f",
    }
)


def idents_in(expr: str) -> set[str]:
    return {m.group(1) for m in _IDENT.finditer(expr or "") if m.group(1) not in _STOP}


def propagate_file(
    content: str,
    seed_taints: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Intraprocedural forward taint over assignments / args / returns / properties.

    ``seed_taints`` maps variable name → source metadata (must include file/line/id).
    Returns map of tainted name → {source, line, via}.
    """
    tainted: dict[str, dict[str, Any]] = {
        k: {**v, "via": "source"} for k, v in seed_taints.items()
    }
    lines = content.splitlines()

    # Multiple passes for simple chains (a=src; b=a; c=b)
    for _ in range(8):
        changed = False
        for i, raw in enumerate(lines):
            line = raw.rstrip()
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            m = _PROP_ASSIGN.match(line)
            if m:
                rhs_names = idents_in(m.group("rhs"))
                if rhs_names & set(tainted):
                    # Track both obj and obj.attr as carriers
                    attr_name = f"{m.group('obj')}.{m.group('attr')}"
                    donor = _pick_donor(rhs_names, tainted)
                    if attr_name not in tainted:
                        tainted[attr_name] = {
                            **donor,
                            "via": "property",
                            "line": i + 1,
                        }
                        changed = True
                    if m.group("obj") not in tainted:
                        tainted[m.group("obj")] = {
                            **donor,
                            "via": "property_obj",
                            "line": i + 1,
                        }
                        changed = True
                continue

            m = _AUG_ASSIGN.match(line) or _ASSIGN.match(line)
            if m:
                lhs = m.group("lhs")
                rhs = m.group("rhs")
                rhs_names = idents_in(rhs)
                # f-string / format / concat of tainted → lhs tainted
                if rhs_names & set(tainted) or _expr_uses_taint(rhs, tainted):
                    donor = _pick_donor(rhs_names, tainted) or next(iter(tainted.values()))
                    if lhs not in tainted or tainted[lhs].get("via") == "source":
                        # Always refresh non-source via for propagation chain
                        if lhs not in tainted:
                            changed = True
                        elif tainted[lhs].get("via") != "source" and tainted[lhs].get("line") != i + 1:
                            pass
                        tainted[lhs] = {
                            **{k: v for k, v in donor.items() if k != "via"},
                            "via": "assignment",
                            "line": i + 1,
                        }
                        if lhs not in seed_taints:
                            changed = True
                continue

            m = _RETURN.match(line)
            if m:
                expr = m.group("expr")
                if _expr_uses_taint(expr, tainted):
                    tainted["__return__"] = {
                        **_pick_donor(idents_in(expr), tainted),
                        "via": "return",
                        "line": i + 1,
                    }
                    changed = True

            # Call arguments: if tainted name appears in args of a call, mark callee__arg
            for cm in _CALL_ARG.finditer(line):
                args = cm.group("args")
                if not args or not _expr_uses_taint(args, tainted):
                    continue
                donor = _pick_donor(idents_in(args), tainted)
                key = f"__arg__:{cm.group('callee')}"
                if key not in tainted:
                    tainted[key] = {
                        **donor,
                        "via": "call_arg",
                        "line": i + 1,
                        "callee": cm.group("callee"),
                    }
                    changed = True

        if not changed:
            break

    return tainted


def sink_uses_taint(sink_line: str, tainted: dict[str, dict[str, Any]]) -> list[str]:
    """Return tainted names that appear in the sink call line."""
    hits: list[str] = []
    # Prefer longer names first (obj.attr before obj)
    for name in sorted(tainted.keys(), key=len, reverse=True):
        if name.startswith("__"):
            continue
        if re.search(rf"(?<![\w\.]){re.escape(name)}(?![\w])", sink_line):
            hits.append(name)
    # Also: requests.get(url) where url is tainted — covered above
    # Direct request.* in sink line
    if re.search(r"\brequest\.(args|form|values|json|get_json|data)\b", sink_line):
        hits.append("request")
    if re.search(r"\breq\.(query|params|body)\b", sink_line):
        hits.append("req")
    return hits


def _expr_uses_taint(expr: str, tainted: dict[str, dict[str, Any]]) -> bool:
    names = idents_in(expr)
    if names & set(tainted):
        return True
    # f"...{var}..."
    for name in tainted:
        if name.startswith("__"):
            continue
        if f"{{{name}" in expr or f"${{{name}" in expr:
            return True
        if re.search(rf"(?<![\w\.]){re.escape(name)}(?![\w])", expr):
            return True
    if re.search(r"\brequest\.(args|form|values|json|get_json|data)\b", expr):
        return True
    if re.search(r"\breq\.(query|params|body)\b", expr):
        return True
    return False


def _pick_donor(
    names: set[str], tainted: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    for n in names:
        if n in tainted:
            return dict(tainted[n])
    # fallback first
    if tainted:
        return dict(next(iter(tainted.values())))
    return {}
