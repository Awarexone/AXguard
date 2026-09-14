"""Hunter registry for Phase 3 verification."""

from __future__ import annotations

from engines.verify.hunter import SecurityHunter
from engines.verify.hunters.command_injection import CommandInjectionHunter
from engines.verify.hunters.path_traversal import PathTraversalHunter
from engines.verify.hunters.sql_injection import SqlInjectionHunter
from engines.verify.hunters.ssrf import SsrfHunter
from engines.verify.hunters.xss import XssHunter

_DEFAULT_HUNTERS: list[SecurityHunter] = [
    SqlInjectionHunter(),
    SsrfHunter(),
    XssHunter(),
    CommandInjectionHunter(),
    PathTraversalHunter(),
]


def default_hunters() -> list[SecurityHunter]:
    return list(_DEFAULT_HUNTERS)


def get_hunter(name: str) -> SecurityHunter | None:
    for h in _DEFAULT_HUNTERS:
        if h.name == name:
            return h
    return None


__all__ = [
    "CommandInjectionHunter",
    "PathTraversalHunter",
    "SqlInjectionHunter",
    "SsrfHunter",
    "XssHunter",
    "default_hunters",
    "get_hunter",
]
