"""Ambiguous case — unknown attacker control → unknowns / MEDIUM or LOW / UNKNOWN."""

from __future__ import annotations


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


def run_report(query):
    """
    Sink with unclear attacker control / no request source in-scope.
    expected: unknowns present, confidence not HIGH/VERY_HIGH.
    """
    cur = get_cursor()
    cur.execute(query)
    return True
