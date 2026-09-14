"""Ambiguous control / unclear attacker input — REQUIRES_REVIEW or UNVERIFIED."""

from __future__ import annotations


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


def run_report(query):
    """
    Sink with unclear attacker control / no request source in-scope.
    expected: REQUIRES_REVIEW or UNVERIFIED (never invent CONFIRMED).
    """
    cur = get_cursor()
    cur.execute(query)
    return True
