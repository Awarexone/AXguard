"""Ambiguous sink: execute(query) with unclear control — expect UNVERIFIED."""

from __future__ import annotations


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


def run_report(query):
    """
    Sink with unclear attacker control / no request source in-scope.
    expected.json: UNVERIFIED (prefer over inventing VERIFIED).
    """
    cur = get_cursor()
    cur.execute(query)
    return True
