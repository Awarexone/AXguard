"""Named sanitize() that does nothing effective — must NOT auto FALSE_POSITIVE."""

from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


def sanitize(value: str) -> str:
    """Looks protective by name but returns the value unchanged."""
    return value


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


@app.route("/q", methods=["GET"])
def query_items():
    raw = request.args.get("q") or ""
    cleaned = sanitize(raw)
    cur = get_cursor()
    # noop sanitize — still tainted; expect CONFIRMED / LIKELY / REQUIRES_REVIEW (not FP-only)
    cur.execute(f"SELECT * FROM items WHERE tag = '{cleaned}'")
    return {"ok": True}
