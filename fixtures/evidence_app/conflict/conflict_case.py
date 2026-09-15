"""Auth missing locally but a global middleware provides it → CONFLICT / REQUIRES_REVIEW.

The handler itself has a tainted SQL sink (supporting evidence). A sibling
``auth_middleware.py`` enforces authorization globally (counter evidence for the
authorization aspect). Support and counter disagree → the evidence engine should
record a conflict resolved to REQUIRES_REVIEW rather than inventing SAFE.
"""

from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


@app.route("/admin/report", methods=["GET"])
def admin_report():
    # No local authorization check here — relies on the global middleware.
    name = request.args.get("name")
    cur = get_cursor()
    cur.execute(f"SELECT * FROM reports WHERE owner = '{name}'")
    return {"ok": True}
