"""True-positive SQLi: strong evidence → HIGH / VERY_HIGH confidence."""

from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


def get_cursor():
    class _C:
        def execute(self, sql, *args):
            return sql

    return _C()


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q")
    cur = get_cursor()
    # expected: strong supporting evidence, HIGH/VERY_HIGH confidence
    cur.execute(f"SELECT * FROM items WHERE name = '{q}'")
    return {"ok": True}
