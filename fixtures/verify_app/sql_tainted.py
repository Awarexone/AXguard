"""True-positive SQLi: request → f-string execute — expect VERIFIED or LIKELY."""

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
    # expected.json: VERIFIED or LIKELY
    cur.execute(f"SELECT * FROM items WHERE name = '{q}'")
    return {"ok": True}
