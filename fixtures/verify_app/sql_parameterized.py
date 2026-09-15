"""False-positive SQLi: parameterized execute — expect FALSE_POSITIVE."""

from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


def get_cursor():
    class _C:
        def execute(self, sql, params=None):
            return sql

    return _C()


@app.route("/users", methods=["GET"])
def users():
    user_id = request.args.get("id")
    cur = get_cursor()
    # expected.json: FALSE_POSITIVE (bound args)
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return {"ok": True}
