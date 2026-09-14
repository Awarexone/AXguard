"""Dataflow fixture: parameterized SQL + allowlisted host (controls present)."""

from __future__ import annotations

from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_HOSTS = {"example.com", "cdn.example.com"}


def get_cursor():
    class _C:
        def execute(self, sql, params=None):
            return sql

    return _C()


@app.route("/users", methods=["GET"])
def users():
    user_id = request.args.get("id")
    cur = get_cursor()
    # Parameterized — should not look like confirmed unsanitized SQL path.
    cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    return {"ok": True}


@app.route("/preview", methods=["GET"])
def preview():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    hostname = parsed.hostname or ""
    if hostname not in ALLOWED_HOSTS:
        return {"error": "host not allowed"}, 400
    return requests.get(url, timeout=5).text
