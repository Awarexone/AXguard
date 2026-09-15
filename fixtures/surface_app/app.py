"""Surface-mapping fixture app — not for deployment."""

from __future__ import annotations

import requests
from flask import Flask, jsonify, request

from auth import require_auth

# Placeholder only — surface engine must redact values in output.
API_KEY = "REDACTED_TEST_ONLY"

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Public health check — no auth."""
    return jsonify({"status": "ok"})


@app.route("/api/users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id: str):
    """Authenticated user lookup."""
    row = db_query("SELECT id, email FROM users WHERE id = ?", user_id)
    return jsonify({"user": row})


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    """Inbound payment webhook."""
    payload = request.get_data()
    # Signature verification omitted in fixture.
    return jsonify({"received": True, "bytes": len(payload)})


def db_query(sql: str, *params):
    """DB query helper used by API handlers."""
    # Fixture stub — no real DB connection.
    return {"sql": sql, "params": params}


def fetch_profile(url: str):
    """Outbound HTTP call (SSRF-candidate sink for inventory)."""
    return requests.get(url, timeout=5)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
