"""Phase 6 Part 2 fixture — confused deputy (server acts with its own authority).

ATTACK-GRAPH (confused deputy / SSRF-style): a public endpoint accepts a
user-supplied URL and fetches it *using the server's own privileged network
position and credentials*. The server is the "deputy": the attacker cannot
reach the internal metadata/admin service directly, but the server can, and it
does so on the attacker's behalf without re-checking whether the caller is
authorised for the target.

  entrypoint(POST /proxy/fetch, public)
    --triggers--> finding(ssrf / confused-deputy)
    --triggers--> internal endpoint reachable only from the server
    --exposes--> asset(internal API token store)

This exercises the what-if `unrestricted_egress` scenario and the cross-service
trust-boundary logic (internal ≠ trusted). Credentials here are placeholders.
"""

from __future__ import annotations

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ATTACK-GRAPH: asset (kind=credential) — placeholders only.
INTERNAL_API_TOKENS = {
    "internal_api_token": "REDACTED_KEY",
    "aws_secret_key": "REDACTED_KEY",
}


@app.route("/proxy/fetch", methods=["POST"])
def proxy_fetch():
    """Public endpoint: fetches an arbitrary user-supplied URL server-side."""
    target_url = request.json.get("url") if request.is_json else request.form.get("url")
    # ATTACK-GRAPH: confused deputy — no host allowlist; the server fetches
    # whatever the caller names, using its own trusted network position.
    resp = requests.get(target_url, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text[:2000]})


@app.route("/internal/tokens", methods=["GET"])
def internal_tokens():
    """Intended internal-only: relies on unenforced network placement."""
    return jsonify({"tokens": INTERNAL_API_TOKENS})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
