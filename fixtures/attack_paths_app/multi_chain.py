"""Phase 6 fixture — 3-hop chain: SSRF -> internal endpoint -> credential exposure.

ATTACK-GRAPH intended chain (expected.json: multi_chain):
  entrypoint(POST /integrations/preview, unauthenticated)
    --triggers--> finding(ssrf)
    --triggers--> entrypoint(GET /internal/admin/config, intended internal-only)
    --exposes--> asset(cloud credentials + internal API tokens)

Realistic enough for later dataflow/call-graph resolution: the SSRF sink's
response is round-tripped back to the caller, and the "internal" endpoint is
reachable over the same Flask app (no network segmentation enforced in code),
so a naive network-layer assumption ("internal, therefore safe") does not
hold. Expected path status: CONFIRMED or LIKELY (no effective control blocks
the internal hop).
"""

from __future__ import annotations

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# ATTACK-GRAPH: asset (node, kind=credential) — placeholders only.
CLOUD_CREDENTIALS = {
    "aws_access_key": "REDACTED_KEY",
    "aws_secret_key": "REDACTED_KEY",
    "internal_api_token": "REDACTED_KEY",
}


# ATTACK-GRAPH: entrypoint (node) — public webhook-preview style feature.
@app.route("/integrations/preview", methods=["POST"])
def preview_integration():
    """Fetches a user-supplied URL to render a link preview."""
    target_url = request.json.get("url") if request.is_json else request.form.get("url")

    # ATTACK-GRAPH: finding (node, kind=ssrf) — attacker fully controls the
    # host, including internal/loopback addresses. No allowlist check here.
    resp = requests.get(target_url, timeout=5)

    # ATTACK-GRAPH: triggers edge — the SSRF response body is returned
    # verbatim, so an attacker pointing target_url at the internal admin
    # endpoint below reads its response through this proxy.
    return jsonify({"status": resp.status_code, "body": resp.text[:2000]})


# ATTACK-GRAPH: entrypoint (node) — intended to be "internal-only" but is
# just another route on the same Flask app; nothing enforces network
# segmentation or authentication in code.
@app.route("/internal/admin/config", methods=["GET"])
def internal_admin_config():
    """No auth decorator: relies entirely on (unenforced) network placement."""
    # ATTACK-GRAPH: exposes edge — internal config handler returns live
    # cloud + API credentials.
    return jsonify({"config": CLOUD_CREDENTIALS})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
