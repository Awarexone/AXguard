"""Phase 6 corpus fixture — CONFUSED DEPUTY: a privileged service acts on an
attacker-chosen object using its own credentials, without checking the
caller's authority over that specific object.

ATTACK-GRAPH intended chain (expected.json: confused_deputy):
  identity(any authenticated caller)
    --triggers--> finding(confused-deputy on POST /refunds/issue)
    --delegates--> external_service(billing API, called with the service's
                    own privileged API key, not the caller's)
    --exposes--> asset(another customer's refund/payment data)

`issue_refund` never checks that `customer_id` belongs to the caller — it
just uses `BILLING_SERVICE_KEY` (a secret the *service* holds, not the user)
to call the upstream billing API for whatever `customer_id` the request
supplies. Any authenticated user can trigger a refund/lookup against ANY
other customer's account because the deputy (this service) is more
privileged than its caller and never re-derives authority from the caller's
own identity — the classic confused-deputy shape, distinct from BOLA (no
per-object re-check on a *locally* stored record) because the privilege
being abused here is delegated to a *third-party* service call.

Expected path status: CONFIRMED or LIKELY once a chaining detector for this
pattern exists. No currently-shipped detector recognizes "own-credential
delegation to an upstream service without per-object authority re-check" as
distinct from BOLA (see docs/attack-graph.md "Non-goals" / structural seed
notes) — this case is a forward-looking regression anchor, marked `soft` in
expected.json so the suite stays green until a detector lands.
"""

from __future__ import annotations

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# ATTACK-GRAPH: asset (node, kind=credential) — the *service's* own
# privileged key, never the caller's. Placeholder only.
BILLING_SERVICE_KEY = "REDACTED_KEY"
BILLING_API_BASE = "https://billing.internal.example.com"


def current_user_id() -> str:
    # Fixture stub: normally derived from a verified session/JWT.
    return request.headers.get("X-User-Id", "user-1")


# ATTACK-GRAPH: entrypoint (node) — authenticated, but authentication only
# proves *who is calling*, not that the caller may act on `customer_id`.
@app.route("/refunds/issue", methods=["POST"])
def issue_refund():
    """Issues a refund for a customer, using the service's own billing key."""
    body = request.get_json(silent=True) or {}
    customer_id = body.get("customer_id")
    amount = body.get("amount")

    # ATTACK-GRAPH: finding (node, kind=confused-deputy) — no check that
    # current_user_id() is entitled to act on customer_id; the service uses
    # its OWN privileged key regardless of whose refund is being requested.
    resp = requests.post(
        f"{BILLING_API_BASE}/customers/{customer_id}/refunds",
        json={"amount": amount},
        headers={"Authorization": f"Bearer {BILLING_SERVICE_KEY}"},
        timeout=5,
    )

    # ATTACK-GRAPH: exposes edge — the response (including another
    # customer's refund/payment details) flows straight back to the caller.
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
