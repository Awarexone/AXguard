"""Phase 6 corpus fixture — STATE-DEPENDENT / CROSS-REQUEST chain (TOCTOU).

ATTACK-GRAPH intended chain (expected.json: state_dependent_chain):
  entrypoint(POST /cart/apply-coupon, authenticated)          [request-1]
    --triggers--> finding(unvalidated discount stored in session state)
    --state--> entrypoint(POST /cart/checkout, authenticated)  [request-2]
    --exposes--> asset(order pricing / revenue)

Neither request is vulnerable in isolation — the bug only exists across the
*sequence* of two requests sharing session state: request-1 stores a
client-controlled discount percentage into the session without validating it
against a server-side coupon table; request-2 (a separate HTTP request,
possibly much later, possibly from a different device) trusts that stored
value at checkout without re-validating it. The `# ATTACK-GRAPH: request-1`
/ `# ATTACK-GRAPH: request-2` comment markers below stand in for the two
separate HTTP calls a real dynamic/integration test would issue — this is a
static fixture, so the two-request sequence is documented rather than
executed.

Expected path status: CONFIRMED or LIKELY once a chaining detector for
cross-request / state-dependent sequences exists. This needs session-state
dataflow tracked *across* two distinct handlers, which no currently-shipped
detector performs (chaining.py's builders are all single-file, single-
request-scoped) — see docs/attack-graph.md. This case is a forward-looking
regression anchor, marked `soft` in expected.json so the suite stays green
until a detector lands.
"""

from __future__ import annotations

from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = "REDACTED_KEY"  # placeholder only, never a real secret

CART_TOTALS = {"user-1": 100.0, "user-2": 250.0}


def current_user_id() -> str:
    return request.headers.get("X-User-Id", "user-1")


# ATTACK-GRAPH: request-1 — entrypoint (node) stores a client-supplied
# discount percentage into session state with no server-side coupon lookup.
@app.route("/cart/apply-coupon", methods=["POST"])
def apply_coupon():
    """Applies a coupon code the client claims is valid."""
    body = request.get_json(silent=True) or {}
    # ATTACK-GRAPH: finding (node, kind=unvalidated-state) — discount_percent
    # is taken verbatim from the request and persisted into session state;
    # there is no lookup against a coupon table to confirm it is legitimate.
    discount_percent = body.get("discount_percent", 0)
    session["discount_percent"] = discount_percent
    return jsonify({"applied": True})


# ATTACK-GRAPH: request-2 — a later, separate entrypoint (node) that trusts
# the state written by apply_coupon() with no re-validation.
@app.route("/cart/checkout", methods=["POST"])
def checkout():
    """Finalizes the order total using whatever discount is in session state."""
    user_id = current_user_id()
    base_total = CART_TOTALS.get(user_id, 0.0)

    # ATTACK-GRAPH: state edge — trusts session["discount_percent"] set by
    # apply_coupon() in an earlier, unrelated request with no re-check.
    discount_percent = session.get("discount_percent", 0)
    final_total = base_total * (1 - (discount_percent / 100.0))

    # ATTACK-GRAPH: asset (node, kind=financial) — order pricing/revenue,
    # exposed to an arbitrary attacker-chosen discount across two requests.
    return jsonify({"total": final_total})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
