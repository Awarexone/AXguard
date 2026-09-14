"""Phase 6 corpus fixture — user -> mass-assignment -> admin (privilege escalation).

ATTACK-GRAPH intended chain (expected.json: privilege_escalation):
  identity(role=user, authenticated)
    --triggers--> finding(mass-assignment / broken-authz on /profile/update)
    --escalates_to--> identity(role=admin)
    --triggers--> entrypoint(GET /admin/dashboard, requires_admin — trusts role claim)
    --exposes--> asset(customer billing directory)

Any authenticated low-privilege user can flip their own `role` field via the
profile-update endpoint, then pass the (still-broken) admin gate because it
only checks the mutable, attacker-controlled `role` column — no server-side
allowlist of who may hold "admin", no re-verification against an
authoritative source. Expected path status: CONFIRMED or LIKELY (the
`require_admin` control is ineffective, so it does not downgrade to
BLOCKED).
"""

from __future__ import annotations

from functools import wraps

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# Fixture in-memory "database" — placeholder only.
ACCOUNTS = {
    "acct-1": {"id": "acct-1", "email": "carol@example.com", "role": "user"},
    "acct-2": {"id": "acct-2", "email": "dave@example.com", "role": "user"},
}

# ATTACK-GRAPH: asset (node, kind=pii) — full billing directory.
BILLING_DIRECTORY = {
    "acct-1": {"invoice": "inv-a1", "amount": 120, "billing_email": "REDACTED_KEY"},
    "acct-2": {"invoice": "inv-a2", "amount": 340, "billing_email": "REDACTED_KEY"},
}


def current_account_id() -> str:
    # Fixture stub: normally derived from a verified session/JWT.
    return request.headers.get("X-Account-Id", "acct-1")


# ATTACK-GRAPH: control (node, kind=authorization, effectiveness=ineffective)
# Looks like a role gate, but it trusts the same mutable `role` field the
# attacker can set via /profile/update below.
def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        account = ACCOUNTS.get(current_account_id())
        if not account or account.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        g.account = account
        return view(*args, **kwargs)

    return wrapper


# ATTACK-GRAPH: finding (node, kind=broken-authz / mass-assignment) —
# accepts and applies the entire request body, including `role`, to the
# caller's own record with no allowlist of updatable fields.
@app.route("/profile/update", methods=["POST"])
def update_profile():
    """Self-service profile update — should only allow email/display fields."""
    account_id = current_account_id()
    account = ACCOUNTS.get(account_id)
    if not account:
        return jsonify({"error": "not_found"}), 404

    updates = request.get_json(silent=True) or {}
    # ATTACK-GRAPH: escalates_to edge — no field allowlist; `role` passes
    # straight through, so a "user" can set role="admin" on themselves.
    account.update(updates)
    return jsonify({"account": account})


# ATTACK-GRAPH: entrypoint (node) — gated by the ineffective control above.
@app.route("/admin/dashboard", methods=["GET"])
@require_admin
def admin_dashboard():
    """Admin-only billing directory."""
    return jsonify({"billing": list(BILLING_DIRECTORY.values())})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
