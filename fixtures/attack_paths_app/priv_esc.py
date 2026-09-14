"""Phase 6 fixture — user -> authz weakness -> admin (privilege escalation).

ATTACK-GRAPH intended chain (expected.json: priv_esc):
  identity(role=user, authenticated)
    --triggers--> finding(mass-assignment / broken-authz on /account/update)
    --escalates_to--> identity(role=admin)
    --triggers--> entrypoint(GET /admin/users, requires_admin — trusts role claim)
    --exposes--> asset(full user directory incl. emails)

Any authenticated low-privilege user can flip their own `role` field via the
account-update endpoint, then pass the (now-effectively-broken) admin gate
because it only checks the mutable, attacker-controlled `role` column.
Expected path status: CONFIRMED or LIKELY (the `require_admin` control here
is ineffective — see below — so it does not downgrade to BLOCKED).
"""

from __future__ import annotations

from functools import wraps

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# Fixture in-memory "database" — placeholder only.
USERS = {
    "user-1": {"id": "user-1", "email": "alice@example.com", "role": "user"},
    "user-2": {"id": "user-2", "email": "bob@example.com", "role": "user"},
}


def current_user_id() -> str:
    # Fixture stub: normally derived from a verified session/JWT.
    return request.headers.get("X-User-Id", "user-1")


# ATTACK-GRAPH: control (node, kind=authorization, effectiveness=ineffective)
# Looks like a role gate, but it trusts the same mutable `role` field the
# attacker can set via /account/update below — no server-side allowlist of
# who may hold "admin", no re-verification against an authoritative source.
def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = USERS.get(current_user_id())
        if not user or user.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        g.user = user
        return view(*args, **kwargs)

    return wrapper


# ATTACK-GRAPH: finding (node, kind=broken-authz / mass-assignment) —
# accepts and applies the entire request body, including `role`, to the
# caller's own record with no allowlist of updatable fields.
@app.route("/account/update", methods=["POST"])
def update_account():
    """Self-service profile update — should only allow email/display fields."""
    user_id = current_user_id()
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "not_found"}), 404

    updates = request.get_json(silent=True) or {}
    # ATTACK-GRAPH: escalates_to edge — no field allowlist; `role` passes
    # straight through, so a "user" can set role="admin" on themselves.
    user.update(updates)
    return jsonify({"user": user})


# ATTACK-GRAPH: entrypoint (node) — gated by the ineffective control above.
@app.route("/admin/users", methods=["GET"])
@require_admin
def list_all_users():
    """Admin-only directory listing."""
    # ATTACK-GRAPH: asset (node, kind=pii) — full user directory.
    return jsonify({"users": list(USERS.values())})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
