"""Phase 6 fixture — vuln blocked by effective auth.

ATTACK-GRAPH intended chain (expected.json: blocked_path):
  entrypoint(GET /admin/reports, requires_admin — EFFECTIVE)
    --triggers--> finding(sql-injection)
    --exposes--> asset(revenue report data)

The sink-level vulnerability (string-built SQL) is real, but the entrypoint
enforces authentication AND role checks correctly and consistently (the
decorator actually validates the token and short-circuits on failure — no
name-only stub). Expected path status: BLOCKED (control effectiveness =
confirmed on the `reaches` edge). The underlying finding itself may still be
reported standalone as CONFIRMED/LIKELY by Phase 3/4 — Phase 6 does not
erase it, it just marks the *path* to an unauthenticated attacker as blocked.
"""

from __future__ import annotations

from functools import wraps

import jwt
from flask import Flask, g, jsonify, request

app = Flask(__name__)

# Placeholder only — never a real secret.
SESSION_SECRET = "REDACTED_KEY"


# ATTACK-GRAPH: control (node, kind=authorization, effectiveness=confirmed)
# Real check: verifies signature, checks expiry (via jwt.decode), and checks
# role — every failure path returns before reaching the handler body.
def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        try:
            claims = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "unauthorized"}), 401
        if claims.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        g.user = claims
        return view(*args, **kwargs)

    return wrapper


# ATTACK-GRAPH: entrypoint (node) — reachable only after require_admin passes.
@app.route("/admin/reports", methods=["GET"])
@require_admin
def admin_reports():
    """Admin-only report export — auth is effective, but the query is not safe."""
    period = request.args.get("period", "monthly")

    # ATTACK-GRAPH: finding (node, kind=sql-injection) — still a real bug,
    # but only reachable by an already-authenticated admin.
    import sqlite3

    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM revenue_reports WHERE period = '" + period + "'"
    rows = conn.execute(query).fetchall()

    # ATTACK-GRAPH: asset (node) — revenue data, gated behind the confirmed
    # control above.
    return jsonify({"rows": rows})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
