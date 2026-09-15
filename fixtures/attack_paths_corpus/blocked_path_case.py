"""Phase 6 corpus fixture — BLOCKED path: effective admin auth gates a real sink bug.

ATTACK-GRAPH intended chain (expected.json: blocked_path_case):
  entrypoint(GET /admin/exports, requires_admin — EFFECTIVE)
    --triggers--> finding(sql-injection)
    --exposes--> asset(export batch data)

The sink-level vulnerability (string-built SQL) is real, but require_admin
verifies signature + expiry (jwt.decode) and checks role, failing closed on
every branch (returns 401/403 before the handler body runs). Expected path
status: BLOCKED for the unauthenticated-attacker path — the underlying
finding may still stand alone as CONFIRMED/LIKELY for an already-
authenticated admin; Phase 6 does not erase it, it marks the *path* blocked.
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
@app.route("/admin/exports", methods=["GET"])
@require_admin
def admin_exports():
    """Admin-only export listing — auth is effective, but the query is not safe."""
    batch = request.args.get("batch", "latest")

    # ATTACK-GRAPH: finding (node, kind=sql-injection) — still a real bug,
    # but only reachable by an already-authenticated admin.
    import sqlite3

    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM export_batches WHERE batch = '" + batch + "'"
    rows = conn.execute(query).fetchall()

    # ATTACK-GRAPH: asset (node) — export batch data, gated behind the
    # confirmed control above.
    return jsonify({"rows": rows})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
