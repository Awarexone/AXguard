"""Phase 6 fixture — simple 2-hop chain: public endpoint -> vuln -> sensitive resource.

ATTACK-GRAPH intended chain (expected.json: simple_chain):
  entrypoint(GET /export, unauthenticated)
    --triggers--> finding(sql-injection)
    --exposes--> asset(customers table: emails + payment tokens)

No control sits on this path. Expected path status: CONFIRMED or LIKELY.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "app.db"


def get_db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


# ATTACK-GRAPH: entrypoint (node) — public, no auth decorator at all.
@app.route("/export", methods=["GET"])
def export_customers():
    """Public export endpoint — no authentication required."""
    fmt = request.args.get("format", "json")

    # ATTACK-GRAPH: finding (node, kind=sql-injection) — unsanitized string
    # concatenation directly into the query. Source: request.args (untrusted).
    query = "SELECT id, email, payment_token FROM customers WHERE format = '" + fmt + "'"
    conn = get_db()
    rows = conn.execute(query).fetchall()

    # ATTACK-GRAPH: asset (node, kind=database/credential) — payment_token is a
    # sensitive credential-like field. This is the "exposes" edge target.
    return jsonify({"rows": rows})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
