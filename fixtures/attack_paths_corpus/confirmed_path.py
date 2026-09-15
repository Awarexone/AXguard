"""Phase 6 corpus fixture — CONFIRMED path: public entrypoint -> sql-injection -> sensitive asset.

ATTACK-GRAPH intended chain (expected.json: confirmed_path):
  entrypoint(GET /orders/search, unauthenticated)
    --triggers--> finding(sql-injection)
    --exposes--> asset(orders table: customer emails + card tokens)

No control sits on this path. Expected path status: CONFIRMED or LIKELY.
This case is a stable, always-on regression anchor for the corpus — a
distinct file/route from fixtures/attack_paths_app/simple_chain.py so the
two suites never collide on the same source location.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "orders.db"


def get_db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


# ATTACK-GRAPH: entrypoint (node) — public, no auth decorator at all.
@app.route("/orders/search", methods=["GET"])
def search_orders():
    """Public order-search endpoint — no authentication required."""
    term = request.args.get("q", "")

    # ATTACK-GRAPH: finding (node, kind=sql-injection) — unsanitized string
    # concatenation directly into the query. Source: request.args (untrusted).
    query = "SELECT id, customer_email, card_token FROM orders WHERE note = '" + term + "'"
    conn = get_db()
    rows = conn.execute(query).fetchall()

    # ATTACK-GRAPH: asset (node, kind=database/credential) — card_token is a
    # sensitive credential-like field. This is the "exposes" edge target.
    return jsonify({"rows": rows})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
