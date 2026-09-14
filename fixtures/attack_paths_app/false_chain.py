"""Phase 6 fixture — two unrelated vulns that must NOT chain.

ATTACK-GRAPH: this file intentionally contains two real, independent
findings that share nothing (no shared data flow, no shared call path, no
shared asset, not even the same request lifecycle):

  finding_a: reflected XSS in /search (renders query param into HTML)
  finding_b: path traversal in /reports/download (reads file by name param)

They live in the same Flask app and the same file, which is exactly the
trap: a naive "co-located in one file => chainable" heuristic (like the
same-file co-location fallback in app_model.graph) must NOT be upgraded into
an attack path between them. There is no edge connecting finding_a's output
to finding_b's input, no shared session/identity requirement, and no control
handoff between them.

Expected: two independent standalone findings, zero cross-finding path
between finding_a and finding_b. If a future engine emits a path linking
them, that path's status must be INVALID (or the path must simply not be
generated at all — see docs/attack-graph.md "Dead ends").
"""

from __future__ import annotations

import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/var/app/reports"


# ATTACK-GRAPH: finding_a (node, kind=xss) — standalone, no downstream use.
@app.route("/search", methods=["GET"])
def search():
    """Reflects the query term directly into an HTML fragment."""
    term = request.args.get("q", "")
    return f"<html><body><p>Results for: {term}</p></body></html>"


# ATTACK-GRAPH: finding_b (node, kind=path-traversal) — standalone, does not
# consume anything derived from /search and has no auth relationship to it.
@app.route("/reports/download", methods=["GET"])
def download_report():
    """Reads a report file by name with no path normalization/allowlist."""
    filename = request.args.get("name", "summary.pdf")
    full_path = os.path.join(REPORTS_DIR, filename)
    with open(full_path, "rb") as fh:
        data = fh.read()
    return data, 200, {"Content-Type": "application/octet-stream"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
