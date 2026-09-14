"""Phase 6 corpus fixture — FALSE path: two unrelated vulns must NOT chain.

  finding_a: reflected XSS in /profile (renders a name param into HTML)
  finding_b: local file inclusion in /files/read (reads a file by name param)

Same trap as fixtures/attack_paths_app/false_chain.py, on distinct routes/
file so this corpus is self-contained: same-file co-location must never be
upgraded into a chain by a naive heuristic. There is no shared data flow, no
shared call path, no shared asset, and no shared request lifecycle between
finding_a and finding_b.

Expected: two independent standalone findings, zero cross-finding path. If a
future engine ever emits a path linking them, that path's status must be
INVALID (or, preferably, no such path is generated at all).
"""

from __future__ import annotations

import os

from flask import Flask, request

app = Flask(__name__)

UPLOADS_DIR = "/var/app/uploads"


# ATTACK-GRAPH: finding_a (node, kind=xss) — standalone, no downstream use.
@app.route("/profile", methods=["GET"])
def profile():
    """Reflects the display name directly into an HTML fragment."""
    name = request.args.get("name", "")
    return f"<html><body><h1>Welcome, {name}</h1></body></html>"


# ATTACK-GRAPH: finding_b (node, kind=path-traversal) — standalone, does not
# consume anything derived from /profile and has no auth relationship to it.
@app.route("/files/read", methods=["GET"])
def read_file():
    """Reads an uploaded file by name with no path normalization/allowlist."""
    filename = request.args.get("name", "readme.txt")
    full_path = os.path.join(UPLOADS_DIR, filename)
    with open(full_path, "rb") as fh:
        data = fh.read()
    return data, 200, {"Content-Type": "application/octet-stream"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
