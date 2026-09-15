"""Phase 6 Part 2 fixture — adversarial false relation (must NOT chain).

ATTACK-GRAPH (adversarial): two real but *independent* findings that share only
this file. They are crafted to bait a naive linker into fabricating a chain:

  finding_a: reflected XSS in /profile/preview (renders `bio` into HTML)
  finding_b: open redirect in /go (redirects to a caller-supplied `next` URL)

There is deliberately **no** shared data flow, no shared identity/session
requirement, no control handoff, and no asset in common. A tempting-but-false
"story" (XSS could steal a cookie, which could be used somewhere, which could
redirect...) is NOT supported by any code-visible edge. The engine must emit
two standalone findings and **zero** cross-finding path between them — exactly
as with `fixtures/attack_paths_app/false_chain.py`. If a path linking the two
is ever emitted, it must be INVALID; the preferred outcome is no path at all.
"""

from __future__ import annotations

from flask import Flask, request, redirect

app = Flask(__name__)


# ATTACK-GRAPH: finding_a (kind=xss) — standalone, output not consumed anywhere.
@app.route("/profile/preview", methods=["GET"])
def profile_preview():
    """Reflects an unsanitised bio field straight into HTML."""
    bio = request.args.get("bio", "")
    return f"<html><body><div class='bio'>{bio}</div></body></html>"


# ATTACK-GRAPH: finding_b (kind=open-redirect) — standalone, unrelated to /profile.
@app.route("/go", methods=["GET"])
def go():
    """Redirects to a caller-supplied URL with no allowlist."""
    next_url = request.args.get("next", "/")
    return redirect(next_url)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
