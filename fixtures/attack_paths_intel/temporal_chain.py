"""Phase 6 Part 2 fixture — multi-step *temporal* chain (register → verify → reset).

ATTACK-GRAPH (temporal): these three handlers form an ordered, stateful account
lifecycle. Each step assumes state produced by the previous one:

  register  --> account created (unverified)      [previous: no account]
  verify    --> account verified, token consumed   [previous: unverified account]
  reset     --> credential rotated via reset token [previous: verified account]

The abuse case is temporal, not single-request: e.g. a reset token that stays
valid after verification, or a verification step that can be skipped so a reset
is honoured on an unverified (attacker-registered) account. `engines/attack_graph/
temporal.py` should detect this as a `LIKELY` account_recovery chain because the
steps co-locate in one module in the expected order. It is never CONFIRMED —
static analysis cannot prove the cross-request state transition on its own.
"""

from __future__ import annotations

from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory placeholder state (fixture only — not real storage).
ACCOUNTS: dict[str, dict] = {}
RESET_TOKENS: dict[str, str] = {}


@app.route("/auth/register", methods=["POST"])
def register():
    """Step 1 — create an unverified account."""
    email = (request.json or {}).get("email", "")
    ACCOUNTS[email] = {"verified": False}
    return jsonify({"status": "registered", "email": email})


@app.route("/auth/verify", methods=["POST"])
def verify():
    """Step 2 — mark the account verified once the email token is presented."""
    email = (request.json or {}).get("email", "")
    if email in ACCOUNTS:
        ACCOUNTS[email]["verified"] = True
    return jsonify({"status": "verified", "email": email})


@app.route("/auth/reset", methods=["POST"])
def reset_password():
    """Step 3 — issue/consume a password reset token and rotate the credential."""
    email = (request.json or {}).get("email", "")
    token = (request.json or {}).get("token", "")
    # NOTE (temporal): no check that the reset token was invalidated by verify,
    # and no check that the account is actually verified before honouring reset.
    if RESET_TOKENS.get(email) == token:
        ACCOUNTS.setdefault(email, {})["password_rotated"] = True
        return jsonify({"status": "reset"})
    return jsonify({"status": "invalid"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
