"""Global authorization middleware — counter-evidence for the authorization aspect."""

from __future__ import annotations

from flask import Flask, abort, request

app = Flask(__name__)


def has_permission(user, action) -> bool:
    return bool(user) and action in getattr(user, "scopes", [])


@app.before_request
def require_auth():
    """Enforced for every request before any handler runs."""
    user = getattr(request, "user", None)
    if not check_permission(user):
        abort(403)


def check_permission(user) -> bool:
    # Authorization is enforced globally here, not in each handler.
    return has_permission(user, "read")
