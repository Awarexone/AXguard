"""Auth middleware evidence for surface mapping fixtures."""

from __future__ import annotations

from functools import wraps

import jwt
from flask import g, jsonify, request

# Session/JWT secret placeholder — must be redacted in model output.
SESSION_SECRET = "REDACTED_TEST_ONLY"


def require_auth(view):
    """JWT/session middleware — looks like auth is required nearby."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        try:
            claims = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "unauthorized"}), 401
        g.user = claims
        g.role = claims.get("role", "user")
        return view(*args, **kwargs)

    return wrapper


def require_admin(view):
    """Role gate referencing admin."""

    @wraps(view)
    @require_auth
    def wrapper(*args, **kwargs):
        if getattr(g, "role", None) != "admin":
            return jsonify({"error": "forbidden"}), 403
        return view(*args, **kwargs)

    return wrapper
