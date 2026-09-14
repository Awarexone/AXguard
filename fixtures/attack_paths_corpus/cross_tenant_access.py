"""Phase 6 corpus fixture — tenant A -> weak authz -> tenant B (cross-tenant / BOLA).

ATTACK-GRAPH intended chain (expected.json: cross_tenant_access):
  identity(tenant=A, authenticated)
    --triggers--> finding(broken-object-level-authz on
                  /workspaces/<org_id>/statements/<statement_id>)
    --crosses_tenant--> identity/asset(tenant=B statement + billing contact PII)

`require_workspace_member` confirms the *caller* belongs to `org_id` in the
URL, but never re-checks that the *statement actually returned* belongs to
that same org_id. A tenant-A user who guesses or enumerates another
tenant's `statement_id` reads tenant-B billing data. Expected path status:
CONFIRMED or LIKELY (tenant-scoping control is present but ineffective for
the actual query performed, so it does not block).
"""

from __future__ import annotations

from functools import wraps

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# Fixture in-memory "database" — placeholder only.
STATEMENTS = {
    "stmt-100": {
        "id": "stmt-100",
        "org_id": "org-a",
        "invoice": "inv-100",
        "amount": 700,
        "billing_email": "REDACTED_KEY",
    },
    "stmt-200": {
        "id": "stmt-200",
        "org_id": "org-b",
        "invoice": "inv-200",
        "amount": 1100,
        "billing_email": "REDACTED_KEY",
    },
}


def current_org_id() -> str:
    # Fixture stub: normally derived from a verified session/JWT claim.
    return request.headers.get("X-Org-Id", "org-a")


# ATTACK-GRAPH: control (node, kind=tenant-scoping, effectiveness=likely-but-incomplete)
# Confirms the *caller* belongs to org_id in the URL, but never re-checks
# that the *statement actually returned* belongs to that same org_id.
def require_workspace_member(view):
    @wraps(view)
    def wrapper(org_id: str, *args, **kwargs):
        if current_org_id() != org_id:
            return jsonify({"error": "forbidden"}), 403
        g.org_id = org_id
        return view(org_id, *args, **kwargs)

    return wrapper


# ATTACK-GRAPH: entrypoint (node) — org_id in the path looks scoped, but the
# lookup below ignores it.
@app.route("/workspaces/<org_id>/statements/<statement_id>", methods=["GET"])
@require_workspace_member
def get_statement(org_id: str, statement_id: str):
    """Fetch a single billing statement for the caller's workspace."""
    # ATTACK-GRAPH: finding (node, kind=broken-object-level-authz) — looked
    # up by statement_id alone; org_id from the URL/control is never
    # compared against statement["org_id"].
    statement = STATEMENTS.get(statement_id)
    if not statement:
        return jsonify({"error": "not_found"}), 404

    # ATTACK-GRAPH: crosses_tenant edge — a tenant-A caller supplying
    # statement_id="stmt-200" (org-b's statement) still gets a 200 with
    # org-b's billing PII.
    return jsonify({"statement": statement})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
