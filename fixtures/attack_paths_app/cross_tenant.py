"""Phase 6 fixture — tenant A -> weak authz -> tenant B (BOLA / cross-tenant).

ATTACK-GRAPH intended chain (expected.json: cross_tenant):
  identity(tenant=A, authenticated)
    --triggers--> finding(broken-object-level-authz on /orgs/<org_id>/invoices/<invoice_id>)
    --crosses_tenant--> identity/asset(tenant=B invoice + billing contact PII)

The endpoint checks that the caller belongs to *some* org (authenticated),
and even checks `org_id` against the caller's own org, but then looks the
invoice up by `invoice_id` alone in a global table with no re-check that the
returned invoice actually belongs to `org_id`. A tenant-A user who guesses
or enumerates another tenant's `invoice_id` reads tenant-B billing data.
Expected path status: CONFIRMED or LIKELY (tenant-scoping control is present
but ineffective for the actual query performed, so it does not block).
"""

from __future__ import annotations

from functools import wraps

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# Fixture in-memory "database" — placeholder only.
INVOICES = {
    "inv-100": {"id": "inv-100", "org_id": "org-a", "amount": 500, "billing_email": "REDACTED_KEY"},
    "inv-200": {"id": "inv-200", "org_id": "org-b", "amount": 900, "billing_email": "REDACTED_KEY"},
}


def current_org_id() -> str:
    # Fixture stub: normally derived from a verified session/JWT claim.
    return request.headers.get("X-Org-Id", "org-a")


# ATTACK-GRAPH: control (node, kind=tenant-scoping, effectiveness=likely-but-incomplete)
# Confirms the *caller* belongs to org_id in the URL, but never re-checks
# that the *invoice actually returned* belongs to that same org_id.
def require_org_member(view):
    @wraps(view)
    def wrapper(org_id: str, *args, **kwargs):
        if current_org_id() != org_id:
            return jsonify({"error": "forbidden"}), 403
        g.org_id = org_id
        return view(org_id, *args, **kwargs)

    return wrapper


# ATTACK-GRAPH: entrypoint (node) — org_id in the path looks scoped, but the
# lookup below ignores it.
@app.route("/orgs/<org_id>/invoices/<invoice_id>", methods=["GET"])
@require_org_member
def get_invoice(org_id: str, invoice_id: str):
    """Fetch a single invoice for the caller's org."""
    # ATTACK-GRAPH: finding (node, kind=broken-object-level-authz) — looked
    # up by invoice_id alone; org_id from the URL/control is never compared
    # against invoice["org_id"].
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "not_found"}), 404

    # ATTACK-GRAPH: crosses_tenant edge — a tenant-A caller supplying
    # invoice_id="inv-200" (org-b's invoice) still gets a 200 with org-b's
    # billing PII.
    return jsonify({"invoice": invoice})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
