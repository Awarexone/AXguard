"""Phase 6 fixture — finding with unknown network reachability.

ATTACK-GRAPH intended chain (expected.json: unknown_reachability):
  entrypoint(queue consumer: process_export_job)
    --triggers--> finding(command-injection)
    --exposes--> asset(host filesystem)

The vulnerability itself is real (unsanitized shell command built from a
queue message field), but static analysis alone cannot determine who can
publish to this queue — it may be internal-only (worker-to-worker), it may
be reachable from a public-facing API that enqueues jobs, or it may accept
messages from a third-party webhook relay. There is no code-visible trust
boundary here to classify it either way.

Expected path status: UNVERIFIED (reachability = unknown). Do NOT default to
either "public" (over-claiming) or "internal, therefore safe"
(under-claiming) — this is exactly the case Phase 6 should surface for
human review rather than silently resolving in either direction.
"""

from __future__ import annotations

import subprocess

# ATTACK-GRAPH: entrypoint (node, reachability=unknown) — no HTTP route, no
# visible publisher of this queue in this file or anywhere else in this
# fixture app. Could be internal-only or could be fed by a public API.
def process_export_job(message: dict) -> bytes:
    """Consumes a job message and shells out to a report-conversion tool."""
    export_format = message.get("format", "pdf")
    job_id = message.get("job_id", "unknown")

    # ATTACK-GRAPH: finding (node, kind=command-injection) — export_format
    # comes straight from the queue message with no allowlist/validation.
    cmd = f"convert-report --id {job_id} --format {export_format} --out /tmp/out.bin"
    result = subprocess.run(cmd, shell=True, capture_output=True)

    # ATTACK-GRAPH: asset (node, kind=filesystem) — arbitrary command
    # execution on the worker host.
    return result.stdout


if __name__ == "__main__":
    # Fixture stub — no real queue wiring; illustrates the handler shape only.
    process_export_job({"format": "pdf", "job_id": "1234"})
