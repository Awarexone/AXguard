"""Phase 6 corpus fixture — finding with an unknown activation prerequisite.

ATTACK-GRAPH intended chain (expected.json: unknown_prerequisite):
  entrypoint(scheduled task: run_legacy_sync, prerequisite=unknown)
    --triggers--> finding(command-injection)
    --exposes--> asset(host filesystem)

The vulnerability itself is real (unsanitized shell command built from a
remote config payload), but static analysis alone cannot determine whether
this code path is ever actually reachable: it only runs when a remote
feature-flag service returns `legacy_sync_enabled=true`, a value that lives
entirely outside this codebase. There is no code-visible way to resolve that
prerequisite either way.

This differs from fixtures/attack_paths_app/unknown_reachability.py (unknown
*network* reachability): here the network path is fully internal/scheduled
either way — the *precondition* for the vulnerable branch to ever execute is
what's unknown, not who can reach it.

Expected path status: UNVERIFIED (prerequisite = unknown). Do NOT default to
either "always enabled" (over-claiming) or "never enabled, therefore safe"
(under-claiming) — this is exactly the case Phase 6 should surface for human
review rather than silently resolving in either direction.
"""

from __future__ import annotations

import subprocess


# ATTACK-GRAPH: entrypoint (node, reachability=unknown) — no HTTP route; runs
# only when a remote feature-flag service (not visible in this codebase)
# reports the legacy-sync flag as enabled. Could be always-on, could be
# permanently disabled — unknown from static analysis alone.
def run_legacy_sync(config_update: dict) -> bytes:
    """Applies a legacy sync payload, gated by an externally-managed flag."""
    sync_target = config_update.get("target", "primary")
    sync_id = config_update.get("sync_id", "unknown")

    # ATTACK-GRAPH: finding (node, kind=command-injection) — sync_target
    # comes straight from the remote config payload with no allowlist.
    cmd = f"legacy-sync --id {sync_id} --target {sync_target} --out /tmp/sync.log"
    result = subprocess.run(cmd, shell=True, capture_output=True)

    # ATTACK-GRAPH: asset (node, kind=filesystem) — arbitrary command
    # execution on the host running the sync job, if/when the flag is on.
    return result.stdout


if __name__ == "__main__":
    # Fixture stub — no real scheduler wiring; illustrates the handler shape.
    run_legacy_sync({"target": "primary", "sync_id": "abc123"})
