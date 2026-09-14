"""Comment-only mentions — must NOT become confirmed controls/services.

This module intentionally has no stripe SDK usage and no admin role checks.
Documentation below is for false-positive regression only.

# Notes for maintainers:
# - Someone mentioned integrating stripe webhooks in the future.
# - An "admin" dashboard was discussed in planning docs.
# - Do not treat these comments as live payment or auth controls.
"""

# Variables named generically; no Stripe client, no admin gate.
FEATURE_NOTES = (
    "TODO: research stripe billing options later",
    "TODO: maybe add admin UI someday",
)


def describe_roadmap() -> str:
    """Returns planning text that mentions admin and stripe in comments only."""
    # stripe admin — words appear in this comment alone
    return "roadmap placeholder"
