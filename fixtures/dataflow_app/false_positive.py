"""Dataflow fixture: comment-only execute — must not become a confirmed path."""

from __future__ import annotations

# False positive bait — comment only, no live call:
# execute(user_input)
# cursor.execute(f"SELECT {user_input}")
# requests.get(user_url)

PLACEHOLDER = True
