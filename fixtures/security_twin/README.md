# Security Twin fixtures

Golden expectations for the Security Twin engine (`engines/twin/`).

- **Source app:** `fixtures/attack_paths_app` (same vulnerable chains as Phase 6).
- **expected.json:** Stable twin summary counts from `build_security_twin` — not timestamps.
- Tests live in `tests/test_security_twin.py` and use `tmp_path` for report writes.

Do not deploy these fixtures.
