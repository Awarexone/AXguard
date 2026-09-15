# API Security Notes

- Default bind is loopback only (`127.0.0.1:8787`).
- No AwareXone cloud, accounts, or telemetry in the API path.
- Bearer keys use `axg_` prefix and are stored hashed.
- Do not expose the API on a public interface without auth, TLS termination, and network controls you own.
- LLM calls use stdlib `urllib` to **your** endpoint only — never an AXGuard-hosted model.
