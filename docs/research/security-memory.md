# Research: AXGuard Security Memory (Longitudinal Security Intelligence)

**Status:** Internal research ahead of `engines/memory/`  
**Date:** 2026-09  
**Stance:** Prefer structured history over scan caches. Prefer UNKNOWN over inventing continuity.

---

## 1. Problem

A conventional scanner thinks: *scan again*.

AXGuard already builds application models, evidence, adversary judgments, and attack paths. What it lacks is a **persistent, versioned security memory** that answers:

- What did we previously observe / prove / reject?
- Which controls and paths still hold?
- What changed since revision *A*?
- Which fixed issues **regressed**?
- Which false-positive decisions must be **re-evaluated** because their justifying control changed?

This is longitudinal security intelligence — not result caching.

---

## 2. Existing approaches

### 2.1 Incremental static analysis

| Approach | What it does | Limitation |
|---|---|---|
| **CodeQL overlay / PR incremental analysis** | Reuses base databases; analyzes changed code; reports new alerts in the diff | Optimizes *scan cost*; does not model finding lifecycle or FP control justification across revisions ([GitHub Changelog May 2025](https://github.blog/changelog/2025-05-28-incremental-security-analysis-makes-codeql-up-to-20-faster-in-pull-requests/), [Sep 2025 all languages](https://github.blog/changelog/2025-09-23-incremental-security-analysis-with-codeql-is-now-available-for-all-languages/), [CLI overlay docs](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/incremental-analysis)) |
| **Semgrep / SAST CI caches** | Rule-result caching, partial re-scan | Cache invalidation is file/rule coarse; little cross-run control reasoning |
| **Build caches / analysis DBs** | Persist intermediate IR | Not a security decision history |

**Takeaway:** Incremental analysis solves *speed*. Security Memory must solve *continuity of security conclusions*.

### 2.2 Vulnerability lifecycle / tracking

Issue trackers (GHAS alerts, Jira, DefectDojo, Faraday) track alert open/close by identity. They rarely store:

- evidence chains that justified a FALSE_POSITIVE
- which control made a path BLOCKED
- that removing middleware should reopen a rejected finding

### 2.3 Temporal attack graphs / knowledge graphs

Cloud CNAPP graphs (Wiz, etc.) are temporal at the *estate* layer. Academic temporal attack graphs model state over time but are rarely shipped as **local pre-ship code twins**.

AXGuard already has structural path fingerprints (`engines/attack_graph/diff.py`) and predictive trend reports — the right primitives for a memory layer.

### 2.4 Provenance & evidence stores

Content-addressed evidence (AXGuard `EvidenceStore` with `content_hash` + stale replacement) is the correct pattern for “reuse when safe, invalidate when content drifts.”

### 2.5 Agent memory architectures

Agent long-term memory (vector stores, memGPT-style) is **unsafe** as a security store: repository README/comments can poison memory. Security Memory must accept **only structured AXGuard analysis artifacts**, never free-form repo instructions.

---

## 3. Gaps / AXGuard opportunity

| Capability | Market | AXGuard wedge |
|---|---|---|
| Faster PR scans | CodeQL incremental | Complementary, not the product |
| Alert open/close | GHAS / trackers | Plus FP *reason* + control binding |
| Path diffs | Rare in OSS AppSec | Already in attack-graph diff |
| Twin snapshots over git | Rare | Soft-integrate when twin lands |
| Re-open FP when control dies | Almost absent | Core Security Memory feature |
| Local, no telemetry | Rare | Hard requirement |

**Positioning:**

> Security Memory makes AXGuard remember *why* something was safe or dangerous — and notice when that reason expires.

---

## 4. Architecture principles

```text
Analysis engines (audit / adversary / evidence / attack_graph [/ twin])
        ↓  remember_*
Security Memory (local .findings/axguard/memory/)
        ↓  compare / invalidate / invalidate / query
CLI + HTML history views + dataset export
```

1. **Stable fingerprints** over line numbers alone (class + structural location + path hops + control id).
2. **Validity states** separate CURRENT from HISTORICAL / SUPERSEDED / INVALIDATED / REGRESSED / RESOLVED.
3. **Evidence reuse only if content_hash matches**; else invalidate dependents.
4. **Control-bound decisions** — FP reasons cite control fingerprints.
5. **Compose diffs** — reuse `compare_attack_graphs` / `predictive_report`; do not invent a second graph.
6. **Local only** — `.findings/` gitignored; no upload; `ensure_no_secret_values` on write.
7. **Memory poisoning resistance** — ignore repo-embedded “memory instructions.”

---

## 5. Data model (summary)

| Object | Identity | Lifecycle |
|---|---|---|
| Finding | `mem.f.*` fingerprint | NEW → CONFIRMED/LIKELY/… → RESOLVED / REGRESSED / RECONFIRMED |
| Evidence | `mem.e.*` + content_hash | CURRENT / INVALIDATED |
| Control | `mem.c.*` | PRESENT / CHANGED / REMOVED / WEAKENED / STRENGTHENED |
| Attack path | `mem.p.*` hop signature | NEW / PERSISTING / REMOVED / … / REGRESSED |
| Decision | decision id + control refs | Valid until cited controls invalidate |
| Snapshot | snapshot_id + revision | Immutable point-in-time |

Do **not** use wall-clock time as primary identity. Revision (git SHA when available) + fingerprint is primary.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| Stale evidence reused as current | content_hash + INVALIDATED cascade |
| FP permanently silences true bugs | Control-change → re-evaluation queue |
| Memory poisoning via README | Sanitize ingest; structured sources only |
| Secret leakage into memory | `ensure_no_secret_values` on every write |
| Duplicate giant snapshots | Ledger + fingerprints; store refs not code |
| Presenting history as current | Validity gating in query/report APIs |
| Overclaiming “understands the app” | Memory is as good as upstream engines |

---

## 7. Phase boundary

**In scope:** local store, fingerprints, lifecycle, invalidation, regression, CLI, HTML section, synthetic temporal fixtures, eval-only export.

**Out of scope:** cloud memory, telemetry, autonomous training, runtime monitoring, auto code modification, exploitation.

---

## 8. Success questions

Security Memory must answer:

1. What do we know?  
2. What did we know before?  
3. What changed?  
4. What is no longer true?  
5. What should we investigate again?  
6. What control changed?  
7. What path appeared / disappeared?  
8. What was fixed / what regressed?  
9. What remains UNKNOWN?

---

## 9. Sources

- CodeQL incremental analysis (2025): https://github.blog/changelog/2025-05-28-incremental-security-analysis-makes-codeql-up-to-20-faster-in-pull-requests/
- CodeQL all-language incremental: https://github.blog/changelog/2025-09-23-incremental-security-analysis-with-codeql-is-now-available-for-all-languages/
- CodeQL CLI overlay analysis: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/incremental-analysis
- AXGuard attack-graph diff / evidence store (in-repo)

---

## 10. Conclusion

Incremental scanners optimize *recomputing*. Security Memory optimizes *remembering for security reasons* — especially the fragile cases: false positives justified by controls, and attack paths that should reopen when those controls regress.
