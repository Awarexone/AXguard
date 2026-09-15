# False-Positive Hard-Negative Corpus — Research Notes

Phase 9 research for the AXGuard training-data pipeline. This document defines how to build **hard-negative** false-positive (FP) training examples aligned with Phase 4 adversary `false_positive_reasons` codes — not toy “obviously safe” snippets.

**Scope:** research and schema design only. No engine changes. Labels must match what the deterministic adversary emits today (`engines/adversary/schema.py`).

---

## 1. Why hard negatives matter

Static scanners and LLM judges over-call. A useful FP corpus teaches models to **disprove** findings with the same structured vocabulary the adversary uses — without collapsing real bugs into SAFE.

| Easy negative (avoid as primary training mass) | Hard negative (target) |
|---|---|
| Comment-only SQLi bait | Live f-string SQL **next to** a dead parameterized helper in another branch |
| `cur.execute("... ?", (x,))` in isolation | Parameterized query where **one** dynamic fragment still concatenates |
| Function named `sanitize()` returning input unchanged | Partial HTML escape in HTML context but raw `|safe` in Jinja branch |
| “This is fixed — ignore” comment | Adversarial comment **plus** real taint — comment must be ignored, path judged on code |
| `@login_required` on unrelated route | Auth on entrypoint but IDOR on nested resource the finding actually describes |

Hard negatives should **look like findings** to a pattern matcher or shallow judge: dangerous sink, user-ish input nearby, scary string — but adversary counter-evidence and challenge answers should resolve to `FALSE_POSITIVE` with specific reason codes (or `REQUIRES_REVIEW` / `UNVERIFIED` when the engine prefers uncertainty over inventing SAFE).

---

## 2. Adversary FP reason codes (canonical set)

These 14 codes are the only valid `false_positive_reasons[]` values for labeled training rows:

| Code | Typical trigger (adversary logic) |
|---|---|
| `SOURCE_NOT_CONTROLLED` | Source not attacker-controlled (`attacker_controlled=no`, trusted input) |
| `SINK_NOT_REACHABLE` | Sink on dead / admin-only / feature-flagged path (pair with reachability evidence) |
| `DATA_FLOW_NOT_CONFIRMED` | No confirmed taint path; often stays `UNVERIFIED` + `INSUFFICIENT_EVIDENCE` |
| `SAFE_VALIDATION` | Confirmed allowlist, path jail, argv validation, hostname reject |
| `SAFE_SANITIZATION` | Context-correct escape (not name-only `sanitize()`) |
| `SAFE_PARAMETERIZATION` | Bound args / ORM filter at sink — no f-string/format concat |
| `AUTHORIZATION_PRESENT` | AuthZ enforced on the vulnerable operation (rarely sole FP for injection) |
| `TENANT_ISOLATION_PRESENT` | Cross-tenant guard on the data path under review |
| `FRAMEWORK_PROTECTION` | Auto-escaping template engine + no `\|safe` / raw HTML bypass |
| `CONFIGURATION_PREVENTS_EXPLOIT` | Security-relevant config (e.g. SSRF allowlist env) changes behavior |
| `UNREACHABLE_CODE` | Dead code, unreachable branch, post-`return` sink |
| `TRUSTED_INPUT` | Bundled with `SOURCE_NOT_CONTROLLED` when trust is explicit |
| `CONTRADICTORY_EVIDENCE` | Strong counter-evidence vs surviving risk → often `REQUIRES_REVIEW` |
| `INSUFFICIENT_EVIDENCE` | Light challenge / ambiguous control — prefer `UNVERIFIED` or `REQUIRES_REVIEW` |

**Labeling rule:** copy codes from a real `axguard adversary` run when possible. Synthetic rows must be manually verified against the decision tree in `engines/adversary/refine.py` (`decide_outcome`).

---

## 3. Corpus row types

### 3.1 End-to-end adversary finding (primary)

One row = one challenged finding with full context the adversary sees: Phase 3 judgment, Phase 2 candidate, counter-evidence hits, control analysis, challenge answers, final status.

### 3.2 Paired near-miss (recommended for hard negatives)

Two snippets from the **same app theme**, same vuln class:

- **A (FP):** effective control → `FALSE_POSITIVE` + reason codes  
- **B (TP):** superficially similar, control ineffective / bypassable → `CONFIRMED` or `LIKELY`

Models learn contrast, not keyword triggers.

### 3.3 Counter-evidence-only micro-rows (secondary)

Smaller rows for retrieval or classifier heads: `(snippet, counter_evidence_kind, strength)` → predicted FP code. Use sparingly; always link back to a parent finding id.

---

## 4. JSON shapes

### 4.1 Training record envelope

```json
{
  "schema_version": "1.0.0",
  "corpus": "axguard-fp-hard-negatives",
  "record_id": "fp.hn.sql-param-vs-fstring.001",
  "split": "train",
  "language": "python",
  "frameworks": ["flask"],
  "vulnerability_type": "sql-injection",
  "difficulty": "hard",
  "pair_group": "fp.hn.sql-param-vs-fstring",
  "pair_role": "false_positive",
  "source": {
    "kind": "synthetic",
    "provenance": "manual",
    "fixture_ref": null,
    "adversary_run_id": null
  },
  "files": [
    {"path": "app/routes/users.py", "role": "primary"},
    {"path": "app/db/helpers.py", "role": "counter_evidence"}
  ],
  "inputs": {
    "judgment": { },
    "candidate": { },
    "application_model_excerpt": { },
    "dataflow_excerpt": { }
  },
  "labels": {
    "status": "FALSE_POSITIVE",
    "false_positive_reasons": ["SAFE_PARAMETERIZATION"],
    "confidence": "likely",
    "forbidden_statuses": ["CONFIRMED"]
  },
  "teaching_notes": "Hunter flags execute() line; adversary confirms bound tuple at same sink.",
  "negative_quality": {
    "is_hard_negative": true,
    "superficial_similarity_to_tp": 0.85,
    "toy_risk": "low"
  }
}
```

### 4.2 `inputs.judgment` (Phase 3)

```json
{
  "candidate_id": "cand.sql.users.42",
  "status": "VERIFIED",
  "vulnerability_type": "sql-injection",
  "severity": "high",
  "confidence": "confirmed",
  "answers": {
    "attacker_controlled": "yes",
    "reaches_sink": "yes",
    "dataflow_link_present": "yes",
    "sink_dangerous": "yes"
  },
  "evidence": [
    {
      "type": "sink",
      "file": "app/routes/users.py",
      "line": 28,
      "snippet": "cur.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"
    }
  ],
  "false_positive_reasons": []
}
```

For hard negatives, **`prior_judge_status` is often over-call** (`VERIFIED` / `LIKELY`). The training target is the adversary correction.

### 4.3 `inputs.candidate` (Phase 2)

```json
{
  "id": "cand.sql.users.42",
  "vulnerability_type": "sql-injection",
  "location": {"file": "app/routes/users.py", "line": 28},
  "source": {
    "symbol": "request.args.get",
    "file": "app/routes/users.py",
    "line": 26,
    "trust_level": "untrusted"
  },
  "sink": {
    "symbol": "cursor.execute",
    "file": "app/routes/users.py",
    "line": 28
  },
  "data_flow": {
    "path_id": "df.users.email.28",
    "taint_state": "tainted"
  },
  "evidence": [
    {
      "type": "dataflow",
      "snippet": "email = request.args.get(\"email\")\ncur.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"
    }
  ]
}
```

### 4.4 Expected adversary output (`labels` + optional full mirror)

```json
{
  "id": "adv.a1b2c3d4e5",
  "status": "FALSE_POSITIVE",
  "false_positive_reasons": ["SAFE_PARAMETERIZATION"],
  "confidence": "likely",
  "reasoning": "Effective control with no clear bypass — finding disproved.",
  "prior_judge_status": "VERIFIED",
  "challenges": {
    "attacker_controlled": "yes",
    "taint_reaches_sink": "yes",
    "control_effective": "yes",
    "control_bypassable": "no",
    "has_sanitization": "unknown"
  },
  "control_analysis": {
    "effectiveness": "confirmed",
    "bypassable": "no",
    "name_only_control": false,
    "notes": ["Parameterized query with bound arguments"]
  },
  "counter_evidence": [
    {
      "kind": "parameterization",
      "strength": "confirmed",
      "reason": "Parameterized / bound SQL arguments",
      "evidence": {
        "file": "app/routes/users.py",
        "line": 28,
        "snippet": "cur.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"
      }
    }
  ],
  "surviving_evidence": []
}
```

### 4.5 Hard-negative pair manifest

```json
{
  "pair_group": "fp.hn.sql-param-vs-fstring",
  "vulnerability_type": "sql-injection",
  "records": [
    {"record_id": "fp.hn.sql-param-vs-fstring.001", "pair_role": "false_positive", "status": "FALSE_POSITIVE"},
    {"record_id": "fp.hn.sql-param-vs-fstring.002", "pair_role": "true_positive", "status": "CONFIRMED"}
  ],
  "contrast_axis": "parameterization effective vs f-string concat at same handler shape"
}
```

---

## 5. Hard-negative patterns by reason code

Each subsection: **near-miss that fools scanners**, **why adversary says FP**, **paired TP variant**.

### 5.1 `SAFE_PARAMETERIZATION`

**Hard FP:** Handler builds SQL with scary string formatting in logs/debug only; **live** path uses `?` / `%s` / `:name` with tuple/dict second arg. Or SQLAlchemy `text("... :id").bindparams(...)`.

**Fools because:** Same function contains f-string SQL in unused branch; hunter anchors on `execute(` + user input symbol.

**Paired TP:** `cur.execute(f"SELECT ... {user_id}")` or `execute(query % user_input)` on the reachable path.

### 5.2 `SAFE_VALIDATION` / `CONFIGURATION_PREVENTS_EXPLOIT`

**Hard FP (SSRF):** `urlparse` + `if host not in ALLOWED_HOSTS: raise ...` before `requests.get`. Weak `startswith("https://")` **alone** is *not* hard FP — adversary marks ineffective (`noop_sanitize` analog).

**Hard FP (path):** `Path(base).resolve()` + `relative_to(base)` jail — not mere `os.path.normpath`.

**Paired TP:** Allowlist check on wrong field (scheme only); normalization without jail (`../` escape).

### 5.3 `SAFE_SANITIZATION` / `FRAMEWORK_PROTECTION`

**Hard FP:** Jinja2 autoescape on by default; user input in `{{ name }}` without `|safe`. Counter-evidence: framework + escape API.

**Hard FP:** React default JSX encoding; sink is text node not `dangerouslySetInnerHTML`.

**Paired TP:** `Markup(...)`, `|safe`, `innerHTML =`, `dangerouslySetInnerHTML` on tainted data (see `controls_bypass._xss`).

**Not FP:** `def sanitize(x): return x` — name-only control → must **not** train as `SAFE_SANITIZATION` (see `fixtures/adversary_app/noop_sanitize.py`).

### 5.4 `SOURCE_NOT_CONTROLLED` / `TRUSTED_INPUT`

**Hard FP:** Finding on `os.environ["INTERNAL_CONFIG"]`, compile-time constant, admin-seeded DB row, or server-side job payload — looks like “external input” in generic taint analysis.

**Hard FP:** Secondary sanitization of **trusted** webhook signed with HMAC; attacker_controlled=no when signature verified before use.

**Paired TP:** Same handler but signature check missing or compares wrong secret.

### 5.5 `SINK_NOT_REACHABLE` / `UNREACHABLE_CODE`

**Hard FP:** Vulnerable-looking sink after `raise`, `sys.exit`, `if False:`, feature flag `if not ENABLE_LEGACY: return`, or route registered only in test config.

**Paired TP:** Same sink reachable from production route / default flag on.

### 5.6 `DATA_FLOW_NOT_CONFIRMED` / `INSUFFICIENT_EVIDENCE`

**Hard FP:** Co-located source and sink, no interprocedural path — hunter candidate only. Adversary prefers `UNVERIFIED` + `INSUFFICIENT_EVIDENCE`, not `FALSE_POSITIVE`, unless taint explicitly `no` (see `fixtures/adversary_app/ambiguous.py`).

**Train both outcomes:** teach **uncertainty** vs **disproof**.

### 5.7 `AUTHORIZATION_PRESENT` / `TENANT_ISOLATION_PRESENT`

**Hard FP:** Strong authZ on **object referenced by finding** — e.g. `@permission_required("delete_user")` on delete handler; finding was generic “SQLi” on unrelated read.

**Caution:** Auth on route ≠ FP for IDOR on `{id}` — hard negative must show auth **covers the sensitive operation**.

**Paired TP:** Auth decorator on list endpoint only; detail endpoint missing check.

### 5.8 `CONTRADICTORY_EVIDENCE`

**Hard FP / review:** Confirmed parameterization **and** confirmed f-string in different branches — surviving risk unclear → `REQUIRES_REVIEW` + `CONTRADICTORY_EVIDENCE`, not clean FP.

Use for calibration rows; label `REQUIRES_REVIEW` honestly.

---

## 6. Building pipeline (research workflow)

1. **Seed from fixtures** — `fixtures/adversary_app/`, `fixtures/verify_app/`, `fixtures/evidence_app/` for baseline shapes; extend with hard variants.
2. **Run pipeline** — `axguard audit` → collect `verification.json`, `adversary.json`; strip secrets via `ensure_no_secret_values`.
3. **Mutate for hardness** — add decoy patterns (dead f-string, noop sanitize, misleading comment); re-run adversary; capture label delta.
4. **Pair generation** — minimal diff between FP and TP (one line / one branch).
5. **Human review gate** — two reviewers: one agrees status + reason codes match `decide_outcome` logic.
6. **Difficulty tag** — `easy` (comment bait) ≤10% of train; `hard` ≥60%.

---

## 7. Quality rubric

| Dimension | Pass | Fail |
|---|---|---|
| Superficial signal | Scanner/Judge would flag | Obviously comment/test only |
| Label alignment | Status + codes match adversary | Invented SAFE without control evidence |
| Name-only trap | `noop_sanitize` stays TP/review | Labeled FP because function name |
| Comment injection | Adversarial comment ignored | Label driven by comment text |
| Reason code precision | Codes match control type | Generic FP without codes |
| Pair integrity | TP differs on one axis | Unrelated snippets |

---

## 8. Splits and contamination

| Split | Contents |
|---|---|
| `train` | Hard negatives + paired TPs; synthetic mutations of in-repo fixtures |
| `dev` | Held-out pairs from same generator templates |
| `eval` | Never-seen apps; manual hard cases; **frozen** public benchmark ports only via held-out ids |

**Do not** train on verbatim copies of eval fixtures used in CI (`fixtures/adversary_app/expected.json` cases can appear in eval, not train, if the goal is regression-style measurement).

Store `content_hash` per file blob to dedupe near-identical rows across splits.

---

## 9. Anti-patterns (insufficient corpus mass)

- Rows where the only signal is `# False positive bait`
- Single-line parameterized queries with no decoy
- FP labels without at least one structured reason code (except deliberate `INSUFFICIENT_EVIDENCE` uncertainty rows)
- Using `AUTHORIZATION_PRESENT` as sole reason for SQLi FP on concatenated query
- Treating MCP/agent findings with this schema without separate AI corpus (see `ai-security-corpus.md`)

---

## 10. References (in-repo)

- FP reason constants: `engines/adversary/schema.py`
- Outcome decision tree: `engines/adversary/refine.py` (`decide_outcome`)
- Control effectiveness: `engines/adversary/controls_bypass.py`
- Counter-evidence kinds: `engines/adversary/counter_evidence.py`
- Regression fixtures: `fixtures/adversary_app/`, `fixtures/verify_app/`
- Adversary artifact shape: `engines/adversary/adversary.py` (`FalsePositiveAdversary.challenge`)
