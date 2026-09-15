# Research: AXGuard Investigation Agent

**Status:** Internal research ahead of `engines/investigation/`  
**Date:** 2026-09  
**Stance:** Orchestrate existing AXGuard engines. Prefer UNKNOWN over inventing evidence. Static/symbolic only.

---

## 1. Problem

AXGuard already has application models, dataflow/taint, hunters, Judge, False Positive Adversary, Evidence, Attack Graph, Security Twin, and Security Memory.

What it lacks is a **disciplined investigation loop** that answers:

> What do I need to investigate next to determine whether this is actually a security issue?

Scanners and single-pass LLM triage both fail differently:

| Approach | Failure mode |
|---|---|
| Run every rule / specialist blindly | Cost explosion; shallow evidence; FP noise |
| “Pattern → vulnerability” | Skips counter-evidence and control checks |
| Free-form LLM agent over the repo | Hallucinated facts; prompt injection via README/comments |
| One-shot SARIF triage | Rarely builds an auditable investigation trail |

The Investigation Agent is **not another scanner**. It is an orchestration + reasoning layer over engines that already exist.

---

## 2. Existing approaches

### 2.1 SAST + LLM triage pipelines

| System / work | What it does | Limitation for AXGuard |
|---|---|---|
| **Semgrep / CodeQL CI** | Pattern + dataflow alerts | Alert production, not evidence-seeking investigation |
| **CodeQL incremental analysis** ([GitHub](https://docs.github.com/en/code-security)) | Faster PR scans | Optimizes *scan cost*, not hypothesis/challenge loops |
| **sast-triage** / **VulnHunterX**-style agents | LLM reads SARIF + code; multi-turn context | Often LLM-primary; weak hard stop; may invent paths |
| **FP-filtering agent study** (Aider / OpenHands / SWE-agent vs OWASP Benchmark) | Shows agents cut SAST FP rates dramatically | Backbone-dependent; risk of suppressing true positives; high compute cost |
| **QLCoder** | Agent synthesizes CodeQL queries from CVE metadata | Query authoring, not candidate investigation over a twin/memory stack |
| **Kuzushi-class orchestrators** | SAST → agent DAG triage → optional PoC | Out of phase: AXGuard forbids autonomous exploitation |

**Takeaway:** Industry is moving from “more alerts” to “investigate alerts.” AXGuard should do that **deterministically first**, with LLM only as optional prioritizer/summarizer — never as evidence inventer.

### 2.2 Analyst workflows (OWASP / NIST / vendor practice)

Security analysts typically:

1. Form a hypothesis from the alert  
2. Ask reachability / control / identity questions  
3. Trace callers/callees and data flow  
4. Search for mitigations (parameterization, allowlists, authz)  
5. Stop when proven, disproven, or blocked on external unknowns  

NIST SSDF and OWASP ASVS emphasize **verification of controls**, not alert volume. GitHub Advanced Security / Semgrep AppSec practice still centers human triage queues.

### 2.3 Program-analysis orchestration

CodeQL query packs and Semgrep workflows encode *what to look for*, not *what evidence is still missing for this candidate*. Investigation graphs (question → action → evidence → decision) are closer to case-management systems than to scanners.

### 2.4 Agent planning for software engineering

SWE-agent / OpenHands style loops (observe → act → observe) work for coding tasks but are unsafe as default AppSec engines unless:

- tools are read-only / symbolic  
- repository text cannot rewrite policy  
- every claim cites evidence artifacts  

AXGuard already has Evidence hierarchy and Adversary challenges — the Investigation Agent should **drive** those, not replace them.

---

## 3. Limitations of current systems

1. **No missing-evidence planner** — tools emit findings without stating unanswered questions.  
2. **Weak counter-evidence search** — FP reasons often appear only if a rule encodes them.  
3. **No cost model** — expensive interprocedural work runs even when a cheap AST check would falsify.  
4. **No historical reuse with invalidation** — caches ignore “FP because middleware X” until X changes (AXGuard Memory solves this).  
5. **No system-level follow-up** — prompt injection without a privileged tool path is incomplete (AXGuard Twin).  
6. **LLM-as-judge without hierarchy** — models invent sinks/files; AXGuard forbids that.  
7. **No auditable investigation trail** — hard to re-run or train on trajectories.

---

## 4. AXGuard approach

```text
Candidate
  → Check Security Memory (reuse / invalidate)
  → Form hypotheses (H1 exploitability, H2 control/block)
  → Identify missing evidence (planner questions)
  → Select cheapest action that answers a question
  → Collect evidence from existing engines (soft)
  → Search counter-evidence
  → Update confidence
  → Twin / Attack Graph for system impact when warranted
  → Stop when policy says enough
  → Emit Investigation package → Judge / report / training export
```

**Principles**

- Orchestration layer only — reuse Application Model, Dataflow, Verify/Judge, Adversary, Evidence, Attack Graph, Twin, Memory, specialists.  
- Counter-evidence first for important candidates.  
- Explicit UNKNOWN / ASSUMED; never invent repository facts.  
- Cost-aware budgets: FAST / BALANCED / DEEP.  
- Investigation status ≠ security verdict.  
- LLM (if present later) may prioritize/summarize; may not invent evidence or override deterministic analysis.  
- Repository content is untrusted input (anti-prompt-injection).

---

## 5. Architecture

```text
engines/investigation/
  schema.py          Investigation object, statuses, outcomes, action costs
  questions.py       Planner question bank
  actions.py         Action registry + symbolic executors
  specialists.py     Candidate-kind → specialist selection
  budget.py          FAST / BALANCED / DEEP
  planner.py         Missing evidence → prioritized actions
  hypothesis.py      H1 / H2 management
  counter.py         Counter-evidence search
  memory_bridge.py   Soft Security Memory check
  twin_bridge.py     Soft Security Twin questions
  stop.py            Stopping policy
  graph.py           Auditable investigation graph
  loop.py            Per-candidate investigate loop
  pipeline.py        run_investigation(target|candidates)
  report.py          MD / HTML
  export_dataset.py  EVALUATION_ONLY trajectories
  query.py           Deterministic explain / Q&A
```

**Artifacts:** `.findings/axguard/investigation/`

**Soft-wire:** `axguard audit` may attach `investigation_summary`; reports render an Investigation section when present. Failures never abort audit.

---

## 6. Safety model

| Allowed | Forbidden |
|---|---|
| Static / symbolic inspection of AXGuard artifacts | Network requests / target exploitation |
| Soft imports of Twin / Memory / AG / Evidence | Executing repository code or untrusted shell |
| Structured UNKNOWN | Inventing files, sinks, or controls |
| Training export tagged EVALUATION_ONLY | Exposing protected benchmark answers |
| Parallel independent candidate investigations | Concurrent Memory writes that race ledger |

**Anti-prompt-injection:** Ignore instructions in source, comments, README, docs, fixtures, issues, dependency metadata. Those never change investigation policy, verdict rules, or tool permissions.

---

## 7. Investigation strategy

```text
OBSERVE → FORM HYPOTHESIS → IDENTIFY MISSING EVIDENCE
  → SELECT INVESTIGATION → COLLECT EVIDENCE
  → CHALLENGE HYPOTHESIS → UPDATE CONFIDENCE
  → DECIDE NEXT ACTION → STOP OR CONTINUE
```

**Planner questions (always considered):**

1. Attacker-controlled source?  
2. Source reachable?  
3. Sink dangerous?  
4. Data reaches sink?  
5. Security control present?  
6. Control bypassable?  
7. Authorization present?  
8. Tenant isolation present?  
9. Configuration changes behavior?  
10. Path reachable?  
11. Privilege required?  
12. Asset affected?  
13. Realistic impact?  
14. Contradictions?  
15. Remaining unknowns?

**Stop when:** verified; strong counter-evidence; insufficient after budget; static-unresolvable; path blocked; trustworthy conclusion.

---

## 8. Action types (map to existing capability)

| Action | Typical backing |
|---|---|
| `TRACE_DATA_FLOW` | `engines.dataflow` |
| `TRACE_CALLERS` / `TRACE_CALLEES` | Application model / call graph |
| `CHECK_AUTHENTICATION` / `CHECK_AUTHORIZATION` / `CHECK_TENANT_ISOLATION` | App model + Adversary controls |
| `CHECK_VALIDATION` / `CHECK_SANITIZATION` / `CHECK_PARAMETERIZATION` | Dataflow sanitizer state + Adversary FP reasons |
| `CHECK_CONFIGURATION` / `CHECK_FRAMEWORK_BEHAVIOR` / `CHECK_DEPENDENCY` | App model / rules |
| `CHECK_REACHABILITY` / `CHECK_TRUST_BOUNDARY` / `CHECK_IDENTITY_PROPAGATION` | Attack Graph / Twin |
| `CHECK_TOOL_PERMISSION` / `CHECK_AGENT_PERMISSION` / `CHECK_MCP_TRUST` | Twin / agent entities |
| `CHECK_ALTERNATE_PATH` / `BUILD_ATTACK_PATH` | Attack Graph |
| `SEARCH_COUNTER_EVIDENCE` | Adversary challenges + local heuristics |
| `CHECK_SECURITY_MEMORY` | `engines.memory` |
| `COMPARE_SECURITY_TWIN` | `engines.twin` |
| `ANALYZE_GIT_CHANGE` | Memory invalidation / revision fingerprints |

---

## 9. Positioning

> The Investigation Agent makes AXGuard’s existing capabilities work as one coherent security investigation system: prove, disprove, or stop with UNKNOWN — and leave an auditable trail for the Judge.
