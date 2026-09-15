# Research: AXGuard Security Twin & Counterfactual Analysis

**Status:** Internal research ahead of `engines/twin/`  
**Date:** 2026-09  
**Stance:** Skeptical of marketing. Prefer architectural evidence. Prefer UNKNOWN over invented facts.

---

## 1. Problem statement

Traditional scanners ask: *is this line vulnerable?*

AXGuard already answers reachability, evidence, false-positive resistance, and attack-path composition. The remaining gap is **defensive architecture reasoning**:

- What could an attacker *actually cause this system to do*?
- What changes if one control is removed?
- What changes if an agent gains one tool?
- Which control blocks the most high-impact paths?

That requires a **Security Twin**: a machine-readable, evidence-backed symbolic model of the application’s security structure — **not** a runtime clone, exploit engine, or production simulator.

---

## 2. Industry landscape (what exists)

### 2.1 Agentic AI security (2024–2026)

| Domain | Mature | Partial | Weak |
|---|---|---|---|
| Threat taxonomy | OWASP Agentic Top 10 (ASI01–ASI10) | Mapping to LLM / NHI top tens | Consistent scoring across vendors |
| MCP abuse classes | Tool poisoning, rug pulls, toxic flows (Invariant) | OAuth in MCP spec | Tool metadata as instruction channel in production |
| Runtime control standards | ACS v0.1 preview (hooks + Guardian) | AgBOM concepts | Portable deny/modify across MCP/A2A |
| Agent identity | Entra Agent ID (platform-local) | SPIFFE + OAuth patterns | Dual identity (user vs agent) end-to-end |
| Coding-agent containment | Sandboxes, approval UX | CVE patches per IDE | Repo/issue/MCP bootstrap injection chains |

**Key sources**

- OWASP GenAI / ASI: https://genai.owasp.org/initiatives/agentic-security-initiative/
- OWASP Agentic Top 10 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Agent Control Standard: https://agentcontrolstandard.org/ · https://github.com/GenAI-Security-Project/agent-control-standard
- NIST AI RMF / AI 600-1: https://www.nist.gov/itl/ai-risk-management-framework · https://doi.org/10.6028/NIST.AI.600-1
- Google SAIF / CaMeL: https://saif.google/ · https://arxiv.org/abs/2503.18813
- Invariant Labs MCP research: https://invariantlabs.ai/blog/mcp-security-notification · https://invariantlabs.ai/blog/mcp-github-vulnerability
- Wiz exposed MCP servers: https://www.wiz.io/blog/the-risk-hiding-behind-exposed-mcp-servers
- Anthropic Claude Code sandboxing: https://www.anthropic.com/engineering/claude-code-sandboxing
- Microsoft Entra Agent ID: https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-use-entra-agent-identities

### 2.2 “Security digital twin” — meaning vs marketing

**Defensible meaning (OT/CPS + AppSec):** a synchronized **symbolic** model of inventory + trust + controls + attack paths used for analysis — not a replica of production.

**Marketing stretch:** “we have a graph,” “real-time twin,” “simulates all attacks.”

Cloud CNAPP products (Wiz, Prisma, Microsoft Exposure Management) deliver strong **cloud toxic-combination paths**. SCA vendors (Snyk, Semgrep, Socket, Endor) deliver **dependency reachability**. CodeQL delivers **per-query taint paths**. Few products deliver honest **pre-ship multi-hop chains + control barriers + counterfactual fix impact** in a local OSS tool.

### 2.3 Counterfactual security analysis

Academic work (CMO, CIPHER-A, security-twin Monte Carlo papers) explores “minimal change that alters risk.” Commercial “what-if” is usually remediation narrative, not formal path recomputation with quarantined hypotheticals.

AXGuard already ships `engines/attack_graph/whatif.py` with an honesty contract (`hypothetical: true`, `status: PREDICTIVE`). The Security Twin **composes** that layer — it does not invent a second graph engine.

---

## 3. Gaps (where AXGuard can differentiate)

1. **Intent–capability binding** — what the user asked vs what tools the agent may invoke (ACS Intent/SessionContext direction; adoption thin).
2. **Provenance / taint as security state** — CaMeL-style separation is research-grade; production agents rarely track untrusted tool returns.
3. **Dual-identity confused deputy** — user OAuth + agent NHI + tool credentials rarely modeled as one graph.
4. **Dynamic AgBOM / tool-definition integrity** — scanners snapshot; twins should reason about definition drift and cross-server shadowing.
5. **Measurable control value** — “this tenant check blocks N paths / protects assets X” is rare outside AXGuard’s choke/fix-impact sketches.
6. **Observed vs simulated separation** — market overstates POSSIBLE as CONFIRMED; buyers are fatigued.

**Anti-goals for this phase**

- Another SAST scanner
- Another prompt-injection detector
- Another MCP config scanner
- Real exploitation, runtime enforcement, or autonomous red teaming

---

## 4. AXGuard differentiation

```text
UNDERSTAND THE SYSTEM
→ BUILD ITS SECURITY TWIN
→ MODEL A VIRTUAL ATTACKER (symbolic)
→ SIMULATE ATTACK PATHS ON THE TWIN ONLY
→ ASK "WHAT IF?"
→ MEASURE CONTROL VALUE
→ CALCULATE BLAST RADIUS
→ EXPLAIN WITH EVIDENCE
```

**Positioning (defensible):**

> AXGuard Security Twin is a **local symbolic model** of an application’s exploitable structure — rebuilt before ship — that shows which chains matter, what fixing one control breaks, and what AI/agent permission changes would open — with unknowns labeled and hypotheticals quarantined.

**Reuse, do not duplicate:** `run_attack_graph`, `whatif`, `diff`, `blast`, `choke`, `explain`, `predictive`, application model, dataflow, evidence, adversary.

---

## 5. Architecture rationale

```text
Repository
  → Application Model
  → Data Flow
  → Evidence / Adversary
  → Attack Graph          (existing)
  → Security Twin         (new composition layer)
       ├── Virtual attacker profiles (ASSUMED)
       ├── Symbolic simulation (SIMULATED)
       ├── Counterfactuals (ASSUMED premises → SIMULATED paths)
       ├── Control effectiveness
       ├── Blast radius (evidence-backed edges only)
       └── Regression compare (before/after twins)
```

**Mandatory fact layers**

| Layer | Meaning |
|---|---|
| OBSERVED | Found in repository / analysis artifacts |
| INFERRED | Derived from evidence with stated confidence |
| SIMULATED | Symbolic walk / counterfactual output |
| ASSUMED | Explicit user premise (“remove tenant isolation”) |

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| Overclaiming “digital twin” | Document fidelity = static evidence; no runtime sync |
| Fabricated hops | Only reuse existing AG edges/nodes |
| POSSIBLE presented as CONFIRMED | Separate report sections + PREDICTIVE status |
| Twin becomes a second graph engine | Thin orchestration only |
| Network / exploit leakage | Hard ban: no requests, no payload exec, no MCP run |
| Policy / ACS compliance claims | Align terminology; do not claim conformance |

---

## 7. Future opportunities (out of phase)

- ACS Guardian export / OTel span sync
- Runtime AgBOM drift monitors
- Cloud IAM export partners (do not fake CSPM)
- Model training on twin Q/A examples (Phase 9+; eval-only until approved)
- Exact min-cut solvers (current choke points remain heuristics)

---

## 8. Benchmark dimensions (research)

1. Attack-path prediction accuracy  
2. Counterfactual accuracy (paths opened/closed under premise)  
3. Control effectiveness ranking  
4. Blast-radius faithfulness to graph edges  
5. Agent privilege reasoning (UNKNOWN when no evidence)  
6. Trust-boundary reasoning  
7. Regression (git before/after) false-path rate  

Measure precision, recall, false-path rate, and UNKNOWN handling — never punish honesty.

---

## 9. Conclusion

The Security Twin is the productization of a question the market under-serves:

**Show me what could happen — and what changes if I change the security architecture.**

AXGuard should earn trust by keeping simulation symbolic, evidence-bound, and clearly labeled — not by inventing a louder scanner.
