# Sources & inspiration

AXguard’s class taxonomy and review habits are informed by public security frameworks and research datasets. This file **summarizes** provenance for agents and humans. Do not paste large copyrighted excerpts into reports or skills.

## Standards & frameworks

| Source | Use in AXguard |
|--------|----------------|
| [OWASP Top 10 (2021)](https://owasp.org/Top10/) | Primary risk labels (A01 access control, A03 injection, A05 misconfig, A10 SSRF, …) |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | API/IDOR, auth, SSRF, security misconfig framing for backends |
| [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | Agent/tooling risks: prompt injection, excessive agency, sensitive disclosure |
| [CWE](https://cwe.mitre.org/) | Stable weakness IDs on findings (e.g. CWE-89, CWE-639, CWE-918, CWE-798) |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) (optional depth) | Verification-style fix bar when users want stricter checklists |

## Datasets (training / pattern mining inspiration)

Summaries only — pull upstream for licensing and full content:

| Dataset | Notes |
|---------|--------|
| [CyberNative/Code_Vulnerability_Security_DPO](https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO) | Preference-style pairs around vulnerable vs safer code; useful for shaping “what broken looks like” vs remediation tone — not copied into AXguard rules verbatim |
| [ismailtasdelen/unified-vulnerability-intelligence-dataset](https://huggingface.co/datasets/ismailtasdelen/unified-vulnerability-intelligence-dataset) (UVID) | Unified vuln intelligence fields; informs labeling consistency (CWE/severity/class) for pre-ship reporting |

## Pattern catalogs

| Source | Notes |
|--------|-------|
| Agentic-Bug-Hunter **web2-vuln-classes** patterns | Community/agent-oriented web vuln class breakdowns (IDOR, injection, SSRF, XSS, etc.). AXguard mirrors the *class coverage* and static-review mindset; it does **not** reproduce large pattern lists or exploit recipes verbatim |

## How AXguard uses these

1. **Rule packs** under `rules/` encode high-signal regex/heuristic leads with CWE/OWASP tags.
2. **Skills** (`axguard-audit`, `preship`, `cso`, `triage`, `remediate`, `report`, `knowledge`) teach hunter workflow, FP discipline, and fixes.
3. **CLI** (`axguard audit` / `axguard scan`) runs deterministic matching — skills must not invent nonexistent subcommands.

## Attribution hygiene

- Prefer linking to OWASP/CWE pages over quoting long definitions.
- When dataset-inspired, describe the *idea* (e.g. “prefer safer parameterized form”) rather than copying sample vulnerable programs from the dataset.
- Keep AXguard output defensive and pre-ship focused.
