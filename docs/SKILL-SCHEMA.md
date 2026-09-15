# Skill frontmatter schema (AXGuard)

Every domain skill under `skills/security/` SHOULD use this YAML frontmatter.

```yaml
---
name: skill-name
description: When to load this skill (trigger phrases + security task).
version: "1.0.0"
author: AwareXone
license: MIT
domain: application-security   # discovery | identity | application-security | infrastructure | ai-security | operations
subcategory: web-security
tags: []
frameworks:
  cwe: []
  owasp_top10: []      # e.g. A01:2021
  owasp_api_top10: []  # e.g. API1:2023
  owasp_llm_top10: []  # e.g. LLM01
  owasp_wstg: []       # only verified WSTG-* IDs
  owasp_asvs: []       # only verified requirement IDs
  mitre_attack: []
  mitre_atlas: []
  nist_csf: []
  nist_ai_rmf: []
related_skills: []
related_commands: []   # existing /axguard-* commands if any
related_rules: []      # rules/*.json id prefixes if any
references: []
last_reviewed: "2026-09-15"
---
```

## Body sections (include when useful — no filler)

1. Purpose  
2. When to Use / When Not to Use  
3. Security Concepts  
4. Threat Model  
5. Preconditions / Inputs  
6. Discovery  
7. Analysis Workflow (decision process)  
8. Data Flow  
9. Validation  
10. Exploitability Assessment (authorized / defensive)  
11. Evidence Requirements  
12. False Positive Controls  
13. Severity Assessment  
14. Impact Assessment  
15. Remediation  
16. Verification  
17. Reporting  
18. Related Skills  
19. Framework Mapping  
20. References  
21. Research Provenance  

## Confidence model (findings)

`CONFIRMED` | `HIGH` | `MEDIUM` | `LOW` | `INFORMATIONAL`

Never jump from hypothesis → confirmed without evidence.
