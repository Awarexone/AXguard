# Research provenance index

This tree records **sources** used to engineer AXGuard security skills.

Rules:

- Prefer official standards (OWASP, MITRE, NIST, CWE, CISA).
- Do not dump datasets into the repo.
- Do not copy large copyrighted texts.
- Derived knowledge only, with provenance recorded here.
- If a claim cannot be verified, mark `UNVERIFIED` in the skill — do not invent IDs.

## Layout

| Path | Contents |
|---|---|
| [sources.yaml](sources.yaml) | Primary frameworks + AwareXone + HF notes |
| [repositories.yaml](repositories.yaml) | AwareXone + methodology GitHub repos |
| [datasets.yaml](datasets.yaml) | Hugging Face evaluations (metadata / derived only) |
| [frameworks/README.md](frameworks/README.md) | Verified OWASP / CWE ID tables |

## Pipeline

```text
Public Sources → Collection → Normalization → Dedup → Classification
→ Validation → Framework Mapping → Skill Generation → Review → SKILL.md
```

Skill registry: [`../skills/index.yaml`](../skills/index.yaml)  
Schema: [`../docs/SKILL-SCHEMA.md`](../docs/SKILL-SCHEMA.md)  
Validator: `python scripts/validate_skills.py`
