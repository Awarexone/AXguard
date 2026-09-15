# License gate policy (Phase 9)

## Public training corpus

| License family | Default |
|---|---|
| MIT, Apache-2.0, BSD, CC0, CC-BY | Eligible **only if** `license_verified=true` |
| CC-BY-SA, GPL-family, CC-BY-NC, Custom | EVALUATION_ONLY / human review |
| Proprietary, Unknown | Never auto-approve for public TRAINING |

Human approval is required before promoting restricted licenses, exporting
processed corpora publicly, or uploading anywhere.

Implemented in `engines/data/license_gate.py`.
