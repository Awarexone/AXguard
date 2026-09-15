# Security Memory temporal fixture

Regression narrative used by `tests/test_security_memory.py` **without git**.

## Story

| Version | What changed | Memory expectation |
|---|---|---|
| **A** (`snapshot_a.json`) | AuthZ middleware control is **present** and effective. Finding `sql.tainted` is rejected as `FALSE_POSITIVE` because the control blocks the path. | Control `CONTROL_PRESENT`; finding lifecycle `FALSE_POSITIVE` / `CURRENT` |
| **B** (`snapshot_b.json`) | Same code path, but the control was **removed**. Finding resurfaces as `CONFIRMED`. | Control absent → `RESOLVED` / `CONTROL_REMOVED`; finding **REGRESSED** / needs re-eval of the prior FP decision |

## How to use

```python
from engines.memory import compare_snapshots, detect_regressions
import json
from pathlib import Path

root = Path("fixtures/security_memory")
a = json.loads((root / "snapshot_a.json").read_text())
b = json.loads((root / "snapshot_b.json").read_text())
reg = detect_regressions(a, b)
assert any(x["outcome"] == "REGRESSED" for x in reg["REGRESSED"])
```

See `expected.json` for the regression contract asserted by tests.
