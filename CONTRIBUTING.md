# Contributing to AXguard

Thanks for helping ship a sharper pre-ship gate. One focused change per PR keeps review fast.

## What we need most

| Contribution | Why |
|---|---|
| New detection rules + fixtures | Better coverage |
| False-positive fixes with regression tests | Signal over noise |
| Artifact/bytecode scanners (JS bundles, WASM) | Roadmap |
| Agent command/skill polish | Better plugin UX |
| Docs / examples | Faster onboarding |

## Setup

See **[DEV.md](DEV.md)** for full developer setup. Short version:

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Workflow

```bash
git checkout -b feat/your-change
# edit…
pytest -q
axguard audit fixtures/vuln_app --no-banner
git commit -m "feat: short why-focused message"
git push -u origin HEAD
# open PR against main
```

## Guidelines

1. Check existing issues / open PRs first.  
2. User-facing commands → update `COMMANDS-QUICK-REF.md` (+ README table if it is a new workflow).  
3. New rules → follow [docs/adding-rules.md](docs/adding-rules.md).  
4. No live secrets in the tree.  
5. Match the existing tone: professional, terse, hunter-grade.

## License

By contributing you agree your changes are licensed under the MIT License (`LICENSE`).

## Contact

- General: [hello@awarexone.com](mailto:hello@awarexone.com)
- Business / B2B: [b2b@awarexone.com](mailto:b2b@awarexone.com)
- Founder: [shuvon@awarexone.com](mailto:shuvon@awarexone.com)