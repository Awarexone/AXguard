# Engagement messaging

AXGuard may show a short, contextual note after useful work (audit, scan, attack paths) or at the bottom of an HTML report. Messaging is **value-first**: security findings always outrank support asks.

## Local state

Preferences and journey state live only on disk:

```text
~/.axguard/engagement.json
```

Nothing is sent over the network. There is no telemetry, star scraping, or remote “engagement sync.”

## Opt out

```bash
axguard engage disable   # stop promotional / support messaging
axguard engage enable    # turn it back on
axguard engage dismiss   # cool down after a support ask
axguard about            # project story (explicit; records ABOUT_VIEWED)
```

Per-command skip:

```bash
axguard audit . --no-engage
axguard scan . --no-engage
axguard paths . --no-engage
```

## Principles

1. **Security first** — critical/high findings block GitHub/YC/support CTAs.
2. **No dark patterns** — no urgency, fake social proof, or invented YC status.
3. **Local only** — state file is optional; delete it to reset.
4. **One message** — CLI prints at most one engagement block after the real report.
