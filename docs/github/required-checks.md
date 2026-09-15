# Required checks (branch protection)

Use GitHub **branch protection** / rulesets so merges wait on the AXGuard Check
Run. AXGuard itself never changes repository settings.

Related: [pr-ux.md](pr-ux.md) · [install.md](install.md).

---

## Default check name

From `.axguard.yml` (see [config.md](config.md)):

```yaml
review:
  check_name: "AXGuard Security Review"
```

Pre-ship mode may use `AXGuard Pre-Ship` when enabled.

---

## Enable as required

1. Repo → **Settings** → **Branches** (or **Rules** / rulesets).
2. Edit the rule for your default branch.
3. Enable **Require status checks to pass before merging**.
4. Search for and select **AXGuard Security Review** (exact `check_name`).
5. Optionally require branches to be up to date.

Tips:

- The check must have run at least once on the repo before it appears in the picker.
- Prefer requiring the check only after the App is installed on that repository.
- Do not require a check you have not installed — PRs will block forever.

---

## Policy alignment

Check conclusion mapping lives in the adapter (PASS / PASS_WITH_NOTES /
REVIEW_REQUIRED / FAIL). Branch protection only sees GitHub’s conclusion enum
(`success`, `failure`, `neutral`, …). Align `policy.fail_on` in `.axguard.yml`
with how strictly you want merges blocked.
