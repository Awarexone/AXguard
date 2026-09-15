# Security Policy — AXGuard

AXGuard is an open-source pre-ship security tool. We take reports about
AXGuard itself seriously and appreciate responsible disclosure.

## Reporting a vulnerability

Please report security issues in AXGuard through **GitHub Private Vulnerability
Reporting** on this repository:

https://github.com/Awarexone/AXguard/security/advisories/new

If Private Vulnerability Reporting is unavailable, contact maintainers using
the project contacts already published in the README
([hello@awarexone.com](mailto:hello@awarexone.com) /
[shuvon@awarexone.com](mailto:shuvon@awarexone.com)) and mark the message as a
**security report**. Do not file a public GitHub issue for an unpatched
vulnerability.

## What to include

- Affected version / commit (or release tag)
- Description of the issue and impact
- Clear reproduction steps or a minimal proof-of-concept
- Whether the issue is already public elsewhere
- Any suggested remediation (optional)

## Disclosure

Please **do not** publicly disclose an unpatched vulnerability, publish exploit
details, or discuss the report in public channels until maintainers have had a
reasonable chance to investigate and ship a fix.

We aim to acknowledge reports promptly and keep reporters informed of status.

## Scope notes

- Intentional insecure snippets under `fixtures/` and detection patterns under
  `rules/` are for scanner self-tests — not production vulnerabilities.
- Reports that require paid third-party services or out-of-scope social
  engineering are not accepted as AXGuard product defects.
