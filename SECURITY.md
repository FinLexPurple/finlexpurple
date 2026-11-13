# Security Policy

FinLexPurple is an offensive security tool, and we take the security of the tool
itself seriously. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through either channel:

1. **GitHub Private Vulnerability Reporting (preferred).** Go to the
   [Security tab](https://github.com/FinLexPurple/finlexpurple/security/advisories/new)
   and open a private advisory. This keeps the report, the discussion, and the fix in
   one place and lets us credit you through GitHub.
2. **Email.** Write to **security@finlexpurple.com**.

Please include, as far as you can:

- the version or commit (`finlexpurple --version`),
- a description of the issue and its impact,
- steps to reproduce, or a proof of concept,
- any suggested remediation.

## What to expect

FinLexPurple is maintained by a small team, so we set expectations we can actually
meet rather than a formal SLA:

- We aim to **acknowledge** a report within a few business days.
- We will keep you updated as we investigate, confirm, and work on a fix.
- We will let you know when a fix ships, and we are happy to credit you in the advisory
  and release notes unless you ask us not to.

We ask that you give us a reasonable opportunity to address an issue before any public
disclosure, and that you avoid privacy violations, data destruction, or service
degradation while researching.

## Scope

### In scope

Vulnerabilities in FinLexPurple's own code and release artifacts, for example:

- flaws that let a scanned target, a malicious response, a crafted report, or an
  intelligence pack execute code, escalate privileges, or escape the tool's sandbox on
  the operator's machine;
- ways to bypass or silently weaken a safety control — the approval gate, egress
  default-deny, hard-gated categories, iteration or request budgets;
- ways to forge, tamper with, or replay an evidence bundle so that `verify-bundle`
  accepts a bundle that does not reflect a real, reproduced finding;
- integrity or supply-chain issues in how FinLexPurple builds, signs, or publishes
  its packages and intelligence packs;
- leakage of secrets, targets, or scan data the tool was trusted to keep local.

### Out of scope

- **Findings FinLexPurple reports about a target you scanned.** Those are the tool
  working as intended. Report them to the owner of that application, not to us.
- Vulnerabilities in third-party scanners FinLexPurple optionally wraps (osv-scanner,
  pip-audit, Trivy, Grype, Dockle, hadolint, cosign) — report those upstream.
- Issues that require a malicious maintainer, a compromised developer machine, or
  physical access.
- Reports from automated scanners with no demonstrated, tool-specific impact.
- Missing hardening that does not correspond to a concrete exploit (for example,
  "header X is not set") unless you can show real impact.

Testing against FinLexPurple is welcome **only** against infrastructure you control —
your own installation and your own test targets. Do not use a FinLexPurple report
about a third party as a vulnerability report to us.

## Supported versions

FinLexPurple is **pre-1.0 and under active development.** Security fixes land on the
**latest release and the `main` branch**; we do not backport to older pre-1.0
versions. Please upgrade to the latest version before reporting, and expect that the
fix for a confirmed issue will be an upgrade rather than a patch to an old line.

| Version | Supported |
| --- | --- |
| Latest release / `main` | Yes |
| Older pre-1.0 releases | No — please upgrade |

Once FinLexPurple reaches 1.0, this policy will be updated with a concrete
supported-version window.
