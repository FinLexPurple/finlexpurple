<div align="center">

# FinLexPurple

### A local, autonomous security agent for financial applications. Findings you can actually prove.

<p>
<a href="https://github.com/FinLexPurple/finlexpurple/actions/workflows/tests.yml"><img src="https://github.com/FinLexPurple/finlexpurple/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
<a href="https://pypi.org/project/finlexpurple/"><img src="https://img.shields.io/pypi/v/finlexpurple?color=2DD4BF" alt="PyPI version"></a>
<a href="https://pypi.org/project/finlexpurple/"><img src="https://img.shields.io/pypi/pyversions/finlexpurple" alt="Python versions"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache-2.0"></a>
<a href="https://github.com/FinLexPurple/finlexpurple/stargazers"><img src="https://img.shields.io/github/stars/FinLexPurple/finlexpurple?style=social" alt="GitHub stars"></a>
</p>

<p>
<a href="https://finlexpurple.com">Website</a>
&nbsp;·&nbsp;
<a href="https://pypi.org/project/finlexpurple/">PyPI</a>
&nbsp;·&nbsp;
<a href="CHANGELOG.md">Changelog</a>
&nbsp;·&nbsp;
<a href="CONTRIBUTING.md">Contributing</a>
&nbsp;·&nbsp;
<a href="https://github.com/FinLexPurple/finlexpurple/discussions">Discussions</a>
&nbsp;·&nbsp;
<a href="https://discord.gg/QFBX5sgGGN">Discord</a>
</p>

</div>

---

FinLexPurple tests a financial application and everything it trusts, then keeps only
the findings it can back with evidence. A finding is marked **verified** only after
code re-executes it, and every verified finding ships with an **evidence bundle** that
anyone can re-check offline — no scan, no network, no trust in the tool required.

It is open source under Apache-2.0, runs on your own hardware (fully local through
Ollama, with cloud model providers optional), and is built for the business-logic
flaws that generic scanners miss: price tampering, webhook forgery, refund abuse,
coupon abuse, payment-status trust, and order IDOR.

> **Pre-1.0.** FinLexPurple is beta software under active development. The data
> contract and evidence-bundle format are frozen; surfaces and flags may still change
> before 1.0. See the [status table](#what-it-tests) for exactly what is wired today.

If this project is useful to you, please **star the repository** — it is the single
most helpful thing you can do to help other people find it.

## Contents

- [Why FinLexPurple](#why-finlexpurple)
- [Quick start](#quick-start)
- [How verification works](#how-verification-works)
- [What it tests](#what-it-tests)
- [Output formats](#output-formats)
- [Interactive chat mode](#interactive-chat-mode)
- [Safety and authorization](#safety-and-authorization)
- [Intelligence packs](#intelligence-packs)
- [Contributing](#contributing)
- [Resources](#resources)
- [Security](#security)
- [License](#license)

## Why FinLexPurple

Most security tools report what an AI or a heuristic *thinks* is a vulnerability.
That leaves a human to re-triage every finding by hand, and it is why "AI pentester"
output is so often noise. FinLexPurple inverts the default: the model proposes, and
then **code decides**.

- **Proof, not confidence.** A large language model may plan and propose an exploit,
  but it can never mark a finding verified. Only a deterministic replay engine that
  reproduces the effect can do that. Everything else is surfaced as *reported* for a
  human to judge — never silently promoted.
- **Re-checkable evidence.** Each verified finding is written as a signed evidence
  bundle. `finlexpurple verify-bundle` re-validates it with no scan and no network,
  so a reviewer, a CI pipeline, or a maintainer on the other side of a report can
  confirm the result independently.
- **Local and air-gapped by default.** Runs on your own hardware through Ollama.
  Cloud model providers are optional, egress is default-deny, iteration caps are on,
  and reports are written owner-only.
- **Built for financial business logic.** Generic scanners find injection and
  misconfiguration. FinLexPurple adds the money-path classes — price tampering,
  webhook signature bypass, refund and coupon abuse, payment-status trust, double
  processing — each with its own replay that reads the *result* back from an
  independent oracle (the charged amount, the settlement status) rather than trusting
  a reflected response.

## Quick start

Requires **Python 3.10 or newer**.

```bash
pip install finlexpurple
```

```bash
# 1. See your hardware and which optional tools are installed
finlexpurple doctor --tools

# 2. Choose a model provider and hardware tier (interactive)
finlexpurple setup

# 3. Scan a target you are authorized to test
finlexpurple scan --target https://app.example.com/

# 4. Re-check any verified finding, offline
finlexpurple verify-bundle ./finlexpurple-reports/<run>/evidence/<id>.bundle.json
```

The external scanners FinLexPurple can wrap (osv-scanner, pip-audit, Trivy, Grype,
Dockle, hadolint, cosign) are all optional and detected at runtime; `doctor --tools`
shows what is present.

> **Authorization is required.** `scan` asks you to confirm scope and attest
> authorization on every run, and records it in a tamper-evident audit log. Only test
> systems you own or have explicit, written permission to test.

## How verification works

Every finding carries a status. The status is assigned by exactly one place in the
code — the replay path — and it is the only route to `verified`.

| Status | Meaning |
| --- | --- |
| `verified` | A replay engine re-executed the finding and reproduced its effect. |
| `reported` | Surfaced for a human. No replay engine, or the effect could not be reproduced. |
| `not_reproduced` | A replay ran and the effect did **not** occur. |
| `inconclusive` | A replay ran but could not reach a definitive result (e.g. no readback oracle). |
| `blocked` | The approval gate or egress policy stopped the replay before it ran. |

A language model is never consulted to assign a status. If the replay cannot prove
the effect, the finding stays unproven — FinLexPurple does not round up.

### Evidence bundles

Each verified finding is written as an evidence bundle: a canonical record of the
request, the response, and the reproduced effect, addressed by a content hash. When
signing material is available, bundles are signed keyless (Sigstore/cosign); when it
is not, FinLexPurple falls back to a **hash-only** bundle and says so plainly rather
than implying a signature it does not have. Either way:

```bash
finlexpurple verify-bundle evidence/<finding>.bundle.json
```

re-checks the bundle with no scan and no network. Integrity rests on the content
hash; a signature, when present, is verified against a pinned identity.

## What it tests

Two families. **Web** classes run end-to-end in `scan`. **Financial** (business-logic)
classes run through the gated financial agent.

A class is **replay-backed** when a verification engine can re-execute the finding and
promote it to `verified`; otherwise it is **reported-only** — surfaced for a human and
never auto-verified.

### Web

| Class | Verification | Evidence shape |
| --- | --- | --- |
| SQL injection | Replay-backed | `http_request_response` |
| Reflected XSS | Replay-backed (headless browser) | `reflected_payload` |
| IDOR | Replay-backed (cross-session) | `cross_session_response` |
| SSRF | Replay-backed (out-of-band canary) | `oob_interaction` |
| Cache poisoning | Replay-backed | `header_response` |
| Security misconfiguration | Reported-only | `header_response` |
| Auth misconfiguration | Reported-only | `header_response` |

### Financial (business logic)

| Class | Verification | Evidence shape |
| --- | --- | --- |
| Price tampering | Replay-backed (gated) | `charged_amount_readback` |
| Webhook signature bypass | Replay-backed (gated) | `settlement_readback` |
| Order IDOR | Replay-backed (cross-session) | `cross_session_response` |
| Coupon / discount abuse | Replay-backed (gated) | `discounted_total_readback` |
| Payment-status trust | Replay-backed (gated) | `paid_status_readback` |
| Refund abuse | Replay-backed (gated) | `over_refund_readback` |
| Race condition (double-processing) | Replay-backed (gated); verification is best-effort | `double_processing_readback` |

**Replay-backed does not mean always-verified.** It means a verification engine
*exists* and will promote the finding to `verified` when it reproduces the effect
against an independent readback oracle (the charged amount, the settlement status, the
refunded total). When it cannot reproduce the effect — no oracle, a blocked gate, an
ambiguous result — the finding stays `reported` or `inconclusive`. Race-condition
verification in particular is inherently timing-dependent and will often remain
inconclusive; FinLexPurple reports it honestly rather than forcing a `verified`.

Beyond `scan`, the MCP-tool, supply-chain, and container modules run as their own
flows today; folding every surface into a single `scan` is in progress.

## Output formats

A run writes a machine-readable `report.json` (with a `schema_version` and a published
JSON Schema), plus additive exports for the tools teams already use:

- **SARIF 2.1.0** — for GitHub code scanning and IDE integrations
- **CycloneDX 1.6** and **SPDX 2.3** — dependency and container SBOM findings
- **Markdown** — a human-readable summary

## Interactive chat mode

```bash
finlexpurple chat
```

`chat` is an interactive terminal UI over the same engine as the CLI. It reuses the
exact same approval gates, egress policy, and capability caps — nothing in chat mode
loosens a gate or a cap. Every state-changing probe the model chooses to run is
always confirmed with you first, regardless of your approval setting, and hard-gated
categories can never be auto-allowed.

## Safety and authorization

FinLexPurple is an offensive security tool. Its safety model is not advisory:

- **Default-deny egress.** Network destinations are blocked unless explicitly allowed.
- **Approval gates on state-changing actions.** Any probe that could change state is
  gated before anything is sent. Sensitive categories (banking, teller, vault, MCP)
  are **hard-gated** and can never be allowed through configuration.
- **Iteration and request budgets** are on by default.
- **Owner-only reports** and a **tamper-evident audit log** of every authorization
  attestation.

Only test systems you own or are explicitly authorized, in writing, to test.
Unauthorized scanning may be illegal, and you are responsible for using FinLexPurple
lawfully.

## Intelligence packs

FinLexPurple can load optional **intelligence packs**: signed, data-only, advisory-only
JSON that sharpens detection for known patterns. Packs carry no executable code, are
distributed as public GitHub Releases over anonymous HTTPS, and are entirely optional —
the tool runs fully offline without them.

## Contributing

**FinLexPurple is open source, and contributions from anyone are welcome.** You do not
need to be a security researcher or to ask permission — a bug report, a doc fix, a new
detector, a replay engine for an unverified class, or a vulnerable test app all help.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup and the quality
  gate (tests, ruff, mypy must all pass).
- Because this is a security tool, correctness, safety, and honesty about what works
  come before features. A new class ships with its replay, or it ships clearly marked
  reported-only.
- Be excellent to each other — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security issue in FinLexPurple itself? Please follow
  [SECURITY.md](SECURITY.md) instead of opening a public issue.

New here? Start with an issue labeled
[`good first issue`](https://github.com/FinLexPurple/finlexpurple/labels/good%20first%20issue).

## Resources

**Website**
https://finlexpurple.com

**Install**
`pip install finlexpurple`

**Source code and releases**
- https://github.com/FinLexPurple/finlexpurple
- https://github.com/FinLexPurple/finlexpurple/releases

**Report a bug or request a feature**
https://github.com/FinLexPurple/finlexpurple/issues

**Community**
- Discord: https://discord.gg/QFBX5sgGGN
- X: https://x.com/finlexpurple

**Contact**
- General: hello@finlexpurple.com
- Support: support@finlexpurple.com
- Security reports: security@finlexpurple.com

**Maintainer**
Muhammad Ibrahim — https://www.mibrahimdev.tech

If FinLexPurple saves you time, a **star** helps more people find it. Thank you.

## Security

To report a vulnerability in FinLexPurple, see [SECURITY.md](SECURITY.md), or email
security@finlexpurple.com. Please do not open public issues for security reports.

## License

Apache License 2.0 — see [LICENSE](LICENSE). "FinLexPurple" and the FinLexPurple logo
are trademarks; see [TRADEMARKS.md](TRADEMARKS.md) for permitted use.
