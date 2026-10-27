# FinLexPurple

**A local, air-gapped-capable, hardened autonomous security agent that tests a
financial application — and everything it now trusts.**

A modern financial app is no longer just its own code and endpoints. It trusts
AI agents and their MCP tool integrations, a tree of third-party software
dependencies, and the container images it ships in. FinLexPurple's thesis is
**one engagement, whole surface**: test the application *and* its AI/MCP
integrations, its dependencies, and its containers together — with findings that
are **deterministically verified** (re-executed by code, not asserted by an LLM)
and **cryptographically provable** (a signed, reproducible evidence bundle per
verified finding).

> **AUTHORIZATION REQUIRED — this is an offensive security tool.** Only run
> FinLexPurple against systems you own or have **explicit, written authorization**
> to test. Unauthorized scanning may be illegal. The tool requires you to attest
> authorization for each target (recorded in a tamper-evident audit log), runs
> default-deny egress and spend/iteration caps, and never auto-exploits financial
> or MCP actions without a human gate — but **you are responsible** for using it
> lawfully.

---

## Project status (honest)

FinLexPurple is in **active, pre-1.0 development**, released milestone by
milestone. What works today:

| Capability | Status |
|---|---|
| Hardware/provider setup, scope confirmation + authorization attestation | yes — works |
| `scan` end-to-end: recon → web detectors → verification → report | yes — works |
| Web detectors (SQLi/XSS/IDOR/SSRF…) + deterministic verification | yes — runs in `scan` |
| Signed evidence bundle + standalone `verify-bundle` | yes — works (`scan` writes a bundle per verified finding) |
| MCP offensive testing | yes — module (runnable; not yet auto-run by `scan`) |
| Supply-chain (OSV/pip-audit wrap, slopsquat, typosquat, secrets) | yes — module (`--include` wiring is a follow-up) |
| Container (Trivy/Grype/Dockle/hadolint wrap, escape checks) | yes — module (`--include` wiring is a follow-up) |
| AST CodeFix (tree-sitter, JS/TS + Python) | yes — module (whitebox `scan` flow is a follow-up) |
| Reporting engine (`report.json`/`report.md`, text badges, 0600) | yes — runs in `scan` |

**The web path is wired end-to-end.** `finlexpurple scan --target <url>` confirms
scope + authorization, runs recon, runs the web detectors through a scope-safe
prober, verifies each finding by deterministic replay, and writes a full report
tree (`report.json`, `report.md`, `evidence/`, `replay-logs/`, and a signed
bundle per verified finding) into `./finlexpurple-reports/<run>/`.

**Still a follow-up:** the supply-chain and container surfaces (`--include
supplychain|container`) and the whitebox CodeFix flow (`--path … --mode
whitebox --fix-mode agent`) are complete, tested modules but are **not yet
auto-run by `scan`** — run them via their module entry points for now. See the
[CHANGELOG](CHANGELOG.md) for exact per-release status.

This is a pre-release; the API, CLI flags, and output layout may change before
1.0.

**Latest release:** [0.3.0 release report](docs/releases/0.3.0.md) — the M3
milestone, with the real end-to-end demo result (4 verified findings) and CI
status. See the [CHANGELOG](CHANGELOG.md) for full per-release detail.

---

## Install

Requires Python 3.10+.

```bash
pip install finlexpurple
```

Some capabilities **wrap best-of-breed open-source scanners** rather than
reimplementing them. Install the ones you need and check availability with
`finlexpurple doctor --tools`:

- Supply-chain: [osv-scanner](https://google.github.io/osv-scanner/), [pip-audit](https://pypi.org/project/pip-audit/)
- Container: [Trivy](https://trivy.dev/), [Grype](https://github.com/anchore/grype), [Dockle](https://github.com/goodwithtech/dockle), [hadolint](https://github.com/hadolint/hadolint)
- Evidence signing: [cosign](https://docs.sigstore.dev/cosign/) (optional; bundles are hash-only without it)
- Container isolation: Docker (Standard tier)

Missing tools are reported clearly and their steps are **skipped**, never faked.

## Usage

```bash
# 1. See your hardware and which external scanners are installed
finlexpurple doctor
finlexpurple doctor --tools

# 2. Configure model provider / hardware tier, and the container-isolation tier
finlexpurple setup
finlexpurple setup-isolation
finlexpurple init                 # create a local .env from the template

# 3. Scan a target you are authorized to test (confirms scope + attestation,
#    then recon + the orchestration loop). You will be asked to confirm scope.
finlexpurple scan --target https://app.example.com/
finlexpurple scan --target 10.0.0.0/24 --root-url http://10.0.0.5/   # IP/CIDR
finlexpurple resume <run-id>      # resume a paused run

# 4. Independently re-verify a finding's evidence bundle — offline, standalone
finlexpurple verify-bundle ./finlexpurple-reports/<run>/evidence/<id>.bundle.json
```

Run state and reports are written under `./finlexpurple-reports/` (gitignored;
reports are `0600` on POSIX because they contain real vulnerability detail).

### Hardening controls (default-on)

Every control below is on by default; you widen or narrow it, never switch it
off:

- **Dollar spend cap** — `MAX_SPEND_USD` (default `5.00`). Every model call is
  metered against real provider pricing through a single choke point; when the
  cap is reached the run stops at a safe point and is **resumable** (`resume
  <run-id>`) — spend carries across the resume. Raise the number for a looser
  budget.
- **Iteration / tool-call caps and a per-target request kill-ceiling** — bound a
  runaway run and the traffic it can send at a target.
- **Default-deny egress** — a run may reach only the confirmed in-scope target
  and your configured model provider; everything else is blocked and logged.
- **Tiered container isolation** — `ISOLATION_TIER` is `none` / `standard`
  (hardened Docker, the default) / `maximum`. **Maximum** adds the gVisor
  (`runsc`) runtime on top of every Standard hardening flag; gVisor is
  Linux-only and installed separately, and where it is absent the Maximum tier
  logs a warning and falls back to the Standard hardened container rather than
  silently claiming protection it cannot give. Configure with
  `finlexpurple setup-isolation`.

Each report finding also **names the agent** that produced it, and
`finlexpurple --version` prints the semver plus a cosmetic release codename
(e.g. `0.3.0 (Foothold)`); the codename is never parsed in place of the version.

### The verify-bundle flow (the credibility differentiator)

A verified finding is backed by a reproducible **evidence bundle**: the exact
request/response, the deterministic replay log, and a canonical content hash
(and, when cosign is available and you are online, a Sigstore signature). Anyone
— an auditor, a client, a regulator — can re-check it on their own machine, with
**no scan and no network**:

```bash
finlexpurple verify-bundle finding.bundle.json
finlexpurple verify-bundle finding.bundle.json --expected-hash sha256:<from-the-report>
```

It recomputes the hash and reports tampering clearly; a bundle altered after
creation fails verification.

## What makes it different

1. **Deterministic exploit verifier** — findings are re-executed by code, never trusted on an LLM's say-so.
2. **Local / air-gapped / bring-your-own-model** — runs fully local via Ollama; cloud providers optional.
3. **AI-agent / MCP offensive testing** — active prompt-injection, tool-poisoning, exfiltration-oracle testing (hard-gated).
4. **Hardened by default** — default-deny egress, spend/iteration caps, never mounts the Docker socket, never privileged.
5. **Fintech business-logic specialization** — a suite of financial-domain agents (later milestone).
6. **Slopsquatting / hallucinated-dependency detection** — catches packages an AI coding agent might invent or that were attacker-registered.
7. **Payment-SDK typosquat detection** — fake Stripe/JazzCash/Easypaisa/Paysafe-style packages.
8. **Privacy-by-architecture install counter** — opt-in, cannot identify you.
9. **Three-state verified badge + aggregate "% verified"** — `[VERIFIED]` / `[REPORTED]` / `[HUMAN-CONFIRMED]`, as plain text (no emoji).
10. **One engagement, whole surface** — app + AI/MCP + dependencies + containers, not four-to-six stitched-together tools.
11. **Reproducible, signed evidence bundle per finding** — independently re-verifiable.
12. **Tiered container isolation** — the scan runs inside a hardened boundary (None / Standard-Docker / Maximum-gVisor).

Where mature OSS scanners exist, FinLexPurple **wraps** them (Trivy, Grype,
OSV-Scanner, pip-audit, mcp-scan, hadolint, Dockle) and normalizes their real
output into one finding schema — it does not reimplement their databases.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
