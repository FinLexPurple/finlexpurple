# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0b2] - 2026-11-08

First **0.4.0 beta** (codename *Pivot*). Adds the gated financial verification
classes (Phase 2) and the machine-readable report emitters (Phase 3). Published
to **TestPyPI only**; the PyPI Trusted Publisher stays configured and pending for
the eventual stable `0.4.0`. Verify the release's PEP 740 attestations as
described in [docs/releases/0.4.0b2.md](docs/releases/0.4.0b2.md).

Supersedes the unpublished `0.4.0b1` tag, whose release workflow failed its quality
gate before building or publishing anything; this beta fixes the two causes (see
**Fixed**).

### Added

- **Financial verification classes** (Phase 2) — each a gated, replay-backed
  check on the one capability contract, verified only by an in-scope read-back,
  never an LLM:
  - **Order IDOR** (2.1) — a two-session cross-account order read; reproduced
    when the non-owner receives the owner's exact object.
  - **Coupon abuse** (2.2) — a client-supplied coupon the shop never issued;
    reproduced when a read-back shows the illegitimate discount durably applied.
  - **Payment-status trust** (2.3) — a client-set order status persisted without
    settlement; reproduced when a read-back shows the order durably marked.
  - **Refund abuse** (2.4) — an over-refund with no amount/idempotency check; the
    gated re-send is the double-refund corollary; reproduced when the refunded
    total durably exceeds the amount paid.
  - **Race condition** (2.5) — a check-then-act double-processing opportunity,
    verified by a **bounded, rate-limited, gated** concurrency harness. Marked
    `VERIFIED` only on a deterministic in-scope double-processing read-back;
    otherwise an honest `INCONCLUSIVE` human-review lead (never a forced verdict,
    never evidence the race is absent).
- **SARIF 2.1.0 report writer** (Phase 3, Unit 3.1) — `--format sarif`. `ruleId`
  from the rule catalog, `level` from the frozen severity map, the versioned
  fingerprint under `partialFingerprints`; a `physicalLocation` only when a real
  source file exists, else a `logicalLocation` (the GitHub code-scanning display
  caveat is documented, never worked around).
- **CycloneDX 1.6 and SPDX 2.3 SBOM writers** (Phase 3, Unit 3.2) —
  `--format cyclonedx` / `--format spdx`. Components/packages are built from the
  frozen package URLs; CycloneDX emits a VEX entry (`analysis.state=exploitable`)
  for verified, purl-bearing findings. Empty when the report carries no purls —
  emitted truthfully, never fabricated.

### Changed

- The rule catalog now carries every Phase-2 financial class, so every emitter's
  rule metadata is complete.
- All machine report formats (`json`, `sarif`, `cyclonedx`, `spdx`) render from a
  single shared report document, so they cannot drift from one another.

### Fixed

- **Release CI on Python 3.10** — the release-pipeline guard test read
  `pyproject.toml` with `tomllib`, which is standard-library only from Python 3.11;
  the quality jobs run on 3.10 (the minimum supported version), so it failed to
  import. It now falls back to the `tomli` backport (added as a `python_version <
  "3.11"` dev dependency).
- **Self-audit of the unpublished package** — the supply-chain audit job ran
  `pip-audit --strict` over the whole environment, including our own editable
  install, and failed because the pre-release version is not yet on PyPI. It now
  audits a frozen list of the non-editable dependencies, excluding our own package
  while keeping `--strict` over every real dependency.

### Security

- Report formats validate offline against vendored official JSON Schemas (SARIF
  2.1.0, CycloneDX 1.6, SPDX 2.3); the air-gapped tool never fetches at runtime.
- Release workflow actions are pinned to commit SHAs; publishing keeps PEP 740
  Sigstore attestations via Trusted Publishing, with no stored API tokens.

## [0.3.0] - 2026-10-22

Milestone M3 (Phases 11–16). This milestone adds deterministic verification and
the capabilities built on it. Every module below is implemented and tested;
see **Known limitations** for how they are (and are not yet) reachable.

Release report (real demo result + CI + PyPI link): [docs/releases/0.3.0.md](docs/releases/0.3.0.md).

### Added

- **Deterministic verification engine** (Phase 11) — re-executes a finding by
  code (SQLi error reproduction, IDOR two-session diff, SSRF out-of-band canary,
  XSS via a headless-browser runner); a finding is `verified` only on a real
  reproduction, never on an LLM's confidence. Quote-grounding rejects any
  human-facing claim that cites evidence not present in the finding.
- **Signed evidence bundle + `verify-bundle`** (Phase 12) — a reproducible
  per-finding bundle (request/response, replay log, canonical hash; Sigstore/
  cosign signature when online, hash-only offline). `finlexpurple verify-bundle`
  re-checks a bundle **standalone and fully offline**, and detects tampering.
- **Supply-chain module** (Phase 13) — wraps OSV-Scanner and pip-audit
  (real JSON normalized to findings), plus original slopsquat / hallucinated-
  dependency, payment-SDK typosquat, and secrets detection; online/offline modes
  labeled honestly.
- **Container module** (Phase 14) — wraps Trivy, Grype, Dockle, and hadolint,
  plus original exposed-Docker-socket and container-escape-class checks. The
  module never mounts the host socket and never runs privileged.
- **AST CodeFix / whitebox module** (Phase 15) — tree-sitter parsing for JS/TS
  and Python; minimal, reviewable diff patches; a safety gate (only-the-
  construct, re-parse, backup-before-write) and local branch/commit output that
  never pushes or opens a PR.
- **Reporting engine** (Phase 16) — `report.json` / `report.md` with
  code-computed statistics (no LLM), text badges (`[VERIFIED]` / `[REPORTED]` /
  `[HUMAN-CONFIRMED]`, no emoji), signed-bundle references for verified findings,
  written `0600` at rest.

### Known limitations

- **`scan` web path is end-to-end; other surfaces are not auto-run yet.**
  `finlexpurple scan --target <url>` now runs the full web path — scope
  confirmation + authorization attestation → recon → web detectors (through a
  scope-safe, egress-checked, kill-ceiling-capped prober) → deterministic
  verification → a written report tree (`report.json`, `report.md`, `evidence/`,
  `replay-logs/`, and a signed bundle per verified finding). (Confirmed against a
  deliberately vulnerable local target: 8 findings, 2 verified — SQLi reproduced
  and SSRF confirmed by out-of-band canary.) **Not yet auto-run by `scan`:** the
  supply-chain and container surfaces (`--include supplychain|container`) and the
  whitebox CodeFix flow (`--path … --mode whitebox`); those modules are complete
  and tested and are run via their module entry points for now.
- **Default-on *dollar* spend cap is not yet enforced.** Of the §15 hardening
  defaults, the default-on **iteration / tool-call** cap
  (`orchestrator/iteration_limits.py`) and the **per-target request
  kill-ceiling** (`security/budget.py`) are enforced today, but the **maximum
  dollar-spend-per-run** cap is **not** — it is finalized in Phase 20. Until
  then, bound a run's cost via the iteration/tool-call caps; do not rely on a
  dollar ceiling that does not yet exist.
- **Air-gapped scanner feeds** — the wrapped scanners download/cache their own
  vulnerability databases on first use; pre-fetched offline feed bundles are a
  later deployment concern.

## [0.2.0a1] - 2026-10-20

Milestone M2 (Phases 7–10). This is an **alpha**: it adds the detection and
safety substrate, but **deterministic verification is not in this release** —
findings are captured and reported, not yet independently re-verified (that is
Phase 11 / M3). Scanning does not yet run the detectors end to end from the
`scan` command; the detectors and the MCP module are runnable/importable and
individually tested.

### Added

- **Shared substrate & container isolation** — the universal `Finding` schema;
  a hardened sandboxed external-process runner (argument lists only, enforced
  timeouts); default-deny egress policy; tamper-evident hash-chained audit log;
  request budget/kill-ceiling and rate limiter; prompt-injection "untrusted
  data" typing; secrets hygiene; safe-failure framework; and tiered container
  isolation (None / Standard hardened-Docker; Maximum/gVisor is deferred to a
  later phase). `finlexpurple doctor --tools` and a `setup-isolation` step.
- **Human-in-the-loop gates** — an approval gate whose hard-gated categories
  (banking, Teller, Vault, MCP) always pause for approval and cannot be disabled
  by config; Agent/Human fix-mode selection; authorization/scope attestation
  recorded in the audit log; and a kill switch for a graceful stop at a safe
  point (`finlexpurple resume <run-id>`).
- **AI-agent / MCP offensive testing (flagship)** — prompt-injection,
  tool-poisoning, and exfiltration-oracle testers (exfiltration confirmed only
  by an out-of-band canary, never the agent's claim), all hard-gated; plus a
  passive mcp-scan wrapper that normalizes real tool JSON into findings.
- **Web vulnerability detectors** — SQLi, reflected XSS, IDOR, SSRF, plus
  cache-poisoning and auth/generic misconfiguration, dispatched by endpoint
  shape and probed through a scope-safe, egress-checked HTTP prober.

### Security

- Hardened-by-default execution: default-deny egress, default-on request
  kill-ceiling, container isolation that never mounts the Docker socket and
  never runs privileged, and a non-overridable approval gate for the
  highest-risk categories.

### Not yet included

- Deterministic exploit verification (Phase 11), signed evidence bundles
  (Phase 12), supply-chain and container *target* scanning (Phases 13–14), and
  end-to-end wiring of detection into the `scan` command.

## [0.1.0a1] - 2026-10-19

### Added

- Hardware-aware setup with model-tier recommendations, provider selection,
  disk-space warnings, and a privacy-conscious `doctor` command.
- Cloud and Ollama provider adapters behind a shared typed interface.
- Explicit target confirmation and exact scope enforcement for URL, IP/CIDR,
  and local-directory targets.
- Bounded HTTP reconnaissance with endpoint catalogs, passive fingerprints,
  robots.txt hints, and query-value redaction in logs.
- Cross-platform CI checks and local synthetic fixtures for hardware and scope
  behavior.

### Security

- Release publishing uses GitHub Actions Trusted Publishing (OIDC), without
  stored PyPI or TestPyPI API tokens.
- Stable PyPI publishing is isolated behind the `pypi-production` environment.
