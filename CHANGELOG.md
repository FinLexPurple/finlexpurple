# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
