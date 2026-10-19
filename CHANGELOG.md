# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
