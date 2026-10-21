# Contributing to FinLexPurple

Thanks for your interest. FinLexPurple is a security tool, so correctness,
safety, and honesty about what works are the priorities over features.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/FinLexPurple/finlexpurple.git
cd finlexpurple
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Some features wrap external scanners (osv-scanner, pip-audit, Trivy, Grype,
Dockle, hadolint, cosign). Install the ones relevant to your change; run
`finlexpurple doctor --tools` to see what is present.

## The quality gate (all three must pass)

```bash
python -m pytest -q
python -m ruff check .
python -m mypy --platform win32 && python -m mypy --platform darwin && python -m mypy --platform linux
```

mypy is checked on all three platforms because the tool ships cross-platform; a
change that only type-checks on one OS will fail CI. Add or update tests for any
behavior change — a test committed alongside the code it covers.

## Principles (please keep these)

- **Wrap, don't rebuild.** Where a mature OSS scanner exists, wrap it: run it
  through the hardened sandbox, parse its **real** exit status / structured
  output, and normalize into the `Finding` schema. Never paraphrase a scanner's
  prose into a finding, and never report "0 findings / clean" when a tool
  actually errored — surface the error.
- **Never weaken a safety rule.** Default-deny egress, spend/iteration caps,
  the non-overridable approval gate for banking/teller/vault/MCP, never mounting
  the Docker socket, never running privileged, 0600 reports, and the
  tamper-evident audit log are load-bearing. Changes must not relax them.
- **Verification over assertion.** A finding is only `[VERIFIED]` when a
  deterministic replay reproduces it — never on an LLM's confidence. Any
  human-facing claim that quotes evidence must pass quote-grounding.
- **Be honest about status.** If something is not wired end-to-end, say so in
  the README/CHANGELOG rather than implying it works.

## Reporting security issues

Please do not open a public issue for a vulnerability in FinLexPurple itself.
Report it privately to the maintainers first.

## License

By contributing you agree your contributions are licensed under the Apache
License 2.0, the same as the project.
