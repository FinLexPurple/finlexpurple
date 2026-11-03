# FinLexPurple public contracts (0.4.0)

This file is the frozen, public surface of FinLexPurple. Only three things are
public contracts; everything else is internal and may change without notice:

1. the **command-line interface** (commands, flags, exit codes);
2. **`report.json`** (schema in `src/finlexpurple/reporting/report.schema.json`,
   `schema_version` 1);
3. the **evidence bundle** (`*.bundle.json`, media type
   `application/vnd.finlexpurple.evidence-bundle+json`; current format
   `flp-bundle/v1`, with `flp-bundle/v0` still accepted by `verify-bundle`
   forever).

Python modules under `finlexpurple.*` are **internal**: import them at your own
risk; they are not covered by any compatibility promise.

## Commands

Frozen command set:

| Command | Purpose |
| --- | --- |
| `scan` | Confirm scope, map endpoints, run the bounded orchestration, write a report. |
| `verify-bundle` | Offline-verify an evidence bundle (any released format). |
| `setup` | First-run environment/model setup. |
| `init` | Create a starter `.env`. |
| `resume` | Resume a saved run by run id. |
| `telemetry` | `show` / `on` / `off` for optional, off-by-default telemetry. |
| `feedback` | Record local feedback on a finding. |
| `agents` | `list` the named security agents. |
| `run` | Run a single named agent/specialist. |

Operational helpers (present, not part of the minimal contract): `doctor`,
`setup-isolation`.

**Reserved** (defined, exit non-zero with a clear message, not yet available):
`push`, `auth`.

### `scan` flags

`--target`, `--resume`, `--root-url`, `--respect-robots/--ignore-robots`,
`--request-delay`, `--order-status-url`, `--llm-plan`, `--fix-mode`,
`--format {json,md}` (repeatable; default: both — `sarif`/`cyclonedx`/`spdx` are
reserved for a later release), `--output <dir>`, `--fail-on {none,verified}`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean. |
| `1` | Tool / runtime error. |
| `2` | Usage / argument error (includes the reserved `push`/`auth`). |
| `3` | `--fail-on` threshold met (e.g. a `verified` finding was produced). |

## Environment variables

Our own settings are canonically **`FLP_`**-prefixed. Each also accepts its
pre-0.4.0 name as a **back-compat alias** (canonical preferred when both are
set), so existing `.env` files keep working.

| Canonical (FLP_) | Legacy alias (still accepted) |
| --- | --- |
| `FLP_LLM_PROVIDER` | `LLM_PROVIDER` |
| `FLP_OLLAMA_MODEL` / `FLP_OLLAMA_HOST` | `OLLAMA_MODEL` / `OLLAMA_HOST` |
| `FLP_ANTHROPIC_MODEL` / `FLP_OPENAI_MODEL` / `FLP_OPENROUTER_MODEL` / `FLP_GEMINI_MODEL` | same without `FLP_` |
| `FLP_FALLBACK_LLM_PROVIDER` | `FALLBACK_LLM_PROVIDER` |
| `FLP_MODEL_TIER` | `MODEL_TIER` |
| `FLP_REQUIRE_HUMAN_APPROVAL` | `REQUIRE_HUMAN_APPROVAL` |
| `FLP_MAX_SPEND_USD` | `MAX_SPEND_USD` |
| `FLP_ORDER_STATUS_URL` | (new in 0.4.0) |
| `FLP_LLM_PLAN` | (new in 0.4.0) |
| `FLP_INTEL_PACKS_PULL_URL` / `FLP_INTEL_PACKS_SIG_URL` | `INTEL_PACKS_PULL_URL` / `INTEL_PACKS_SIG_URL` |
| `FLP_INTEL_PINNED_IDENTITY` / `FLP_INTEL_EXPECTED_SHA256` | `INTEL_PINNED_IDENTITY` / `INTEL_EXPECTED_SHA256` |
| `FLP_INTEL_PACKS_EGRESS_HOSTS` | `INTEL_PACKS_EGRESS_HOSTS` |

**Provider API keys keep their standard, un-prefixed names**: `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`.

Telemetry env vars (`TELEMETRY_ENABLED`, `TELEMETRY_ENDPOINT`) and the telemetry
opt-out convention are frozen separately with the telemetry envelope.

## Run-directory layout

A run writes a single relocatable directory named by its run id
(`<slug>-<hash8>-<ULID>`):

```
<run_id>/
  run-state.json            # resumable state (names only; no query values/bodies)
  report.json               # the machine-readable report (schema_version 1)
  report.md                 # the human-readable report
  audit.jsonl               # tamper-evident audit log
  evidence/<slug>.json          # per-finding captured evidence
  evidence/<slug>.bundle.json   # per-verified-finding signed/hashed evidence bundle
  replay-logs/<slug>.log        # per-finding deterministic replay log
```

`<slug>` is the filesystem-safe form of a finding id (the id value keeps its
`flp1:sha256:` prefix inside `report.json`). All paths in `report.json` are
relative — a run directory can be moved or copied and still verify.
