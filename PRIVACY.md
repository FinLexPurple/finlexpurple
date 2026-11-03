# FinLexPurple telemetry privacy

Telemetry is **opt-in and off by default**. Nothing is ever sent unless you turn
it on with `finlexpurple telemetry on`. It is never sent in the background —
only an explicit command transmits, and only while it is on. Its sole purpose is
to improve detection accuracy and false-positive rates; it is never used for ad
targeting, resale, or any other purpose.

This document lists **every field that can ever leave your machine**. The
allow-list in `src/finlexpurple/telemetry/allowlist.py` is the single source of
truth; the sender refuses to transmit any field not listed there, including
inside a nested `props` map.

## Turning it off / opting out

- `finlexpurple telemetry off` — persists `TELEMETRY_ENABLED=false`.
- `FINLEXPURPLE_TELEMETRY=0` (or `false`/`off`/`no`/`disabled`) — forces
  telemetry off **even if it is otherwise enabled**.
- `DO_NOT_TRACK=1` — the common cross-tool opt-out convention, also honoured.
- `finlexpurple telemetry reset` — discards the local random install id and
  generates a fresh one (severing any link to prior pings).

An air-gapped deployment can set `FINLEXPURPLE_TELEMETRY=0` (or `DO_NOT_TRACK=1`)
to guarantee nothing is ever attempted.

## The event envelope (schema_version 1)

The four product-analytics events share one versioned envelope. Every field is a
coarse, non-identifying fact.

| Field | What it is | Example |
| --- | --- | --- |
| `schema_version` | Envelope version (an integer; `1` today). | `1` |
| `event` | Which event this is (a fixed enum). | `scan_completed` |
| `tool_version` | The FinLexPurple version. | `0.3.0` |
| `python_version` | The Python version running the tool. | `3.12.3` |
| `os` | OS **family** only (`sys.platform`) — never a hostname. | `linux` |
| `install_id` | A random local UUIDv4 generated **only after opt-in**; not derived from any machine property; resettable. | `11111111-1111-4111-8111-111111111111` |
| `ts_day` | The UTC calendar **day** only — never a precise time. | `2026-11-03` |
| `props` | The event-specific map below (allow-listed keys only). | `{...}` |

## The four events and their `props`

| Event | `props` keys | Meaning |
| --- | --- | --- |
| `install` | *(none)* | A one-time install ping: the envelope and the random install id, nothing else. |
| `scan_completed` | `web`, `mcp`, `deps`, `container` | Which scan surfaces ran (booleans — never a target or URL). |
| `scan_completed` | `reported`, `verified`, `human_confirmed`, `inconclusive`, `not_reproduced`, `blocked` | Finding counts by status, **bucketed** (`0` / `1-9` / `10-49` / `50+`) — never a raw count. |
| `bundle_created` | `bundle_mode` | `hashed` or `signed`. |
| `bundle_verified` | `verify_result` | `pass` or `fail`. |

## The feedback event (pre-existing; §8)

Run/finding feedback is recorded **locally** first. If (and only if) telemetry is
on, an allow-listed feedback payload may be sent. It keeps its flat pre-0.4.0
shape and, by design, **does not carry the install id** — feedback is never tied
to an install.

| Field | What it is |
| --- | --- |
| `event` | `feedback`. |
| `app_version`, `python_version`, `platform` | The same coarse version/OS facts as above. |
| `run_rating` | Your run rating: `good` / `ok` / `bad` (only if you gave one). |
| `finding_mark` | Your mark: `true-positive` / `false-positive` (only if you gave one). |
| `vulnerability_class` | The finding's generic class (e.g. `sqli`) — never its URL, payload, run id, or finding id. |

## What is never sent

Targets, URLs, request/response data, payloads, headers, source code, API keys,
run ids, finding ids, hostnames, IP addresses, email addresses, or any other
machine or user identifier. These keys are rejected by the allow-list gate.
