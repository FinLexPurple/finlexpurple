"""Opt-in, allow-listed telemetry and the privacy-by-architecture install counter.

Phase 17 (architecture.md), implementing decisions.md §8 (opt-in, allow-listed
telemetry — off by default, only a fixed allow-list of fields may ever be sent,
never raw scan data / targets / keys / source) and §22 (an install counter that
is *architecturally* incapable of identifying anyone: one random local UUID,
distinct-count only). This is the **package side only** — the receiving endpoint
(a Cloudflare Worker + D1) lives in the separate webapp repo and is not built
here. Telemetry is never sent in the background: only an explicit command sends,
and only when the user has turned it on.
"""
