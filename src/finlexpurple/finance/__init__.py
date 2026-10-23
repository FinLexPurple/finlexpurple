"""Financial testing agents (Phase 19; decisions.md §7, §14).

The eight-agent financial suite. Phase 19a ships the triage agent (Compass), the
core payment agent (Cashier), the banking agent (Teller), and the shared
hard-gate framework; Phase 19b adds Ledger, Broker, Vault, Underwriter, and
Courier. Teller (and, in 19b, Vault) are **hard-gated**: read-only by default,
every state-changing step always pauses for human approval, and no config,
environment variable, or plan tier can disable that (§14).
"""
