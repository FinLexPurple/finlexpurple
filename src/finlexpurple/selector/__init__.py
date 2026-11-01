"""Scan front-door selector (decisions / refinements — Decision 1).

A scan does not run every specialist against every target. The selector is one
**bounded reasoning pass at scan start** that reads the Phase 5 recon fingerprint
and endpoint catalog and **selects and orders** which already-registered
specialists/checks run (saving the BYO-key user's tokens — one triage call
instead of eighteen specialists). It never runs an autonomous loop.

The subpackage has three parts:

* :mod:`capability_gap` — a report-only record of a technology/vuln class the
  registry has no specialist for; the system never generates one at runtime.
* :mod:`relevance` — deterministic relevance selection over the fixed registry
  (Compass triage + endpoint shape); the ground truth and the fallback.
* :mod:`selector` — one bounded, permute/subset-only LLM pass over the registry
  (same boundary as ``orchestrator/planner.py``), falling back to relevance on
  any provider error, budget stop, or non-conforming output.

The selector only decides *what runs and in what order*. It never verifies a
finding, never touches a gate, and never mutates status — those invariants live
in ``verifier/`` and ``gates/`` and are untouched here.
"""
