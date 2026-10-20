"""Reproducible, tamper-evident evidence bundles (Phase 12; decisions.md §23).

A bundle packages everything a third party needs to independently confirm a
finding: the exact request/response evidence, the deterministic replay log, a
canonical content hash, and — where possible — a signature. The hash is always
produced; the signature is best-effort and its presence or absence is always
disclosed honestly.
"""
