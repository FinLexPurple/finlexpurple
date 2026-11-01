"""Intelligence pattern packs — data-only, advisory-only (Decision 2).

A pack is **data**, never code: a signed, versioned bundle of JSON pattern
records that say "for fingerprint X, these already-registered checks reproduced
the issue, in this order." The CLI uses a verified pack **only** to reorder which
already-relevant, already-registered checks run first — the same permutation-only
boundary the planner and selector obey. A pack can never add an action, cause an
unselected specialist to run, change a gate decision, or move a finding toward
``VERIFIED``.

Trust flow (see docs/refinements.md): a private master repo holds raw records;
CI builds a signed, data-only pack and publishes it to a **separate public**
GitHub Releases channel; the installed CLI downloads it **anonymously over
HTTPS**, verifies the signature against a **pinned** publishing-workflow identity,
and caches it. The CLI holds no credential for either repo, and packs are parsed
and schema-validated as data — never executed.
"""
