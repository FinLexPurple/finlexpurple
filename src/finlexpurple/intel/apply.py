"""Advisory-only pack application — the hard safety boundary (Decision 2).

A verified pack may do exactly **one** thing: suggest an *ordering* over the
checks the selector already chose for this target. It plugs in *after* relevance
selection and can only permute that set. Enforced here, structurally:

* **Never expands scope.** The result is always a permutation of the
  already-selected names. A pack name that the selector did not select is
  ignored — never added — so a pack can never make an unselected specialist run.
* **Never gates or verifies.** This module returns an ordered list of agent
  names and nothing else. It has no access to the approval gate, to
  ``Finding.status``, or to ``verifier/`` — so a pack structurally cannot change
  a gate decision or move a finding toward ``VERIFIED``.
* **Community data is quarantined.** Records with ``provenance == "community"``
  are ignored unless the caller explicitly opts in (``trust_community``); even
  then they can only reorder. Trust is never derived from a submitter count.

If the permutation invariant is ever violated (it cannot be by construction),
:class:`PackScopeError` is raised rather than returning an expanded scope.
"""

from __future__ import annotations

from finlexpurple.intel.pack import Pack


class PackScopeError(RuntimeError):
    """A pack attempted to change more than the order of already-selected checks."""


def reorder_selection(
    selected: list[str], pack: Pack, fingerprint: str, *, trust_community: bool = False
) -> list[str]:
    """Return ``selected`` reordered by the pack's hint for ``fingerprint``; same set, always.

    The first matching, trusted pattern record provides an ordering hint. Names in
    that hint that are **also** in ``selected`` move to the front in the hint's
    order; the remaining selected names keep their original relative order. Names
    in the hint that were not selected are ignored (never added). With no matching
    trusted record, ``selected`` is returned unchanged.
    """

    hint: list[str] = []
    for record in pack.patterns:
        if record.fingerprint != fingerprint:
            continue
        if record.provenance == "community" and not trust_community:
            continue  # quarantined: advisory only, never trusted by submitter count
        hint = record.ordered_agents
        break

    if not hint:
        return list(selected)

    selected_set = set(selected)
    front = [name for name in hint if name in selected_set]        # only already-selected names
    front_set = set(front)
    rest = [name for name in selected if name not in front_set]    # the rest, order preserved
    result = front + rest

    # Permutation-only invariant, enforced (not merely asserted): identical set.
    if set(result) != selected_set or len(result) != len(selected):
        raise PackScopeError(
            "a pack ordering changed the set of selected checks; refusing to apply "
            "(a pack may only reorder, never add or drop a check)."
        )
    return result
