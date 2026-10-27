"""Phase 20 §28 #2: dependency-confusion guard for our own namespace."""

from __future__ import annotations

from finlexpurple.supplychain.namespace_guard import (
    audit_environment,
    audit_namespace,
    canonical_name,
    in_our_namespace,
)

_OURS = {"Author": "FinLexPurple", "Home-page": "https://github.com/FinLexPurple/finlexpurple"}


def test_canonicalization_and_namespace_membership() -> None:
    assert canonical_name("FinLexPurple") == "finlexpurple"
    assert canonical_name("finlexpurple_foo") == "finlexpurple-foo"
    assert in_our_namespace("finlexpurple")
    assert in_our_namespace("FinLexPurple_Plugin")
    assert not in_our_namespace("requests")
    assert not in_our_namespace("finlexpurpled")  # a lookalike, not our namespace prefix


def test_registered_first_party_package_is_silent() -> None:
    assert audit_namespace([("finlexpurple", _OURS)]) == []


def test_out_of_namespace_packages_are_ignored() -> None:
    assert audit_namespace([("httpx", {}), ("pydantic", {"Author": "someone"})]) == []


def test_unregistered_namespace_package_is_flagged() -> None:
    # A package squatting the finlexpurple-* prefix we did not publish.
    warnings = audit_namespace([("finlexpurple-pro", {"Author": "attacker"})])
    assert len(warnings) == 1
    assert warnings[0].distribution == "finlexpurple-pro"
    assert "not a registered first-party" in warnings[0].reason


def test_first_party_name_without_our_provenance_is_flagged() -> None:
    # Right name, but the installed copy carries none of our provenance markers.
    warnings = audit_namespace([("finlexpurple", {"Author": "mallory", "Home-page": "http://evil"})])
    assert len(warnings) == 1
    assert "provenance" in warnings[0].reason


def test_our_own_installed_package_passes_the_guard() -> None:
    # The real environment this test runs in has our package installed from our
    # own metadata, so the guard must not flag it.
    warnings = [w for w in audit_environment() if w.distribution.lower() == "finlexpurple"]
    assert warnings == []
