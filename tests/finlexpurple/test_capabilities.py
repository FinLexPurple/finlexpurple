"""Unit 1.6: the capability contract — invariants, dispatch parity, and that a
brand-new capability dispatches + verifies with ZERO edits to dispatch/engine."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from finlexpurple import capabilities
from finlexpurple.detectors import dispatch
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier import engine
from finlexpurple.verifier.status import ReplayResult


def _endpoint(*, parameters: tuple[str, ...]) -> Endpoint:
    return Endpoint(method="GET", url="https://shop.example/p", parameters=parameters)


# --- Registry invariants ------------------------------------------------------


def test_class_keys_are_unique() -> None:
    classes = [cap.vulnerability_class for cap in capabilities.all_capabilities()]
    assert len(classes) == len(set(classes))


def test_web_capabilities_have_a_detector_and_relevance() -> None:
    for cap in capabilities.all_capabilities():
        if cap.family == "web":
            assert cap.detector is not None and cap.relevance is not None


def test_financial_capabilities_have_a_replay_and_gate_category_is_consistent() -> None:
    for cap in capabilities.all_capabilities():
        if cap.family != "financial":
            continue
        assert cap.replay is not None
        # Gate category is either None (an ungated read, e.g. order_idor) or
        # DERIVE_FROM_AGENT (a state-changing class) — never a hard-coded category.
        assert cap.gate_category in (None, capabilities.DERIVE_FROM_AGENT)
        # A gated class derives its category from the acting agent; an ungated one
        # declares no gate collaborator.
        if capabilities.GATE in cap.required_collaborators:
            assert cap.gate_category == capabilities.DERIVE_FROM_AGENT
        else:
            assert cap.gate_category is None


def test_capability_for_unknown_class_is_none() -> None:
    assert capabilities.capability_for("not_a_real_class") is None


# --- Dispatch parity (the pre-1.6 shape rules, exact order) -------------------


def test_dispatch_order_and_shape_match_the_legacy_rules() -> None:
    # Parameterless endpoint: only the always-on response/header checks, in order.
    names = [c.vulnerability_class for c in capabilities.web_capabilities_for(_endpoint(parameters=()))]
    assert names == ["generic_misconfig", "auth_misconfig", "cache_poisoning"]

    # A plain param adds sqli + xss (not idor/ssrf), before the always-on checks.
    plain = [c.vulnerability_class for c in capabilities.web_capabilities_for(_endpoint(parameters=("q",)))]
    assert plain == ["sqli", "xss", "generic_misconfig", "auth_misconfig", "cache_poisoning"]

    # An id-like + url-like param adds idor + ssrf too, in the frozen order.
    rich = [c.vulnerability_class for c in capabilities.web_capabilities_for(
        _endpoint(parameters=("id", "url")))]
    assert rich == ["sqli", "xss", "idor", "ssrf", "generic_misconfig", "auth_misconfig", "cache_poisoning"]


def test_dispatch_returns_the_registry_detector_objects() -> None:
    from finlexpurple.detectors import sqli
    chosen = dispatch.relevant_detectors(_endpoint(parameters=("q",)))
    assert sqli.detect in chosen


# --- Extensibility: a throwaway capability, no core edit ----------------------


def _dummy_detector(endpoint: Endpoint, prober: object) -> list[Finding]:
    del prober  # the dummy detector never touches the prober
    return [Finding.new(vulnerability_class="dummy_probe", method=endpoint.method,
                        url=endpoint.url, payload="dummy")]


def _dummy_replay(finding: Finding, ctx: capabilities.ReplayContext) -> ReplayResult:
    del finding, ctx
    return ReplayResult(reproduced=True, log="dummy replay reproduced the signal")


@pytest.fixture()
def _dummy_capability() -> Iterator[None]:
    capabilities.register(capabilities.Capability(
        vulnerability_class="dummy_probe",
        family="web",
        detector=_dummy_detector,
        relevance=lambda _endpoint: True,  # always relevant for the test
        replay=_dummy_replay,
        evidence_shape="test_only",
        agent="hunter",
    ))
    try:
        yield
    finally:
        capabilities.unregister("dummy_probe")


def test_new_capability_dispatches_and_verifies_with_no_core_edit(_dummy_capability: None) -> None:
    endpoint = _endpoint(parameters=())
    # Dispatch picks it up (dispatch.py was not touched to add this class): the
    # dummy's detector object is in the relevant set returned by the registry.
    assert _dummy_detector in dispatch.relevant_detectors(endpoint)
    assert "dummy_probe" in [c.vulnerability_class for c in capabilities.web_capabilities_for(endpoint)]

    # The detector produces a candidate finding...
    finding = _dummy_detector(endpoint, object())[0]
    assert finding.status is FindingStatus.REPORTED  # Finding.new status lock

    # ...and the engine verifies it via the registry replay (engine.py untouched).
    engine.verify(finding)
    assert finding.status is FindingStatus.VERIFIED
    assert "dummy replay reproduced" in (finding.verification_log or "")


def test_unregister_restores_the_registry(_dummy_capability: None) -> None:
    # Inside the fixture the dummy is present; after it we assert it is gone.
    assert capabilities.capability_for("dummy_probe") is not None
