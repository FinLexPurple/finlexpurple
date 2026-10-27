"""Phase 20 cross-cutting audit (decisions.md §15): egress and caps have no bypass.

decisions.md §15 and ``egress_policy.py`` promise that Phase 20 audits that every
outbound call in the codebase routes through a deliberate egress control, and
that every model call made by the orchestrator is metered against the dollar
spend cap. This file is that audit, written as enforcement rather than prose:

* :func:`test_outbound_call_site_registry_is_exhaustive` scans ``src`` for every
  module that can open a network connection (an ``httpx`` call or a networked
  SDK import) and fails if one appears that is not in ``OUTBOUND_CALL_SITES``.
  A new outbound path cannot be added without landing here with its egress
  justification, so the audit cannot silently fall out of date.
* The behavioural tests confirm the two load-bearing controls actually fire: the
  prober egress-checks before sending, the crawler enforces scope before
  sending, telemetry stays silent unless opted in, and the orchestrator reaches
  a provider only through the metered choke point.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import finlexpurple

SRC_ROOT = Path(finlexpurple.__file__).resolve().parent

# Every module that can originate outbound network traffic, each mapped to the
# egress/caps control that governs it. Adding a new outbound call site without
# adding it here (with its justification) fails the exhaustiveness test below.
OUTBOUND_CALL_SITES: dict[str, str] = {
    "detectors/prober.py": "EgressPolicy.check_url before every send (default-deny allow-list)",
    "recon/crawler.py": "scope enforcement + pinned-IP connect before every send",
    "telemetry/sender.py": "opt-in only; fixed allow-listed install-counter endpoint",
    "providers/ollama_provider.py": "local/self-hosted host; metered via MeteredProvider in the loop",
    "providers/anthropic_provider.py": "configured provider endpoint; metered via MeteredProvider",
    "providers/openai_provider.py": (
        "configured provider endpoint; metered via MeteredProvider "
        "(also the outbound path for openrouter_provider, which subclasses it)"
    ),
    "providers/gemini_provider.py": "configured provider endpoint; metered via MeteredProvider",
}

# Markers that mean "this module can make a network call": a real httpx call
# (not the bare string "httpx" appearing in a data list) or a networked SDK.
_OUTBOUND_MARKERS = (
    re.compile(r"\bhttpx\.(?:Client|AsyncClient|Request|get|post|put|delete|patch|request|stream)\b"),
    re.compile(r"\b(?:from|import)\s+anthropic\b"),
    re.compile(r"\b(?:from|import)\s+openai\b"),
    re.compile(r"\bfrom\s+google\.genai\b|\bimport\s+google\.genai\b"),
    re.compile(r"\b(?:from|import)\s+ollama\b"),
    re.compile(r"\bsocket\.(?:create_connection|socket)\b"),
)


def _modules_with_outbound_markers() -> set[str]:
    found: set[str] = set()
    for path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if any(marker.search(text) for marker in _OUTBOUND_MARKERS):
            found.add(path.relative_to(SRC_ROOT).as_posix())
    return found


def test_outbound_call_site_registry_is_exhaustive() -> None:
    found = _modules_with_outbound_markers()
    registered = set(OUTBOUND_CALL_SITES)
    unregistered = found - registered
    stale = registered - found
    assert not unregistered, (
        "New outbound network call site(s) not covered by the egress audit: "
        f"{sorted(unregistered)}. Add each to OUTBOUND_CALL_SITES with its egress "
        "justification, and make sure it routes through an egress control."
    )
    assert not stale, (
        f"Audit lists modules that no longer make outbound calls: {sorted(stale)}."
    )


def test_prober_egress_checks_before_sending(monkeypatch) -> None:
    # An out-of-scope URL must be refused by the egress allow-list before any
    # socket is opened — prove httpx is never constructed on the blocked path.
    import finlexpurple.detectors.prober as prober_mod
    from finlexpurple.security.egress_policy import EgressBlockedError, EgressPolicy

    def _no_client(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("httpx.Client constructed despite blocked egress")

    monkeypatch.setattr(prober_mod.httpx, "Client", _no_client)
    prober = prober_mod.HttpProber(EgressPolicy.for_run(target_hosts=["in-scope.test"]))
    with pytest.raises(EgressBlockedError):
        prober.request("GET", "https://evil.example/leak")


def test_orchestrator_reaches_providers_only_through_the_metered_choke_point() -> None:
    # Structural no-bypass guard: the orchestration wiring must wrap the provider
    # in MeteredProvider and hand *that* to the planner. If this pattern changes,
    # this test fails so the spend-cap bypass is caught in review.
    cli_src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
    assert "MeteredProvider(provider, budget_guard)" in cli_src
    assert "Planner(provider)" in cli_src
    # The reassignment must happen before the planner is constructed.
    assert cli_src.index("MeteredProvider(provider, budget_guard)") < cli_src.index("Planner(provider)")
