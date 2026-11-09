"""The scan op renders recon -> detect -> verify as live stages over the real read-only detectors."""

from __future__ import annotations

import io

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.tui.dispatch import _scan_stages
from finlexpurple.tui.theme import make_console


class _BenignProber:
    """A prober that answers every probe with a benign 200 — no network, no findings signal."""

    def __init__(self) -> None:
        self.calls = 0

    def request(self, method, url, *, params=None, headers=None, body=None):
        self.calls += 1
        return ProbeResponse(status_code=200, headers={}, text="ok")


def _console():
    return make_console(file=io.StringIO(), no_color=True, force_terminal=True, width=100)


def test_scan_stages_render_recon_detect_verify_in_order() -> None:
    endpoints = [
        Endpoint(method="GET", url="https://shop.example/a"),
        Endpoint(method="GET", url="https://shop.example/b", parameters=("id",)),
    ]
    prober = _BenignProber()
    console = _console()
    count, findings = _scan_stages(
        console, recon=lambda _root: endpoints, prober=prober, root_url="https://shop.example/"
    )
    out = console.file.getvalue()
    # All three live stages rendered, recon before detect before verify.
    assert "recon" in out and "detect" in out and "verify" in out
    assert out.index("recon") < out.index("detect") < out.index("verify")
    assert "2 endpoint(s)" in out          # recon reported the surface it was given
    assert count == 2
    assert prober.calls > 0                # detection actually probed through the given prober
    # Benign responses verify to nothing: no finding is falsely marked verified.
    from finlexpurple.detectors.schema import FindingStatus

    assert all(f.status is not FindingStatus.VERIFIED for f in findings)


def test_scan_stages_with_no_endpoints_still_renders_all_stages() -> None:
    console = _console()
    count, findings = _scan_stages(
        console, recon=lambda _root: [], prober=_BenignProber(), root_url="https://shop.example/"
    )
    out = console.file.getvalue()
    assert count == 0 and findings == []
    assert "recon" in out and "detect" in out and "verify" in out
    assert "0 endpoint(s)" in out
