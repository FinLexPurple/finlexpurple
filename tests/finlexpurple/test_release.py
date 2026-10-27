"""Phase 20: the cosmetic release-codename scheme (decisions.md §16)."""

from __future__ import annotations

from finlexpurple import __version__
from finlexpurple.release import RELEASE_CODENAMES, codename_for, version_line


def test_codenames_track_the_minor_version_from_the_first_release() -> None:
    assert codename_for("0.1.0") == "Recon"      # first real release
    assert codename_for("0.2.0") == "Vantage"
    assert codename_for("0.3.0") == "Foothold"
    assert codename_for("0.4.0") == "Pivot"


def test_codename_is_always_a_pool_member_and_never_raises() -> None:
    assert codename_for("not-a-version") in RELEASE_CODENAMES  # cosmetic, no crash
    assert codename_for(__version__) in RELEASE_CODENAMES


def test_version_line_keeps_the_canonical_semver() -> None:
    line = version_line()
    assert line.startswith(__version__)           # semver is canonical, not replaced
    assert codename_for(__version__) in line
