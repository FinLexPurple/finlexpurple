"""Unit 3.3: the release pipeline is trust-critical, so its shape is guarded here.

These checks fail loudly if a future edit weakens the PyPI release channel: drops
Trusted Publishing / PEP 740 attestations, unpins an action back to a mutable tag,
removes the approval-gated environment, or lets the tagged version drift from the
CHANGELOG. They also assert the three version identifiers agree, so the commit that
gets tagged is internally consistent.
"""

from __future__ import annotations

import re
from pathlib import Path

try:  # `tomllib` is stdlib from Python 3.11; 3.10 (our minimum) uses the tomli backport.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

import finlexpurple

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_CHANGELOG = _ROOT / "CHANGELOG.md"


def _workflow() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


def _pyproject_version() -> str:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]


def test_version_is_consistent_across_pyproject_init_and_is_the_beta() -> None:
    version = _pyproject_version()
    assert version == finlexpurple.__version__  # the tagged commit is self-consistent
    assert version == "0.4.0b2"


def test_changelog_has_a_section_for_the_current_version() -> None:
    # The release workflow extracts `## [<version>]` for the GitHub Release notes.
    assert f"## [{_pyproject_version()}]" in _CHANGELOG.read_text(encoding="utf-8")


def test_workflow_triggers_only_on_version_tags_with_least_privilege() -> None:
    text = _workflow()
    assert "tags:" in text and '"v*"' in text
    assert "permissions:\n  contents: read" in text  # least privilege at the top


def test_publish_uses_trusted_publishing_with_attestations() -> None:
    text = _workflow()
    # PyPA's publishing action, at the release/v1 ref that carries PEP 740 support.
    assert "pypa/gh-action-pypi-publish@release/v1" in text
    # OIDC Trusted Publishing (no stored tokens) + attestations explicitly on.
    assert "id-token: write" in text
    assert text.count("attestations: true") >= 2
    # Never a manual twine upload to publish (twine check in `build` is fine).
    assert "twine upload" not in text


def test_publish_targets_are_the_expected_approval_gated_environments() -> None:
    text = _workflow()
    assert "name: testpypi" in text
    assert "repository-url: https://test.pypi.org/legacy/" in text
    # Stable PyPI is isolated behind its own environment and gated to stable tags.
    assert "name: pypi-production" in text
    assert "if: needs.build.outputs.is_stable == 'true'" in text


def test_every_third_party_action_is_pinned_to_a_commit_sha() -> None:
    text = _workflow()
    # Every `uses:` of a versioned third-party action must be a 40-hex commit SHA,
    # except pypa/gh-action-pypi-publish, which PyPA ships on the release/v1 ref.
    uses = re.findall(r"uses:\s*([^\s@]+)@([^\s#]+)", text)
    assert uses, "no action references found"
    for action, ref in uses:
        if action == "pypa/gh-action-pypi-publish":
            assert ref == "release/v1"
        else:
            assert re.fullmatch(r"[0-9a-f]{40}", ref), f"{action} is not SHA-pinned: {ref!r}"
