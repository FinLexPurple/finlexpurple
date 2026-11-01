"""Decision 2 Step 2: the delivered publish workflow matches the CLI's baked pin.

The packs repo's ``intel-pack.yml`` is what signs releases, and the CLI pins that
exact identity. These are in two different repos, so this test guards against
silent drift: if the workflow filename, repo, trigger, or signing step changes
without the baked pin changing to match (or vice versa), the signed channel would
either stop verifying or verify against the wrong signer. Either is caught here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.intel import config

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _REPO_ROOT / "deploy" / "finlexpurple-intelligence-packs" / ".github" / "workflows" / "intel-pack.yml"


@pytest.fixture(scope="module")
def workflow_text() -> str:
    assert _WORKFLOW.exists(), f"publish workflow missing at {_WORKFLOW}"
    return _WORKFLOW.read_text(encoding="utf-8")


def test_workflow_triggers_only_on_version_tags(workflow_text: str) -> None:
    assert "tags:" in workflow_text
    assert "'v*'" in workflow_text


def test_workflow_uses_least_privilege_then_grants_oidc_and_contents(workflow_text: str) -> None:
    assert "permissions: {}" in workflow_text  # least privilege at the top
    assert "id-token: write" in workflow_text  # Sigstore keyless OIDC
    assert "contents: write" in workflow_text  # create the Release / upload assets


def test_workflow_keyless_signs_the_pack_into_the_expected_bundle(workflow_text: str) -> None:
    assert "cosign sign-blob" in workflow_text
    assert "--bundle pack.sig.json pack.json" in workflow_text
    # It self-verifies against its own identity + the documented issuer before releasing.
    assert "cosign verify-blob" in workflow_text
    assert "token.actions.githubusercontent.com" in workflow_text


def test_baked_pin_matches_the_delivered_workflow() -> None:
    # The workflow file is literally named intel-pack.yml ...
    assert _WORKFLOW.name == "intel-pack.yml"
    # ... and the baked identity regexp pins exactly that file, in the packs repo, on tags only.
    regexp = config.DEFAULT_PINNED_IDENTITY_REGEXP
    assert "finlexpurple-intelligence-packs" in regexp
    assert r"intel-pack\.yml" in regexp
    assert "refs/tags/" in regexp
    # The pinned repo is the same repo the baked channel URL points at.
    assert "FinLexPurple/finlexpurple-intelligence-packs" in config.DEFAULT_PACKS_URL
