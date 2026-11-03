"""Unit 1.1: ``verify-bundle`` is a forever contract.

Every bundle format ever released keeps a golden vector in the repo, and CI
re-verifies all of them. ``v0-0.3.0.bundle.json`` is a genuine hash-only bundle
produced by 0.3.0 (the legacy ``flp-bundle/v0`` shape); ``v1.bundle.json`` is a
frozen ``flp-bundle/v1`` (DSSE + in-toto Statement) bundle. If a future change
stops either from verifying, that is a backward-incompatibility and this test
must fail. These files are pinned to LF in ``.gitattributes`` so a CRLF checkout
cannot alter the hashed bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

from finlexpurple.evidence.bundle import (
    BUNDLE_FORMAT_V0,
    BUNDLE_FORMAT_V1,
    detect_format,
)
from finlexpurple.evidence.verify import verify_bundle

_GOLDEN = Path(__file__).parent / "golden"


def _read(name: str) -> str:
    return (_GOLDEN / name).read_text(encoding="utf-8")


def test_v0_golden_vector_still_verifies() -> None:
    text = _read("v0-0.3.0.bundle.json")
    assert detect_format(json.loads(text)) == BUNDLE_FORMAT_V0
    report = verify_bundle(text)
    assert report.ok is True
    assert report.hash_ok is True


def test_v1_golden_vector_verifies() -> None:
    text = _read("v1.bundle.json")
    assert detect_format(json.loads(text)) == BUNDLE_FORMAT_V1
    report = verify_bundle(text)
    assert report.ok is True
    assert report.hash_ok is True
    assert report.signing_mode in {"hash-only", "hashed"}


def test_v1_golden_vector_byte_tamper_fails() -> None:
    bundle = json.loads(_read("v1.bundle.json"))
    payload = bundle["dsse"]["payload"]
    bundle["dsse"]["payload"] = ("A" if payload[0] != "A" else "B") + payload[1:]
    report = verify_bundle(json.dumps(bundle))
    assert report.ok is False
    assert report.hash_ok is False
