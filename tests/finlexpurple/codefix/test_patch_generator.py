"""Phase 15: minimal AST-driven patch generation (yaml.load -> yaml.safe_load)."""

from __future__ import annotations

from pathlib import Path

from finlexpurple.codefix.parser import CodeLanguage, parse
from finlexpurple.codefix.patch_generator import generate_patch

_VULN = "import yaml\n\ndef load_config(path):\n    with open(path) as f:\n        return yaml.load(f.read())\n"


def test_generates_minimal_patch_for_yaml_load() -> None:
    patch = generate_patch(Path("config.py"), _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    assert patch.vulnerability_class == "insecure_deserialization"
    assert b"yaml.safe_load(f.read())" in patch.patched
    assert b"yaml.load(" not in patch.patched
    # Minimal: exactly one changed region, and the patched source still parses.
    assert len(patch.fixes) == 1
    assert parse(patch.patched, CodeLanguage.PYTHON).has_error is False


def test_diff_is_unified_and_changes_only_the_one_line() -> None:
    patch = generate_patch(Path("config.py"), _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    added = [ln for ln in patch.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln for ln in patch.diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    assert len(added) == 1 and len(removed) == 1
    assert "safe_load" in added[0]
    assert "yaml.load" in removed[0]


def test_no_match_returns_none() -> None:
    assert generate_patch(Path("clean.py"), "x = 1\n", CodeLanguage.PYTHON) is None


def test_handles_multiple_occurrences() -> None:
    src = "import yaml\na = yaml.load(x)\nb = yaml.load(y)\n"
    patch = generate_patch(Path("m.py"), src, CodeLanguage.PYTHON)
    assert patch is not None
    assert len(patch.fixes) == 2
    assert patch.patched.count(b"safe_load") == 2
