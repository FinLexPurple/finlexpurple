"""Phase 15 §5a acceptance: the four CodeFix checklist items, end to end.

Uses a deliberately vulnerable Python file (``yaml.load`` of untrusted input)
and walks: parse JS/TS + Python; a generated patch fixes the flaw and re-parses;
a syntax-breaking patch is rejected and never written; no patch is applied
without a backup existing first.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.codefix.parser import CodeLanguage, parse
from finlexpurple.codefix.patch_generator import Fix, Patch, generate_patch
from finlexpurple.codefix.safety_checks import UnsafePatchError, apply_patch, verify_patch
from finlexpurple.gates.fix_mode import FixMode

_VULN_PY = "import yaml\n\ndef load(path):\n    return yaml.load(open(path).read())\n"


def test_item1_parses_js_ts_and_python() -> None:
    assert parse("const x = 1;\n", CodeLanguage.JAVASCRIPT).has_error is False
    assert parse("let y: number = 2;\n", CodeLanguage.TYPESCRIPT).has_error is False
    assert parse(_VULN_PY, CodeLanguage.PYTHON).has_error is False


def test_item2_patch_fixes_flaw_and_reparses(tmp_path: Path) -> None:
    f = tmp_path / "config.py"
    f.write_text(_VULN_PY, encoding="utf-8")
    patch = generate_patch(f, _VULN_PY, CodeLanguage.PYTHON)
    assert patch is not None
    apply_patch(patch, fix_mode=FixMode.AGENT)
    fixed = f.read_text()
    assert "yaml.safe_load(" in fixed and "yaml.load(" not in fixed  # flaw fixed
    assert parse(fixed, CodeLanguage.PYTHON).has_error is False       # still parses


def test_item3_syntax_breaking_patch_is_rejected_and_not_written(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("x = 1\n", encoding="utf-8")
    bad = Patch(
        path=f,
        language=CodeLanguage.PYTHON,
        vulnerability_class="t",
        description="t",
        original=b"x = 1\n",
        patched=b"x = (\n",  # resplice of the fix below, but breaks parsing
        fixes=(Fix("t", "t", 4, 5, b"("),),
        diff="",
    )
    with pytest.raises(UnsafePatchError):
        verify_patch(bad)
    # apply_patch must also refuse and leave the file untouched.
    with pytest.raises(UnsafePatchError):
        apply_patch(bad, fix_mode=FixMode.AGENT)
    assert f.read_text() == "x = 1\n"


def test_item4_no_patch_applied_without_a_backup(tmp_path: Path) -> None:
    f = tmp_path / "config.py"
    f.write_text(_VULN_PY, encoding="utf-8")
    patch = generate_patch(f, _VULN_PY, CodeLanguage.PYTHON)
    assert patch is not None
    result = apply_patch(patch, fix_mode=FixMode.AGENT)
    assert result.applied is True
    assert result.backup_path is not None and result.backup_path.exists()
    # The backup holds the original, pre-fix source.
    assert result.backup_path.read_text() == _VULN_PY
