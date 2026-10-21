"""Phase 15: safety gate — only-the-construct, re-parse, backup-before-write."""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.codefix.parser import CodeLanguage
from finlexpurple.codefix.patch_generator import Fix, Patch, generate_patch
from finlexpurple.codefix.safety_checks import (
    UnsafePatchError,
    apply_patch,
    backup_file,
    verify_patch,
)
from finlexpurple.gates.fix_mode import FixMode

_VULN = "import yaml\nobj = yaml.load(data)\n"


def _patch(original: bytes, fixes: tuple[Fix, ...], patched: bytes, path: Path) -> Patch:
    return Patch(
        path=path,
        language=CodeLanguage.PYTHON,
        vulnerability_class="test",
        description="test",
        original=original,
        patched=patched,
        fixes=fixes,
        diff="",
    )


def test_verify_accepts_a_real_minimal_patch(tmp_path: Path) -> None:
    patch = generate_patch(tmp_path / "c.py", _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    verify_patch(patch)  # does not raise


def test_rejects_patch_that_edits_outside_the_construct(tmp_path: Path) -> None:
    original = b"x = 1\n"
    fix = Fix("t", "t", 4, 5, b"2")  # replace '1' -> '2'
    stray = b"x = 2\nENTIRE_EXTRA_LINE\n"  # not what resplicing the fix produces
    with pytest.raises(UnsafePatchError, match="outside"):
        verify_patch(_patch(original, (fix,), stray, tmp_path / "x.py"))


def test_rejects_patch_that_breaks_parsing(tmp_path: Path) -> None:
    original = b"x = 1\n"
    fix = Fix("t", "t", 4, 5, b"(")  # replace '1' -> '(' : valid splice, broken syntax
    patched = b"x = (\n"
    with pytest.raises(UnsafePatchError, match="does not parse"):
        verify_patch(_patch(original, (fix,), patched, tmp_path / "x.py"))


def test_backup_file_copies_original(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("original\n", encoding="utf-8")
    backup = backup_file(f)
    assert backup.name == "a.py.flp.bak"
    assert backup.read_text() == "original\n"


def test_agent_mode_applies_after_backup(tmp_path: Path) -> None:
    f = tmp_path / "c.py"
    f.write_bytes(_VULN.encode())
    patch = generate_patch(f, _VULN, CodeLanguage.PYTHON)
    assert patch is not None

    result = apply_patch(patch, fix_mode=FixMode.AGENT)

    assert result.applied is True
    # Acceptance item 4: a backup exists, and it holds the ORIGINAL (pre-fix) bytes.
    assert result.backup_path is not None and result.backup_path.exists()
    assert result.backup_path.read_bytes() == _VULN.encode()
    assert b"safe_load" in f.read_bytes()  # the fix was written


def test_human_mode_writes_nothing(tmp_path: Path) -> None:
    f = tmp_path / "c.py"
    f.write_bytes(_VULN.encode())
    patch = generate_patch(f, _VULN, CodeLanguage.PYTHON)
    assert patch is not None

    result = apply_patch(patch, fix_mode=FixMode.HUMAN)

    assert result.applied is False
    assert result.backup_path is None
    assert f.read_bytes() == _VULN.encode()  # unchanged
    assert not (tmp_path / "c.py.flp.bak").exists()
