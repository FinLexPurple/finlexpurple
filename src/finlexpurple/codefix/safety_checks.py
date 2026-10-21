"""Safety gate between a generated patch and the filesystem (Phase 15; §9, §2).

Three guarantees, enforced here rather than trusted to the caller:

* **Touches only the vulnerable construct.** The patched bytes must equal the
  original with *only* the located fix spans replaced — no stray edits anywhere
  else in the file (verified by independently re-splicing).
* **Still parses.** The patched source is re-parsed with the real tree-sitter
  grammar; if it introduces a syntax error the original did not have, the patch
  is rejected and never written.
* **Backup before any write.** The original file is copied to a ``.flp.bak``
  sibling *before* the patched content is written, so no patch is ever applied
  without a backup already on disk.

Whether a patch is written at all is governed by the user's fix mode (§2):
Agent Fix may apply it; Human Fix only ever emits the diff.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from finlexpurple.codefix.parser import parse
from finlexpurple.codefix.patch_generator import Fix, Patch
from finlexpurple.gates.fix_mode import FixMode

BACKUP_SUFFIX = ".flp.bak"


class UnsafePatchError(ValueError):
    """A patch failed a safety check and must not be written."""


@dataclass(frozen=True)
class ApplyResult:
    """The outcome of an apply attempt."""

    applied: bool
    backup_path: Path | None
    reason: str


def _resplice(original: bytes, fixes: tuple[Fix, ...]) -> bytes:
    """Independently re-derive the patched bytes from the original + fix spans."""

    patched = original
    for fix in sorted(fixes, key=lambda f: f.start_byte, reverse=True):
        patched = patched[: fix.start_byte] + fix.replacement + patched[fix.end_byte :]
    return patched


def verify_patch(patch: Patch) -> None:
    """Raise :class:`UnsafePatchError` unless the patch is safe to apply.

    Checks that the patch touches only its located construct(s) and that the
    patched source still parses cleanly.
    """

    if _resplice(patch.original, patch.fixes) != patch.patched:
        raise UnsafePatchError(
            "patch alters bytes outside the located vulnerable construct(s); refusing it."
        )
    original_parses = not parse(patch.original, patch.language).has_error
    patched_has_error = parse(patch.patched, patch.language).has_error
    if patched_has_error and original_parses:
        raise UnsafePatchError(
            "patched source does not parse; refusing to apply a syntax-breaking fix."
        )


def backup_file(path: Path) -> Path:
    """Copy ``path`` to a ``.flp.bak`` sibling and return the backup path."""

    backup = path.with_name(path.name + BACKUP_SUFFIX)
    backup.write_bytes(path.read_bytes())
    return backup


def apply_patch(patch: Patch, *, fix_mode: FixMode) -> ApplyResult:
    """Apply ``patch`` to its file if the fix mode allows, after a safety check.

    Always verifies safety first (an unsafe patch raises and is never written).
    In Human Fix mode nothing is written. In Agent Fix mode the original is
    backed up *before* the patched content is written.
    """

    verify_patch(patch)  # unsafe patches never reach the filesystem
    if not fix_mode.applies_patches:  # property, True only in Agent Fix mode
        return ApplyResult(
            applied=False,
            backup_path=None,
            reason="Human fix mode: diff emitted for review; no file written.",
        )
    backup = backup_file(patch.path)  # backup exists before any write
    patch.path.write_bytes(patch.patched)
    return ApplyResult(
        applied=True,
        backup_path=backup,
        reason="Agent fix mode: patch applied after backing up the original.",
    )
