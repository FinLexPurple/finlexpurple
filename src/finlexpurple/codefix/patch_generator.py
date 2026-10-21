"""Generate minimal, reviewable fix patches from the AST (Phase 15; §9, §2).

A fixer locates a vulnerable construct in the real tree-sitter AST and returns a
``Fix``: a single byte-range replacement, never a full-file rewrite (§9). The
patch is emitted as a unified diff suitable for a pull request. Fixers are
registered per language so new ones (and new grammars) can be added without a
rewrite.

v1 ships a Python ``yaml.load`` → ``yaml.safe_load`` fixer (unsafe
deserialization). Parsing covers JS/TS as well (parser.py); JS/TS *fixers* are a
documented extension point — a fixer only needs to be added to ``_FIXERS``.
"""

from __future__ import annotations

import difflib
from collections.abc import Callable
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from finlexpurple.codefix.parser import CodeLanguage, ParseResult, parse, walk


@dataclass(frozen=True)
class Fix:
    """A single, minimal byte-range replacement locating one vulnerable construct."""

    vulnerability_class: str
    description: str
    start_byte: int
    end_byte: int
    replacement: bytes


@dataclass(frozen=True)
class Patch:
    """A generated fix for one file: the minimal edits plus a unified diff."""

    path: Path
    language: CodeLanguage
    vulnerability_class: str
    description: str
    original: bytes
    patched: bytes
    fixes: tuple[Fix, ...]
    diff: str


Fixer = Callable[[ParseResult], list[Fix]]


def _fix_yaml_load(result: ParseResult) -> list[Fix]:
    """Python: rewrite ``yaml.load(...)`` to ``yaml.safe_load(...)``.

    Matches a call whose function is the attribute ``yaml.load`` and replaces
    only the ``load`` identifier — the minimal change that removes arbitrary
    object construction while leaving arguments and layout untouched.
    """

    fixes: list[Fix] = []
    for node in walk(result.root):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "attribute":
            continue
        if result.source[fn.start_byte : fn.end_byte] != b"yaml.load":
            continue
        for child in fn.children:
            if child.type == "identifier" and result.source[child.start_byte : child.end_byte] == b"load":
                fixes.append(
                    Fix(
                        vulnerability_class="insecure_deserialization",
                        description="Use yaml.safe_load() instead of yaml.load() to prevent "
                        "arbitrary object construction from untrusted YAML.",
                        start_byte=child.start_byte,
                        end_byte=child.end_byte,
                        replacement=b"safe_load",
                    )
                )
    return fixes


# Per-language fixer registry — the single place a new fixer is added.
_FIXERS: dict[CodeLanguage, list[Fixer]] = {
    CodeLanguage.PYTHON: [_fix_yaml_load],
    CodeLanguage.JAVASCRIPT: [],
    CodeLanguage.TYPESCRIPT: [],
}


def _splice(original: bytes, fixes: list[Fix]) -> bytes:
    """Apply non-overlapping byte-range replacements, right to left (offset-safe)."""

    patched = original
    for fix in sorted(fixes, key=lambda f: f.start_byte, reverse=True):
        patched = patched[: fix.start_byte] + fix.replacement + patched[fix.end_byte :]
    return patched


def _overlapping(fixes: list[Fix]) -> bool:
    ordered = sorted(fixes, key=lambda f: f.start_byte)
    return any(a.end_byte > b.start_byte for a, b in pairwise(ordered))


def generate_patch(path: Path, source: str | bytes, language: CodeLanguage) -> Patch | None:
    """Return a :class:`Patch` for ``source``, or ``None`` if no fixer matched.

    Runs the language's fixers over the real AST and splices their minimal
    replacements into the patched content, then builds a unified diff. Returns
    ``None`` (no fix found) rather than an empty/again-rewritten file.
    """

    result = parse(source, language)
    fixes: list[Fix] = []
    for fixer in _FIXERS.get(language, []):
        fixes.extend(fixer(result))
    if not fixes:
        return None
    if _overlapping(fixes):
        # Conservative: never emit an ambiguous, overlapping-edit patch.
        raise ValueError("overlapping fixes in one file are not supported; aborting patch.")

    original = result.source
    patched = _splice(original, fixes)
    diff = "".join(
        difflib.unified_diff(
            original.decode("utf-8", errors="replace").splitlines(keepends=True),
            patched.decode("utf-8", errors="replace").splitlines(keepends=True),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
        )
    )
    return Patch(
        path=path,
        language=language,
        vulnerability_class=fixes[0].vulnerability_class,
        description=fixes[0].description,
        original=original,
        patched=patched,
        fixes=tuple(fixes),
        diff=diff,
    )
