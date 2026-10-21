"""AST parsing for the CodeFix/whitebox module (Phase 15; decisions.md §9).

Wraps the tree-sitter parsing library — the "tree-based parsing library capable
of supporting additional languages later without a rewrite" (§9). v1 language
scope is **JavaScript/TypeScript and Python only**; the ``Language`` enum plus
the extension map are the single place a new grammar is added.

Parse errors are surfaced, never hidden: ``ParseResult.has_error`` reflects
tree-sitter's own error state (``root_node.has_error``), so a caller — e.g. the
safety check that re-parses a patched file — can refuse to proceed on a file the
real parser could not parse cleanly.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from functools import cache
from pathlib import Path

import tree_sitter_javascript as _ts_js
import tree_sitter_python as _ts_py
import tree_sitter_typescript as _ts_ts
from tree_sitter import Language, Node, Parser, Tree


class CodeLanguage(str, Enum):
    """The languages the CodeFix module can parse (v1: JS/TS + Python only)."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


class UnsupportedLanguageError(ValueError):
    """A file's language is outside the CodeFix v1 scope (JS/TS + Python)."""


# The one place languages are registered. Add a grammar here to extend scope.
_LANGUAGE_FACTORIES = {
    CodeLanguage.PYTHON: _ts_py.language,
    CodeLanguage.JAVASCRIPT: _ts_js.language,
    CodeLanguage.TYPESCRIPT: _ts_ts.language_typescript,
}

_EXTENSION_LANGUAGE = {
    ".py": CodeLanguage.PYTHON,
    ".js": CodeLanguage.JAVASCRIPT,
    ".jsx": CodeLanguage.JAVASCRIPT,
    ".mjs": CodeLanguage.JAVASCRIPT,
    ".cjs": CodeLanguage.JAVASCRIPT,
    ".ts": CodeLanguage.TYPESCRIPT,
    ".tsx": CodeLanguage.TYPESCRIPT,
}


@dataclass(frozen=True)
class ParseResult:
    """A parsed tree plus the real parser's error state and the source bytes."""

    tree: Tree
    language: CodeLanguage
    source: bytes

    @property
    def root(self) -> Node:
        return self.tree.root_node

    @property
    def has_error(self) -> bool:
        """True if tree-sitter marked any syntax error (surfaced, never hidden)."""

        return self.tree.root_node.has_error


def language_for_path(path: Path) -> CodeLanguage:
    """Map a file path to its language, or raise :class:`UnsupportedLanguageError`."""

    language = _EXTENSION_LANGUAGE.get(path.suffix.lower())
    if language is None:
        raise UnsupportedLanguageError(
            f"{path.name}: CodeFix v1 supports only Python and JavaScript/TypeScript."
        )
    return language


@cache
def _parser_for(language: CodeLanguage) -> Parser:
    return Parser(Language(_LANGUAGE_FACTORIES[language]()))


def parse(source: str | bytes, language: CodeLanguage) -> ParseResult:
    """Parse ``source`` in ``language`` with the real tree-sitter grammar."""

    data = source.encode("utf-8") if isinstance(source, str) else source
    tree = _parser_for(language).parse(data)
    return ParseResult(tree=tree, language=language, source=data)


def parse_path(path: Path) -> ParseResult:
    """Parse a file, choosing the grammar from its extension."""

    language = language_for_path(path)
    return parse(path.read_bytes(), language)


def walk(node: Node) -> Iterator[Node]:
    """Yield ``node`` and all its descendants, depth-first."""

    yield node
    for child in node.children:
        yield from walk(child)
