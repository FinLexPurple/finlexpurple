"""Phase 15: tree-sitter parsing for Python and JS/TS, with real error detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.codefix.parser import (
    CodeLanguage,
    UnsupportedLanguageError,
    language_for_path,
    parse,
    parse_path,
)


def test_parses_representative_python() -> None:
    result = parse("import os\n\ndef f(x):\n    return os.path.join(x, 'a')\n", CodeLanguage.PYTHON)
    assert result.has_error is False
    assert result.root.type == "module"


def test_parses_representative_javascript() -> None:
    result = parse("const add = (a, b) => a + b;\nexport default add;\n", CodeLanguage.JAVASCRIPT)
    assert result.has_error is False
    assert result.root.type == "program"


def test_parses_representative_typescript() -> None:
    result = parse("function greet(name: string): string {\n  return `hi ${name}`;\n}\n", CodeLanguage.TYPESCRIPT)
    assert result.has_error is False
    assert result.root.type == "program"


def test_syntax_error_is_surfaced_not_hidden() -> None:
    # A real syntax error must set has_error (the safety check relies on this).
    assert parse("def broken(:\n", CodeLanguage.PYTHON).has_error is True


def test_language_for_path_maps_extensions() -> None:
    assert language_for_path(Path("a.py")) is CodeLanguage.PYTHON
    assert language_for_path(Path("a.jsx")) is CodeLanguage.JAVASCRIPT
    assert language_for_path(Path("a.tsx")) is CodeLanguage.TYPESCRIPT


def test_unsupported_language_raises() -> None:
    with pytest.raises(UnsupportedLanguageError):
        language_for_path(Path("main.go"))


def test_parse_path_reads_and_parses(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("x = 1\n", encoding="utf-8")
    assert parse_path(f).has_error is False
