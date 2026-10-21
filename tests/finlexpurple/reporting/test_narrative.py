"""Phase 16: explanations are grounded or templated, never fabricated."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding
from finlexpurple.reporting.narrative import (
    Explanation,
    build_narrative,
    suggested_fix,
    template_explanation,
)


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="sqli",
        method="GET",
        url="http://t.invalid/search",
        payload="q='",
        response_snapshot="You have an error in your SQL syntax near ''",
    )


def test_template_used_when_no_explainer() -> None:
    f = _finding()
    assert build_narrative(f) == template_explanation(f)
    assert "sqli" in build_narrative(f)


def test_grounded_explanation_is_used() -> None:
    f = _finding()
    good = lambda fi: Explanation(
        text="The endpoint reflected a database error.",
        quotes=["error in your SQL syntax"],  # present in the evidence
    )
    assert build_narrative(f, explainer=good) == "The endpoint reflected a database error."


def test_ungrounded_explanation_is_rejected_and_templated() -> None:
    f = _finding()
    fabricated = lambda fi: Explanation(
        text="The database dropped the users table.",
        quotes=["DROP TABLE users"],  # NOT in the evidence
    )
    result = build_narrative(f, explainer=fabricated)
    assert result == template_explanation(f)
    assert "DROP TABLE users" not in result  # fabricated claim never reaches the report


def test_explainer_error_falls_back_to_template() -> None:
    f = _finding()
    def boom(fi: Finding) -> Explanation:
        raise RuntimeError("provider down")

    assert build_narrative(f, explainer=boom) == template_explanation(f)


def test_suggested_fix_is_template_based() -> None:
    f = _finding()
    assert "parameterized" in suggested_fix(f).lower()
