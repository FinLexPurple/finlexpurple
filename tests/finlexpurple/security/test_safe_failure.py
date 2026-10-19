"""Phase 7: safe-failure framework (decisions.md §28 item 10)."""

from __future__ import annotations

import pytest

from finlexpurple.security.safe_failure import SafeFailureController, StoppedAtSafePoint


def test_checkpoint_is_a_no_op_without_a_stop_request() -> None:
    controller = SafeFailureController()
    controller.checkpoint()  # does nothing


def test_checkpoint_halts_cleanly_after_a_stop_request() -> None:
    controller = SafeFailureController()
    controller.request_stop()
    assert controller.stop_requested is True
    with pytest.raises(StoppedAtSafePoint):
        controller.checkpoint()


def test_stop_is_deferred_inside_a_critical_section() -> None:
    controller = SafeFailureController()
    with controller.critical_section():
        controller.request_stop()
        # A stop requested mid-step must NOT interrupt it here.
        controller.checkpoint()  # deferred: does not raise inside the section
    # Once out of the section, the next safe point honors the stop.
    with pytest.raises(StoppedAtSafePoint):
        controller.checkpoint()


def test_critical_section_rolls_back_on_failure_then_reraises() -> None:
    controller = SafeFailureController()
    rolled_back: list[str] = []

    with (
        pytest.raises(ValueError, match="boom"),
        controller.critical_section(rollback=lambda: rolled_back.append("undone")),
    ):
        raise ValueError("boom")

    assert rolled_back == ["undone"]
    assert controller.in_critical_section is False


def test_rollback_failure_does_not_mask_original_error() -> None:
    controller = SafeFailureController()

    def bad_rollback() -> None:
        raise RuntimeError("rollback also failed")

    with (
        pytest.raises(ValueError, match="original"),
        controller.critical_section(rollback=bad_rollback),
    ):
        raise ValueError("original")
