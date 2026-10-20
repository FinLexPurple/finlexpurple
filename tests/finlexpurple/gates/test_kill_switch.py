"""Phase 8: kill switch / emergency stop (decisions.md §28 item 8)."""

from __future__ import annotations

import signal
import sys

import pytest

from finlexpurple.gates.kill_switch import KillSwitch
from finlexpurple.security.safe_failure import SafeFailureController, StoppedAtSafePoint


def test_trigger_requests_stop_and_calls_on_stop() -> None:
    controller = SafeFailureController()
    saved: list[str] = []
    switch = KillSwitch(controller, on_stop=lambda: saved.append("state-saved"))
    switch.trigger()
    assert controller.stop_requested is True
    assert saved == ["state-saved"]


def test_signal_handler_requests_stop() -> None:
    controller = SafeFailureController()
    switch = KillSwitch(controller)
    switch._handler(int(signal.SIGINT), None)
    assert controller.stop_requested is True


def test_arm_installs_a_working_handler_and_disarm_restores() -> None:
    controller = SafeFailureController()
    original = signal.getsignal(signal.SIGINT)
    switch = KillSwitch(controller)
    switch.arm()
    installed = signal.getsignal(signal.SIGINT)
    assert installed is not original  # a handler was installed
    installed(int(signal.SIGINT), None)  # and it requests a stop when invoked
    assert controller.stop_requested is True
    if sys.platform != "win32":
        assert signal.getsignal(signal.SIGTERM) is not original
    switch.disarm()
    assert signal.getsignal(signal.SIGINT) is original  # previous handler restored


def test_context_manager_arms_and_disarms() -> None:
    controller = SafeFailureController()
    original = signal.getsignal(signal.SIGINT)
    with KillSwitch(controller):
        assert signal.getsignal(signal.SIGINT) is not original
    assert signal.getsignal(signal.SIGINT) is original


def test_kill_then_checkpoint_halts_at_a_safe_point() -> None:
    # End-to-end against a synthetic run: a stop requested mid-critical-section is
    # deferred, and the run halts cleanly at the next checkpoint (safe point).
    controller = SafeFailureController()
    switch = KillSwitch(controller)
    completed_step = []
    with controller.critical_section():
        switch.trigger()           # operator hits the kill switch mid-step
        completed_step.append("step finished")  # the step still completes
    assert completed_step == ["step finished"]
    with pytest.raises(StoppedAtSafePoint):
        controller.checkpoint()    # halts here, at the safe boundary
