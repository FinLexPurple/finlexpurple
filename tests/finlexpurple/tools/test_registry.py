"""Phase 7: external tool registry and installed-check (decisions.md §20)."""

from __future__ import annotations

import sys

import pytest

from finlexpurple.tools.installed_check import ToolStatus, check_tools, format_tool_report
from finlexpurple.tools.registry import TOOL_REGISTRY, ExternalTool, registered_tools


def test_registry_lists_the_wrapped_scanners_and_docker() -> None:
    names = set(TOOL_REGISTRY)
    assert {"docker", "trivy", "grype", "osv-scanner", "pip-audit", "mcp-scan", "hadolint", "dockle"} <= names
    # Every tool carries a purpose and at least one install hint.
    for tool in registered_tools():
        assert tool.purpose
        assert tool.install_hints


def test_installed_tool_resolves_and_runs() -> None:
    # Use the Python interpreter as a guaranteed-present "tool" to exercise run().
    python_tool = ExternalTool("python", sys.executable, "the interpreter")
    assert python_tool.is_installed()
    result = python_tool.run(["-c", "print('hi')"], timeout=10)
    assert result.returncode == 0 and "hi" in result.stdout


def test_missing_tool_run_raises_filenotfound() -> None:
    absent = ExternalTool("nope", "finlexpurple-not-a-real-binary", "absent")
    assert absent.is_installed() is False
    with pytest.raises(FileNotFoundError, match="not installed"):
        absent.run(["--version"], timeout=5)


def test_report_marks_installed_and_missing_with_os_hint() -> None:
    present = ExternalTool("python", sys.executable, "the interpreter", {"linux": "already here"})
    absent = ExternalTool("ghost", "finlexpurple-absent-binary", "absent", {"linux": "apt install ghost"})
    statuses = check_tools([present, absent])
    assert [s.installed for s in statuses] == [True, False]
    report = format_tool_report(statuses, system="Linux")
    assert "installed  python" in report
    assert "MISSING    ghost" in report
    assert "apt install ghost" in report  # install hint shown for the missing tool


def test_check_tools_returns_status_objects() -> None:
    statuses = check_tools()
    assert statuses and all(isinstance(s, ToolStatus) for s in statuses)
