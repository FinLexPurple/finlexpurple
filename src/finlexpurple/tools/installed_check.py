"""Backing for ``finlexpurple doctor --tools`` (Phase 7).

Reports which registered external tools (registry.py) are installed and, for
any that are missing, prints an OS-appropriate install hint. This is distinct
from the Phase 2 hardware ``doctor``: that reports the machine; this reports the
external scanner binaries the wrap-OSS phases depend on.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass

from finlexpurple.tools.registry import ExternalTool, registered_tools


@dataclass(frozen=True)
class ToolStatus:
    """Whether one registered tool is installed, and where."""

    tool: ExternalTool
    installed: bool
    path: str | None


def _os_key(system: str | None = None) -> str:
    name = (system or platform.system()).lower()
    if name == "darwin":
        return "darwin"
    if name == "windows":
        return "windows"
    return "linux"


def check_tools(tools: list[ExternalTool] | None = None) -> list[ToolStatus]:
    """Return install status for each registered tool (or the given subset)."""

    resolved = tools if tools is not None else registered_tools()
    statuses: list[ToolStatus] = []
    for tool in resolved:
        path = tool.installed_path()
        statuses.append(ToolStatus(tool=tool, installed=path is not None, path=path))
    return statuses


def format_tool_report(statuses: list[ToolStatus], *, system: str | None = None) -> str:
    """Render a human-readable report with per-OS install hints for missing tools."""

    os_key = _os_key(system)
    installed = [s for s in statuses if s.installed]
    missing = [s for s in statuses if not s.installed]
    lines = [
        (
            f"External tools: {len(installed)} installed, {len(missing)} missing "
            f"(install hints shown for the current OS: {os_key})."
        ),
        "",
    ]
    for status in statuses:
        if status.installed:
            lines.append(f"  installed  {status.tool.name:<12} {status.tool.purpose}")
        else:
            lines.append(f"  MISSING    {status.tool.name:<12} {status.tool.purpose}")
    if missing:
        lines.append("")
        lines.append("To install the missing tools:")
        for status in missing:
            hint = status.tool.install_hints.get(os_key, "(see the tool's documentation)")
            lines.append(f"  {status.tool.name}: {hint}")
    return "\n".join(lines)
