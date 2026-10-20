"""Registry of external tools FinLexPurple wraps (Phase 7; decisions.md §20).

Each entry declares an external tool's name, the binary to look for, a one-line
purpose, and per-OS install hints. The registry exists so ``finlexpurple doctor
--tools`` (Phase 7) can report what is installed and tell the user how to get
what is missing, and so later phases run these tools only through the hardened
sandbox. The tools listed are the best-of-breed scanners the product wraps
rather than rebuilds (decisions.md §20); the wrappers that parse their output
into the Finding schema arrive in Phases 13–14.

The install hints are advisory display strings — point the user at the
ecosystem/official docs rather than asserting an exact command that may drift.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from finlexpurple.tools.sandbox import ToolResult, run_sandboxed


@dataclass(frozen=True)
class ExternalTool:
    """Metadata for one wrappable external tool and how to run it safely."""

    name: str
    binary: str
    purpose: str
    install_hints: dict[str, str] = field(default_factory=dict)

    def installed_path(self) -> str | None:
        """Return the resolved path to the binary, or ``None`` if not on PATH."""

        return shutil.which(self.binary)

    def is_installed(self) -> bool:
        return self.installed_path() is not None

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: float,
        cwd: Path | None = None,
    ) -> ToolResult:
        """Run the tool with the given arguments through the hardened sandbox.

        The binary is always argv[0]; callers pass arguments as a list, never a
        shell string. Raises ``FileNotFoundError`` if the tool is not installed.
        """

        if not self.is_installed():
            raise FileNotFoundError(
                f"{self.name} is not installed (binary {self.binary!r} not found on PATH)."
            )
        return run_sandboxed([self.binary, *[str(a) for a in args]], timeout=timeout, cwd=cwd)


# The wrapped best-of-breed scanners (decisions.md §20) plus Docker, which the
# Standard isolation tier (Section 27) needs. Keyed by tool name.
TOOL_REGISTRY: dict[str, ExternalTool] = {
    tool.name: tool
    for tool in (
        ExternalTool(
            "docker", "docker", "Container runtime for the Standard isolation tier",
            {
                "linux": "Install Docker Engine (https://docs.docker.com/engine/install/) or Docker Desktop.",
                "darwin": "Install Docker Desktop (https://docs.docker.com/desktop/install/mac-install/).",
                "windows": "Install Docker Desktop with WSL2 integration (https://docs.docker.com/desktop/install/windows-install/).",
            },
        ),
        ExternalTool(
            "trivy", "trivy", "Container image & filesystem vulnerability scanner (Phase 14)",
            {
                "linux": "See https://trivy.dev/latest/getting-started/installation/",
                "darwin": "brew install trivy",
                "windows": "scoop install trivy (or see https://trivy.dev/latest/getting-started/installation/)",
            },
        ),
        ExternalTool(
            "grype", "grype", "Container image & SBOM vulnerability scanner (Phase 14)",
            {
                "linux": "See https://github.com/anchore/grype#installation",
                "darwin": "brew install grype",
                "windows": "scoop install grype (or see https://github.com/anchore/grype#installation)",
            },
        ),
        ExternalTool(
            "osv-scanner", "osv-scanner", "Dependency vulnerability scanner via OSV (Phase 13)",
            {
                "linux": "See https://google.github.io/osv-scanner/installation/",
                "darwin": "brew install osv-scanner",
                "windows": "scoop install osv-scanner (or see https://google.github.io/osv-scanner/installation/)",
            },
        ),
        ExternalTool(
            "pip-audit", "pip-audit", "Python dependency vulnerability auditor (Phase 13)",
            {
                "linux": "pipx install pip-audit  (or: pip install pip-audit)",
                "darwin": "pipx install pip-audit  (or: pip install pip-audit)",
                "windows": "pipx install pip-audit  (or: pip install pip-audit)",
            },
        ),
        ExternalTool(
            "cosign", "cosign", "Sigstore signing/verification for evidence bundles (Phase 12)",
            {
                "linux": "See https://docs.sigstore.dev/cosign/system_config/installation/",
                "darwin": "brew install cosign",
                "windows": "scoop install cosign (or see https://docs.sigstore.dev/cosign/system_config/installation/)",
            },
        ),
        ExternalTool(
            "mcp-scan", "mcp-scan", "Passive MCP configuration scanner (Phase 9)",
            {
                "linux": "pipx install mcp-scan  (verify the current command in its project docs)",
                "darwin": "pipx install mcp-scan  (verify the current command in its project docs)",
                "windows": "pipx install mcp-scan  (verify the current command in its project docs)",
            },
        ),
        ExternalTool(
            "hadolint", "hadolint", "Dockerfile linter (Phase 14)",
            {
                "linux": "See https://github.com/hadolint/hadolint#install",
                "darwin": "brew install hadolint",
                "windows": "scoop install hadolint (or see https://github.com/hadolint/hadolint#install)",
            },
        ),
        ExternalTool(
            "dockle", "dockle", "Container image best-practice/CIS checker (Phase 14)",
            {
                "linux": "See https://github.com/goodwithtech/dockle#installation",
                "darwin": "brew install dockle",
                "windows": "scoop install dockle (or see https://github.com/goodwithtech/dockle#installation)",
            },
        ),
    )
}


def registered_tools() -> list[ExternalTool]:
    """Return the registered tools in stable (name-sorted) order."""

    return [TOOL_REGISTRY[name] for name in sorted(TOOL_REGISTRY)]
