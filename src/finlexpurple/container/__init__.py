"""Container testing module (Phase 14; decisions.md §20, §25, §15).

Tests the containers a *target* ships in — image CVEs (Trivy, Grype),
Dockerfile/image best-practice and CIS checks (Dockle, hadolint), and original
checks for an exposed Docker socket and container-escape classes. The wrapped
scanners' real output is normalized into the Finding schema, never paraphrased
(§20).

This module tests the TARGET's containers; it is **distinct** from the agent's
own §27 isolation tiers (the sandbox we run *inside*). It also holds itself to
the rules it checks for: it never mounts the host Docker socket and never runs
privileged (§15).
"""
