"""Exposed-socket and container-escape-class checks (Phase 14; §25, §15).

Original engineering (not a wrapped tool): detect the misconfigurations that let
a container escape to the host — an exposed Docker socket, a privileged
container, dangerous added capabilities, shared host namespaces, and sensitive
host-path mounts. These are the **same escape classes the agent audits its own
sandbox against** (§15).

Every check here is **static analysis** of a Dockerfile, a docker-compose file,
or a ``docker inspect`` config dict. This module never runs Docker, never mounts
the host Docker socket, and never runs anything privileged — it holds itself to
the rules it checks for (§15).
"""

from __future__ import annotations

from typing import Any

from finlexpurple.detectors.schema import Finding, Severity

_DOCKER_SOCKET = "/var/run/docker.sock"
# Capabilities that materially enable container escape or host compromise.
_DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN", "ALL"}
# Host paths whose mount into a container is an escape/host-compromise risk.
_SENSITIVE_PATHS = ("/", "/etc", "/root", "/var/run", "/proc", "/sys", "/boot", "/dev")


def _finding(klass: str, message: str, *, severity: Severity, location: str, detail: str) -> Finding:
    return Finding.new(
        vulnerability_class=klass,
        method="CONTAINER",
        url=location,
        payload=f"{klass}:{detail}",
        response_snapshot=f"{message} (source: {location})",
        expected_signal=message,
        severity=severity,
    )


def _host_path_is_sensitive(host_path: str) -> bool:
    host_path = host_path.rstrip("/") or "/"
    return any(host_path == p or host_path.startswith(p + "/") for p in _SENSITIVE_PATHS)


def check_dockerfile(text: str, *, location: str = "Dockerfile") -> list[Finding]:
    """Flag escape-relevant posture in a Dockerfile (currently: runs as root)."""

    users = [
        line.split(None, 1)[1].strip()
        for line in text.splitlines()
        if line.strip().upper().startswith("USER ") and len(line.split(None, 1)) > 1
    ]
    runs_as_root = not users or users[-1].split(":", 1)[0] in {"root", "0"}
    if runs_as_root:
        return [
            _finding(
                "container_runs_as_root",
                "container runs as root (no non-root USER set); a container escape then lands as host-adjacent root",
                severity=Severity.MEDIUM,
                location=location,
                detail="no-USER" if not users else users[-1],
            )
        ]
    return []


def check_runtime_config(config: dict[str, Any], *, location: str = "docker inspect") -> list[Finding]:
    """Flag escape classes in a ``docker inspect`` style config dict."""

    findings: list[Finding] = []
    host = config.get("HostConfig", config) if isinstance(config, dict) else {}
    if not isinstance(host, dict):
        host = {}

    if host.get("Privileged") is True:
        findings.append(
            _finding(
                "privileged_container",
                "container runs privileged (--privileged); this is a direct path to host root",
                severity=Severity.CRITICAL,
                location=location,
                detail="Privileged=true",
            )
        )

    binds = list(host.get("Binds") or [])
    mounts = config.get("Mounts") or []
    mount_sources = [m.get("Source", "") for m in mounts if isinstance(m, dict)]
    bind_sources = [b.split(":", 1)[0] for b in binds if isinstance(b, str)]
    for source in bind_sources + mount_sources:
        if source == _DOCKER_SOCKET:
            findings.append(
                _finding(
                    "exposed_docker_socket",
                    "the host Docker socket is mounted into the container; this is equivalent to host root",
                    severity=Severity.CRITICAL,
                    location=location,
                    detail=_DOCKER_SOCKET,
                )
            )
        elif source and _host_path_is_sensitive(source):
            findings.append(
                _finding(
                    "sensitive_host_mount",
                    f"a sensitive host path {source!r} is mounted into the container",
                    severity=Severity.HIGH,
                    location=location,
                    detail=source,
                )
            )

    caps = {str(c).upper().removeprefix("CAP_") for c in (host.get("CapAdd") or [])}
    for cap in sorted(caps & _DANGEROUS_CAPS):
        findings.append(
            _finding(
                "dangerous_capability",
                f"the container adds a dangerous capability (CAP_{cap})",
                severity=Severity.HIGH,
                location=location,
                detail=cap,
            )
        )

    for key, value in (("PidMode", host.get("PidMode")), ("NetworkMode", host.get("NetworkMode")),
                       ("IpcMode", host.get("IpcMode"))):
        if str(value).lower() == "host":
            findings.append(
                _finding(
                    "host_namespace_sharing",
                    f"the container shares the host namespace ({key}=host)",
                    severity=Severity.HIGH,
                    location=location,
                    detail=f"{key}=host",
                )
            )
    return findings


def check_compose(data: dict[str, Any], *, location: str = "docker-compose.yml") -> list[Finding]:
    """Flag escape classes across the services of a parsed docker-compose file."""

    findings: list[Finding] = []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        return findings
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        where = f"{location}#{name}"
        if service.get("privileged") is True:
            findings.append(
                _finding(
                    "privileged_container",
                    f"service {name!r} runs privileged (privileged: true)",
                    severity=Severity.CRITICAL,
                    location=where,
                    detail="privileged",
                )
            )
        for volume in service.get("volumes", []) or []:
            source = str(volume).split(":", 1)[0] if isinstance(volume, str) else ""
            if source == _DOCKER_SOCKET:
                findings.append(
                    _finding(
                        "exposed_docker_socket",
                        f"service {name!r} mounts the host Docker socket (equivalent to host root)",
                        severity=Severity.CRITICAL,
                        location=where,
                        detail=_DOCKER_SOCKET,
                    )
                )
            elif source and _host_path_is_sensitive(source):
                findings.append(
                    _finding(
                        "sensitive_host_mount",
                        f"service {name!r} mounts a sensitive host path {source!r}",
                        severity=Severity.HIGH,
                        location=where,
                        detail=source,
                    )
                )
        caps = {str(c).upper().removeprefix("CAP_") for c in (service.get("cap_add") or [])}
        for cap in sorted(caps & _DANGEROUS_CAPS):
            findings.append(
                _finding(
                    "dangerous_capability",
                    f"service {name!r} adds a dangerous capability (CAP_{cap})",
                    severity=Severity.HIGH,
                    location=where,
                    detail=cap,
                )
            )
        for key in ("pid", "network_mode", "ipc"):
            if str(service.get(key, "")).lower() == "host":
                findings.append(
                    _finding(
                        "host_namespace_sharing",
                        f"service {name!r} shares the host namespace ({key}: host)",
                        severity=Severity.HIGH,
                        location=where,
                        detail=f"{key}=host",
                    )
                )
    return findings
